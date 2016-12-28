// Copyright 2016 The Fuchsia Authors
//
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT

#include <err.h>
#include <new.h>
#include <platform.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <trace.h>

#include <kernel/auto_lock.h>
#include <kernel/vm/vm_object.h>
#include <kernel/vm/vm_address_region.h>

#include <lib/console.h>
#include <lib/user_copy.h>
#include <lib/user_copy/user_ptr.h>
#include <lib/ktrace.h>

#include <lk/init.h>
#include <platform/debug.h>

#include <magenta/process_dispatcher.h>
#include <magenta/syscalls/debug.h>
#include <magenta/thread_dispatcher.h>
#include <magenta/user_copy.h>

#include <mxtl/array.h>

#include "syscalls_priv.h"

#define LOCAL_TRACE 0

constexpr uint32_t kMaxDebugWriteSize = 256u;
constexpr size_t kMaxDebugReadBlock = 64 * 1024u * 1024u;
constexpr size_t kMaxDebugWriteBlock = 64 * 1024u * 1024u;

constexpr uint32_t kMaxThreadStateSize = MX_MAX_THREAD_STATE_SIZE;

#if WITH_LIB_DEBUGLOG
#include <lib/debuglog.h>
#endif

mx_status_t sys_debug_read(mx_handle_t handle, void* ptr, uint32_t len) {
    LTRACEF("ptr %p\n", ptr);

    // TODO: finer grained validation
    mx_status_t status;
    if ((status = validate_resource_handle(handle)) < 0) {
        return status;
    }

    if (!len)
        return 0;
    // TODO: remove this cast.
    auto uptr = reinterpret_cast<uint8_t*>(ptr);
    auto end = uptr + len;

    for (; uptr != end; ++uptr) {
        int c = getchar();
        if (c < 0)
            break;

        if (c == '\r')
            c = '\n';
        if (copy_to_user_u8_unsafe(uptr, static_cast<uint8_t>(c)) != NO_ERROR)
            break;
    }
    // TODO: fix this cast, which can overflow.
    return static_cast<int>(reinterpret_cast<char*>(uptr) - reinterpret_cast<char*>(ptr));
}

mx_status_t sys_debug_write(const void* ptr, uint32_t len) {
    LTRACEF("ptr %p, len %u\n", ptr, len);

    if (len > kMaxDebugWriteSize)
        len = kMaxDebugWriteSize;

    char buf[kMaxDebugWriteSize];
    if (magenta_copy_from_user(ptr, buf, len) != NO_ERROR)
        return ERR_INVALID_ARGS;

    for (uint32_t i = 0; i < len; i++) {
        platform_dputc(buf[i]);
    }
    return len;
}

mx_status_t sys_debug_send_command(mx_handle_t handle, const void* ptr, uint32_t len) {
    LTRACEF("ptr %p, len %u\n", ptr, len);

    // TODO: finer grained validation
    mx_status_t status;
    if ((status = validate_resource_handle(handle)) < 0) {
        return status;
    }

    if (len > kMaxDebugWriteSize)
        return ERR_INVALID_ARGS;

    char buf[kMaxDebugWriteSize + 2];
    if (magenta_copy_from_user(ptr, buf, len) != NO_ERROR)
        return ERR_INVALID_ARGS;

    buf[len] = '\n';
    buf[len + 1] = 0;
    return console_run_script(buf);
}

mx_handle_t sys_debug_transfer_handle(mx_handle_t proc, mx_handle_t src_handle) {
    auto up = ProcessDispatcher::GetCurrent();

    mxtl::RefPtr<ProcessDispatcher> process;
    mx_status_t status = up->GetDispatcher(proc, &process,
                                           MX_RIGHT_READ | MX_RIGHT_WRITE);
    if (status != NO_ERROR)
        return status;

    // Disallow this call on self.
    if (process.get() == up)
        return ERR_INVALID_ARGS;

    HandleUniquePtr handle = up->RemoveHandle(src_handle);
    if (!handle)
        return ERR_BAD_HANDLE;

    auto dest_hv = process->MapHandleToValue(handle.get());
    process->AddHandle(mxtl::move(handle));
    return dest_hv;
}

mx_status_t sys_process_read_memory(mx_handle_t proc, uintptr_t vaddr,
                                    void* _buffer,
                                    size_t len, size_t* _actual) {
    if (!_buffer)
        return ERR_INVALID_ARGS;
    if (len == 0 || len > kMaxDebugReadBlock)
        return ERR_INVALID_ARGS;

    auto up = ProcessDispatcher::GetCurrent();

    mxtl::RefPtr<ProcessDispatcher> process;
    mx_status_t status = up->GetDispatcher(proc, &process,
                                           MX_RIGHT_READ | MX_RIGHT_WRITE);
    if (status != NO_ERROR)
        return status;

    auto aspace = process->aspace();
    if (!aspace)
        return ERR_BAD_STATE;

    auto region = aspace->FindRegion(vaddr);
    if (!region)
        return ERR_NO_MEMORY;

    auto vm_mapping = region->as_vm_mapping();
    if (!vm_mapping)
        return ERR_NO_MEMORY;

    auto vmo = vm_mapping->vmo();
    if (!vmo)
        return ERR_NO_MEMORY;

    uint64_t offset = vaddr - vm_mapping->base() + vm_mapping->object_offset();
    size_t read = 0;

    status_t st = vmo->ReadUser(make_user_ptr(_buffer), offset, len, &read);

    if (st == NO_ERROR) {
        if (make_user_ptr(_actual).copy_to_user(static_cast<size_t>(read)) != NO_ERROR)
            return ERR_INVALID_ARGS;
    }
    return st;
}

mx_status_t sys_process_write_memory(mx_handle_t proc, uintptr_t vaddr,
                                     const void* _buffer,
                                     size_t len, size_t* _actual) {
    if (!_buffer)
        return ERR_INVALID_ARGS;
    if (len == 0 || len > kMaxDebugWriteBlock)
        return ERR_INVALID_ARGS;

    auto up = ProcessDispatcher::GetCurrent();

    mxtl::RefPtr<ProcessDispatcher> process;
    mx_status_t status = up->GetDispatcher(proc, &process, MX_RIGHT_WRITE);
    if (status != NO_ERROR)
        return status;

    auto aspace = process->aspace();
    if (!aspace)
        return ERR_BAD_STATE;

    auto region = aspace->FindRegion(vaddr);
    if (!region)
        return ERR_NO_MEMORY;

    auto vm_mapping = region->as_vm_mapping();
    if (!vm_mapping)
        return ERR_NO_MEMORY;

    auto vmo = vm_mapping->vmo();
    if (!vmo)
        return ERR_NO_MEMORY;

    uint64_t offset = vaddr - vm_mapping->base() + vm_mapping->object_offset();
    size_t written = 0;

    status_t st = vmo->WriteUser(make_user_ptr(_buffer), offset, len, &written);

    if (st == NO_ERROR) {
        if (make_user_ptr(_actual).copy_to_user(static_cast<size_t>(written)) != NO_ERROR)
            return ERR_INVALID_ARGS;
    }
    return st;
}

mx_status_t sys_ktrace_read(mx_handle_t handle, void* _data,
                            uint32_t offset, uint32_t len,
                            uint32_t* _actual) {
    // TODO: finer grained validation
    mx_status_t status;
    if ((status = validate_resource_handle(handle)) < 0) {
        return status;
    }

    int result = ktrace_read_user(_data, offset, len);
    if (result < 0)
        return result;

    return make_user_ptr(_actual).copy_to_user(static_cast<uint32_t>(result));
}

mx_status_t sys_ktrace_control(mx_handle_t handle, uint32_t action, uint32_t options, void* _ptr) {
    // TODO: finer grained validation
    mx_status_t status;
    if ((status = validate_resource_handle(handle)) < 0) {
        return status;
    }

    switch (action) {
    case KTRACE_ACTION_NEW_PROBE: {
        char name[MX_MAX_NAME_LEN];
        if (make_user_ptr(_ptr).copy_array_from_user(name, sizeof(name) - 1) != NO_ERROR)
            return ERR_INVALID_ARGS;
        name[sizeof(name) - 1] = 0;
        return ktrace_control(action, options, name);
    }
    default:
        return ktrace_control(action, options, nullptr);
    }
}

mx_status_t sys_ktrace_write(mx_handle_t handle, uint32_t event_id, uint32_t arg0, uint32_t arg1) {
    // TODO: finer grained validation
    mx_status_t status;
    if ((status = validate_resource_handle(handle)) < 0) {
        return status;
    }

    if (event_id > 0x7FF) {
        return ERR_INVALID_ARGS;
    }

    uint32_t* args = static_cast<uint32_t*>(ktrace_open(TAG_PROBE_24(event_id)));
    if (!args) {
        //  There is not a single reason for failure. Assume it reached the end.
        return ERR_UNAVAILABLE;
    }

    args[0] = arg0;
    args[1] = arg1;
    return NO_ERROR;
}

mx_status_t sys_perf_trace_read(mx_handle_t handle, void* _data,
                                uint32_t offset, uint32_t len,
                                uint32_t* _actual) {
    // TODO: finer grained validation
    mx_status_t status;
    if ((status = validate_resource_handle(handle)) < 0) {
        return status;
    }

    int result = ktrace_read_user(_data, offset, len);
    if (result < 0)
        return result;

    return make_user_ptr(_actual).copy_to_user(static_cast<uint32_t>(result));
}

mx_status_t sys_perf_trace_control(mx_handle_t handle, uint32_t action, uint32_t options, void* _ptr) {
    // TODO: finer grained validation
    mx_status_t status;
    if ((status = validate_resource_handle(handle)) < 0) {
        return status;
    }

    switch (action) {
    case KTRACE_ACTION_NEW_PROBE: {
        char name[MX_MAX_NAME_LEN];
        if (make_user_ptr(_ptr).copy_array_from_user(name, sizeof(name) - 1) != NO_ERROR)
            return ERR_INVALID_ARGS;
        name[sizeof(name) - 1] = 0;
        return ktrace_control(action, options, name);
    }
    default:
        return ktrace_control(action, options, nullptr);
    }
}

mx_status_t sys_thread_read_state(mx_handle_t handle, uint32_t state_kind,
                                  void* _buffer,
                                  uint32_t buffer_len, uint32_t* _actual) {
    LTRACEF("handle %d, state_kind %u\n", handle, state_kind);

    auto up = ProcessDispatcher::GetCurrent();

    // TODO(dje): debug rights
    mxtl::RefPtr<ThreadDispatcher> thread;
    mx_status_t status = up->GetDispatcher(handle, &thread, MX_RIGHT_READ);
    if (status != NO_ERROR)
        return status;

    // avoid malloc'ing insane amounts
    if (buffer_len > kMaxThreadStateSize)
        return ERR_INVALID_ARGS;

    AllocChecker ac;
    uint8_t* tmp_buf = new (&ac) uint8_t [buffer_len];
    if (!ac.check())
        return ERR_NO_MEMORY;
    mxtl::Array<uint8_t> bytes(tmp_buf, buffer_len);

    status = thread->thread()->ReadState(state_kind, bytes.get(), &buffer_len);

    // Always set the actual size so the caller can provide larger buffers.
    // The value is only usable if the status is NO_ERROR or ERR_BUFFER_TOO_SMALL.
    if (status == NO_ERROR || status == ERR_BUFFER_TOO_SMALL) {
        if (make_user_ptr(_actual).copy_to_user(buffer_len) != NO_ERROR)
            return ERR_INVALID_ARGS;
    }

    if (status != NO_ERROR)
        return status;

    if (make_user_ptr(_buffer).copy_array_to_user(bytes.get(), buffer_len) != NO_ERROR)
        return ERR_INVALID_ARGS;

    return NO_ERROR;
}

mx_status_t sys_thread_write_state(mx_handle_t handle, uint32_t state_kind,
                                   const void* _buffer, uint32_t buffer_len) {
    LTRACEF("handle %d, state_kind %u\n", handle, state_kind);

    auto up = ProcessDispatcher::GetCurrent();

    // TODO(dje): debug rights
    mxtl::RefPtr<ThreadDispatcher> thread;
    mx_status_t status = up->GetDispatcher(handle, &thread, MX_RIGHT_WRITE);
    if (status != NO_ERROR)
        return status;

    // avoid malloc'ing insane amounts
    if (buffer_len > kMaxThreadStateSize)
        return ERR_INVALID_ARGS;

    AllocChecker ac;
    uint8_t* tmp_buf = new (&ac) uint8_t [buffer_len];
    if (!ac.check())
        return ERR_NO_MEMORY;
    mxtl::Array<uint8_t> bytes(tmp_buf, buffer_len);

    status = make_user_ptr(_buffer).copy_array_from_user(bytes.get(), buffer_len);
    if (status != NO_ERROR)
        return ERR_INVALID_ARGS;

    // TODO(dje): Setting privileged values in registers.
    status = thread->thread()->WriteState(state_kind, bytes.get(), buffer_len, false);
    return status;
}
