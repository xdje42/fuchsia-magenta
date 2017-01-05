// Copyright 2016 The Fuchsia Authors
//
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT

#include "lib/mtrace.h"

#include <arch/user_copy.h>
#include <kernel/mp.h>
#include <magenta/mtrace.h>

#ifdef __x86_64__
#include "arch/x86/processor_trace.h"
#endif

status_t mtrace_control(uint32_t action, uint32_t options, void* arg) {
#ifdef __x86_64__
    switch (action) {
    case MTRACE_ACTION_ALLOC: {
        return x86_processor_trace_alloc();
    }
    case MTRACE_ACTION_START: {
        return x86_processor_trace_start();
    }
    case MTRACE_ACTION_STOP: {
        return x86_processor_trace_stop();
    }
    case MTRACE_ACTION_FREE: {
        return x86_processor_trace_free();
    }
    default:
        return ERR_INVALID_ARGS;
    }
#endif

    return ERR_NOT_SUPPORTED;
}

status_t mtrace_read(uint32_t action, void* ptr, size_t off, size_t len,
                   size_t* actual) {
#ifdef __x86_64__
    switch (action) {
    case MTRACE_READ_DATA_SIZE: {
        size_t capture_size[x86_num_cpus];
        if (off != 0 || len != sizeof(capture_size))
            return ERR_INVALID_ARGS;
        auto status = x86_processor_trace_read_size(capture_size,
                                                    x86_num_cpus);
        if (status != NO_ERROR)
            return status;
        *actual = len;
        return arch_copy_to_user(ptr, capture_size, sizeof(capture_size));
    }
    case MTRACE_READ_DATA_BYTES ... MTRACE_READ_DATA_BYTES + SMP_MAX_CPUS - 1: {
        return x86_processor_trace_read_bytes(action - MTRACE_READ_DATA_BYTES,
                                              ptr, off, len, actual);
    }
    default:
        return ERR_INVALID_ARGS;
    }
#endif

    return ERR_NOT_SUPPORTED;
}
