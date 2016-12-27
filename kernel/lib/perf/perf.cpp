// Copyright 2016 The Fuchsia Authors
//
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT

#include "lib/perf.h"

#include <kernel/vm.h>
#include <list.h>
#include <new.h>

#include "magenta/perf.h"

#ifdef __x86_64__
#include "arch/x86/processor_trace.h"
#endif

// 8MB
#define NR_PAGES (8 * 1024 * 1024 / 4096)
// Ideally we'd have one big contiguous piece of memory. That's unlikely,
// so try to get several pieces of this size.
#define CHUNK_PAGES_LOG2 2 // 16KB

static struct list_node perf_data_page_list
  = LIST_INITIAL_VALUE(perf_data_page_list);
static vm_page_t** perf_data_page_array = nullptr;

static size_t capture_size = 0;

status_t perf_control(uint32_t action, uint32_t options, void* arg, size_t* out_arg) {
    status_t status;

    switch (action) {
    case PERF_ACTION_INIT: {
        if (!list_is_empty(&perf_data_page_list))
            return ERR_BAD_STATE;
        DEBUG_ASSERT(perf_data_page_array == nullptr);
        AllocChecker ac;
        perf_data_page_array = new (&ac) vm_page_t*[NR_PAGES];
        if (!ac.check())
            return ERR_NO_MEMORY;
        size_t chunk_pages = 1 << CHUNK_PAGES_LOG2;
        for (size_t i = 0; i < NR_PAGES; i += chunk_pages) {
            uint8_t alignment_log2 = PAGE_SIZE_SHIFT + CHUNK_PAGES_LOG2;
            size_t count = pmm_alloc_contiguous(chunk_pages, 0, alignment_log2, nullptr, &perf_data_page_list);
            if (count != chunk_pages) {
                size_t count2 = pmm_free(&perf_data_page_list);
                DEBUG_ASSERT(count2 == i);
                DEBUG_ASSERT(list_is_empty(&perf_data_page_list));
                delete[] perf_data_page_array;
                perf_data_page_array = nullptr;
                return ERR_NO_MEMORY;
            }
        }
        vm_page_t* p;
        size_t i = 0;
        list_for_every_entry (&perf_data_page_list, p, vm_page_t, free.node) {
            perf_data_page_array[i++] = p;
        }
        capture_size = 0;
        return NO_ERROR;
    }
    case PERF_ACTION_START: {
        if (list_is_empty(&perf_data_page_list))
            return ERR_BAD_STATE;
        status = x86_processor_trace_enable(perf_data_page_array, NR_PAGES);
        return status;
    }
    case PERF_ACTION_STOP: {
        if (list_is_empty(&perf_data_page_list))
            return ERR_BAD_STATE;
        status = x86_processor_trace_disable(&capture_size);
        if (status != NO_ERROR)
            return status;
        return NO_ERROR;
    }
    case PERF_ACTION_GET_SIZE: {
        *out_arg = capture_size;
        return NO_ERROR;
    }
    case PERF_ACTION_END: {
        status = x86_processor_trace_free();
        if (status != NO_ERROR)
            return status;
        if (!list_is_empty(&perf_data_page_list)) {
            DEBUG_ASSERT(perf_data_page_array);
            size_t count = pmm_free(&perf_data_page_list);
            DEBUG_ASSERT(count == NR_PAGES);
            DEBUG_ASSERT(list_is_empty(&perf_data_page_list));
            delete[] perf_data_page_array;
            perf_data_page_array = nullptr;
        }
        capture_size = 0;
        return NO_ERROR;
    }
    default:
        return ERR_INVALID_ARGS;
    }

    return ERR_NOT_SUPPORTED;
}

int perf_read_user(void* ptr, uint32_t off, uint32_t len) {
    return -1;
}
