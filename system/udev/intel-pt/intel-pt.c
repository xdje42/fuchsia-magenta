// Copyright 2016 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// See the README.md in this directory for documentation.

#include <ddk/binding.h>
#include <ddk/device.h>
#include <ddk/driver.h>
#include <ddk/io-buffer.h>

#include <magenta/syscalls.h>
#include <magenta/types.h>

#include <magenta/device/intel-pt.h>

#include <magenta/syscalls/resource.h>

#include <assert.h>
#include <cpuid.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TRACE 1

#if TRACE
#define xprintf(fmt...) printf(fmt)
#else
#define xprintf(fmt...) \
    do {                \
    } while (0)
#endif

typedef enum {
    IPT_TRACE_CPUS,
    IPT_TRACE_THREADS
} ipt_trace_mode_t;

typedef struct ipt_per_trace_state {
    // the cpu or thread this buffer is assigned to
    // Which value to use is determined by the trace mode.
    union {
        uint32_t cpuno;
        mx_handle_t thread;
    } owner;

    // number of buffers, each 2^|buffer_order| pages in size
    uint32_t num_buffers;
    // log2 size of each buffer, in pages
    uint32_t buffer_order;
    // if true then the buffer is circular, otherwise tracing stops when the
    // buffer fills
    bool is_circular;
    // true if allocated
    bool allocated;
    // number of ToPA tables needed
    uint32_t num_tables;

    // msrs
    uint64_t ctl;
    uint64_t status;
    uint64_t output_base;
    uint64_t output_mask_ptrs;
    uint64_t cr3_match;
    struct {
        uint64_t a,b;
    } addr_ranges[IPT_MAX_NUM_ADDR_RANGES];

    // trace buffers and ToPA tables
    // ToPA: Table of Physical Addresses
    io_buffer_t* buffers;
    io_buffer_t* topas;
} ipt_per_trace_state_t;

typedef struct ipt_device {
    mx_device_t device;

    ipt_trace_mode_t mode;

    // # of entries in |per_trace_state|.
    // When tracing by cpu, this is the max number of cpus.
    // When tracing by thread, this is the max number of threads.
    // TODO(dje): Add support for dynamically growing the vector.
    uint32_t num_traces;

    // one entry for each trace
    ipt_per_trace_state_t* per_trace_state;

    // Only one open of this device is supported at a time.
    // TODO(dje): wip wip wip
    bool opened;

    // Once tracing has started various things are not allowed until it stops.
    bool active;
} ipt_device_t;

#define get_ipt_device(dev) containerof(dev, ipt_device_t, device)

static uint32_t ipt_config_family;
static uint32_t ipt_config_model;
static uint32_t ipt_config_stepping;

static uint32_t ipt_config_addr_cfg_max = 0;
static uint32_t ipt_config_mtc_freq_mask = 0;
static uint32_t ipt_config_cyc_thresh_mask = 0;
static uint32_t ipt_config_psb_freq_mask = 0;
static uint32_t ipt_config_addr_range_num = 0;
static uint32_t ipt_config_bus_freq = 0;

static bool ipt_config_cr3_filtering = false;
static bool ipt_config_psb = false;
static bool ipt_config_ip_filtering = false;
static bool ipt_config_mtc = false;
static bool ipt_config_ptwrite = false;
static bool ipt_config_power_events = false;
static bool ipt_config_output_topa = false;
static bool ipt_config_output_topa_multi = false;
static bool ipt_config_output_single = false;
static bool ipt_config_output_transport = false;
static bool ipt_config_lip = false;

// maximum space, in bytes, for trace buffers (per cpu)
// This isn't necessarily
// MAX_NUM_BUFFERS * (1 << (MAX_BUFFER_ORDER + PAGE_SIZE_SHIFT)).
// Buffers have to be contiguous pages, but we can have a lot of them.
// Supporting large buffers and/or lots of them is for experimentation.
#define MAX_PER_TRACE_SPACE (256 * 1024 * 1024)

// maximum number of buffers
#define MAX_NUM_BUFFERS 1024

// maximum size of each buffer, in pages (1MB)
#define MAX_BUFFER_ORDER 8

#if PAGE_SIZE == 4096
#define PAGE_SIZE_SHIFT 12
#else
#error "unsupported page size"
#endif

#define BIT(x, b) ((x) & (1u << (b)))

static mx_status_t x86_pt_free(ipt_device_t* ipt_dev);


// The userspace side of the driver

static void x86_pt_init(void)
{
    unsigned a, b, c, d, max_leaf;

    max_leaf = __get_cpuid_max(0, NULL);
    if (max_leaf < 0x14) {
        xprintf("IPT: No PT support\n");
        return;
    }

    __cpuid(1, a, b, c, d);
    ipt_config_stepping = a & 0xf;
    ipt_config_model = (a >> 4) & 0xf;
    ipt_config_family = (a >> 8) & 0xf;
    if (ipt_config_family == 0xf)
        ipt_config_family += (a >> 20) & 0xff;
    if (ipt_config_family == 6 || ipt_config_family == 0xf)
        ipt_config_model += ((a >> 16) & 0xf) << 4;

    __cpuid_count(0x07, 0, a, b, c, d);
    if (!BIT(b, 25)) {
        xprintf("IPT: No PT support\n");
        return;
    }
    __cpuid_count(0x14, 0, a, b, c, d);
    if (BIT(b, 2))
        ipt_config_addr_cfg_max = 2;
    if (BIT(b, 1) && a >= 1) {
        unsigned a1, b1, c1, d1;
        __cpuid_count(0x14, 1, a1, b1, c1, d1);
        ipt_config_mtc_freq_mask = (a1 >> 16) & 0xffff;
        ipt_config_cyc_thresh_mask = b1 & 0xffff;
        ipt_config_psb_freq_mask = (b1 >> 16) & 0xffff;
        ipt_config_addr_range_num = a1 & 0x3;
    }

    if (max_leaf >= 0x15) {
        unsigned a1 = 0, b1 = 0, c1 = 0, d1 = 0;
        __cpuid(0x15, a1, b1, c1, d1);
        if (a1 && b1)
            ipt_config_bus_freq = 1. / ((float)a1 / (float)b1);
    }

    ipt_config_cr3_filtering = !!BIT(b, 0);
    ipt_config_psb = !!BIT(b, 1);
    ipt_config_ip_filtering = !!BIT(b, 2);
    ipt_config_mtc = !!BIT(b, 3);
    ipt_config_ptwrite = !!BIT(b, 4);
    ipt_config_power_events = !!BIT(b, 5);

    ipt_config_output_topa = !!BIT(c, 0);
    ipt_config_output_topa_multi = !!BIT(c, 1);
    ipt_config_output_single = !!BIT(c, 2);
    ipt_config_output_transport = !!BIT(c, 3);
    ipt_config_lip = !!BIT(c, 31);
}

// |mode| is one of IPT_MODE_{CPUS,THREADS}.

static mx_status_t x86_pt_set_mode(ipt_device_t* ipt_dev, uint32_t mode) {
    // TODO(dje): Only change the mode when tracing is fully off in all
    // threads?
    if (ipt_dev->active)
        return ERR_BAD_STATE;

    switch (mode) {
    case IPT_MODE_CPUS:
    case IPT_MODE_THREADS:
        break;
    default:
        return ERR_INVALID_ARGS;
    }

    mx_handle_t resource = get_root_resource();
    mx_status_t status =
        mx_mtrace_control(resource, MTRACE_KIND_IPT, MTRACE_IPT_SET_MODE, 0, &mode, sizeof(mode));
    if (status != NO_ERROR)
        return status;

    switch (mode) {
    case IPT_MODE_CPUS:
        ipt_dev->mode = IPT_TRACE_CPUS;
        break;
    case IPT_MODE_THREADS:
        ipt_dev->mode = IPT_TRACE_THREADS;
        break;
    default:
        assert(false);
    }

    return NO_ERROR;
}

// Create the ToPA for the configured number of pages for |cpu|.
// A circular collection of buffers is set up, even if we're going to apply
// the stop bit to the last entry.

static void make_topa(ipt_device_t* ipt_dev, ipt_per_trace_state_t* per_trace) {
    const size_t run_len_log2 = per_trace->buffer_order;
    assert(run_len_log2 + PAGE_SIZE_SHIFT <= IPT_TOPA_MAX_SHIFT);
    assert(run_len_log2 + PAGE_SIZE_SHIFT >= IPT_TOPA_MIN_SHIFT);

    uint32_t curr_table = 0;
    uint32_t curr_idx = 0;
    uint64_t* last_entry = NULL;

    // Note: An early version of this patch auto-computed the desired grouping
    // of pages with sufficient alignment. If you find yourself needing this
    // functionality again, see change 9470.

    for (uint32_t i = 0; i < per_trace->num_buffers; ++i) {
        io_buffer_t* buffer = &per_trace->buffers[i];
        io_buffer_t* topa = &per_trace->topas[curr_table];
        mx_paddr_t pa = io_buffer_phys(buffer);

        uint64_t val = IPT_TOPA_ENTRY_PHYS_ADDR(pa) |
            IPT_TOPA_ENTRY_SIZE(run_len_log2 + PAGE_SIZE_SHIFT);
        uint64_t* table = io_buffer_virt(topa);
        table[curr_idx] = val;
        last_entry = &table[curr_idx];

        // Make sure we leave one at the end of the table for the END marker
        if (unlikely(curr_idx >= IPT_TOPA_MAX_TABLE_ENTRIES - 2)) {
            curr_idx = 0;
            curr_table++;
        } else {
            curr_idx++;
        }
    }

    assert(curr_table + 1 == per_trace->num_tables ||
           // If the last table is full curr_table will be the next one.
           curr_table == per_trace->num_tables);

    // Populate END entries for completed tables
    // Assume the table is circular. We'll set the stop bit on the last
    // entry later.
    for (uint32_t i = 0; i < curr_table; ++i) {
        io_buffer_t* this_table = &per_trace->topas[i];
        io_buffer_t* next_table;
        if (i == per_trace->num_tables - 1) {
            next_table = &per_trace->topas[0];
        } else {
            next_table = &per_trace->topas[i + 1];
        }

        mx_paddr_t next_table_pa = io_buffer_phys(next_table);
        uint64_t val = IPT_TOPA_ENTRY_PHYS_ADDR(next_table_pa) | IPT_TOPA_ENTRY_END;
        uint64_t* table = io_buffer_virt(this_table);
        table[IPT_TOPA_MAX_TABLE_ENTRIES - 1] = val;
    }

    // Populate the END entry for a possibly non-full last table
    if (curr_table < per_trace->num_tables) {
        io_buffer_t* this_table = &per_trace->topas[curr_table];
        io_buffer_t* first_table = &per_trace->topas[0];
        mx_paddr_t first_table_pa = io_buffer_phys(first_table);
        uint64_t val = IPT_TOPA_ENTRY_PHYS_ADDR(first_table_pa) | IPT_TOPA_ENTRY_END;
        uint64_t* table = io_buffer_virt(this_table);
        table[curr_idx] = val;
    }

    // Add the STOP flag to the last non-END entry in the tables
    assert(last_entry);
    if (!per_trace->is_circular)
        *last_entry |= IPT_TOPA_ENTRY_STOP;
}

// Compute the number of ToPA entries needed for the configured number of
// buffers.
// The output count includes the END entries across all needed tables.

static uint32_t compute_topa_entry_count(ipt_device_t* ipt_dev, ipt_per_trace_state_t* per_trace) {
    uint32_t num_entries = per_trace->num_buffers;
    uint32_t num_end_entries = (num_entries + IPT_TOPA_MAX_TABLE_ENTRIES - 2) /
        (IPT_TOPA_MAX_TABLE_ENTRIES - 1);
    uint32_t result = num_entries + num_end_entries;

    xprintf("IPT: compute_topa_entry_count: num_entries: %u\n", num_entries);
    xprintf("IPT: compute_topa_entry_count: num_end_entries: %u\n", num_end_entries);
    xprintf("IPT: compute_topa_entry_count: total entries: %u\n", result);

    return result;
}

// Walk the tables to discover how much data has been captured for |per_trace|.

static size_t compute_capture_size(ipt_device_t* ipt_dev, ipt_per_trace_state_t* per_trace) {
    uint64_t curr_table_paddr = per_trace->output_base;
    uint32_t curr_table_entry_idx = (uint32_t)per_trace->output_mask_ptrs >> 7;
    uint32_t curr_entry_offset = (uint32_t)(per_trace->output_mask_ptrs >> 32);

    xprintf("IPT: compute_capture_size: trace %tu\n", per_trace - ipt_dev->per_trace_state);
    xprintf("IPT: curr_table_paddr 0x%" PRIx64 ", curr_table_entry_idx %u, curr_entry_offset %u\n",
            curr_table_paddr, curr_table_entry_idx, curr_entry_offset);

    size_t total_size = 0;
    for (uint32_t table = 0; table < per_trace->num_tables; ++table) {
        // Get the physical address so that we can compare it with the value
        // in output_base.
        mx_paddr_t table_paddr = io_buffer_phys(&per_trace->topas[table]);

        for (uint32_t entry = 0; entry < IPT_TOPA_MAX_TABLE_ENTRIES - 1; ++entry) {
            if (table_paddr == curr_table_paddr && entry >= curr_table_entry_idx) {
                total_size += curr_entry_offset;
                return total_size;
            }
            uint64_t* table_ptr = io_buffer_virt(&per_trace->topas[table]);
            uint64_t topa_entry = table_ptr[entry];
            total_size += 1UL << IPT_TOPA_ENTRY_EXTRACT_SIZE(topa_entry);
        }
    }

    // Should be unreachable.
    // TODO(dje): Later flag state as broken.
    xprintf("IPT: unexpectedly exited capture loop\n");
    return 0;
}

static mx_status_t x86_pt_alloc_buffer1(ipt_device_t* ipt_dev, ipt_per_trace_state_t* per_trace,
                                        uint32_t num, uint32_t order, bool is_circular) {
    mx_status_t status;
    size_t buffer_pages = 1 << order;

    per_trace->num_buffers = num;
    per_trace->buffer_order = order;
    per_trace->is_circular = is_circular;

    per_trace->buffers = calloc(per_trace->num_buffers, sizeof(io_buffer_t));
    if (per_trace->buffers == NULL)
        return ERR_NO_MEMORY;

    for (uint32_t i = 0; i < num; ++i) {
        // ToPA entries of size N must be aligned to N, too.
        uint32_t alignment_log2 = PAGE_SIZE_SHIFT + order;
        status = io_buffer_init_aligned(&per_trace->buffers[i], buffer_pages * PAGE_SIZE, alignment_log2, IO_BUFFER_RW);
        if (status != NO_ERROR)
            return status;
        // Keep track of allocated buffers as we go in case we later fail:
        // we want to be able to free those that got allocated.
        ++per_trace->num_buffers;
    }

    // TODO(dje): No need to allocate the max on the last table.
    uint32_t entry_count = compute_topa_entry_count(ipt_dev, per_trace);
    uint32_t table_count = (entry_count + IPT_TOPA_MAX_TABLE_ENTRIES - 1) /
            IPT_TOPA_MAX_TABLE_ENTRIES;

    if (entry_count < 2) {
        xprintf("IPT: INVALID ENTRY COUNT: %u\n", entry_count);
        return ERR_INVALID_ARGS;
    }

    // Some early Processor Trace implementations only supported having a
    // table with a single real entry and an END.
    if (!ipt_config_output_topa_multi && entry_count > 2)
        return ERR_NOT_SUPPORTED;

    // Allocate Table(s) of Physical Addresses (ToPA) for each cpu.

    per_trace->topas = calloc(table_count, sizeof(io_buffer_t));
    if (per_trace->topas == NULL)
        return ERR_NO_MEMORY;

    for (uint32_t i = 0; i < table_count; ++i) {
        status = io_buffer_init(&per_trace->topas[i], sizeof(uint64_t) * IPT_TOPA_MAX_TABLE_ENTRIES, IO_BUFFER_RW);
        if (status != NO_ERROR)
            return ERR_NO_MEMORY;
        // Keep track of allocated tables as we go in case we later fail:
        // we want to be able to free those that got allocated.
        ++per_trace->num_tables;
    }

    make_topa(ipt_dev, per_trace);

    return NO_ERROR;
}

static void x86_pt_free_buffer1(ipt_device_t* ipt_dev, ipt_per_trace_state_t* per_trace) {
    for (uint32_t i = 0; i < per_trace->num_buffers; ++i) {
        io_buffer_release(&per_trace->buffers[i]);
    }
    free(per_trace->buffers);
    per_trace->buffers = NULL;

    for (uint32_t i = 0; i < per_trace->num_tables; ++i) {
        io_buffer_release(&per_trace->topas[i]);
    }
    free(per_trace->topas);
    per_trace->topas = NULL;
}

static mx_status_t x86_pt_alloc_buffer(ipt_device_t* ipt_dev,
                                       const ioctl_ipt_buffer_config_t* config,
                                       uint32_t* out_index) {
    if (config->num_buffers == 0 || config->num_buffers > MAX_NUM_BUFFERS)
        return ERR_INVALID_ARGS;
    if (config->buffer_order > MAX_BUFFER_ORDER)
        return ERR_INVALID_ARGS;
    size_t buffer_pages = 1 << config->buffer_order;
    size_t nr_pages = config->num_buffers * buffer_pages;
    size_t total_per_trace = nr_pages * PAGE_SIZE;
    if (total_per_trace > MAX_PER_TRACE_SPACE)
        return ERR_INVALID_ARGS;

    uint64_t settable_ctl_mask = (
        IPT_CTL_OS_ALLOWED |
        IPT_CTL_USER_ALLOWED |
        IPT_CTL_TSC_EN |
        IPT_CTL_DIS_RETC |
        IPT_CTL_BRANCH_EN
        );
    if (ipt_config_ptwrite)
        settable_ctl_mask |= IPT_CTL_PTW_EN | IPT_CTL_FUP_ON_PTW;
    if (ipt_config_cr3_filtering)
        settable_ctl_mask |= IPT_CTL_CR3_FILTER;
    if (ipt_config_mtc)
        settable_ctl_mask |= IPT_CTL_MTC_EN | IPT_CTL_MTC_FREQ;
    if (ipt_config_power_events)
        settable_ctl_mask |= IPT_CTL_POWER_EVENT_EN;
    if (ipt_config_ip_filtering)
        settable_ctl_mask |= (IPT_CTL_ADDR0 |
                              IPT_CTL_ADDR1 |
                              IPT_CTL_ADDR2 |
                              IPT_CTL_ADDR3);
    if (ipt_config_psb)
        settable_ctl_mask |= (IPT_CTL_CYC_EN |
                              IPT_CTL_PSB_FREQ |
                              IPT_CTL_CYC_THRESH);
    if ((config->ctl & ~settable_ctl_mask) != 0)
        return ERR_INVALID_ARGS;

    uint32_t index;
    for (index = 0; index < ipt_dev->num_traces; ++index) {
        if (!ipt_dev->per_trace_state[index].allocated)
            break;
    }
    if (index == ipt_dev->num_traces)
        return ERR_NO_RESOURCES;

    ipt_per_trace_state_t* per_trace = &ipt_dev->per_trace_state[index];
    memset(per_trace, 0, sizeof(*per_trace));
    mx_status_t status = x86_pt_alloc_buffer1(ipt_dev, per_trace,
                                              config->num_buffers, config->buffer_order, config->is_circular);
    if (status != NO_ERROR) {
        x86_pt_free_buffer1(ipt_dev, per_trace);
        return status;
    }

    per_trace->ctl = config->ctl;
    per_trace->status = 0;
    per_trace->output_base = io_buffer_phys(&per_trace->topas[0]);
    per_trace->output_mask_ptrs = 0;
    per_trace->cr3_match = config->cr3_match;
    static_assert(sizeof(per_trace->addr_ranges) == sizeof(config->addr_ranges),
                  "addr range size mismatch");
    memcpy(per_trace->addr_ranges, config->addr_ranges, sizeof(config->addr_ranges));
    per_trace->allocated = true;
    *out_index = index;
    return NO_ERROR;
}

static mx_status_t x86_pt_assign_buffer_thread(ipt_device_t* ipt_dev, uint32_t index, mx_handle_t thread) {
    mx_handle_close(thread);
    return ERR_NOT_SUPPORTED;
}

static mx_status_t x86_pt_release_buffer_thread(ipt_device_t* ipt_dev, uint32_t index, mx_handle_t thread) {
    mx_handle_close(thread);
    return ERR_NOT_SUPPORTED;
}

static mx_status_t x86_pt_free_buffer(ipt_device_t* ipt_dev, uint32_t index) {
    if (ipt_dev->active)
        return ERR_BAD_STATE;
    if (index >= ipt_dev->num_traces)
        return ERR_INVALID_ARGS;
    assert(ipt_dev->per_trace_state);
    ipt_per_trace_state_t* per_trace = &ipt_dev->per_trace_state[index];
    if (!per_trace->allocated)
        return ERR_INVALID_ARGS;
    x86_pt_free_buffer1(ipt_dev, per_trace);
    per_trace->allocated = false;
    return NO_ERROR;
}

// Allocate space for the trace buffers, for each cpu,
// and do any other initialization needed prior to starting a trace.

static mx_status_t x86_pt_cpu_mode_alloc(ipt_device_t* ipt_dev) {
    // TODO: lock
    if (ipt_dev->active)
        return ERR_BAD_STATE;
    if (ipt_dev->mode != IPT_TRACE_CPUS)
        return ERR_BAD_STATE;

    mx_handle_t resource = get_root_resource();
    return mx_mtrace_control(resource, MTRACE_KIND_IPT, MTRACE_IPT_CPU_MODE_ALLOC, 0, NULL, 0);
}

// Begin tracing, cpu mode.

static mx_status_t x86_pt_cpu_mode_start(ipt_device_t* ipt_dev) {
    if (ipt_dev->active)
        return ERR_BAD_STATE;
    if (ipt_dev->mode != IPT_TRACE_CPUS)
        return ERR_BAD_STATE;
    assert(ipt_dev->per_trace_state);

    mx_handle_t resource = get_root_resource();
    mx_status_t status;

    for (uint32_t cpu = 0; cpu < ipt_dev->num_traces; ++cpu) {
        ipt_per_trace_state_t* per_trace = &ipt_dev->per_trace_state[cpu];

        mx_x86_pt_regs_t regs;
        regs.ctl = per_trace->ctl;
        regs.ctl |= IPT_CTL_TOPA | IPT_CTL_TRACE_EN;
        regs.status = per_trace->status;
        regs.output_base = per_trace->output_base;
        regs.output_mask_ptrs = per_trace->output_mask_ptrs;
        regs.cr3_match = per_trace->cr3_match;
        memcpy(regs.addr_ranges, per_trace->addr_ranges, sizeof(per_trace->addr_ranges));

        status = mx_mtrace_control(resource, MTRACE_KIND_IPT, MTRACE_IPT_STAGE_CPU_DATA,
                                   cpu, &regs, sizeof(regs));
        if (status != NO_ERROR)
            return status;
    }

    status = mx_mtrace_control(resource, MTRACE_KIND_IPT, MTRACE_IPT_CPU_MODE_START,
                               0, NULL, 0);
    if (status != NO_ERROR)
        return status;
    ipt_dev->active = true;
    return NO_ERROR;
}

// Stop tracing.

static mx_status_t x86_pt_cpu_mode_stop(ipt_device_t* ipt_dev) {
    if (!ipt_dev->active)
        return ERR_BAD_STATE;
    assert(ipt_dev->per_trace_state);

    mx_handle_t resource = get_root_resource();

    mx_status_t status = mx_mtrace_control(resource, MTRACE_KIND_IPT, MTRACE_IPT_CPU_MODE_STOP,
                                           0, NULL, 0);
    if (status != NO_ERROR)
        return status;
    ipt_dev->active = false;

    for (uint32_t cpu = 0; cpu < ipt_dev->num_traces; ++cpu) {
        ipt_per_trace_state_t* per_trace = &ipt_dev->per_trace_state[cpu];

        mx_x86_pt_regs_t regs;
        status = mx_mtrace_control(resource, MTRACE_KIND_IPT, MTRACE_IPT_GET_CPU_DATA,
                                   cpu, &regs, sizeof(regs));
        if (status != NO_ERROR)
            return status;
        per_trace->ctl = regs.ctl;
        per_trace->status = regs.status;
        per_trace->output_base = regs.output_base;
        per_trace->output_mask_ptrs = regs.output_mask_ptrs;
        per_trace->cr3_match = regs.cr3_match;
        memcpy(per_trace->addr_ranges, regs.addr_ranges, sizeof(per_trace->addr_ranges));
    }

    return NO_ERROR;
}

// Release resources acquired by x86_pt_cpu_mode_alloc.

static mx_status_t x86_pt_cpu_mode_free(ipt_device_t* ipt_dev) {
    if (ipt_dev->active)
        return ERR_BAD_STATE;

    mx_handle_t resource = get_root_resource();
    mx_status_t status =
        mx_mtrace_control(resource, MTRACE_KIND_IPT, MTRACE_IPT_CPU_MODE_FREE, 0, NULL, 0);
    // TODO(dje): This really shouldn't fail. What to do?
    // For now flag things as busted and prevent further use.
    if (status != NO_ERROR)
        return NO_ERROR;

    return NO_ERROR;
}


// The DDK interface

static mx_status_t ipt_open(mx_device_t* dev, mx_device_t** dev_out, uint32_t flags) {
    // TODO(dje): For now we only support ToPA.
    if (!ipt_config_output_topa)
        return ERR_NOT_SUPPORTED;

    // TODO(dje): What's the best way to allow only one open at a time?
    // [We could allow multiple, but multiple clients trying to control
    // tracing is problematic so just punt.]
    // TODO(dje): Locking
    ipt_device_t* ipt_dev = get_ipt_device(dev);
    if (ipt_dev->opened)
        return ERR_ALREADY_BOUND;

    if (ipt_dev->active)
        assert(ipt_dev->per_trace_state);

    if (!ipt_dev->per_trace_state) {
        ipt_dev->num_traces = mx_num_cpus();

        ipt_dev->per_trace_state = calloc(ipt_dev->num_traces, sizeof(ipt_dev->per_trace_state[0]));
        if (!ipt_dev->per_trace_state)
            return ERR_NO_MEMORY;

        // reset values that have defaults
        ipt_dev->mode = IPT_TRACE_CPUS;
    }

    ipt_dev->opened = true;
    return NO_ERROR;
}

static mx_status_t ipt_close(mx_device_t* dev, uint32_t flags) {
    ipt_device_t* ipt_dev = get_ipt_device(dev);

    ipt_dev->opened = false;
    return NO_ERROR;
}

static ssize_t ipt_set_mode(ipt_device_t* ipt_dev,
                            const void* cmd, size_t cmdlen,
                            void* reply, size_t max) {
    if (max != 0)
        return ERR_INVALID_ARGS;
    uint32_t mode;
    if (cmdlen != sizeof(mode))
        return ERR_INVALID_ARGS;
    memcpy(&mode, cmd, sizeof(mode));
    return x86_pt_set_mode(ipt_dev, mode);
}

static ssize_t ipt_alloc_buffer(ipt_device_t* ipt_dev,
                                const void* cmd, size_t cmdlen,
                                void* reply, size_t max) {
    ioctl_ipt_buffer_config_t config;
    if (cmdlen != sizeof(config))
        return ERR_INVALID_ARGS;
    memcpy(&config, cmd, sizeof(config));
    uint32_t index;
    if (max < sizeof(index))
        return ERR_BUFFER_TOO_SMALL;
    mx_status_t status = x86_pt_alloc_buffer(ipt_dev, &config, &index);
    if (status != NO_ERROR)
        return status;
    memcpy(reply, &index, sizeof(index));
    return sizeof(index);
}

static ssize_t ipt_assign_buffer_thread(ipt_device_t* ipt_dev,
                                        const void* cmd, size_t cmdlen,
                                        void* reply, size_t max) {
    ioctl_ipt_assign_buffer_thread_t assign;
    if (cmdlen != sizeof(assign))
        return ERR_INVALID_ARGS;
    if (max != 0)
        return ERR_INVALID_ARGS;
    memcpy(&assign, cmd, sizeof(assign));
    return x86_pt_assign_buffer_thread(ipt_dev, assign.descriptor, assign.thread);
}

static ssize_t ipt_release_buffer_thread(ipt_device_t* ipt_dev,
                                         const void* cmd, size_t cmdlen,
                                         void* reply, size_t max) {
    ioctl_ipt_assign_buffer_thread_t assign;
    if (cmdlen != sizeof(assign))
        return ERR_INVALID_ARGS;
    if (max != 0)
        return ERR_INVALID_ARGS;
    memcpy(&assign, cmd, sizeof(assign));
    return x86_pt_release_buffer_thread(ipt_dev, assign.descriptor, assign.thread);
}

static ssize_t ipt_get_buffer_config(ipt_device_t* ipt_dev,
                                     const void* cmd, size_t cmdlen,
                                     void* reply, size_t max) {
    uint32_t index;
    ioctl_ipt_buffer_config_t config;

    if (cmdlen != sizeof(index))
        return ERR_INVALID_ARGS;
    if (max < sizeof(config))
        return ERR_BUFFER_TOO_SMALL;

    memcpy(&index, cmd, sizeof(index));
    if (index >= ipt_dev->num_traces)
        return ERR_INVALID_ARGS;
    ipt_per_trace_state_t* per_trace = &ipt_dev->per_trace_state[index];
    if (!per_trace->allocated)
        return ERR_INVALID_ARGS;

    config.num_buffers = per_trace->num_buffers;
    config.buffer_order = per_trace->buffer_order;
    config.is_circular = per_trace->is_circular;
    config.ctl = per_trace->ctl;
    config.cr3_match = per_trace->cr3_match;
    static_assert(sizeof(config.addr_ranges) == sizeof(per_trace->addr_ranges),
                  "addr range size mismatch");
    memcpy(config.addr_ranges, per_trace->addr_ranges, sizeof(per_trace->addr_ranges));
    memcpy(reply, &config, sizeof(config));
    return sizeof(config);
}

static ssize_t ipt_get_buffer_data(ipt_device_t* ipt_dev,
                                   const void* cmd, size_t cmdlen,
                                   void* reply, size_t max) {
    if (ipt_dev->active)
        return ERR_BAD_STATE;

    uint32_t index;
    if (cmdlen != sizeof(index))
        return ERR_INVALID_ARGS;
    memcpy(&index, cmd, sizeof(index));
    if (index >= ipt_dev->num_traces)
        return ERR_INVALID_ARGS;
    ipt_per_trace_state_t* per_trace = &ipt_dev->per_trace_state[index];
    if (!per_trace->allocated)
        return ERR_INVALID_ARGS;

    ioctl_ipt_buffer_data_t data;
    if (max < sizeof(data))
        return ERR_BUFFER_TOO_SMALL;

    data.capture_size = compute_capture_size(ipt_dev, per_trace);
    memcpy(reply, &data, sizeof(data));
    return sizeof(data);
}

static ssize_t ipt_get_buffer_handle(ipt_device_t* ipt_dev,
                                     const void* cmd, size_t cmdlen,
                                     void* reply, size_t max) {
    ioctl_ipt_buffer_handle_rqst_t rqst;
    mx_handle_t h;

    if (cmdlen != sizeof(rqst))
        return ERR_INVALID_ARGS;
    if (max < sizeof(h))
        return ERR_BUFFER_TOO_SMALL;

    memcpy(&rqst, cmd, sizeof(rqst));
    if (rqst.descriptor >= ipt_dev->num_traces)
        return ERR_INVALID_ARGS;
    ipt_per_trace_state_t* per_trace = &ipt_dev->per_trace_state[rqst.descriptor];
    if (!per_trace->allocated)
        return ERR_INVALID_ARGS;
    if (rqst.buffer_num >= per_trace->num_buffers)
        return ERR_INVALID_ARGS;
    mx_status_t status = mx_handle_duplicate(per_trace->buffers[rqst.buffer_num].vmo_handle, MX_RIGHT_SAME_RIGHTS, &h);
    if (status < 0)
        return status;
    memcpy(reply, &h, sizeof(h));
    return sizeof(h);
}

static ssize_t ipt_free_buffer(ipt_device_t* ipt_dev,
                               const void* cmd, size_t cmdlen,
                               void* reply, size_t max) {
    uint32_t index;

    if (cmdlen != sizeof(index))
        return ERR_INVALID_ARGS;
    if (max != 0)
        return ERR_INVALID_ARGS;

    memcpy(&index, cmd, sizeof(index));
    x86_pt_free_buffer(ipt_dev, index);
    return 0;
}

static ssize_t ipt_ioctl(mx_device_t* dev, uint32_t op,
                         const void* cmd, size_t cmdlen,
                         void* reply, size_t max) {
    ipt_device_t* ipt_dev = get_ipt_device(dev);

    switch (op) {
    case IOCTL_IPT_SET_MODE:
        return ipt_set_mode(ipt_dev, cmd, cmdlen, reply, max);
    case IOCTL_IPT_ALLOC_BUFFER:
        return ipt_alloc_buffer(ipt_dev, cmd, cmdlen, reply, max);
    case IOCTL_IPT_ASSIGN_BUFFER_THREAD:
        return ipt_assign_buffer_thread(ipt_dev, cmd, cmdlen, reply, max);
    case IOCTL_IPT_RELEASE_BUFFER_THREAD:
        return ipt_release_buffer_thread(ipt_dev, cmd, cmdlen, reply, max); 
   case IOCTL_IPT_GET_BUFFER_CONFIG:
        return ipt_get_buffer_config(ipt_dev, cmd, cmdlen, reply, max);
    case IOCTL_IPT_GET_BUFFER_DATA:
        return ipt_get_buffer_data(ipt_dev, cmd, cmdlen, reply, max);
    case IOCTL_IPT_GET_BUFFER_HANDLE:
        return ipt_get_buffer_handle(ipt_dev, cmd, cmdlen, reply, max);
    case IOCTL_IPT_FREE_BUFFER:
        return ipt_free_buffer(ipt_dev, cmd, cmdlen, reply, max);

    case IOCTL_IPT_CPU_MODE_ALLOC:
        if (cmdlen != 0 || max != 0)
            return ERR_INVALID_ARGS;
        return x86_pt_cpu_mode_alloc(ipt_dev);
    case IOCTL_IPT_CPU_MODE_START:
        if (cmdlen != 0 || max != 0)
            return ERR_INVALID_ARGS;
        return x86_pt_cpu_mode_start(ipt_dev);
    case IOCTL_IPT_CPU_MODE_STOP:
        if (cmdlen != 0 || max != 0)
            return ERR_INVALID_ARGS;
        return x86_pt_cpu_mode_stop(ipt_dev);
    case IOCTL_IPT_CPU_MODE_FREE:
        if (cmdlen != 0 || max != 0)
            return ERR_INVALID_ARGS;
        return x86_pt_cpu_mode_free(ipt_dev);

    default:
        return ERR_INVALID_ARGS;
    }
}

static mx_status_t ipt_release(mx_device_t* dev) {
    ipt_device_t* ipt_dev = get_ipt_device(dev);

    // TODO(dje): Neither of these should fail. What to do?
    // For now flag things as busted and prevent further use.
    x86_pt_cpu_mode_stop(ipt_dev);
    x86_pt_cpu_mode_free(ipt_dev);

    free(ipt_dev);

    return NO_ERROR;
}

static mx_protocol_device_t ipt_device_proto = {
    .open = ipt_open,
    .close = ipt_close,
    .ioctl = ipt_ioctl,
    .release = ipt_release,
};

static mx_status_t ipt_init(mx_driver_t* driver) {
    x86_pt_init();

    ipt_device_t* ipt_dev = calloc(1, sizeof(*ipt_dev));
    if (!ipt_dev)
        return ERR_NO_MEMORY;

    device_init(&ipt_dev->device, driver, "intel-pt", &ipt_device_proto);

    mx_status_t status;
    if ((status = device_add(&ipt_dev->device, driver_get_misc_device())) < 0) {
        free(ipt_dev);
        return status;
    }

    return NO_ERROR;
}

mx_driver_t _driver_intel_pt = {
    .ops = {
        .init = ipt_init,
    },
};

MAGENTA_DRIVER_BEGIN(_driver_intel_pt, "intel-pt", "magenta", "0.1", 0)
MAGENTA_DRIVER_END(_driver_intel_pt)
