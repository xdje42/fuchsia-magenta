// Copyright 2016 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// See the README.md in this directory for documentation.

// TODOs(dje):
// - handle driver crashes
//   - need to turn off tracing
//   - need to keep buffer/table vmos alive until then

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

// Macros for building entries for the Table of Physical Addresses
#define TOPA_ENTRY_PHYS_ADDR(x) ((uint64_t)(x) & ~((1ULL<<12)-1))
#define TOPA_ENTRY_SIZE(size_log2) ((uint64_t)((size_log2) - 12) << 6)
#define TOPA_ENTRY_STOP (1ULL << 4)
#define TOPA_ENTRY_INT (1ULL << 2)
#define TOPA_ENTRY_END (1ULL << 0)

// Macros for extracting info from ToPA entries
#define TOPA_ENTRY_EXTRACT_PHYS_ADDR(e) ((mx_paddr_t)((e) & ~((1ULL<<12)-1)))
#define TOPA_ENTRY_EXTRACT_SIZE(e) ((uint)((((e) >> 6) & 0xf) + 12))

// Macros for building IA32_RTIT_CTL values
#define RTIT_CTL_TRACE_EN (1ULL<<0)
#define RTIT_CTL_CYC_EN (1ULL<<1)
#define RTIT_CTL_OS_ALLOWED (1ULL<<2)
#define RTIT_CTL_USER_ALLOWED (1ULL<<3)
#define RTIT_CTL_POWER_EVENT_EN (1ULL<<4)
#define RTIT_CTL_FUP_ON_PTW (1ULL<<5)
#define RTIT_CTL_FABRIC_EN (1ULL<<6)
#define RTIT_CTL_CR3_FILTER (1ULL<<7)
#define RTIT_CTL_TOPA (1ULL<<8)
#define RTIT_CTL_MTC_EN (1ULL<<9)
#define RTIT_CTL_TSC_EN (1ULL<<10)
#define RTIT_CTL_DIS_RETC (1ULL<<11)
#define RTIT_CTL_PTW_EN (1ULL<<12)
#define RTIT_CTL_BRANCH_EN (1ULL<<13)

// Masks for reading IA32_RTIT_STATUS
#define RTIT_STATUS_FILTER_EN (1ULL<<0)
#define RTIT_STATUS_CONTEXT_EN (1ULL<<1)
#define RTIT_STATUS_TRIGGER_EN (1ULL<<2)
#define RTIT_STATUS_ERROR (1ULL<<4)
#define RTIT_STATUS_STOPPED (1ULL<<5)

#define MAX_NUM_ADDR_RANGES 4

// Valid ToPA entry sizes
#define TOPA_MIN_SHIFT 12
#define TOPA_MAX_SHIFT 27

// Arbitarily picked constants for ourselves
// ToPA tables are 16KB in size (technically can be up to 256MB).
// A 16KB table provides 2047 non-END entries, so at the
// minimum can provide a capture buffer of just under 8MB.
#define TOPA_MAX_TABLE_ENTRIES 2048 // Use up to 16-KB tables (2048 8-byte entries)

typedef struct ipt_per_cpu_state {
    // msrs
    uint64_t ctl;
    uint64_t status;
    uint64_t output_base;
    uint64_t output_mask_ptrs;

    // trace buffers and ToPA tables
    // ToPA: Table of Physical Addresses
    io_buffer_t* buffers;
    io_buffer_t* topas;
} ipt_per_cpu_state_t;

typedef struct ipt_device {
    mx_device_t device;

    // Number of entries in |per_cpu_state|.
    uint32_t num_cpus;

    ipt_per_cpu_state_t* per_cpu_state;

    // Only one open of this device is supported at a time.
    bool opened;

    bool active;

    // number of buffers, each 2^|buffer_order| pages in size
    size_t num_buffers;

    // log2 size of each buffer, in pages
    uint8_t buffer_order;

    // number of ToPA tables needed
    size_t num_tables;

    // user configurable settings
    uint64_t ctl_config;

    // the cr3 filter value, only used if enabled
    uint64_t cr3_filter;

    // address range registers
    struct {
        uint64_t a,b;
    } addr_ranges[MAX_NUM_ADDR_RANGES];
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
#define MAX_PER_CPU_SPACE (64 * 1024 * 1024)

// default number of buffers, each 2^|buffer_order| pages in size
#define DEFAULT_NUM_BUFFERS 16

// maximum number of buffers
#define MAX_NUM_BUFFERS 1024

// log2 size of each buffer, in pages, default is 16KB
#define DEFAULT_BUFFER_ORDER 2

// maximum size of each buffer, in pages (1MB)
#define MAX_BUFFER_ORDER 8

#if PAGE_SIZE == 4096
#define PAGE_SIZE_SHIFT 12
#else
#error "unsupported page size"
#endif

#define BIT(x) (1u << (x))

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
    if ((b & BIT(25)) == 0) {
        xprintf("IPT: No PT support\n");
        return;
    }
    __cpuid_count(0x14, 0, a, b, c, d);
    if (b & BIT(2))
        ipt_config_addr_cfg_max = 2;
    if ((b & BIT(1)) && a >= 1) {
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

    ipt_config_cr3_filtering = !!(b & BIT(0));
    ipt_config_psb = !!(b & BIT(1));
    ipt_config_ip_filtering = !!(b & BIT(2));
    ipt_config_mtc = !!(b & BIT(3));
    ipt_config_ptwrite = !!(b & BIT(4));
    ipt_config_power_events = !!(b & BIT(5));

    ipt_config_output_topa = !!(c & BIT(0));
    ipt_config_output_topa_multi = !!(c & BIT(1));
    ipt_config_output_single = !!(c & BIT(2));
    ipt_config_output_transport = !!(c & BIT(3));
    ipt_config_lip = !!(c & BIT(31));
}

// Create the ToPA for the configured number of pages for |cpu|.
// A circular collection of buffers is set up, even if we're going to apply
// the stop bit to the last entry.

static void make_topa(ipt_device_t* ipt_dev, uint32_t cpu) {
    ipt_per_cpu_state_t* per_cpu = &ipt_dev->per_cpu_state[cpu];
    const size_t run_len_log2 = ipt_dev->buffer_order;
    assert(run_len_log2 + PAGE_SIZE_SHIFT <= TOPA_MAX_SHIFT);
    assert(run_len_log2 + PAGE_SIZE_SHIFT >= TOPA_MIN_SHIFT);

    size_t curr_table = 0;
    size_t curr_idx = 0;
    uint64_t* last_entry = NULL;

    // Note: An early version of this patch auto-computed the desired grouping
    // of pages with sufficient alignment. If you find yourself needing this
    // functionality again, see change 9470.

    for (size_t i = 0; i < ipt_dev->num_buffers; ++i) {
        io_buffer_t* buffer = &per_cpu->buffers[i];
        io_buffer_t* topa = &per_cpu->topas[curr_table];
        mx_paddr_t pa = io_buffer_phys(buffer);

        uint64_t val = TOPA_ENTRY_PHYS_ADDR(pa) |
            TOPA_ENTRY_SIZE(run_len_log2 + PAGE_SIZE_SHIFT);
        uint64_t* table = io_buffer_virt(topa);
        table[curr_idx] = val;
        last_entry = &table[curr_idx];

        // Make sure we leave one at the end of the table for the END marker
        if (unlikely(curr_idx >= TOPA_MAX_TABLE_ENTRIES - 2)) {
            curr_idx = 0;
            curr_table++;
        } else {
            curr_idx++;
        }
    }

    assert(curr_table + 1 == ipt_dev->num_tables ||
           // If the last table is full curr_table will be the next one.
           curr_table == ipt_dev->num_tables);

    // Populate END entries for completed tables
    for (size_t i = 0; i < curr_table; ++i) {
        io_buffer_t* this_table = &per_cpu->topas[i];
        io_buffer_t* next_table;
        if (i == ipt_dev->num_tables - 1) {
            next_table = &per_cpu->topas[0];
        } else {
            next_table = &per_cpu->topas[i + 1];
        }

        mx_paddr_t next_table_pa = io_buffer_phys(next_table);
        uint64_t val = TOPA_ENTRY_PHYS_ADDR(next_table_pa) | TOPA_ENTRY_END;
        uint64_t* table = io_buffer_virt(this_table);
        table[TOPA_MAX_TABLE_ENTRIES - 1] = val;
    }

    // Populate the END entry for a possibly non-full last table
    if (curr_table < ipt_dev->num_tables) {
        io_buffer_t* this_table = &per_cpu->topas[curr_table];
        io_buffer_t* first_table = &per_cpu->topas[0];
        mx_paddr_t first_table_pa = io_buffer_phys(first_table);
        uint64_t val = TOPA_ENTRY_PHYS_ADDR(first_table_pa) | TOPA_ENTRY_END;
        uint64_t* table = io_buffer_virt(this_table);
        table[curr_idx] = val;
    }

    // Add the STOP flag to the last non-END entry in the tables
    assert(last_entry);
    *last_entry |= TOPA_ENTRY_STOP;
}

// Compute the number of ToPA entries needed for the configured number of
// buffers.
// The output count includes the END entries across all needed tables.

static size_t compute_topa_entry_count(ipt_device_t* ipt_dev) {
    size_t num_entries = ipt_dev->num_buffers;
    size_t num_end_entries = (num_entries + TOPA_MAX_TABLE_ENTRIES - 2) /
        (TOPA_MAX_TABLE_ENTRIES - 1);
    size_t result = num_entries + num_end_entries;

    xprintf("IPT: compute_topa_entry_count: num_entries: %zu\n", num_entries);
    xprintf("IPT: compute_topa_entry_count: num_end_entries: %zu\n", num_end_entries);
    xprintf("IPT: compute_topa_entry_count: total entries: %zu\n", result);

    return result;
}

// Walk the tables to discover how much data has been captured for |cpu|.

static size_t compute_capture_size(ipt_device_t* ipt_dev, uint32_t cpu) {
    ipt_per_cpu_state_t* per_cpu = &ipt_dev->per_cpu_state[cpu];

    uint64_t curr_table_paddr = per_cpu->output_base;
    uint32_t curr_table_entry_idx = (uint32_t)per_cpu->output_mask_ptrs >> 7;
    uint32_t curr_entry_offset = (uint32_t)(per_cpu->output_mask_ptrs >> 32);

    xprintf("IPT: compute_capture_size: cpu %u\n", cpu);
    xprintf("IPT: curr_table_paddr 0x%" PRIx64 ", curr_table_entry_idx %u, curr_entry_offset %u\n",
            curr_table_paddr, curr_table_entry_idx, curr_entry_offset);

    size_t total_size = 0;
    for (size_t table = 0; table < ipt_dev->num_tables; ++table) {
        // Get the physical address so that we can compare it with the value
        // in output_base.
        mx_paddr_t table_paddr = io_buffer_phys(&per_cpu->topas[table]);

        for (size_t entry = 0; entry < TOPA_MAX_TABLE_ENTRIES - 1; ++entry) {
            if (table_paddr == curr_table_paddr && entry >= curr_table_entry_idx) {
                total_size += curr_entry_offset;
                return total_size;
            }
            uint64_t* table_ptr = io_buffer_virt(&per_cpu->topas[table]);
            uint64_t topa_entry = table_ptr[entry];
            total_size += 1UL << TOPA_ENTRY_EXTRACT_SIZE(topa_entry);
        }
    }

    // Should be unreachable.
    // TODO(dje): Later flag state as broken.
    xprintf("IPT: unexpectedly exited capture loop\n");
    return 0;
}

// Subroutine of x86_pt_alloc() to simplify it.

static mx_status_t x86_pt_alloc1(ipt_device_t* ipt_dev) {
    mx_status_t status;
    uint32_t num_cpus = mx_num_cpus();
    size_t buffer_pages = 1 << ipt_dev->buffer_order;

    for (uint32_t cpu = 0; cpu < num_cpus; ++cpu) {
        ipt_per_cpu_state_t* per_cpu = &ipt_dev->per_cpu_state[cpu];

        per_cpu->buffers = calloc(ipt_dev->num_buffers, sizeof(io_buffer_t));
        if (per_cpu->buffers == NULL)
            return ERR_NO_MEMORY;

        for (size_t i = 0; i < ipt_dev->num_buffers; ++i) {
            // ToPA entries of size N must be aligned to N, too.
            uint8_t alignment_log2 = PAGE_SIZE_SHIFT + ipt_dev->buffer_order;
            status = io_buffer_init_aligned(&per_cpu->buffers[i], buffer_pages * PAGE_SIZE, alignment_log2, IO_BUFFER_RW);
            if (status != NO_ERROR)
                return status;
        }
    }

    // TODO(dje): No need to allocate the max on the last table.
    size_t entry_count = compute_topa_entry_count(ipt_dev);
    size_t table_count = (entry_count + TOPA_MAX_TABLE_ENTRIES - 1) /
            TOPA_MAX_TABLE_ENTRIES;

    if (entry_count < 2) {
        xprintf("IPT: INVALID ENTRY COUNT: %zu\n", entry_count);
        return ERR_INVALID_ARGS;
    }

    // Some early Processor Trace implementations only supported having a
    // table with a single real entry and an END.
    if (!ipt_config_output_topa_multi && entry_count > 2)
        return ERR_NOT_SUPPORTED;

    // Allocate Table(s) of Physical Addresses (ToPA) for each cpu.

    ipt_dev->num_tables = table_count;

    for (uint32_t cpu = 0; cpu < num_cpus; ++cpu) {
        ipt_per_cpu_state_t* per_cpu = &ipt_dev->per_cpu_state[cpu];

        per_cpu->topas = calloc(table_count, sizeof(io_buffer_t));
        if (per_cpu->topas == NULL)
            return ERR_NO_MEMORY;

        for (size_t i = 0; i < table_count; ++i) {
            status = io_buffer_init(&per_cpu->topas[i], sizeof(uint64_t) * TOPA_MAX_TABLE_ENTRIES, IO_BUFFER_RW);
            if (status != NO_ERROR)
                return ERR_NO_MEMORY;
        }

        make_topa(ipt_dev, cpu);
    }

    return NO_ERROR;
}

// Allocate space for the trace buffers, for each cpu,
// and do any other initialization needed prior to starting a trace.

static mx_status_t x86_pt_alloc(ipt_device_t* ipt_dev) {
    // TODO(dje): For now we only support ToPA.
    if (!ipt_config_output_topa)
        return ERR_NOT_SUPPORTED;

    // TODO: lock
    if (ipt_dev->active)
        return ERR_BAD_STATE;

    mx_status_t status = x86_pt_alloc1(ipt_dev);
    if (status != NO_ERROR) {
        x86_pt_free(ipt_dev);
        return status;
    }

    mx_handle_t resource = get_root_resource();
    status = mx_mtrace_control(resource, MTRACE_KIND_IPT, MTRACE_IPT_ALLOC, 0, NULL, 0);
    if (status != NO_ERROR)
        return status;

    return NO_ERROR;
}

// Begin tracing.

static mx_status_t x86_pt_start(ipt_device_t* ipt_dev) {
    if (ipt_dev->active)
        return ERR_BAD_STATE;
    if (!ipt_dev->per_cpu_state)
        return ERR_BAD_STATE;

    mx_handle_t resource = get_root_resource();
    mx_status_t status;

    for (uint32_t cpu = 0; cpu < ipt_dev->num_cpus; ++cpu) {
        ipt_per_cpu_state_t* per_cpu = &ipt_dev->per_cpu_state[cpu];

        // Stage the ctl value for enabling the trace
        uint64_t ctl = RTIT_CTL_TOPA | RTIT_CTL_TRACE_EN;
        // TODO(teisenbe): Allow caller provided flags for controlling
        // these options.
        ctl |= RTIT_CTL_USER_ALLOWED | RTIT_CTL_OS_ALLOWED;
        ctl |= RTIT_CTL_BRANCH_EN;
        ctl |= RTIT_CTL_TSC_EN;
        //ctl |= RTIT_CTL_PTW_EN; -- causes gpf
        status = mx_mtrace_control(resource, MTRACE_KIND_IPT, MTRACE_IPT_STAGE_CTL,
                                   cpu, &ctl, sizeof(ctl));
        if (status != NO_ERROR)
            return status;

        uint64_t status = 0;
        status = mx_mtrace_control(resource, MTRACE_KIND_IPT, MTRACE_IPT_STAGE_STATUS,
                                   cpu, &status, sizeof(status));
        if (status != NO_ERROR)
            return status;

        uint64_t output_base = io_buffer_phys(&per_cpu->topas[0]);
        status = mx_mtrace_control(resource, MTRACE_KIND_IPT, MTRACE_IPT_STAGE_OUTPUT_BASE,
                                   cpu, &output_base, sizeof(output_base));
        if (status != NO_ERROR)
            return status;

        uint64_t output_mask_ptrs = 0;
        status = mx_mtrace_control(resource, MTRACE_KIND_IPT, MTRACE_IPT_STAGE_OUTPUT_MASK_PTRS,
                                   cpu, &output_mask_ptrs, sizeof(output_mask_ptrs));
        if (status != NO_ERROR)
            return status;
    }

    status = mx_mtrace_control(resource, MTRACE_KIND_IPT, MTRACE_IPT_START,
                               0, NULL, 0);
    if (status != NO_ERROR)
        return status;
    ipt_dev->active = true;
    return NO_ERROR;
}

// Stop tracing.

static mx_status_t x86_pt_stop(ipt_device_t* ipt_dev) {
    if (!ipt_dev->active)
        return ERR_BAD_STATE;

    mx_handle_t resource = get_root_resource();

    mx_status_t status = mx_mtrace_control(resource, MTRACE_KIND_IPT, MTRACE_IPT_STOP,
                                           0, NULL, 0);
    if (status != NO_ERROR)
        return status;
    ipt_dev->active = false;

    for (uint32_t cpu = 0; cpu < ipt_dev->num_cpus; ++cpu) {
        ipt_per_cpu_state_t* per_cpu = &ipt_dev->per_cpu_state[cpu];

        status = mx_mtrace_control(resource, MTRACE_KIND_IPT, MTRACE_IPT_GET_CTL,
                                   cpu, &per_cpu->ctl, sizeof(per_cpu->ctl));
        if (status != NO_ERROR)
            return status;

        status = mx_mtrace_control(resource, MTRACE_KIND_IPT, MTRACE_IPT_GET_STATUS,
                                   cpu, &per_cpu->status, sizeof(per_cpu->status));
        if (status != NO_ERROR)
            return status;

        status = mx_mtrace_control(resource, MTRACE_KIND_IPT, MTRACE_IPT_GET_OUTPUT_BASE,
                                   cpu, &per_cpu->output_base, sizeof(per_cpu->output_base));
        if (status != NO_ERROR)
            return status;

        status = mx_mtrace_control(resource, MTRACE_KIND_IPT, MTRACE_IPT_GET_OUTPUT_MASK_PTRS,
                                   cpu, &per_cpu->output_mask_ptrs, sizeof(per_cpu->output_mask_ptrs));
        if (status != NO_ERROR)
            return status;
    }

    return NO_ERROR;
}

// On success |*capture_size| will be populated with the amount of data
// captured for |cpu|.

static mx_status_t x86_pt_read_size(ipt_device_t* ipt_dev, uint32_t cpu, size_t* capture_size) {
    if (cpu >= ipt_dev->num_cpus)
        return ERR_INVALID_ARGS;
    if (ipt_dev->active)
        return ERR_BAD_STATE;

    ipt_per_cpu_state_t* per_cpu = &ipt_dev->per_cpu_state[cpu];
    if (!per_cpu->topas)
        return ERR_BAD_STATE;

    // TODO(dje): Handle if called before tracing done.

    *capture_size = compute_capture_size(ipt_dev, cpu);
    return NO_ERROR;
}

// Release resources acquired by x86_pt_alloc.

static mx_status_t x86_pt_free(ipt_device_t* ipt_dev) {
    if (ipt_dev->active)
        return ERR_BAD_STATE;

    for (uint32_t cpu = 0; cpu < ipt_dev->num_cpus; ++cpu) {
        ipt_per_cpu_state_t* per_cpu = &ipt_dev->per_cpu_state[cpu];

        for (size_t i = 0; i < ipt_dev->num_buffers; ++i) {
            io_buffer_release(&per_cpu->buffers[i]);
        }
        free(per_cpu->buffers);
        per_cpu->buffers = NULL;

        for (size_t i = 0; i < ipt_dev->num_tables; ++i) {
            io_buffer_release(&per_cpu->topas[i]);
        }
        free(per_cpu->topas);
        per_cpu->topas = NULL;
    }

    mx_handle_t resource = get_root_resource();
    mx_status_t status =
        mx_mtrace_control(resource, MTRACE_KIND_IPT, MTRACE_IPT_FREE, 0, NULL, 0);
    // TODO(dje): This really shouldn't fail. What to do?
    // For now flag things as busted and prevent further use.
    if (status != NO_ERROR)
        return NO_ERROR;

    return NO_ERROR;
}

static mx_status_t x86_pt_set_buffer_size(ipt_device_t* ipt_dev, size_t order, size_t num) {
    if (order > MAX_BUFFER_ORDER)
        return ERR_INVALID_ARGS;
    if (num == 0 || num > MAX_NUM_BUFFERS)
        return ERR_INVALID_ARGS;
    size_t buffer_pages = 1 << order;
    size_t nr_pages = num * buffer_pages;
    size_t total_per_cpu = nr_pages * PAGE_SIZE;
    if (total_per_cpu > MAX_PER_CPU_SPACE)
        return ERR_INVALID_ARGS;
    ipt_dev->buffer_order = order;
    ipt_dev->num_buffers = num;
    return NO_ERROR;
}

static mx_status_t x86_pt_set_ctl_config(ipt_device_t* ipt_dev, uint64_t ctl_config) {
    const uint64_t settable_mask = (
        IPT_CTL_CYC_EN |
        IPT_CTL_OS_ALLOWED |
        IPT_CTL_USER_ALLOWED |
        IPT_CTL_POWER_EVENT_EN |
        IPT_CTL_FUP_ON_PTW |
        IPT_CTL_CR3_FILTER |
        IPT_CTL_MTC_EN |
        IPT_CTL_TSC_EN |
        IPT_CTL_DIS_RETC |
        IPT_CTL_PTW_EN |
        IPT_CTL_BRANCH_EN |
        IPT_CTL_MTC_FREQ |
        IPT_CTL_CYC_THRESH |
        IPT_CTL_PSB_FREQ |
        IPT_CTL_ADDR0 |
        IPT_CTL_ADDR1 |
        IPT_CTL_ADDR2 |
        IPT_CTL_ADDR3
        );
    if ((ctl_config & ~settable_mask) != 0)
        return ERR_INVALID_ARGS;
    ipt_dev->ctl_config = ctl_config;
    // TODO(dje): Check for unsupported bits being set.
    return NO_ERROR;
}

static mx_status_t x86_pt_set_cr3_filter(ipt_device_t* ipt_dev, uint64_t cr3_filter) {
    ipt_dev->cr3_filter = cr3_filter;
    return NO_ERROR;
}

static mx_status_t x86_pt_set_addr_config(ipt_device_t* ipt_dev, size_t range, size_t a, size_t b) {
    if (range > ipt_config_addr_range_num)
        return ERR_INVALID_ARGS;
    ipt_dev->addr_ranges[range].a = a;
    ipt_dev->addr_ranges[range].b = b;
    return NO_ERROR;
}


// The DDK interface

static mx_status_t ipt_open(mx_device_t* dev, mx_device_t** dev_out, uint32_t flags) {
    // TODO(dje): What's the best way to allow only one open at a time?
    // [We could allow multiple, but multiple clients trying to control
    // tracing is problematic, and currently not supported.
    ipt_device_t* ipt_dev = get_ipt_device(dev);
    if (ipt_dev->opened)
        return ERR_ALREADY_BOUND;

    if (ipt_dev->active && !ipt_dev->per_cpu_state)
        return ERR_BAD_STATE;

    if (!ipt_dev->active && !ipt_dev->per_cpu_state) {
        // TODO(dje): hotplugging/unplugging: later.
        ipt_dev->num_cpus = mx_num_cpus();

        ipt_dev->per_cpu_state = calloc(ipt_dev->num_cpus, sizeof(ipt_dev->per_cpu_state[0]));
        if (!ipt_dev->per_cpu_state)
            return ERR_NO_MEMORY;

        ipt_dev->num_tables = 0;

        // reset values that have defaults
        ipt_dev->num_buffers = DEFAULT_NUM_BUFFERS;
        ipt_dev->buffer_order = DEFAULT_BUFFER_ORDER;
    }

    ipt_dev->opened = true;
    return NO_ERROR;
}

static mx_status_t ipt_close(mx_device_t* dev, uint32_t flags) {
    ipt_device_t* ipt_dev = get_ipt_device(dev);

    ipt_dev->opened = false;
    return NO_ERROR;
}

static ssize_t ipt_write_file(ipt_device_t* ipt_dev,
                              const void* cmd, size_t cmdlen,
                              void* reply, size_t max) {
    if (max != 0)
        return ERR_INVALID_ARGS;

    // Some sensible limit on the file name. There is PATH_MAX, MAXPATHLEN,
    // and others. Not sure what's appropriate here.
    const size_t max_path_len = 1024;
    if (cmdlen > max_path_len)
        return ERR_INVALID_ARGS;

    char* cmdcopy = malloc(cmdlen + 1);
    if (!cmdcopy)
        return ERR_NO_MEMORY;
    memcpy(cmdcopy, cmd, cmdlen);
    cmdcopy[cmdlen] = 0;

    // 10: for cpu number
    size_t pathlen = cmdlen + 10;
    char* path = malloc(pathlen);
    if (!path) {
        free(cmdcopy);
        return ERR_NO_MEMORY;
    }

    int fd = -1;
    size_t buffer_size = (1 << ipt_dev->buffer_order) * PAGE_SIZE;
    mx_status_t status;

    for (uint32_t cpu = 0; cpu < ipt_dev->num_cpus; ++cpu) {
        ipt_per_cpu_state_t* per_cpu = &ipt_dev->per_cpu_state[cpu];
        uint64_t capture_size;
        status = x86_pt_read_size(ipt_dev, cpu, &capture_size);
        if (status != NO_ERROR)
            goto Fail;
        snprintf(path, pathlen, "%s.%u.pt", cmdcopy, cpu);
        fd = open(path, O_CREAT | O_TRUNC | O_RDWR, S_IRUSR | S_IWUSR);
        if (fd < 0) {
            xprintf("IPT: unable to write file: %s: %s\n", path, strerror(errno));
            status = ERR_BAD_PATH;
            goto Fail;
        }
        size_t bytes_left = capture_size;
        for (size_t i = 0; i < ipt_dev->num_buffers && bytes_left > 0; ++i) {
            void* buf = io_buffer_virt(&per_cpu->buffers[i]);
            size_t to_write = buffer_size;
            if (to_write > bytes_left)
                to_write = bytes_left;
            if (write(fd, buf, to_write) != (ssize_t) to_write) {
                xprintf("IPT: short write, file: %s\n", path);
                status = ERR_IO;
                goto Fail;
            }
            bytes_left -= to_write;
        }
        assert(bytes_left == 0);
        close(fd);
        fd = -1;
    }

    status = NO_ERROR;

  Fail:
    free(cmdcopy);
    free(path);
    if (fd != -1)
        close(fd);
    return status;
}

static ssize_t ipt_ioctl(mx_device_t* dev, uint32_t op,
                         const void* cmd, size_t cmdlen,
                         void* reply, size_t max) {
    ipt_device_t* ipt_dev = get_ipt_device(dev);

    switch (op) {
    case IOCTL_IPT_ALLOC:
        if (cmdlen != 0 || max != 0)
            return ERR_INVALID_ARGS;
        return x86_pt_alloc(ipt_dev);
    case IOCTL_IPT_START:
        if (cmdlen != 0 || max != 0)
            return ERR_INVALID_ARGS;
        return x86_pt_start(ipt_dev);
    case IOCTL_IPT_STOP:
        if (cmdlen != 0 || max != 0)
            return ERR_INVALID_ARGS;
        return x86_pt_stop(ipt_dev);
    case IOCTL_IPT_FREE:
        if (cmdlen != 0 || max != 0)
            return ERR_INVALID_ARGS;
        return x86_pt_free(ipt_dev);
    case IOCTL_IPT_WRITE_FILE:
        return ipt_write_file(ipt_dev, cmd, cmdlen, reply, max);
    case IOCTL_IPT_SET_BUFFER_SIZE: {
        if (max != 0)
            return ERR_INVALID_ARGS;
        size_t size[2];
        if (cmdlen != sizeof(size))
            return ERR_INVALID_ARGS;
        memcpy(size, cmd, sizeof(size));
        return x86_pt_set_buffer_size(ipt_dev, size[0], size[1]);
    }
    case IOCTL_IPT_SET_CTL_CONFIG: {
        if (max != 0)
            return ERR_INVALID_ARGS;
        uint64_t ctl_config;
        if (cmdlen != sizeof(ctl_config))
            return ERR_INVALID_ARGS;
        memcpy(&ctl_config, cmd, sizeof(ctl_config));
        return x86_pt_set_ctl_config(ipt_dev, ctl_config);
    }
    case IOCTL_IPT_SET_CR3_FILTER: {
        if (max != 0)
            return ERR_INVALID_ARGS;
        uint64_t cr3_filter;
        if (cmdlen != sizeof(cr3_filter))
            return ERR_INVALID_ARGS;
        memcpy(&cr3_filter, cmd, sizeof(cr3_filter));
        return x86_pt_set_cr3_filter(ipt_dev, cr3_filter);
    }
    case IOCTL_IPT_SET_ADDR_CONFIG: {
        if (max != 0)
            return ERR_INVALID_ARGS;
        uint64_t addr[3];
        if (cmdlen != sizeof(addr))
            return ERR_INVALID_ARGS;
        memcpy(addr, cmd, sizeof(addr));
        return x86_pt_set_addr_config(ipt_dev, addr[0], addr[1], addr[2]);
    }
    default:
        return ERR_INVALID_ARGS;
    }
}

static mx_status_t ipt_release(mx_device_t* dev) {
    ipt_device_t* ipt_dev = get_ipt_device(dev);

    // TODO(dje): Neither of these should fail. What to do?
    // For now flag things as busted and prevent further use.
    x86_pt_stop(ipt_dev);
    x86_pt_free(ipt_dev);

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
