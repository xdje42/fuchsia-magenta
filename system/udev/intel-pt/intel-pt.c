// Copyright 2016 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// See the README.md in this directory for documentation.

#include <ddk/binding.h>
#include <ddk/device.h>
#include <ddk/driver.h>

#include <magenta/intel-pt.h>
#include <magenta/syscalls.h>
#include <magenta/types.h>

#include <magenta/device/intel-pt.h>

#include <magenta/syscalls/resource.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <threads.h>

#define TRACE 1

#if TRACE
#define xprintf(fmt...) printf(fmt)
#else
#define xprintf(fmt...) \
    do {                \
    } while (0)
#endif

typedef struct ipt_per_cpu_state {
    // msrs
    uint64_t ctl;
    uint64_t status;
    uint64_t output_base;
    uint64_t output_mask_ptrs;
    uint64_t cr3_match;

    // trace buffers and ToPA tables
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

} ipt_device_t;

#define get_ipt_device(dev) containerof(dev, ipt_device_t, device)

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

// Valid ToPA entry sizes
#define TOPA_MIN_SHIFT 12
#define TOPA_MAX_SHIFT 27

// Arbitarily picked constants for ourselves
#define TOPA_MAX_TABLE_ENTRIES 2048 // Use up to 16-KB tables

static bool supports_cr3_filtering = false;
static bool supports_psb = false;
static bool supports_ip_filtering = false;
static bool supports_mtc = false;
static bool supports_ptwrite = false;
static bool supports_power_events = false;
static bool supports_output_topa = false;
static bool supports_output_topa_multi = false;
static bool supports_output_single = false;
static bool supports_output_transport = false;

// maximum space, in bytes, for trace buffers (per cpu)
#define MAX_PER_CPU_SPACE (16 * 1024 * 1024)

// default number of buffers, each 2^|buffer_order| pages in size
#define DEFAULT_NUM_BUFFERS 16

// log2 size of each buffer, in pages, default is 16KB
#define DEFAULT_BUFFER_ORDER 2


// The userspace side of the driver

static void x86_pt_init(void)
{
    if (!x86_feature_test(X86_FEATURE_PT)) {
        return;
    }

    struct cpuid_leaf leaf;
    if (!x86_get_cpuid_subleaf(X86_CPUID_PT, 0, &leaf)) {
        return;
    }

    supports_cr3_filtering = !!(leaf.b & (1<<0));
    supports_psb = !!(leaf.b & (1<<1));
    supports_ip_filtering = !!(leaf.b & (1<<2));
    supports_mtc = !!(leaf.b & (1<<3));
    supports_ptwrite = !!(leaf.b & (1<<4));
    supports_power_events = !!(leaf.b & (1<<5));

    supports_output_topa = !!(leaf.c & (1<<0));
    supports_output_topa_multi = !!(leaf.c & (1<<1));
    supports_output_single = !!(leaf.c & (1<<2));
    supports_output_transport = !!(leaf.c & (1<<3));

    // TODO(teisenbe): For IP filtering, MTC, CYC, and PSB support, we need
    // to enumerate subleaf 1
}

// Create a ToPA for the configured number of pages.
// Returns the number of ToPA entries necessary to make use of the array.
// |tables| may be NULL (in which case |table_count| must be zero),
// which means to just compute the required number of entries.
//
// This assumes that tables are 16KB in size (technically can be up to 256MB).
// A 16KB table provides 2047 non-END entries, so at the
// minimum can provide a capture buffer of just under 8MB.  The output count
// includes the END entries across all needed tables.

static size_t make_topa(ipt_device_t* ipt_dev,
                        io_buffer_t* topas, size_t table_count) {
    xprintf("Processing request with %zu pages\n", len);

    const size_t run_len_log2 = ipt_dev->buffer_order;
    const size_t run_len = 1 << run_len_log2;
    DEBUG_ASSERT(run_len_log2 + PAGE_SIZE_SHIFT <= TOPA_MAX_SHIFT);
    DEBUG_ASSERT(run_len_log2 + PAGE_SIZE_SHIFT >= TOPA_MIN_SHIFT);
    size_t len = ipt_dev->num_buffers * run_len;

    size_t num_entries = 0;
    size_t curr_table = 0;
    size_t curr_idx = 0;
    uint64_t* last_entry = NULL;

    // Note: An early version of this patch auto-computed the desired grouping
    // of pages with sufficient alignment. If you find yourself needing this
    // functionality again, check change 9470.

    for (size_t i = 0; i < run_len; ++i) {
        mx_paddr_t pa = io_buffer_phys(&
vm_page_to_paddr(p);

        // Consume all of the pages in this run, and count them as one entry
        if (curr_table < table_count) {
            uint64_t val = TOPA_ENTRY_PHYS_ADDR(pa) |
                    TOPA_ENTRY_SIZE(run_len_log2 + PAGE_SIZE_SHIFT);
            xprintf("Table entry %lu, %lu has shift size %lu\n",
                    curr_table, curr_idx, run_len_log2 + PAGE_SIZE_SHIFT);
            tables[curr_table][curr_idx] = val;
            last_entry = &tables[curr_table][curr_idx];

            // Make sure we leave one at the end of the table for the END marker
            if (unlikely(curr_idx >= TOPA_MAX_TABLE_ENTRIES - 2)) {
                curr_idx = 0;
                curr_table++;
            } else {
                curr_idx++;
            }
        }

        num_entries++;
    }

    size_t num_end_entries = (num_entries + TOPA_MAX_TABLE_ENTRIES - 2) /
            (TOPA_MAX_TABLE_ENTRIES - 1);
    size_t result = num_entries + num_end_entries;
    xprintf("num_end_entries: %zu\n", num_end_entries);
    xprintf("total entries: %zu\n", result);

    if (tables == NULL)
        return result;

    // Populate END entries for completed tables
    for (size_t i = 0; i < curr_table; ++i) {
        void* table_vaddr;
        if (i == table_count - 1) {
            table_vaddr = tables[0];
        } else {
            table_vaddr = tables[i + 1];
        }

        mx_paddr_t next_table_pa = vaddr_to_paddr(table_vaddr);
        uint64_t val = TOPA_ENTRY_PHYS_ADDR(next_table_pa) | TOPA_ENTRY_END;
        tables[i][TOPA_MAX_TABLE_ENTRIES - 1] = val;
    }

    // Populate the END entry for a possibly non-full last table
    if (curr_table < table_count) {
        mx_paddr_t first_table_pa = vaddr_to_paddr(tables[0]);
        uint64_t val = TOPA_ENTRY_PHYS_ADDR(first_table_pa) | TOPA_ENTRY_END;
        tables[curr_table][curr_idx] = val;
    }

    // Add the STOP flag to the last non-END entry in the tables
    if (last_entry) {
        *last_entry |= TOPA_ENTRY_STOP;
    }

    return result;
}

static size_t compute_topa_entry_count(ipt_device_t* ipt_dev) {
    return make_topa(ipt_dev, NULL, 0);
}

// Walk the tables to discover how much data has been captured for |cpu|.

static size_t compute_capture_size(ipt_device_t* ipt_dev, uint32_t cpu) {
    ipt_per_cpu_state_t* per_cpu = &ipt_dev->per_cpu_state[cpu];

    uint64_t curr_table_paddr = per_cpu->output_base;
    uint32_t curr_table_entry_idx = (uint32_t)per_cpu->output_mask_ptrs >> 7;
    uint32_t curr_entry_offset = (uint32_t)(per_cpu->output_mask_ptrs >> 32);

    xprintf("compute_capture_size: cpu %u, tables %p, table_count %zu\n",
            cpu, tables, table_count);
    xprintf("    curr_table_paddr 0x%" PRIx64 ", curr_table_entry_idx %u, curr_entry_offset %u\n",
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

    // Should be unreachable...
#if 0
    panic("unexpectedly exited capture loop");
#else
    xprintf("unexpectedly exited capture loop\n");
    return 0;
#endif
}

// Subroutine of x86_pt_alloc() to simplify it.

static mx_status_t x86_pt_alloc1(ipt_device_t* ipt_dev) {
    mx_status_t status;
    uint32_t num_cpus = mx_num_cpus();
    size_t buffer_pages = 1 << ipt_dev->buffer_order;
    size_t nr_pages = ipt_dev->num_buffers * buffer_pages;
    uint64_t total_per_cpu = nr_pages * PAGE_SIZE;
    if (total_per_cpu > MAX_PER_CPU_SPACE)
        return ERR_INVALID_ARGS;

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
        xprintf("INVALID ENTRY COUNT: %zu\n", entry_count);
        return ERR_INVALID_ARGS;
    }

    // Some early Processor Trace implementations only supported having a
    // table with a single real entry and an END.
    if (!supports_output_topa_multi && entry_count > 2)
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

        make_topa(ipt_dev, per_cpu->topas, table_count);
    }

    return NO_ERROR;
}

// Allocate space for the trace buffers, for each cpu,
// and do any other initialization needed prior to starting a trace.

static mx_status_t x86_pt_alloc(ipt_pt_device_t* ipt_dev) {
    // TODO(dje): For now we only support ToPA.
    if (!supports_output_topa)
        return ERR_NOT_SUPPORTED;

    // TODO: lock
    if (active)
        return ERR_BAD_STATE;

    mx_status_t status = x86_pt_alloc1(ipt_dev);
    if (status != NO_ERROR) {
        x86_pt_free(ipt_dev);
        return status;
    }

    status = mx_mtrace_control(resource, MTRACE_KIND_IPT, MTRACE_IPT_ALLOC, 0, NULL, 0);
    if (status != NO_ERROR)
        return status;

    return NO_ERROR;
}

// Begin tracing.

static mx_status_t x86_pt_start(ipt_device_t* ipt_dev) {
    if (ipt_dev->active)
        return ERR_BAD_STATE;
    if (!ipt->per_cpu_state)
        return ERR_BAD_STATE;

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
        status = mx_mtrace_control(resource, MTRACE_KIND_IPT, MTRACE_IPT_STAGE_STATUS,
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

static mx_status_t x86_pt_stop(ipt_pt_device_t* ipt_dev) {
    if (!active)
        return ERR_BAD_STATE;

    status = mx_mtrace_control(resource, MTRACE_KIND_IPT, MTRACE_IPT_STOP,
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

        status = mx_mtrace_control(resource, MTRACE_KIND_IPT, MTRACE_IPT_STAGE_STATUS,
                                   cpu, &per_cpu->status, sizeof(per_cpu->status));
        if (status != NO_ERROR)
            return status;

        status = mx_mtrace_control(resource, MTRACE_KIND_IPT, MTRACE_IPT_STAGE_OUTPUT_BASE,
                                   cpu, &per_cpu->output_base, sizeof(per_cpu->output_base));
        if (status != NO_ERROR)
            return status;

        status = mx_mtrace_control(resource, MTRACE_KIND_IPT, MTRACE_IPT_STAGE_STATUS,
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

    *capture_size = compute_capture_size(ipt_dev, cpu);
    return NO_ERROR;
}

// Release resources acquired by x86_pt_alloc.

static mx_status_t x86_pt_free(ipt_device_t* ipt_dev) {
    if (active)
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

    mx_status_t status =
        mx_mtrace_control(resource, MTRACE_KIND_IPT, MTRACE_IPT_FREE, 0, NULL, 0);
    // TODO(dje): This really shouldn't fail. What to do?
    // For now flag things as busted and prevent further use.
    if (status != NO_ERROR)
        return NO_ERROR;

    return NO_ERROR;
}


// The DDK interface

static mx_status_t ipt_open(mx_device_t* dev, mx_device_t** dev_out, uint32_t flags) {
    // TODO(dje): What's the best way to allow only one open at a time?
    ipt_device_t* ipt_dev = get_ipt_device(dev);
    if (ipt_dev->opened)
        return ERR_ALREADY_BOUND;

    if (ipt_dev->active)
        return ERR_BAD_STATE;
    if (ipt_dev->per_cpu_state)
        return ERR_BAD_STATE;

    // TODO(dje): hotplugging/unplugging: later.
    ipt_dev->num_cpus = mx_num_cpus();

    ipt_dev->per_cpu_state = calloc(ipt_dev->num_cpus, sizeof(ipt_dev->per_cpu_state[0]));
    ipt_dev->num_tables = 0;

    // reset values that have defaults
    ipt_dev->num_buffers = DEFAULT_NUM_BUFFERS;
    ipt_dev->buffer_order = DEFAULT_BUFFER_ORDER;

    ipt_dev->opened = true;
    ipt_dev->active = false;

    return NO_ERROR;
}

static ssize_t ipt_ioctl(mx_device_t* dev, uint32_t op,
                         const void* cmd, size_t cmdlen,
                         void* reply, size_t max) {
    ipt_device_t* ipt_dev = get_ipt_device(dev);
    mx_handle_t resource = get_root_resource();

    switch (op) {
    case IOCTL_IPT_ALLOC:
        if (cmdlen != 0 || max != 0)
            return ERR_INVALID_ARGS;
        return x86_pt_alloc();
    case IOCTL_IPT_START:
        if (cmdlen != 0 || max != 0)
            return ERR_INVALID_ARGS;
        return x86_pt_start();
    case IOCTL_IPT_STOP:
        if (cmdlen != 0 || max != 0)
            return ERR_INVALID_ARGS;
        return x86_pt_stop();
    case IOCTL_IPT_FREE:
        if (cmdlen != 0 || max != 0)
            return ERR_INVALID_ARGS;
        return x86_pt_free();
    case IOCTL_IPT_GET_DATA_SIZE:
        return NO_ERROR;
    case IOCTL_KTRACE_ADD_PROBE: {
        char name[MX_MAX_NAME_LEN];
        if ((cmdlen >= MX_MAX_NAME_LEN) || (cmdlen < 1) || (max != sizeof(uint32_t))) {
            return ERR_INVALID_ARGS;
        }
        memcpy(name, cmd, cmdlen);
        name[cmdlen] = 0;
        mx_status_t status = mx_ktrace_control(get_root_resource(), KTRACE_ACTION_NEW_PROBE, 0, name);
        if (status < 0) {
            return status;
        }
        *((uint32_t*) reply) = status;
        return sizeof(uint32_t);
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
    ipt_dev->opened = false;

    return NO_ERROR;
}

static mx_protocol_device_t ipt_device_proto = {
    .open = ipt_open,
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
