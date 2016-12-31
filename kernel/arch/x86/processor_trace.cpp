// Copyright 2016 The Fuchsia Authors
//
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT

// We currently only support Table of Physical Addresses mode currently, so that
// we can have stop-on-full behavior rather than wrap-around.

#include <arch/x86.h>
#include <arch/x86/feature.h>
#include <arch/x86/mmu.h>
#include <arch/x86/processor_trace.h>
#include <err.h>
#include <kernel/thread.h>
#include <kernel/vm.h>
#include <pow2.h>
#include <trace.h>

#define LOCAL_TRACE 0

// Control MSRs
#define IA32_RTIT_OUTPUT_BASE 0x560
#define IA32_RTIT_OUTPUT_MASK_PTRS 0x561
#define IA32_RTIT_CTL 0x570
#define IA32_RTIT_STATUS 0x571
#define IA32_RTIT_CR3_MATCH 0x572
#define IA32_RTIT_ADDR0_A 0x580
#define IA32_RTIT_ADDR0_B 0x581
#define IA32_RTIT_ADDR1_A 0x582
#define IA32_RTIT_ADDR1_B 0x583
#define IA32_RTIT_ADDR2_A 0x584
#define IA32_RTIT_ADDR2_B 0x585
#define IA32_RTIT_ADDR3_A 0x586
#define IA32_RTIT_ADDR3_B 0x587

// Macros for building entries for the Table of Physical Addresses
#define TOPA_ENTRY_PHYS_ADDR(x) ((uint64_t)(x) & ~((1ULL<<12)-1))
#define TOPA_ENTRY_SIZE(size_log2) ((uint64_t)((size_log2) - 12) << 6)
#define TOPA_ENTRY_STOP (1ULL << 4)
#define TOPA_ENTRY_INT (1ULL << 1) // FIXME: << 2
#define TOPA_ENTRY_END (1ULL << 0)

// Macros for extracting info from ToPA entries
#define TOPA_ENTRY_EXTRACT_PHYS_ADDR(e) ((paddr_t)((e) & ~((1ULL<<12)-1)))
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

void x86_processor_trace_init(void)
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

// Create a ToPA making use of the pages in the *page_array*, in order.
// Returns the number of ToPA entries necessary to make use of the array.
//
// This assumes that tables are 16KB in size (technically can be up to 256MB).
// A 16KB table provides 2047 non-END entries, so at the
// minimum can provide a capture buffer of just under 8MB.  The output count
// includes the END entries across all neeeded tables.
static size_t make_topa(vm_page_t** page_array, size_t len,
                        uint64_t** tables, size_t table_count) {
    size_t num_entries = 0;

    size_t curr_table = 0;
    size_t curr_idx = 0;
    uint64_t* last_entry = NULL;

    LTRACEF("Processing request with %lu pages\n", len);

    // ToPA entries of size N must be aligned to N, too.  Attempt
    // to find runs of pages that meet these requirements and
    // pack them to reduce ToPA size.
    for (size_t i = 0; i < len; ++i) {
        LTRACEF("  i=%lu\n", i);
        paddr_t pa = vm_page_to_paddr(page_array[i]);

        int best_shift = __builtin_ffsl(pa) - 1;
        if (best_shift < 0 || best_shift >= TOPA_MAX_SHIFT) {
            best_shift = TOPA_MAX_SHIFT;
        }

        // best_shift is now our best possible shfit
        DEBUG_ASSERT(best_shift >= PAGE_SIZE_SHIFT);
        const size_t max_run_len = 1UL << (best_shift - PAGE_SIZE_SHIFT);
        LTRACEF("  best shift: %d, max_run_len %lu\n", best_shift, max_run_len);

        paddr_t prev_pa = pa;
        size_t j;
        for (j = i + 1; j < len && j - i < max_run_len; ++j) {
            paddr_t next_pa = vm_page_to_paddr(page_array[j]);
            if (next_pa != prev_pa + PAGE_SIZE) {
                break;
            }
            prev_pa = next_pa;
        }

        // [i, j) is a range of contiguous pages
        size_t run_len = j - i;
        LTRACEF("  run_len %lu\n", run_len);
        size_t run_len_log2 = log2_ulong_floor(run_len);
        DEBUG_ASSERT(run_len_log2 + PAGE_SIZE_SHIFT <= TOPA_MAX_SHIFT);
        DEBUG_ASSERT(run_len_log2 + PAGE_SIZE_SHIFT >= TOPA_MIN_SHIFT);

        // Consume all of the pages in this run, and count them as one entry
        if (curr_table < table_count) {
            uint64_t val = TOPA_ENTRY_PHYS_ADDR(pa) |
                    TOPA_ENTRY_SIZE(run_len_log2 + PAGE_SIZE_SHIFT);
            LTRACEF("Table entry %lu, %lu has shift size %lu\n", curr_table, curr_idx, run_len_log2 + PAGE_SIZE_SHIFT);
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
        i += (1UL << run_len_log2) - 1;
        num_entries++;
    }

    // Populate END entries for completed tables
    for (size_t i = 0; i < curr_table; ++i) {
        void* table_vaddr;
        if (i == table_count - 1) {
            table_vaddr = tables[0];
        } else {
            table_vaddr = tables[i + 1];
        }

        paddr_t next_table_pa = vaddr_to_paddr(table_vaddr);
        uint64_t val = TOPA_ENTRY_PHYS_ADDR(next_table_pa) | TOPA_ENTRY_END;
        tables[i][TOPA_MAX_TABLE_ENTRIES - 1] = val;
    }

    // Populate the END entry for a possibly non-full last table
    if (curr_table < table_count) {
        paddr_t first_table_pa = vaddr_to_paddr(tables[0]);
        uint64_t val = TOPA_ENTRY_PHYS_ADDR(first_table_pa) | TOPA_ENTRY_END;
        tables[curr_table][curr_idx] = val;
    }

    // Add the STOP flag to the last non-END entry in the tables
    if (last_entry) {
        *last_entry |= TOPA_ENTRY_STOP;
    }

    size_t num_end_entries = (num_entries + TOPA_MAX_TABLE_ENTRIES - 2) /
            (TOPA_MAX_TABLE_ENTRIES - 1);
    LTRACEF("num_end_entries: %lu\n", num_end_entries);

    LTRACEF("total entries: %lu\n", num_entries + num_end_entries);
    return num_entries + num_end_entries;
}

static size_t compute_topa_entry_count(vm_page_t** page_array, size_t len) {
    return make_topa(page_array, len, NULL, 0);
}

// Walk the tables to discover how much has been captured
static size_t compute_capture_size(uint64_t** tables, size_t table_count,
                                   uint64_t curr_table_paddr,
                                   uint32_t curr_table_entry_idx,
                                   uint32_t curr_entry_offset) {
    size_t total_size = 0;
    for (size_t i = 0; i < table_count; ++i) {
        paddr_t table_paddr = vaddr_to_paddr(tables[i]);

        for (size_t j = 0; j < TOPA_MAX_TABLE_ENTRIES - 1; ++j) {
            if (table_paddr == curr_table_paddr && j >= curr_table_entry_idx) {
                total_size += curr_entry_offset;
                return total_size;
            }

            uint64_t entry = tables[i][j];
            total_size += 1UL << TOPA_ENTRY_EXTRACT_SIZE(entry);
        }
    }

    // Should be unreachable...
    panic("unexpectedly exited capture loop");
}

// This operates in the thread-context.  The currently running thread will
// be traced until either trace_disable() is called or until the capture
// buffer fills.
//
// *page_array* is an array of pages to be used as the capture buffer.
// If this function call succeeds, the thread is considered to be holding a
// logical reference to this capture buffer, and trace_disable() *must*
// be invoked before freeing the pages.
status_t x86_processor_trace_enable(vm_page_t** page_array, size_t len) {
    status_t status = ERR_INTERNAL;

    if (!supports_output_topa) {
        return ERR_NOT_SUPPORTED;
    }

    thread_t* thread = get_current_thread();
    if (thread->arch.processor_trace_ctx) {
        return ERR_BAD_STATE;
    }
    if ((read_msr(IA32_RTIT_CTL) & RTIT_CTL_TRACE_EN) ||
        (read_msr(IA32_RTIT_STATUS) & RTIT_STATUS_STOPPED)) {
        return ERR_BAD_STATE;
    }

    size_t entry_count = compute_topa_entry_count(page_array, len);
    size_t table_count = (entry_count + TOPA_MAX_TABLE_ENTRIES - 1) /
            TOPA_MAX_TABLE_ENTRIES;

    if (entry_count < 2) {
        printf("INVALID ENTRY COUNT: %lu\n", entry_count);
        return ERR_INVALID_ARGS;
    }

    // Some early Processor Trace implementations only supported having a
    // table with a single real entry and an END.
    if (!supports_output_topa_multi && entry_count > 2) {
        return ERR_NOT_SUPPORTED;
    }

    // Allocate our Table(s) of Physical Addresses
    // Null-terminate the array, so we don't have to pass around the count
    // for trace_disable().
    auto table_ptrs =
        reinterpret_cast<uint64_t**>(calloc(sizeof(uint64_t*), table_count + 1));
    if (!table_ptrs) {
        return ERR_NO_MEMORY;
    }

    vmm_aspace_t *kernel_aspace = vmm_get_kernel_aspace();
    for (size_t i = 0; i < table_count; ++i) {
        status = vmm_alloc_contiguous(
                kernel_aspace, "intelpt",
                sizeof(uint64_t) * TOPA_MAX_TABLE_ENTRIES, (void**)&table_ptrs[i],
                PAGE_SIZE_SHIFT, 0 /*min_alloc_gap*/, VMM_FLAG_COMMIT,
                ARCH_MMU_FLAG_PERM_READ | ARCH_MMU_FLAG_PERM_WRITE);
        if (status != NO_ERROR) {
            printf("ALLOC FAIL: %08lx\n", sizeof(uint64_t) * TOPA_MAX_TABLE_ENTRIES );
            goto cleanup;
        }
    }

    // xyzdje
    TRACEF("Enabling processor trace, kernel cr3: 0x%" PRIxPTR "\n",
           x86_kernel_cr3());

    {
        make_topa(page_array, len, table_ptrs, table_count);

        paddr_t first_table_phys = vaddr_to_paddr(table_ptrs[0]);

        // Load the ToPA configuration
        write_msr(IA32_RTIT_OUTPUT_BASE, first_table_phys);
        write_msr(IA32_RTIT_OUTPUT_MASK_PTRS, 0);

        // Enable the trace
        uint64_t ctl = RTIT_CTL_TOPA | RTIT_CTL_TRACE_EN;
        // TODO(teisenbe): Allow caller provided flags for controlling
        // these options.
        ctl |= RTIT_CTL_USER_ALLOWED | RTIT_CTL_OS_ALLOWED;
        ctl |= RTIT_CTL_BRANCH_EN;
        ctl |= RTIT_CTL_TSC_EN;
        //ctl |= RTIT_CTL_PTW_EN; -- causes gpf
        write_msr(IA32_RTIT_CTL, ctl);

        // TODO(teisenbe): Change the permssions on the tables to read-only

        thread->arch.processor_trace_ctx = table_ptrs;
        return NO_ERROR;
    }

 cleanup:
    for (size_t i = 0; i < table_count; ++i) {
        if (table_ptrs[i]) {
            vmm_free_region(kernel_aspace, (vaddr_t)table_ptrs[i]);
        }
    }
    free(table_ptrs);
    return status;
}

// *capture_size* will be populated with the amount of data captured, on
// success.
status_t x86_processor_trace_disable(size_t* capture_size) {
    thread_t* thread = get_current_thread();
    if (!thread->arch.processor_trace_ctx) {
        return ERR_BAD_STATE;
    }

    // Disable the trace
    write_msr(IA32_RTIT_CTL, 0);

    // Save info we care about for output
    uint64_t curr_table = read_msr(IA32_RTIT_OUTPUT_BASE);
    uint64_t trace_cursors = read_msr(IA32_RTIT_OUTPUT_MASK_PTRS);

    // Zero all MSRs so that we are in the XSAVE initial configuration
    write_msr(IA32_RTIT_OUTPUT_BASE, 0);
    write_msr(IA32_RTIT_OUTPUT_MASK_PTRS, 0);
    write_msr(IA32_RTIT_STATUS, 0);
    if (supports_cr3_filtering) {
        write_msr(IA32_RTIT_CR3_MATCH, 0);
    }

    // TODO(teisenbe): Clear ADDR* MSRs depending on leaf 1

    auto table_ptrs =
        reinterpret_cast<uint64_t**>(thread->arch.processor_trace_ctx);
    size_t table_count = 0;
    while (table_ptrs[table_count]) {
        table_count++;
    }

    *capture_size = compute_capture_size(table_ptrs, table_count,
                                         curr_table,
                                         (uint32_t)trace_cursors >> 7,
                                         (uint32_t)(trace_cursors >> 32));

    return NO_ERROR;
}

// Release resources acquired by x86_processor_trace_enable.

status_t x86_processor_trace_free(void) {
    thread_t* thread = get_current_thread();
    if (!thread->arch.processor_trace_ctx) {
        return ERR_BAD_STATE;
    }

    auto table_ptrs =
        reinterpret_cast<uint64_t**>(thread->arch.processor_trace_ctx);

    vmm_aspace_t *kernel_aspace = vmm_get_kernel_aspace();
    size_t i = 0;
    while (table_ptrs[i]) {
        vmm_free_region(kernel_aspace, (vaddr_t)table_ptrs[i]);
        ++i;
    }

    free(table_ptrs);
    thread->arch.processor_trace_ctx = NULL;
    return NO_ERROR;
}
