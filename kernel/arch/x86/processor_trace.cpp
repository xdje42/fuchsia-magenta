// Copyright 2016 The Fuchsia Authors
//
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT

// We currently only support Table of Physical Addresses mode currently, so that
// we can have stop-on-full behavior rather than wrap-around.

#include <arch/user_copy.h>
#include <arch/x86.h>
#include <arch/x86/feature.h>
#include <arch/x86/mmu.h>
#include <arch/x86/processor_trace.h>
#include <err.h>
#include <kernel/mp.h>
#include <kernel/thread.h>
#include <kernel/vm.h>
#include <mxtl/macros.h>
#include <mxtl/unique_ptr.h>
#include <new.h>
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

static bool active = false;

// number of buffers, each 2^|pt_buffer_order| pages in size
static size_t pt_num_buffers = 16;

// log2 size of each buffer, in pages, default is 16KB
static uint8_t pt_buffer_order = 2;

// maximum space, in bytes, for trace buffers (per cpu)
static size_t max_per_cpu_space = 16 * 1024 * 1024;

class x86_cpu_pt_data {
  public:
    x86_cpu_pt_data();
    ~x86_cpu_pt_data();

    // these are static values set by x86_processor_trace_alloc.
    struct list_node buffer_page_list_;
    size_t table_count_;
    uint64_t** table_ptrs_;

    // these values are set when tracing stops
    uint64_t curr_table_;
    uint64_t cursors_;

    DISALLOW_COPY_ASSIGN_AND_MOVE(x86_cpu_pt_data);
};
static x86_cpu_pt_data* pt_data;

x86_cpu_pt_data::x86_cpu_pt_data()
    : table_count_(0),
      table_ptrs_(nullptr),
      curr_table_(0),
      cursors_(0) {
    list_initialize(&buffer_page_list_);
}

x86_cpu_pt_data::~x86_cpu_pt_data() {
    pmm_free(&buffer_page_list_);

    if (table_ptrs_) {
        vmm_aspace_t *kernel_aspace = vmm_get_kernel_aspace();
        for (size_t i = 0; i < table_count_; ++i) {
            if (table_ptrs_[i])
                vmm_free_region(kernel_aspace, (vaddr_t)table_ptrs_[i]);
        }
        free(table_ptrs_);
    }
}

static inline vm_page_t* next_page(list_node_t* list, vm_page_t* p) {
    return list_next_type(list, &p->free.node, vm_page_t, free.node);
}

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

// Create a ToPA, using the pages in |pages|.
// |len| is the number of entries in the list.
// Pages are assumed to have been created in sets of contiguous chunks,
// see x86_processor_trace_alloc.
// Returns the number of ToPA entries necessary to make use of the array.
// |tables| may be nullptr (in which case |table_count| must be zero),
// which means to just compute the required number of entries.
//
// This assumes that tables are 16KB in size (technically can be up to 256MB).
// A 16KB table provides 2047 non-END entries, so at the
// minimum can provide a capture buffer of just under 8MB.  The output count
// includes the END entries across all neeeded tables.
static size_t make_topa(list_node_t* pages, size_t len,
                        uint64_t** tables, size_t table_count) {
    LTRACEF("Processing request with %zu pages\n", len);

    const size_t run_len_log2 = pt_buffer_order;
    const size_t run_len = 1 << run_len_log2;
    DEBUG_ASSERT(run_len_log2 + PAGE_SIZE_SHIFT <= TOPA_MAX_SHIFT);
    DEBUG_ASSERT(run_len_log2 + PAGE_SIZE_SHIFT >= TOPA_MIN_SHIFT);
    DEBUG_ASSERT(len == list_length(pages));
    DEBUG_ASSERT(len == pt_num_buffers * run_len);

    size_t num_entries = 0;
    size_t curr_table = 0;
    size_t curr_idx = 0;
    uint64_t* last_entry = nullptr;

    // Note: An early version of this patch auto-computed the desired grouping
    // of pages with sufficient alignment. If you find yourself needing this
    // functionality again, check change 9470.

    vm_page_t* p;

    // Each iteration actually covers run_len entries.
    list_for_every_entry (pages, p, vm_page_t, free.node) {
        paddr_t pa = vm_page_to_paddr(p);

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

        // Verify this group of pages is contiguous.
        vm_page_t* next;
        for (size_t i = 0; i < run_len - 1; ++i) {
            next = next_page(pages, p);
            DEBUG_ASSERT(next);
            paddr_t pa = vm_page_to_paddr(p);
            paddr_t next_pa = vm_page_to_paddr(next);
            DEBUG_ASSERT(next_pa == pa + PAGE_SIZE);
            p = next;
        }
        p = next;

        num_entries++;
    }

    size_t num_end_entries = (num_entries + TOPA_MAX_TABLE_ENTRIES - 2) /
            (TOPA_MAX_TABLE_ENTRIES - 1);
    size_t result = num_entries + num_end_entries;
    LTRACEF("num_end_entries: %zu\n", num_end_entries);
    LTRACEF("total entries: %zu\n", result);

    if (tables == nullptr)
        return result;

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

    return result;
}

static size_t compute_topa_entry_count(list_node_t* pages, size_t len) {
    return make_topa(pages, len, nullptr, 0);
}

// Walk the tables to discover how much has been captured
// TODO(dje): Just pass cpu, ptd.
static size_t compute_capture_size(uint32_t cpu,
                                   uint64_t** tables, size_t table_count,
                                   uint64_t curr_table_paddr,
                                   uint32_t curr_table_entry_idx,
                                   uint32_t curr_entry_offset) {
    TRACEF("compute_capture_size: cpu %u, tables %p, table_count %zu\n",
           cpu, tables, table_count);
    TRACEF("    curr_table_paddr 0x%" PRIx64 ", curr_table_entry_idx %u, curr_entry_offset %u\n",
           curr_table_paddr, curr_table_entry_idx, curr_entry_offset);

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
#if 0
    panic("unexpectedly exited capture loop");
#else
    TRACEF("unexpectedly exited capture loop\n");
    return 0;
#endif
}

// Allocate space for the trace buffers, for each cpu,
// and do any other initialization needed prior to starting a trace.

status_t x86_processor_trace_alloc() {
    if (!supports_output_topa)
        return ERR_NOT_SUPPORTED;

    // TODO: lock
    if (active)
        return ERR_BAD_STATE;
    if (pt_data)
        return ERR_BAD_STATE;

    size_t buffer_pages = 1 << pt_buffer_order;
    size_t nr_pages = pt_num_buffers * buffer_pages;
    uint64_t total_per_cpu = nr_pages * PAGE_SIZE;
    if (total_per_cpu > max_per_cpu_space)
        return ERR_INVALID_ARGS;

    mxtl::unique_ptr<x86_cpu_pt_data[]> data;
    {
        AllocChecker ac;
        data = mxtl::unique_ptr<x86_cpu_pt_data[]>(new (&ac) x86_cpu_pt_data[x86_num_cpus]);
        if (!ac.check())
            return ERR_NO_MEMORY;
    }

    for (size_t cpu = 0; cpu < x86_num_cpus; ++cpu) {
        for (size_t i = 0; i < pt_num_buffers; ++i) {
            // ToPA entries of size N must be aligned to N, too.
            uint8_t alignment_log2 =
                static_cast<uint8_t>(PAGE_SIZE_SHIFT + pt_buffer_order);
            size_t count = pmm_alloc_contiguous(buffer_pages, 0, alignment_log2, nullptr, &data[cpu].buffer_page_list_);
            if (count != buffer_pages)
                return ERR_NO_MEMORY;
        }
    }

    size_t entry_count =
        compute_topa_entry_count(&data[0].buffer_page_list_, nr_pages);
    size_t table_count = (entry_count + TOPA_MAX_TABLE_ENTRIES - 1) /
            TOPA_MAX_TABLE_ENTRIES;

    if (entry_count < 2) {
        TRACEF("INVALID ENTRY COUNT: %zu\n", entry_count);
        return ERR_INVALID_ARGS;
    }

    // Some early Processor Trace implementations only supported having a
    // table with a single real entry and an END.
    if (!supports_output_topa_multi && entry_count > 2)
        return ERR_NOT_SUPPORTED;

    // Allocate Table(s) of Physical Addresses for each cpu.

    vmm_aspace_t *kernel_aspace = vmm_get_kernel_aspace();

    for (size_t cpu = 0; cpu < x86_num_cpus; ++cpu) {
        data[cpu].table_ptrs_ =
            reinterpret_cast<uint64_t**>(calloc(sizeof(uint64_t*), table_count));
        if (!data[cpu].table_ptrs_)
            return ERR_NO_MEMORY;
        data[cpu].table_count_ = table_count;

        for (size_t i = 0; i < table_count; ++i) {
            auto status = vmm_alloc_contiguous(
                kernel_aspace, "intelpt",
                sizeof(uint64_t) * TOPA_MAX_TABLE_ENTRIES,
                (void**)&data[cpu].table_ptrs_[i],
                PAGE_SIZE_SHIFT, 0 /*min_alloc_gap*/, VMM_FLAG_COMMIT,
                ARCH_MMU_FLAG_PERM_READ | ARCH_MMU_FLAG_PERM_WRITE);
            if (status != NO_ERROR)
                return ERR_NO_MEMORY;
         }

        make_topa(&data[cpu].buffer_page_list_, nr_pages,
                  data[cpu].table_ptrs_, table_count);
    }

    pt_data = data.release();

    return NO_ERROR;
}

static void x86_pt_start_task(void* raw_context) {
    DEBUG_ASSERT(arch_ints_disabled());
    DEBUG_ASSERT(raw_context == nullptr);
    DEBUG_ASSERT(active && pt_data);

    DEBUG_ASSERT(!(read_msr(IA32_RTIT_CTL) & RTIT_CTL_TRACE_EN) &&
                 !(read_msr(IA32_RTIT_STATUS) & RTIT_STATUS_STOPPED));

    uint32_t cpu = arch_curr_cpu_num();
    x86_percpu* xpc = x86_get_percpu();
    DEBUG_ASSERT(!xpc->pt_data);
    x86_cpu_pt_data* ptd = &pt_data[cpu];

    xpc->pt_data = ptd;
    ptd->curr_table_ = 0;
    ptd->cursors_ = 0;

    paddr_t first_table_phys = vaddr_to_paddr(ptd->table_ptrs_[0]);

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
}

// Begin the trace.
status_t x86_processor_trace_start() {
    // TODO(dje): Could provide an API to obtain this, but we need to log
    // cr3s for potentially all processes anyway.
    TRACEF("Enabling processor trace, kernel cr3: 0x%" PRIxPTR "\n",
           x86_kernel_cr3());

    if (active)
        return ERR_BAD_STATE;
    if (!pt_data)
        return ERR_BAD_STATE;

    active = true;
    //mp_sync_exec(MP_CPU_ALL, x86_pt_start_task, nullptr);
    return NO_ERROR;
}

static void x86_pt_stop_task(void* raw_context) {
    DEBUG_ASSERT(arch_ints_disabled());
    DEBUG_ASSERT(raw_context == nullptr);

    // Disable the trace
    write_msr(IA32_RTIT_CTL, 0);

    x86_percpu* xpc = x86_get_percpu();
    x86_cpu_pt_data* ptd = xpc->pt_data;
    DEBUG_ASSERT(ptd);

    // Save info we care about for output
    ptd->curr_table_ = read_msr(IA32_RTIT_OUTPUT_BASE);
    ptd->cursors_ = read_msr(IA32_RTIT_OUTPUT_MASK_PTRS);

    // Zero all MSRs so that we are in the XSAVE initial configuration
    write_msr(IA32_RTIT_OUTPUT_BASE, 0);
    write_msr(IA32_RTIT_OUTPUT_MASK_PTRS, 0);
    write_msr(IA32_RTIT_STATUS, 0);
    if (supports_cr3_filtering) {
        write_msr(IA32_RTIT_CR3_MATCH, 0);
    }

    xpc->pt_data = nullptr;

    // TODO(teisenbe): Clear ADDR* MSRs depending on leaf 1
}

status_t x86_processor_trace_stop() {
    if (!active)
        return ERR_BAD_STATE;
    if (!pt_data)
        return ERR_BAD_STATE;

    //mp_sync_exec(MP_CPU_ALL, x86_pt_stop_task, nullptr);
    active = false;
    return NO_ERROR;
}

// On success |*capture_size| will be populated with the amount of data
// captured, for each cpu.
// |capture_size| is an array of at |num_cpus| entries,
// which for simplicity sake must be |x86_num_cpus|.
status_t x86_processor_trace_read_size(size_t* capture_size,
                                       uint32_t num_cpus) {
    DEBUG_ASSERT(num_cpus == x86_num_cpus);
    if (active)
        return ERR_BAD_STATE;
    if (!pt_data)
        return ERR_BAD_STATE;

    for (uint32_t cpu = 0; cpu < num_cpus; ++cpu) {
        x86_cpu_pt_data* ptd = &pt_data[cpu];
        capture_size[cpu] =
            compute_capture_size(cpu, ptd->table_ptrs_, ptd->table_count_,
                                 ptd->curr_table_,
                                 (uint32_t)ptd->cursors_ >> 7,
                                 (uint32_t)(ptd->cursors_ >> 32));
    }

    return NO_ERROR;
}

status_t x86_processor_trace_read_bytes(uint32_t cpu, void* ptr,
                                        size_t off, size_t len,
                                        size_t* out_actual) {
    if (active)
        return ERR_BAD_STATE;
    if (!pt_data)
        return ERR_BAD_STATE;
    if (cpu >= x86_num_cpus)
        return ERR_INVALID_ARGS;
    if (off + len < off)
        return ERR_INVALID_ARGS;

    x86_cpu_pt_data* ptd = &pt_data[cpu];
    size_t capture_size = 
        compute_capture_size(cpu, ptd->table_ptrs_, ptd->table_count_,
                             ptd->curr_table_,
                             (uint32_t)ptd->cursors_ >> 7,
                             (uint32_t)(ptd->cursors_ >> 32));
    if (off >= capture_size) {
        *out_actual = 0;
        return NO_ERROR;
    }
    if (off + len > capture_size)
        len = capture_size - off;

    size_t actual = 0;
    size_t remaining = len;
    list_node_t* pages = &ptd->buffer_page_list_;

    // skip to the right starting page
    size_t page_nr = off / PAGE_SIZE;
    vm_page_t* pg = list_peek_head_type(pages, vm_page_t, free.node);
    DEBUG_ASSERT(pg);
    for (size_t i = 0; i < page_nr; ++i) {
        pg = next_page(pages, pg);
        if (!pg)
            return ERR_INVALID_ARGS;
    }

    // handle potential non-zero offset into first page
    if (off % PAGE_SIZE != 0) {
        actual = PAGE_SIZE - (off % PAGE_SIZE);
        if (actual > remaining)
            actual = remaining;
        auto p = paddr_to_kvaddr(vm_page_to_paddr(pg));
        if (arch_copy_to_user(ptr, p, actual) != NO_ERROR)
            return ERR_INVALID_ARGS;
        remaining -= actual;
        pg = next_page(pages, pg);
    }

    while (remaining > 0) {
        DEBUG_ASSERT(pg);

        uint32_t n = PAGE_SIZE;
        if (n > remaining)
            n = static_cast<uint32_t>(remaining);

        auto p = paddr_to_kvaddr(vm_page_to_paddr(pg));
        if (arch_copy_to_user(ptr, p, n) != NO_ERROR)
            return ERR_INVALID_ARGS;

        ptr = reinterpret_cast<char*>(ptr) + n;
        actual += n;
        remaining -= n;
        pg = next_page(pages, pg);
    }

    *out_actual = actual;
    return NO_ERROR;
}

// Release resources acquired by x86_processor_trace_enable.

status_t x86_processor_trace_free(void) {
    if (active)
        return ERR_BAD_STATE;

    if (pt_data) {
        delete[] pt_data;
        pt_data = nullptr;
    }

    return NO_ERROR;
}
