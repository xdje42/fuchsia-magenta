// Copyright 2016 The Fuchsia Authors
//
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT

// TODO(dje): wip wip wip
// The thought is to use resources (as in ResourceDispatcher), at which point
// this will all get rewritten. Until such time, the goal here is KISS.

// We currently only support Table of Physical Addresses mode currently,
// so that we can have stop-on-full behavior rather than wrap-around.

// This file contains the lower part of Intel Processor Trace support that must
// be done in the kernel (so that we can read/write msrs).
// The userspace driver is in system/udev/intel-pt/intel-pt.c.

#include <arch/user_copy.h>
#include <arch/x86.h>
#include <arch/x86/feature.h>
#include <arch/x86/mmu.h>
#include <arch/x86/mtrace_ipt.h>
#include <err.h>
#include <kernel/mp.h>
#include <kernel/thread.h>
#include <kernel/vm.h>
#include <magenta/device/intel-pt.h>
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

// Our own copy of what h/w supports, mostly for sanity checking.
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

// cr3 filtering staging area
static uint64_t cr3_match;

struct ipt_cpu_state_t {
    uint64_t ctl;
    uint64_t status;
    uint64_t output_base;
    uint64_t output_mask_ptrs;
    uint64_t cr3_match;
    struct {
        uint64_t a,b;
    } addr_ranges[IPT_MAX_NUM_ADDR_RANGES];
};

static ipt_cpu_state_t* ipt_cpu_state;

static bool active = false;

typedef enum {
    IPT_TRACE_CPUS,
    IPT_TRACE_THREADS
} ipt_trace_mode_t;

static ipt_trace_mode_t trace_mode = IPT_TRACE_CPUS;

void x86_processor_trace_init(void)
{
    if (!x86_feature_test(X86_FEATURE_PT)) {
        return;
    }

    struct cpuid_leaf leaf;
    if (!x86_get_cpuid_subleaf(X86_CPUID_PT, 0, &leaf)) {
        return;
    }

    // Keep our own copy of these flags, mostly for potential sanity checks.
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
}

// IPT tracing has two "modes":
// - per-cpu tracing
// - thread-specific tracing
// Tracing can only be done in one mode at a time. This is because saving/
// restoring thread PT state via the xsaves/xrstors instructions is a global
// flag in the XSS msr.

// Worker for mtrace_ipt_set_mode to be executed on all cpus.

static void mtrace_ipt_set_mode_task(void* raw_context) {
    DEBUG_ASSERT(arch_ints_disabled());
    DEBUG_ASSERT(!active);

    // When changing modes make sure all PT MSRs are in the init state.
    // We don't want a value to appear in the xsave buffer and have xrstor
    // #gp because XCOMP_BV has the PT bit set that's not set in XSS.
    write_msr(IA32_RTIT_CTL, 0);
    write_msr(IA32_RTIT_STATUS, 0);
    write_msr(IA32_RTIT_OUTPUT_BASE, 0);
    write_msr(IA32_RTIT_OUTPUT_MASK_PTRS, 0);
    if (supports_cr3_filtering)
        write_msr(IA32_RTIT_CR3_MATCH, 0);
    // TODO(dje): addr range msrs

    ipt_trace_mode_t new_mode = static_cast<ipt_trace_mode_t>(reinterpret_cast<uintptr_t>(raw_context));

    // PT state saving, if supported, was enabled during boot so there's no
    // need to recalculate the xsave space needed.
    if (1) x86_pt_set_mode(new_mode == IPT_TRACE_THREADS);
}

extern "C" bool any_thread_uses_pt(void);

static status_t mtrace_ipt_set_mode(ipt_trace_mode_t mode) {
    if (active)
        return ERR_BAD_STATE;
    if (ipt_cpu_state)
        return ERR_BAD_STATE;

    // TODO(dje): Only change the mode when tracing is fully off in all
    // threads.
    if (any_thread_uses_pt())
        return ERR_BAD_STATE - 1000;

    mp_sync_exec(MP_CPU_ALL, mtrace_ipt_set_mode_task,
                 reinterpret_cast<void*> (mode));
    trace_mode = mode;

    return NO_ERROR;
}

// Allocate all needed state for tracing.

static status_t mtrace_ipt_cpu_mode_alloc() {
    if (trace_mode == IPT_TRACE_THREADS)
        return ERR_BAD_STATE;
    if (active)
        return ERR_BAD_STATE;
    if (ipt_cpu_state)
        return ERR_BAD_STATE;

    uint32_t num_cpus = arch_max_num_cpus();
    ipt_cpu_state =
        reinterpret_cast<ipt_cpu_state_t*>(calloc(num_cpus,
                                                  sizeof(*ipt_cpu_state)));
    if (!ipt_cpu_state)
        return ERR_NO_MEMORY;
    return NO_ERROR;
}

// Free resources obtained by mtrace_ipt_alloc().
// This doesn't care if resources have already been freed to save callers
// from having to care during any cleanup.

static status_t mtrace_ipt_cpu_mode_free() {
    if (trace_mode == IPT_TRACE_THREADS)
        return ERR_BAD_STATE;
    if (active)
        return ERR_BAD_STATE;

    free (ipt_cpu_state);
    ipt_cpu_state = nullptr;
    return NO_ERROR;    
}

static void mtrace_ipt_start_cpu_task(void* raw_context) {
    DEBUG_ASSERT(arch_ints_disabled());
    DEBUG_ASSERT(active && raw_context);

    ipt_cpu_state_t* context = reinterpret_cast<ipt_cpu_state_t*>(raw_context);
    uint32_t cpu = arch_curr_cpu_num();
    ipt_cpu_state_t* state = &context[cpu];

    DEBUG_ASSERT(!(read_msr(IA32_RTIT_CTL) & IPT_CTL_TRACE_EN));
#if 0
    // TODO(dje): Seems like this may be preserved across reboots. True?
    // There's no real need for this test, we've already verified tracing is
    // currently disabled, so disable this check for now.
    DEBUG_ASSERT(!(read_msr(IA32_RTIT_STATUS) & IPT_STATUS_STOPPED));
#endif

    // Load the ToPA configuration
    write_msr(IA32_RTIT_OUTPUT_BASE, state->output_base);
    write_msr(IA32_RTIT_OUTPUT_MASK_PTRS, state->output_mask_ptrs);

    // Load all other msrs, prior to enabling tracing.
    write_msr(IA32_RTIT_STATUS, state->status);
    if (supports_cr3_filtering)
        write_msr(IA32_RTIT_CR3_MATCH, cr3_match);

    // Enable the trace
    write_msr(IA32_RTIT_CTL, state->ctl);
}

// Begin the trace.

static status_t mtrace_ipt_cpu_mode_start() {
    // TODO(dje): Could provide an API to obtain this, but we need to log
    // cr3s for potentially all processes anyway.
    // Could add this to the trace with ptwrite, but if circular buffers are
    // in use it could be lost.
    TRACEF("Enabling processor trace, kernel cr3: 0x%" PRIxPTR "\n",
           x86_kernel_cr3());

    if (trace_mode == IPT_TRACE_THREADS)
        return ERR_BAD_STATE;
    if (active)
        return ERR_BAD_STATE;
    if (!ipt_cpu_state)
        return ERR_BAD_STATE;

    active = true;

    mp_sync_exec(MP_CPU_ALL, mtrace_ipt_start_cpu_task, ipt_cpu_state);

    return NO_ERROR;
}

static void mtrace_ipt_stop_cpu_task(void* raw_context) {
    DEBUG_ASSERT(arch_ints_disabled());
    DEBUG_ASSERT(raw_context);

    ipt_cpu_state_t* context = reinterpret_cast<ipt_cpu_state_t*>(raw_context);
    uint32_t cpu = arch_curr_cpu_num();
    ipt_cpu_state_t* state = &context[cpu];

    // Disable the trace
    write_msr(IA32_RTIT_CTL, 0);

    // Retrieve msr values for later providing to userspace
    state->ctl = 0;
    state->status = read_msr(IA32_RTIT_STATUS);
    state->output_base = read_msr(IA32_RTIT_OUTPUT_BASE);
    state->output_mask_ptrs = read_msr(IA32_RTIT_OUTPUT_MASK_PTRS);

    // Zero all MSRs so that we are in the XSAVE initial configuration.
    // This allows h/w to do some optimizations regarding the state.
    write_msr(IA32_RTIT_STATUS, 0);
    write_msr(IA32_RTIT_OUTPUT_BASE, 0);
    write_msr(IA32_RTIT_OUTPUT_MASK_PTRS, 0);
    if (supports_cr3_filtering)
        write_msr(IA32_RTIT_CR3_MATCH, 0);

    // TODO(teisenbe): Clear ADDR* MSRs depending on leaf 1
}

// This can be called while not active, so the caller doesn't have to care
// during any cleanup.

static status_t mtrace_ipt_cpu_mode_stop() {
    TRACEF("Disabling processor trace\n");

    if (trace_mode == IPT_TRACE_THREADS)
        return ERR_BAD_STATE;
    if (!ipt_cpu_state)
        return ERR_BAD_STATE;

    mp_sync_exec(MP_CPU_ALL, mtrace_ipt_stop_cpu_task, ipt_cpu_state);

    active = false;
    return NO_ERROR;
}

static status_t mtrace_ipt_stage_cpu_data(uint32_t options,
                                          const mx_x86_pt_regs_t* regs) {
    uint32_t cpu = MTRACE_IPT_OPTIONS_CPU(options);
    if ((options & ~MTRACE_IPT_OPTIONS_CPU_MASK) != 0)
        return ERR_INVALID_ARGS;
    uint32_t num_cpus = arch_max_num_cpus();
    if (cpu >= num_cpus)
        return ERR_INVALID_ARGS;

    ipt_cpu_state[cpu].ctl = regs->ctl;
    ipt_cpu_state[cpu].status = regs->status;
    ipt_cpu_state[cpu].output_base = regs->output_base;
    ipt_cpu_state[cpu].output_mask_ptrs = regs->output_mask_ptrs;
    ipt_cpu_state[cpu].cr3_match = regs->cr3_match;
    static_assert(sizeof(ipt_cpu_state[cpu].addr_ranges) == sizeof(regs->addr_ranges));
    memcpy(ipt_cpu_state[cpu].addr_ranges, regs->addr_ranges, sizeof(regs->addr_ranges));

    return NO_ERROR;
}

static status_t mtrace_ipt_get_cpu_data(uint32_t options,
                                        mx_x86_pt_regs_t* regs) {
    uint32_t cpu = MTRACE_IPT_OPTIONS_CPU(options);
    if ((options & ~MTRACE_IPT_OPTIONS_CPU_MASK) != 0)
        return ERR_INVALID_ARGS;
    uint32_t num_cpus = arch_max_num_cpus();
    if (cpu >= num_cpus)
        return ERR_INVALID_ARGS;

    regs->ctl = ipt_cpu_state[cpu].ctl;
    regs->status = ipt_cpu_state[cpu].status;
    regs->output_base = ipt_cpu_state[cpu].output_base;
    regs->output_mask_ptrs = ipt_cpu_state[cpu].output_mask_ptrs;
    regs->cr3_match = ipt_cpu_state[cpu].cr3_match;
    static_assert(sizeof(regs->addr_ranges) == sizeof(ipt_cpu_state[cpu].addr_ranges));
    memcpy(regs->addr_ranges, ipt_cpu_state[cpu].addr_ranges, sizeof(regs->addr_ranges));

    return NO_ERROR;
}

status_t mtrace_ipt_control(uint32_t action, uint32_t options,
                            void* arg, uint32_t size) {
    TRACEF("action %u, options 0x%x, arg %p, size 0x%x\n",
           action, options, arg, size);

    switch (action) {
    case MTRACE_IPT_SET_MODE: {
        if (options != 0)
            return ERR_INVALID_ARGS;
        uint32_t mode;
        if (size != sizeof(mode))
            return ERR_INVALID_ARGS;
        if (arch_copy_from_user(&mode, arg, size) != NO_ERROR)
            return ERR_INVALID_ARGS;
        TRACEF("action %u, mode 0x%x\n", action, mode);
        switch (mode) {
        case IPT_MODE_CPUS:
            return mtrace_ipt_set_mode(IPT_TRACE_CPUS);
        case IPT_MODE_THREADS:
            return mtrace_ipt_set_mode(IPT_TRACE_THREADS);
        default:
            return ERR_INVALID_ARGS;
        }
    }

    case MTRACE_IPT_STAGE_CPU_DATA: {
        mx_x86_pt_regs_t regs;
        if (trace_mode == IPT_TRACE_THREADS)
            return ERR_BAD_STATE;
        if (active)
            return ERR_BAD_STATE;
        if (!ipt_cpu_state)
            return ERR_BAD_STATE;
        if (size != sizeof(regs))
            return ERR_INVALID_ARGS;
        if (arch_copy_from_user(&regs, arg, size) != NO_ERROR)
            return ERR_INVALID_ARGS;
        TRACEF("action %u, ctl 0x%" PRIx64 ", output_base 0x%" PRIx64 "\n",
               action, regs.ctl, regs.output_base);
        return mtrace_ipt_stage_cpu_data(options, &regs);
    }

    case MTRACE_IPT_GET_CPU_DATA: {
        mx_x86_pt_regs_t regs;
        if (trace_mode == IPT_TRACE_THREADS)
            return ERR_BAD_STATE;
        if (active)
            return ERR_BAD_STATE;
        if (!ipt_cpu_state)
            return ERR_BAD_STATE;
        if (size != sizeof(regs))
            return ERR_INVALID_ARGS;
        auto status = mtrace_ipt_get_cpu_data(options, &regs);
        if (status != NO_ERROR)
            return status;
        TRACEF("action %u, ctl 0x%" PRIx64 ", output_base 0x%" PRIx64 "\n",
               action, regs.ctl, regs.output_base);
        if (arch_copy_to_user(arg, &regs, size) != NO_ERROR)
            return ERR_INVALID_ARGS;
        return NO_ERROR;
    }

    case MTRACE_IPT_CPU_MODE_ALLOC:
        if (options != 0 || size != 0)
            return ERR_INVALID_ARGS;
        return mtrace_ipt_cpu_mode_alloc();
    case MTRACE_IPT_CPU_MODE_START:
        if (options != 0 || size != 0)
            return ERR_INVALID_ARGS;
        return mtrace_ipt_cpu_mode_start();
    case MTRACE_IPT_CPU_MODE_STOP:
        if (options != 0 || size != 0)
            return ERR_INVALID_ARGS;
        return mtrace_ipt_cpu_mode_stop();
    case MTRACE_IPT_CPU_MODE_FREE:
        if (options != 0 || size != 0)
            return ERR_INVALID_ARGS;
        return mtrace_ipt_cpu_mode_free();

    default:
        return ERR_INVALID_ARGS;
    }
}
