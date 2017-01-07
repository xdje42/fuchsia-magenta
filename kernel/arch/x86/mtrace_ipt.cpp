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

struct ipt_state {
    uint64_t ctl;
    uint64_t status;
    uint64_t output_base;
    uint64_t output_mask_ptrs;
    uint64_t cr3_match;
};

static ipt_state* ipt_state;

static bool active = false;

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

// Returns nullptr on malloc failure.

static ipt_state* get_ipt_state() {
    if (!ipt_state) {
        uint32_t num_cpus = arch_max_num_cpus();
        ipt_state = reinterpret_cast<ipt_state*>(calloc(num_cpus,
                                                        sizeof(*ipt_state)));
    }
    return ipt_state;
}

// Allocate all needed state for tracing.

static status_t mtrace_ipt_alloc() {
    if (active)
        return ERR_BAD_STATE;
    if (ipt_state)
        return ERR_BAD_STATE;

    ipt_state = get_ipt_state();
    if (!ipt_state)
        return ERR_NO_MEMORY;
    return NO_ERROR;
}

// Free resources obtained by mtrace_ipt_alloc().
// This doesn't care if resources have already been freed to save callers
// from having to care during any cleanup.

static status_t mtrace_ipt_free() {
    if (active)
        return ERR_BAD_STATE;

    free (ipt_state);
    ipt_state = nullptr;
    return NO_ERROR;    
}

static void mtrace_ipt_start_task(void* raw_context) {
    DEBUG_ASSERT(arch_ints_disabled());
    DEBUG_ASSERT(active && raw_context);

    ipt_state* context = reinterpret_case<ipt_state*>(raw_context);
    uint32_t cpu = arch_curr_cpu_num();
    ipt_state* state = &context[cpu];

    DEBUG_ASSERT(!(read_msr(IA32_RTIT_CTL) & RTIT_CTL_TRACE_EN) &&
                 !(read_msr(IA32_RTIT_STATUS) & RTIT_STATUS_STOPPED));

    // Load the ToPA configuration
    write_msr(IA32_RTIT_OUTPUT_BASE, state->output_base);
    write_msr(IA32_RTIT_OUTPUT_MASK_PTRS, state->output_mask_ptrs);

    // Load all other msrs, prior to enabling tracing.
    write_msr(IA32_RTIT_STATUS, state->status);
    write_msr(IA32_RTIT_CR3_MATCH, state->cr3_match);

    // Enable the trace
    write_msr(IA32_RTIT_CTL, state->ctl);
}

// Begin the trace.

static status_t mtrace_ipt_start() {
    // TODO(dje): Could provide an API to obtain this, but we need to log
    // cr3s for potentially all processes anyway.
    // Could add this to the trace with ptwrite, but if circular buffers are
    // in use it could be lost.
    TRACEF("Enabling processor trace, kernel cr3: 0x%" PRIxPTR "\n",
           x86_kernel_cr3());

    if (active)
        return ERR_BAD_STATE;
    if (!ipt_state)
        return ERR_BAD_STATE;

    active = true;

    mp_sync_exec(MP_CPU_ALL, mtrace_ipt_start_task, ipt_state);

    return NO_ERROR;
}

// This can be called while not active, so the caller doesn't have to care
// during any cleanup.

static void mtrace_ipt_stop_task(void* raw_context) {
    DEBUG_ASSERT(arch_ints_disabled());
    DEBUG_ASSERT(raw_context);

    ipt_state* context = reinterpret_case<ipt_state*>(raw_context);
    uint32_t cpu = arch_curr_cpu_num();
    ipt_state* state = &context[cpu];

    // Disable the trace
    write_msr(IA32_RTIT_CTL, 0);

    // Retrieve msr values for later providing to userspace
    state->ctl = 0;
    state->status = read_msr(IA32_RTIT_STATUS);
    state->output_base_ = read_msr(IA32_RTIT_OUTPUT_BASE);
    state->output_mask_ptrs = read_msr(IA32_RTIT_OUTPUT_MASK_PTRS);
    state->cr3_match = read_msr(IA32_RTIT_CR3_MATCH);

    // Zero all MSRs so that we are in the XSAVE initial configuration
    write_msr(IA32_RTIT_STATUS, 0);
    write_msr(IA32_RTIT_OUTPUT_BASE, 0);
    write_msr(IA32_RTIT_OUTPUT_MASK_PTRS, 0);
    if (supports_cr3_filtering) {
        write_msr(IA32_RTIT_CR3_MATCH, 0);
    }

    // TODO(teisenbe): Clear ADDR* MSRs depending on leaf 1
}

static status_t mtrace_ipt_stop() {
    if (!active)
        return ERR_BAD_STATE;
    if (!ipt_state)
        return ERR_BAD_STATE;

    mp_sync_exec(MP_CPU_ALL, mtrace_ipt_stop_task, ipt_state);

    active = false;
    return NO_ERROR;
}

static void mtrace_ipt_stage_msr1(uint32_t action, uint32_t cpu,
                                  uint64_t value) {
    switch (action) {
    case MTRACE_IPT_STAGE_CTL:
        ipt_state[cpu].ctl = value;
        break;
    case MTRACE_IPT_STATE_STATUS:
        ipt_state[cpu].status = value;
        break;
    case MTRACE_IPT_STAGE_OUTPUT_BASE:
        ipt_state[cpu].output_base = value;
        break;
    case MTRACE_IPT_STAGE_OUTPUT_MASK_PTRS:
        ipt_state[cpu].output_mask_ptrs = value;
        break;
    case MTRACE_IPT_STAGE_CR3_MATCH:
        ipt_state[cpu].cr3_match = value;
        break;
    default:
        DEBUG_ASSERT(false);
    }
}

static status_t mtrace_ipt_stage_msr(uint32_t action, uint32_t options,
                                     uint64_t value) {
    uint32_t num_cpus = arch_max_num_cpus();
    uint32_t options_cpu = MTRACE_IPT_OPTIONS_CPU(options);

    if (options_cpu < num_cpus) {
        mtrace_ipt_stage_msr1(action, options_cpu, value);
    } else if (options_cpu == MTRACE_IPT_ALL_CPUS) {
        for (uint32_t cpu = 0; cpu < num_cpus; ++cpu) {
            mtrace_ipt_stage_msr1(action, cpu, value);
        }
    } else {
        return ERR_INVALID_ARGS;
    }

    return NO_ERROR;
}

static uint64_t mtrace_ipt_get_msr1(uint32_t action, uint32_t cpu) {
    switch (action) {
    case MTRACE_IPT_STAGE_CTL:
        return ipt_state[cpu].ctl;
    case MTRACE_IPT_STATE_STATUS:
        return ipt_state[cpu].status;
    case MTRACE_IPT_STAGE_OUTPUT_BASE:
        return ipt_state[cpu].output_base;
    case MTRACE_IPT_STAGE_OUTPUT_MASK_PTRS:
        return ipt_state[cpu].output_mask_ptrs;
    case MTRACE_IPT_STAGE_CR3_MATCH:
        return ipt_state[cpu].cr3_match;
    default:
        DEBUG_ASSERT(false);
    }
}

static status_t mtrace_ipt_get_msr(uint32_t action, uint32_t options,
                                   uint64_t* value) {
    uint32_t num_cpus = arch_max_num_cpus();
    uint32_t options_cpu = MTRACE_IPT_OPTIONS_CPU(options);

    if (options_cpu < num_cpus) {
        *value = mtrace_ipt_get_msr1(action, options_cpu);
        return NO_ERROR;
    }

    return ERR_INVALID_ARGS;
}

status_t mtrace_ipt_control(uint32_t kind, uint32_t action, uint32_t options,
                            void* arg, uint32_t size) {
    DEBUG_ASSERT(kind == MTRACE_KIND_IPT);

    switch (action) {
    case MTRACE_IPT_STAGE_CTL:
    case MTRACE_IPT_STATE_STATUS:
    case MTRACE_IPT_STAGE_OUTPUT_BASE:
    case MTRACE_IPT_STAGE_OUTPUT_MASK_PTRS:
    case MTRACE_IPT_STAGE_CR3_MATCH: {
        if (size != sizeof(uint64_t))
            return ERR_INVALID_ARGS;
        uint64_t value;
        if (arch_copy_from_user(arg, &value, size) != NO_ERROR)
            return ERR_INVALID_ARGS;
        return mtrace_ipt_stage_msr(action, options, value);
    }

    case MTRACE_IPT_GET_CTL:
    case MTRACE_IPT_GET_STATUS:
    case MTRACE_IPT_GET_OUTPUT_BASE:
    case MTRACE_IPT_GET_OUTPUT_MASK_PTRS:
    case MTRACE_IPT_GET_CR3_MATCH: {
        if (size != sizeof(uint64_t))
            return ERR_INVALID_ARGS;
        uint64_t value;
        auto status = mtrace_ipt_get_msr(action, options, &value);
        if (status != NO_ERROR)
            return status;
        if (arch_copy_to_user(arg, &value, size) != NO_ERROR)
            return ERR_INVALID_ARGS;
        return NO_ERROR;
    }

    case MTRACE_IPT_ALLOC:
        return mtrace_ipt_alloc();
    case MTRACE_IPT_START:
        return mtrace_ipt_start();
    case MTRACE_IPT_STOP:
        return mtrace_ipt_stop();
    case MTRACE_IPT_FREE:
        return mtrace_ipt_free();

    default:
        return ERR_INVALID_ARGS;
    }
}
