// Copyright 2016 The Fuchsia Authors
//
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT

/****************************************************************************
 * This file handles detection of supported extended register saving
 * mechanisms.  Of the ones detected, the following is our preference for
 * mechanisms, from best to worst:
 *
 * 1) XSAVES (performs modified+init optimizations, uses compressed register
 *            form, and can save supervisor-only registers)
 * 2) XSAVEOPT (performs modified+init optimizations)
 * 3) XSAVE (no optimizations/compression, but can save all supported extended
 *           registers)
 * 4) FXSAVE (can only save FPU/SSE registers)
 * 5) none (will not save any extended registers, will not allow enabling
 *          features that use extended registers.)
 ****************************************************************************/

#include <arch/ops.h>
#include <arch/x86.h>
#include <arch/x86/mp.h>
#include <arch/x86/feature.h>
#include <arch/x86/registers.h>
#include <arch/x86/mtrace_ipt.h>
#include <magenta/compiler.h>
#include <magenta/device/intel-pt.h>
#include <kernel/spinlock.h>
#include <kernel/thread.h>
#include <string.h>
#include <trace.h>

#define LOCAL_TRACE 0

/* offset in xsave area that components >= 2 start at */
#define XSAVE_EXTENDED_AREA_OFFSET 576
/* bits 2 through 62 of state vector can optionally be set */
#define XSAVE_MAX_EXT_COMPONENTS 61
#define XSAVE_XCOMP_BV_COMPACT (1ULL<<63)
#define XSAVE_STATE_PT_BIT 8
#define XSAVE_STATE_MAX_BIT 62

static void fxsave(void *register_state);
static void fxrstor(void *register_state);
static void xrstor(void *register_state, uint64_t feature_mask);
static void xrstors(void *register_state, uint64_t feature_mask);
static void xsave(void *register_state, uint64_t feature_mask);
static void xsaveopt(void *register_state, uint64_t feature_mask);
static void xsaves(void *register_state, uint64_t feature_mask);

static uint64_t xgetbv(uint32_t reg);
static void xsetbv(uint32_t reg, uint64_t val);

static void read_xsave_state_info(void);
static void recompute_state_size(void);

static struct {
    /* Total size of this component in bytes */
    uint32_t size;
    /* If true, this component must be aligned to a 64-byte boundary */
    bool align64;
} state_components[XSAVE_MAX_EXT_COMPONENTS];

/* Supported bits in XCR0 (each corresponds to a state component) */
static uint64_t xcr0_component_bitmap = 0;
/* Supported bits in IA32_XSS (each corresponds to a state component) */
static uint64_t xss_component_bitmap = 0;
/* Maximum total size for xsave, if all features are enabled */
static size_t xsave_max_area_size = 0;
/* Does this processor support the XSAVES instruction */
static bool xsaves_supported = false;
/* Does this processor support the XSAVEOPT instruction */
static bool xsaveopt_supported = false;
/* Does this processor support the XGETBV instruction with ecx=1 */
static bool xgetbv_1_supported = false;
/* Does this processor support the XSAVE instruction */
static bool xsave_supported = false;
/* Does this processor support FXSAVE */
static bool fxsave_supported = false;
/* Maximum register state size */
static size_t register_state_size = 0;
/* Spinlock to guard register state size changes */
static spin_lock_t state_lock = SPIN_LOCK_INITIAL_VALUE;

/* For FXRSTOR, we need 512 bytes to save the state.  For XSAVE-based
 * mechanisms, we only need 512 + 64 bytes for the initial state, since
 * our initial state only needs to specify some SSE state (masking exceptions),
 * and XSAVE doesn't require space for any disabled register groups after
 * the last enabled one. */
static uint8_t __ALIGNED(64)
    extended_register_init_state[512 + 64] = {0};

/* Format described in Intel 3A section 13.4 */
struct xsave_area {
    /* legacy region */
    uint8_t legacy_region_0[24];
    uint32_t mxcsr;
    uint8_t legacy_region_1[484];

    /* xsave_header */
    uint64_t xstate_bv;
    uint64_t xcomp_bv;
    uint8_t reserved[48];

    uint8_t extended_region[];
} __PACKED;

static void x86_extended_register_cpu_init(void)
{
    if (likely(xsave_supported)) {
        ulong cr4 = x86_get_cr4();
        /* Enable XSAVE feature set */
        x86_set_cr4(cr4 | X86_CR4_OSXSAVE);
        /* Put xcr0 into a known state (X87 must be enabled in this register) */
        xsetbv(0, X86_XSAVE_STATE_X87);
    }

    /* Enable the FPU */
    __UNUSED bool enabled = x86_extended_register_enable_feature(
            X86_EXTENDED_REGISTER_X87);
    DEBUG_ASSERT(enabled);
}

/* Figure out what forms of register saving this machine supports and
 * select the best one */
void x86_extended_register_init(void)
{
    /* Have we already read the cpu support info */
    static bool info_initialized = false;
    bool initialized_cpu_already = false;

    if (!info_initialized) {
        DEBUG_ASSERT(arch_curr_cpu_num() == 0);

        read_xsave_state_info();
        info_initialized = true;

        /* We currently assume that if xsave isn't support fxsave is */
        fxsave_supported = x86_feature_test(X86_FEATURE_FXSR);

        /* Set up initial states */
        if (likely(fxsave_supported || xsave_supported)) {
            x86_extended_register_cpu_init();
            initialized_cpu_already = true;

            /* Intel Vol 3 section 13.5.4 describes the XSAVE initialization. */
            if (xsave_supported) {
                /* The only change we want to make to the init state is having
                 * SIMD exceptions masked */
                struct xsave_area *area =
                        (struct xsave_area *)extended_register_init_state;
                area->xstate_bv |= X86_XSAVE_STATE_SSE;
                area->mxcsr = 0x3f << 7;

                /* If xsaves is being used, then make the saved state be in
                 * compact form.  xrstors will GPF if it is not. */
                if (xsaves_supported) {
                    area->xcomp_bv |= XSAVE_XCOMP_BV_COMPACT;
                    area->xcomp_bv |= area->xstate_bv;
                }
            } else {
                fxsave(&extended_register_init_state);
            }
        }

        if (likely(xsave_supported)) {
            recompute_state_size();
        } else if (fxsave_supported) {
            register_state_size = 512;
        }
    }
    /* Ensure that xsaves_supported == true implies xsave_supported == true */
    DEBUG_ASSERT(!xsaves_supported || xsave_supported);
    /* Ensure that xsaveopt_supported == true implies xsave_supported == true */
    DEBUG_ASSERT(!xsaveopt_supported || xsave_supported);

    if (!initialized_cpu_already) {
        x86_extended_register_cpu_init();
    }
}

bool x86_extended_register_enable_feature(
        enum x86_extended_register_feature feature)
{
    /* We currently assume this is only called during initialization.
     * We rely on interrupts being disabled so xgetbv/xsetbv will not be
     * racey */
    DEBUG_ASSERT(arch_ints_disabled());

    switch (feature) {
        case X86_EXTENDED_REGISTER_X87: {
            if (unlikely(!x86_feature_test(X86_FEATURE_FPU) ||
                         (!fxsave_supported && !xsave_supported))) {
                return false;
            }

            /* No x87 emul, monitor co-processor */
            ulong cr0 = x86_get_cr0();
            cr0 &= ~X86_CR0_EM;
            cr0 |= X86_CR0_NE;
            cr0 |= X86_CR0_MP;
            x86_set_cr0(cr0);

            /* Init x87, starts with exceptions masked */
            __asm__ __volatile__ ("finit" : : : "memory");

            if (likely(xsave_supported)) {
                xsetbv(0, xgetbv(0) | X86_XSAVE_STATE_X87);
            }
            break;
        }
        case X86_EXTENDED_REGISTER_SSE: {
            if (unlikely(
                    !x86_feature_test(X86_FEATURE_SSE) ||
                    !x86_feature_test(X86_FEATURE_SSE2) ||
                    !x86_feature_test(X86_FEATURE_SSE3) ||
                    !x86_feature_test(X86_FEATURE_SSSE3) ||
                    !x86_feature_test(X86_FEATURE_SSE4_1) ||
                    !x86_feature_test(X86_FEATURE_SSE4_2) ||
                    !x86_feature_test(X86_FEATURE_FXSR))) {

                return false;
            }

            /* Init SSE */
            ulong cr4 = x86_get_cr4();
            cr4 |= X86_CR4_OSXMMEXPT;
            cr4 |= X86_CR4_OSFXSR;
            x86_set_cr4(cr4);

            /* mask all exceptions */
            uint32_t mxcsr = 0;
            __asm__ __volatile__("stmxcsr %0" : "=m" (mxcsr));
            mxcsr = (0x3f << 7);
            __asm__ __volatile__("ldmxcsr %0" : : "m" (mxcsr));

            if (likely(xsave_supported)) {
                xsetbv(0, xgetbv(0) | X86_XSAVE_STATE_SSE);
            }
            break;
        }
        case X86_EXTENDED_REGISTER_AVX: {
            if (!xsave_supported ||
                !(xcr0_component_bitmap & X86_XSAVE_STATE_AVX)) {
                return false;
            }

            /* Enable SIMD exceptions */
            ulong cr4 = x86_get_cr4();
            cr4 |= X86_CR4_OSXMMEXPT;
            x86_set_cr4(cr4);

            xsetbv(0, xgetbv(0) | X86_XSAVE_STATE_AVX);
            break;
        }
        case X86_EXTENDED_REGISTER_MPX: {
            /* Currently unsupported */
            return false;
        }
        case X86_EXTENDED_REGISTER_AVX512: {
            const uint64_t xsave_avx512 =
                    X86_XSAVE_STATE_AVX512_OPMASK |
                    X86_XSAVE_STATE_AVX512_LOWERZMM_HIGH |
                    X86_XSAVE_STATE_AVX512_HIGHERZMM;

            if (!xsave_supported ||
                (xcr0_component_bitmap & xsave_avx512) != xsave_avx512) {
                return false;
            }
            xsetbv(0, xgetbv(0) | xsave_avx512);
            break;
        }
        case X86_EXTENDED_REGISTER_PT: {
            if (!xsaves_supported ||
                !(xss_component_bitmap & X86_XSAVE_STATE_PT)) {
                return false;
            }
            x86_pt_set_mode(true);
            break;
        }
        case X86_EXTENDED_REGISTER_PKRU: {
            /* Currently unsupported */
            return false;
        }
        default:
            return false;
    }

    recompute_state_size();
    return true;
}

size_t x86_extended_register_size(void) {
    return register_state_size;
}

void x86_extended_register_init_state(void *register_state)
{
    memcpy(register_state, extended_register_init_state,
           sizeof (extended_register_init_state));
}

void x86_extended_register_save_state(void *register_state)
{
    /* The idle threads have no extended register state */
    if (unlikely(!register_state)) {
        return;
    }

    if (xsaves_supported) {
        xsaves(register_state, ~0ULL);
    } else if (xsaveopt_supported) {
        xsaveopt(register_state, ~0ULL);
    } else if (xsave_supported) {
        xsave(register_state, ~0ULL);
    } else if (fxsave_supported) {
        fxsave(register_state);
    }
}

void x86_extended_register_restore_state(void *register_state)
{
    /* The idle threads have no extended register state */
    if (unlikely(!register_state)) {
        return;
    }

    if (xsaves_supported) {
        xrstors(register_state, ~0ULL);
    } else if (xsave_supported) {
        xrstor(register_state, ~0ULL);
    } else if (fxsave_supported) {
        fxrstor(register_state);
    }
}

void x86_extended_register_context_switch(
        thread_t *old_thread, thread_t *new_thread)
{
#if 0
    //TRACEF("old %p, new %p\n", old_thread, new_thread);
    if (0 && old_thread->arch.extended_register_state) {
        uint64_t* old_header =
            (uint64_t*) ((char*) old_thread->arch.extended_register_state + 512);
        TRACEF("old xstate_bv 0x%" PRIx64 ", xcomp_bv 0x%" PRIx64 "\n",
               old_header[0], old_header[1]);
    }
    if (0 && new_thread->arch.extended_register_state) {
        uint64_t* new_header =
            (uint64_t*) ((char*) new_thread->arch.extended_register_state + 512);
        TRACEF("new xstate_bv 0x%" PRIx64 ", xcomp_bv 0x%" PRIx64 "\n",
               new_header[0], new_header[1]);
    }
#endif

    if (likely(old_thread)) {
        x86_extended_register_save_state(old_thread->arch.extended_register_state);
    }
    x86_extended_register_restore_state(new_thread->arch.extended_register_state);
}

static void read_xsave_state_info(void)
{
    xsave_supported = x86_feature_test(X86_FEATURE_XSAVE);
    if (!xsave_supported) {
        LTRACEF("xsave not supported\n");
        return;
    }

    /* This procedure is described in Intel Vol 1 section 13.2 */

    /* Read feature support from subleaves 0 and 1 */
    struct cpuid_leaf leaf;
    if (!x86_get_cpuid_subleaf(X86_CPUID_XSAVE, 0, &leaf)) {
        LTRACEF("could not find xsave leaf\n");
        goto bailout;
    }
    xcr0_component_bitmap = ((uint64_t)leaf.d << 32) | leaf.a;
    size_t max_area = XSAVE_EXTENDED_AREA_OFFSET;

    x86_get_cpuid_subleaf(X86_CPUID_XSAVE, 1, &leaf);
    xgetbv_1_supported = !!(leaf.a & (1<<2));
    xsaves_supported = !!(leaf.a & (1<<3));
    xsaveopt_supported = !!(leaf.a & (1<<0));
    xss_component_bitmap = ((uint64_t)leaf.d << 32) | leaf.c;

    LTRACEF("xcr0 bitmap: %016" PRIx64 "\n", xcr0_component_bitmap);
    LTRACEF("xss bitmap: %016" PRIx64 "\n", xss_component_bitmap);

    /* Sanity check; all CPUs that support xsave support components 0 and 1 */
    DEBUG_ASSERT((xcr0_component_bitmap & 0x3) == 0x3);
    if ((xcr0_component_bitmap & 0x3) != 0x3) {
        LTRACEF("unexpected xcr0 bitmap %016" PRIx64 "\n",
                xcr0_component_bitmap);
        goto bailout;
    }

    /* Read info about the state components */
    for (uint i = 0; i < XSAVE_MAX_EXT_COMPONENTS; ++i) {
        uint idx = i + 2;
        if (!(xcr0_component_bitmap & (1ULL << idx)) &&
            !(xss_component_bitmap & (1ULL << idx))) {
            continue;
        }
        x86_get_cpuid_subleaf(X86_CPUID_XSAVE, idx, &leaf);

        bool align64 = !!(leaf.c & 0x2);

        state_components[i].size = leaf.a;
        state_components[i].align64 = align64;
        LTRACEF("component %u size: %u (xcr0 %d)\n",
                idx, state_components[i].size,
                !!(xcr0_component_bitmap & (1ULL << idx)));

        if (align64) {
            max_area = ROUNDUP(max_area, 64);
        }
        max_area += leaf.a;
    }
    xsave_max_area_size = max_area;
    LTRACEF("total xsave size: %zu\n", max_area);

    return;
bailout:
    xsave_supported = false;
    xsaves_supported = false;
    xsaveopt_supported = false;
}

static void recompute_state_size(void) {
    if (!xsave_supported) {
        return;
    }

    size_t new_size = 0;
    /* If we're in a compacted form, compute the total size.  The algorithm
     * for this is defined in Intel Vol 1 section 13.4.3 */
    if (xsaves_supported) {
        new_size = XSAVE_EXTENDED_AREA_OFFSET;
        uint64_t enabled_features = xgetbv(0) | read_msr(IA32_XSS_MSR);
        for (uint i = 0; i < XSAVE_MAX_EXT_COMPONENTS; ++i) {
            uint idx = i + 2;
            if (!(enabled_features & (1ULL << idx))) {
                continue;
            }

            if (state_components[i].align64) {
                new_size = ROUNDUP(new_size, 64);
            }
            new_size += state_components[i].size;
        }
    } else {
        /* Otherwise, use CPUID.(EAX=0xD,ECX=1):EBX, which stores the computed
         * maximum size required for saving everything specified in XCR0 */
        struct cpuid_leaf leaf;
        x86_get_cpuid_subleaf(X86_CPUID_XSAVE, 0, &leaf);
        new_size = leaf.b;
    }

    spin_lock(&state_lock);
    /* Only allow size to increase; all CPUs should converge to the same value,
     * but for sanity let's keep it monotonically increasing */
    if (new_size > register_state_size) {
        register_state_size = new_size;
        DEBUG_ASSERT(register_state_size <= X86_MAX_EXTENDED_REGISTER_SIZE);
    }
    spin_unlock(&state_lock);
}

static void fxsave(void *register_state)
{
    __asm__ __volatile__("fxsave %0"
                         : "=m" (*(uint8_t *)register_state)
                         :
                         : "memory");
}

static void fxrstor(void *register_state)
{
    __asm__ __volatile__("fxrstor %0"
                         :
                         : "m" (*(uint8_t *)register_state)
                         : "memory");
}

static void xrstor(void *register_state, uint64_t feature_mask)
{
    __asm__ volatile("xrstor %0"
                     :
                     : "m"(*(uint8_t *)register_state),
                       "d"((uint32_t)(feature_mask >> 32)),
                       "a"((uint32_t)feature_mask)
                     : "memory");
}

static void xrstors(void *register_state, uint64_t feature_mask)
{
    __asm__ volatile("xrstors %0"
                     :
                     : "m"(*(uint8_t *)register_state),
                       "d"((uint32_t)(feature_mask >> 32)),
                       "a"((uint32_t)feature_mask)
                     : "memory");
}


static void xsave(void *register_state, uint64_t feature_mask)
{
    __asm__ volatile("xsave %0"
                     : "+m"(*(uint8_t *)register_state)
                     : "d"((uint32_t)(feature_mask >> 32)),
                       "a"((uint32_t)feature_mask)
                     : "memory");
}

static void xsaveopt(void *register_state, uint64_t feature_mask)
{
    __asm__ volatile("xsaveopt %0"
                     : "+m"(*(uint8_t *)register_state)
                     : "d"((uint32_t)(feature_mask >> 32)),
                       "a"((uint32_t)feature_mask)
                     : "memory");
}

static void xsaves(void *register_state, uint64_t feature_mask)
{
    __asm__ volatile("xsaves %0"
                     : "+m"(*(uint8_t *)register_state)
                     : "d"((uint32_t)(feature_mask >> 32)),
                       "a"((uint32_t)feature_mask)
                     : "memory");
}

static uint64_t xgetbv(uint32_t reg)
{
    uint32_t hi, lo;
    __asm__ volatile("xgetbv"
                     : "=d" (hi), "=a" (lo)
                     : "c"(reg)
                     : "memory");
    return ((uint64_t)hi << 32) + lo;
}

static void xsetbv(uint32_t reg, uint64_t val)
{
    __asm__ volatile("xsetbv"
                     :
                     : "c"(reg), "d"((uint32_t)(val >> 32)), "a"((uint32_t)val)
                     : "memory");
}

extern bool x86_thread_uses_pt(thread_t* t);
bool x86_thread_uses_pt(thread_t* t) {
    if (!t->arch.extended_register_state)
        return false;

    uint64_t* header =
        (uint64_t*) ((char*) t->arch.extended_register_state + 512);
    return !!(header[1] & (1ULL << XSAVE_STATE_PT_BIT));
}

// Set the PT mode to trace either cpus (!threads) or threads.
// WARNING: All PT MSRs should be set to init values before changing the mode.
// See mtrace_ipt_set_mode_task.

void x86_pt_set_mode(bool threads) {
    uint64_t xss = read_msr(IA32_XSS_MSR);
    if (threads)
        xss |= X86_XSAVE_STATE_PT;
    else
        xss &= ~(0ULL + X86_XSAVE_STATE_PT);
    write_msr(IA32_XSS_MSR, xss);
}

static bool x86_pt_get_mode(void) {
    uint64_t xss = read_msr(IA32_XSS_MSR);
    return !!(xss & X86_XSAVE_STATE_PT);
}

/* Layout of PT state in the extended save area.
 * While it may be true that the layout matches the external struct for
 * providing these values (mx_x86_pt_regs_t), we don't assume that.
 * Intel Vol. 1 chapter 13.5.6. */

typedef struct {
    uint64_t ctl;
    uint64_t status;
    uint64_t output_base;
    uint64_t output_mask_ptrs;
    uint64_t cr3_match;
    uint64_t addr0_a, addr0_b;
    uint64_t addr1_a, addr1_b;
} x86_xsave_pt_regs_t;

/* Return the offset of extended component |c| given |bitmap|. */

static size_t get_component_offset(uint c, uint64_t bitmap) {
    size_t offset = 0;
    for (uint i = 2; i < c; ++i) {
        if (!(bitmap & (1ULL << i)))
            continue;
        if (state_components[i].align64)
            offset = ROUNDUP(offset, 64);
        offset += state_components[i].size;
    }
    if (state_components[c].align64)
        offset = ROUNDUP(offset, 64);
    return offset;
}

/* Given a pointer to the extended save area, return a pointer to the PT regs
 * in it. If necessary, this will make room. */

static x86_xsave_pt_regs_t *x86_get_pt_regs_buffer(void *reg_state) {
    /* The extended area header is at offset 512.
       Intel Vol. 1 chapter 13.4.2 */
    uint64_t *header = (uint64_t*) ((char*)reg_state + 512);
    uint64_t xcomp_bv = header[1];
    /* the header is 64 bytes */
    char *base = (char*)header + 64;
    DEBUG_ASSERT(xcomp_bv & XSAVE_XCOMP_BV_COMPACT);

    /* Find the offset where PT regs live. */
    size_t pt_offset = get_component_offset(XSAVE_STATE_PT_BIT, xcomp_bv);

    /* Insert room if needed. The shift needs to take into account any
       potential changes in alignment adjustments. Thus we can't just do a
       memmove. Fortunately this isn't on any hot path, so there's no need
       for extreme efficiency here. In practice there is currently nothing to
       do anyway, so this terminates quickly. */
    uint64_t new_xcomp_bv = xcomp_bv | X86_XSAVE_STATE_PT;
    if (!(xcomp_bv & X86_XSAVE_STATE_PT)) {
        uint64_t remaining = xcomp_bv & ~(XSAVE_XCOMP_BV_COMPACT | ((X86_XSAVE_STATE_PT << 1) - 1));
        if (remaining != 0) {
            for (uint i = XSAVE_STATE_MAX_BIT; i > XSAVE_STATE_PT_BIT; --i) {
                if (xcomp_bv & (1ULL << i)) {
                    size_t old_offset = get_component_offset(i, xcomp_bv);
                    size_t new_offset = get_component_offset(i, new_xcomp_bv);
                    size_t size = state_components[i].size;
                    memmove(base + new_offset, base + old_offset, size);
                }
            }
        }
        memset(base + pt_offset, 0, state_components[XSAVE_STATE_PT_BIT].size);
        header[1] = new_xcomp_bv;
    }

    return (x86_xsave_pt_regs_t*) (base + pt_offset);
}

status_t x86_get_pt_regs(thread_t *thread, void *regs, uint32_t *buf_size) {
#if ARCH_X86_64
    mx_x86_pt_regs_t *r = regs;

    uint32_t provided_buf_size = *buf_size;
    *buf_size = sizeof(*r);

    // Do "buffer too small" checks first. No point in prohibiting the caller
    // from finding out the needed size just because thread tracing is
    // currently disabled.
    if (provided_buf_size < sizeof(*r))
        return ERR_BUFFER_TOO_SMALL;

    if (!x86_feature_test(X86_FEATURE_PT))
        return ERR_NOT_SUPPORTED;
    if (!x86_pt_get_mode())
        return ERR_UNAVAILABLE;

    if ((thread->flags & THREAD_FLAG_STOPPED_FOR_EXCEPTION) == 0)
        return ERR_BAD_STATE;

    const x86_xsave_pt_regs_t *pt = x86_get_pt_regs_buffer(thread->arch.extended_register_state);

    r->ctl = pt->ctl;
    r->status = pt->status;
    r->output_base = pt->output_base;
    r->output_mask_ptrs = pt->output_mask_ptrs;
    r->cr3_match = pt->cr3_match;
    r->addr_ranges[0].a = pt->addr0_a;
    r->addr_ranges[0].b = pt->addr0_b;
    r->addr_ranges[1].a = pt->addr1_a;
    r->addr_ranges[1].b = pt->addr1_b;

    return NO_ERROR;
#else
    return ERR_NOT_SUPPORTED;
#endif
}

status_t x86_set_pt_regs(thread_t *thread, const void *regs, uint32_t buf_size) {
#if ARCH_X86_64
    const mx_x86_pt_regs_t *r = regs;

    if (!x86_feature_test(X86_FEATURE_PT))
        return ERR_NOT_SUPPORTED;
    if (!x86_pt_get_mode())
        return ERR_UNAVAILABLE;

    if (buf_size != sizeof(*r))
        return ERR_INVALID_ARGS;

    if ((thread->flags & THREAD_FLAG_STOPPED_FOR_EXCEPTION) == 0)
        return ERR_BAD_STATE;

    x86_xsave_pt_regs_t *pt = x86_get_pt_regs_buffer(thread->arch.extended_register_state);

    pt->ctl = r->ctl;
    pt->status = r->status;
    pt->output_base = r->output_base;
    pt->output_mask_ptrs = r->output_mask_ptrs;
    pt->cr3_match = r->cr3_match;
    pt->addr0_a = r->addr_ranges[0].a;
    pt->addr0_b = r->addr_ranges[0].b;
    pt->addr1_a = r->addr_ranges[1].a;
    pt->addr1_b = r->addr_ranges[1].b;

    return NO_ERROR;
#else
    return ERR_NOT_SUPPORTED;
#endif
}
