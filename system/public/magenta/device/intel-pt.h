// Copyright 2016 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// TODO(dje): wip wip wip
// What's here now is a simple version to get things going.

#pragma once

#include <magenta/compiler.h>
#include <magenta/device/ioctl.h>
#include <magenta/device/ioctl-wrapper.h>
#include <stddef.h>

__BEGIN_CDECLS

#if !defined(__x86_64__)
#error "unsupported architecture"
#endif

// must be called prior to START, allocate buffers of the specified size
#define IOCTL_IPT_ALLOC \
    IOCTL(IOCTL_KIND_DEFAULT, IOCTL_FAMILY_IPT, 1)
IOCTL_WRAPPER(ioctl_ipt_alloc, IOCTL_IPT_ALLOC);

// turn on processor tracing
#define IOCTL_IPT_START \
    IOCTL(IOCTL_KIND_DEFAULT, IOCTL_FAMILY_IPT, 2)
IOCTL_WRAPPER(ioctl_ipt_start, IOCTL_IPT_START);

// turn off processor tracing
#define IOCTL_IPT_STOP \
    IOCTL(IOCTL_KIND_DEFAULT, IOCTL_FAMILY_IPT, 3)
IOCTL_WRAPPER(ioctl_ipt_stop, IOCTL_IPT_STOP);

// release resources allocated with ALLOC
// must be called prior to reconfiguring buffer sizes
#define IOCTL_IPT_FREE \
    IOCTL(IOCTL_KIND_DEFAULT, IOCTL_FAMILY_IPT, 4)
IOCTL_WRAPPER(ioctl_ipt_free, IOCTL_IPT_FREE);

// write collected data to a file
// TODO(dje): This is just to get things going. At the moment all
// post-processing is done after tracing is complete.
#define IOCTL_IPT_WRITE_FILE \
    IOCTL(IOCTL_KIND_DEFAULT, IOCTL_FAMILY_IPT, 5)
IOCTL_WRAPPER_VARIN(ioctl_ipt_write_file, IOCTL_IPT_WRITE_FILE, char);

// set the buffer size
// The input is an array of two values:
// [0] buffer "order" (#pages as power of 2)
// [1] number of such buffers
#define IOCTL_IPT_SET_BUFFER_SIZE \
    IOCTL(IOCTL_KIND_DEFAULT, IOCTL_FAMILY_IPT, 10)
IOCTL_WRAPPER_VARIN(ioctl_ipt_set_buffer_size, IOCTL_IPT_SET_BUFFER_SIZE, size_t);

// set the configurable bits of the control msr
#define IOCTL_IPT_SET_CTL_CONFIG \
    IOCTL(IOCTL_KIND_DEFAULT, IOCTL_FAMILY_IPT, 11)
IOCTL_WRAPPER_IN(ioctl_ipt_set_ctl_config, IOCTL_IPT_SET_CTL_CONFIG, uint64_t);

// These bits are writable by the user with ioctl_ipt_set_ctl_config.
// The driver will override a setting if it's unsafe (e.g., causes #gpf).
#define IPT_CTL_CYC_EN (1ULL << 1)
#define IPT_CTL_OS_ALLOWED (1ULL << 2)
#define IPT_CTL_USER_ALLOWED (1ULL << 3)
#define IPT_CTL_POWER_EVENT_EN (1ULL << 4)
#define IPT_CTL_FUP_ON_PTW (1ULL << 5)
#define IPT_CTL_CR3_FILTER (1ULL << 7)
#define IPT_CTL_MTC_EN (1ULL << 9)
#define IPT_CTL_TSC_EN (1ULL << 10)
#define IPT_CTL_DIS_RETC (1ULL << 11)
#define IPT_CTL_PTW_EN (1ULL << 12)
#define IPT_CTL_BRANCH_EN (1ULL << 13)
#define IPT_CTL_MTC_FREQ (0xfULL << 14)
#define IPT_CTL_CYC_THRESH (0xfULL << 19)
#define IPT_CTL_PSB_FREQ (0xfULL << 24)
#define IPT_CTL_ADDR0 (0xfULL << 32)
#define IPT_CTL_ADDR1 (0xfULL << 36)
#define IPT_CTL_ADDR2 (0xfULL << 40)
#define IPT_CTL_ADDR3 (0xfULL << 44)

// set the cr3 filter msr
#define IOCTL_IPT_SET_CR3_FILTER \
    IOCTL(IOCTL_KIND_DEFAULT, IOCTL_FAMILY_IPT, 12)
IOCTL_WRAPPER_IN(ioctl_ipt_set_cr3_filter, IOCTL_IPT_SET_CR3_FILTER, uint64_t);

// set address range msrs
// The input is an array of three values:
// [0] address range register number, 0-3
// [1] "A" value
// [2] "B" value
#define IOCTL_IPT_SET_ADDR_CONFIG \
    IOCTL(IOCTL_KIND_DEFAULT, IOCTL_FAMILY_IPT, 13)
IOCTL_WRAPPER_VARIN(ioctl_ipt_set_addr_config, IOCTL_IPT_SET_ADDR_CONFIG, uint64_t);

///////////////////////////////////////////////////////////////////////////////

// The remainder of this file is for use by the driver, not any client.
// It's here to keep things simple while this is wip.

// mtrace_control() can operate on a range of features, for now just IPT.
// It's an abstraction that doesn't mean much, and will likely be replaced
// before it's useful; it's here in the interests of hackability in the
// interim.
#define MTRACE_KIND_IPT 0

// Actions for perf_control

// These actions stage values for later writing via wrmsr, done by
// MTRACE_IPT_START.
// A value can be assigned to all cpus by passing MTRACE_IPT_ALL_CPUS in
// |options|. This obviously doesn't make sense for OUTPUT_BASE, but the driver
// can crash the system in various other ways so we leave it to the driver to
// get right.
#define MTRACE_IPT_STAGE_CTL 0
#define MTRACE_IPT_STAGE_STATUS 1
#define MTRACE_IPT_STAGE_OUTPUT_BASE 2
#define MTRACE_IPT_STAGE_OUTPUT_MASK_PTRS 3
#define MTRACE_IPT_STAGE_CR3_MATCH 4

// These can only be fetched while tracing is stopped.
// MTRACE_IPT_STOP will retrieve all the values and save them.
#define MTRACE_IPT_GET_CTL 10
#define MTRACE_IPT_GET_STATUS 11
#define MTRACE_IPT_GET_OUTPUT_BASE 12
#define MTRACE_IPT_GET_OUTPUT_MASK_PTRS 13
#define MTRACE_IPT_GET_CR3_MATCH 14

#define MTRACE_IPT_ALLOC 20
#define MTRACE_IPT_START 21
#define MTRACE_IPT_STOP 22
#define MTRACE_IPT_FREE 23

// Encode/decode options values for mtrace_control().
// At present we just encode the cpu number here.
// We only support 32 cpus at the moment, the extra bit is for magic values.
#define MTRACE_IPT_OPTIONS_CPU_MASK 0x3f
#define MTRACE_IPT_OPTIONS(cpu) (((cpu) & MTRACE_IPT_OPTIONS_CPU_MASK) + 0)

// TODO(dje): a static assert that this is big enough would be nice
#define MTRACE_IPT_ALL_CPUS 32

#define MTRACE_IPT_OPTIONS_CPU(options) ((options) & MTRACE_IPT_OPTIONS_CPU_MASK)

__END_CDECLS
