// Copyright 2016 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// TODO(dje): wip wip wip

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

// set size of each buffer, in pages, as a power of 2,
#define IOCTL_IPT_SET_BUFFER_ORDER \
    IOCTL(IOCTL_KIND_DEFAULT, IOCTL_FAMILY_IPT, 10)
IOCTL_WRAPPER_IN(ioctl_ipt_set_buffer_order, IOCTL_IPT_SET_BUFFER_ORDER, size_t);

// set number of buffers
#define IOCTL_IPT_SET_NUM_BUFFERS \
    IOCTL(IOCTL_KIND_DEFAULT, IOCTL_FAMILY_IPT, 11)
IOCTL_WRAPPER_IN(ioctl_ipt_set_num_buffers, IOCTL_IPT_SET_NUM_BUFFERS, size_t);

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
