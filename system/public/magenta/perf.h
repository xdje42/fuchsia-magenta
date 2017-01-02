// Copyright 2016 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// TODO(dje): wip wip wip

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#if defined(__x86_64__)

#define PERF_ACTION_ALLOC 0
#define PERF_ACTION_START 1
#define PERF_ACTION_STOP 2
#define PERF_ACTION_FREE 3

#define PERF_READ_DATA_SIZE 0
#define PERF_READ_DATA_BYTES 1 /* + cpu# */

#else
#error "perf not supported for this architecture"
#endif

#ifdef __cplusplus
}
#endif
