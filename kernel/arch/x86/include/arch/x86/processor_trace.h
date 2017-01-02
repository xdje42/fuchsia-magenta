// Copyright 2016 The Fuchsia Authors
//
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT

#pragma once

#include <kernel/thread.h>
#include <list.h>
#include <magenta/compiler.h>
#include <stdint.h>

__BEGIN_CDECLS

void x86_processor_trace_init(void);

__END_CDECLS

#ifdef __cplusplus

status_t x86_processor_trace_alloc();
status_t x86_processor_trace_start();
status_t x86_processor_trace_stop();
status_t x86_processor_trace_free();

status_t x86_processor_trace_read_size(size_t* capture_size,
                                       uint32_t num_cpus);
status_t x86_processor_trace_read_bytes(uint32_t cpu, void* ptr,
                                        size_t off, size_t len,
                                        size_t* actual);

#endif  // __cplusplus
