// Copyright 2016 The Fuchsia Authors
//
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT

#pragma once

#include <err.h>
#include <magenta/compiler.h>
#include <stdint.h>

#ifdef __cplusplus
#include <magenta/thread_dispatcher.h>
#include <mxtl/ref_ptr.h>
#endif

__BEGIN_CDECLS

void x86_processor_trace_init(void);

status_t mtrace_ipt_control(uint32_t action, uint32_t options,
                            void* arg, uint32_t size);

__END_CDECLS
