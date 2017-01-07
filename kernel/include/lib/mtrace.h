// Copyright 2016 The Fuchsia Authors
//
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT

#pragma once

#include <err.h>
#include <magenta/compiler.h>
#include <stdint.h>

__BEGIN_CDECLS

status_t mtrace_control(uint32_t kind, uint32_t action, uint32_t options,
                        void* arg, uint32_t size);

#ifdef __x86_64__
status_t mtrace_ipt_control(uint32_t kind, uint32_t action, uint32_t options,
                            void* arg, uint32_t size);
#endif

__END_CDECLS
