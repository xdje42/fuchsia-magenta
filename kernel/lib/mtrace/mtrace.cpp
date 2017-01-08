// Copyright 2016 The Fuchsia Authors
//
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT

#include "lib/mtrace.h"

#include <arch/user_copy.h>
#include <kernel/mp.h>
#include <magenta/device/intel-pt.h>

#ifdef __x86_64__
#include "arch/x86/mtrace_ipt.h"
#endif

status_t mtrace_control(uint32_t kind, uint32_t action, uint32_t options,
                        void* arg, uint32_t size) {
    switch (kind) {
#ifdef __x86_64__
    case MTRACE_KIND_IPT:
        return mtrace_ipt_control(action, options, arg, size);
#endif
    default:
        return ERR_INVALID_ARGS;
    }
}
