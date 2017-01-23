// Copyright 2016 The Fuchsia Authors
//
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT

#pragma once

#include <err.h>
#include <magenta/compiler.h>
#include <magenta/thread_dispatcher.h>
#include <mxtl/ref_ptr.h>
#include <stdint.h>

status_t mtrace_control(uint32_t kind, uint32_t action, uint32_t options,
                        void* arg, uint32_t size);

status_t mtrace_control_thread(mxtl::RefPtr<ThreadDispatcher> thread,
                               uint32_t kind, uint32_t action, uint32_t options,
                               void* arg, uint32_t size);
