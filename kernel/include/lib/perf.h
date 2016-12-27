// Copyright 2016 The Fuchsia Authors
//
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT

#pragma once

#include <err.h>
#include <magenta/compiler.h>
#include <magenta/perf.h>
#include <stdint.h>

__BEGIN_CDECLS

status_t perf_control(uint32_t action, uint32_t options, void* arg, size_t* out_arg);

int perf_read_user(void* ptr, uint32_t off, uint32_t len);

__END_CDECLS
