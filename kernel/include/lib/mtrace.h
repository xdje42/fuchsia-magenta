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

status_t mtrace_control(uint32_t action, uint32_t options, void* arg);

int mtrace_read(uint32_t action, void* ptr, size_t off, size_t len,
                size_t* actual);

__END_CDECLS
