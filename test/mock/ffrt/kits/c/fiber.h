// Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
#ifndef MOCK_FFRT_API_C_FIBER_H
#define MOCK_FFRT_API_C_FIBER_H

#include "type_def.h"

inline FFRT_C_API int ffrt_fiber_init(
    ffrt_fiber_t *fiber, void (*func)(void *), void *arg, void *stack, size_t stack_size)
{
    return 0;
}

inline FFRT_C_API void ffrt_fiber_switch(ffrt_fiber_t *from, ffrt_fiber_t *to)
{}

#endif