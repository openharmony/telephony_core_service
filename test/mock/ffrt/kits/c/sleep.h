// Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
#ifndef MOCK_FFRT_API_C_SLEEP_H
#define MOCK_FFRT_API_C_SLEEP_H

#include <stdint.h>
#include "type_def.h"

inline FFRT_C_API int ffrt_usleep(uint64_t usec)
{
    return 0;
}

inline FFRT_C_API void ffrt_yield(void)
{}

#endif