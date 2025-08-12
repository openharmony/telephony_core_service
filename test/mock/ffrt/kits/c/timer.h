// Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
#ifndef MOCK_FFRT_API_C_TIMER_H
#define MOCK_FFRT_API_C_TIMER_H

#include <stdbool.h>
#include "type_def.h"

inline FFRT_C_API ffrt_timer_t ffrt_timer_start(
    ffrt_qos_t qos, uint64_t timeout, void *data, ffrt_timer_cb cb, bool repeat)
{
    return {};
}

inline FFRT_C_API int ffrt_timer_stop(ffrt_qos_t qos, ffrt_timer_t handle)
{
    return 0;
}

#endif