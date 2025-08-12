// Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
#ifndef MOCK_FFRT_API_C_DEADLINE_H
#define MOCK_FFRT_API_C_DEADLINE_H
#include <stdint.h>
#include "type_def_ext.h"

inline FFRT_C_API ffrt_interval_t ffrt_interval_create(uint64_t deadline_us, ffrt_qos_t qos)
{
    return nullptr;
}

inline FFRT_C_API int ffrt_interval_update(ffrt_interval_t it, uint64_t new_deadline_us)
{
    return 0;
}

inline FFRT_C_API int ffrt_interval_begin(ffrt_interval_t it)
{
    return 0;
}

inline FFRT_C_API int ffrt_interval_end(ffrt_interval_t it)
{
    return 0;
}

inline FFRT_C_API void ffrt_interval_destroy(ffrt_interval_t it)
{}

inline FFRT_C_API int ffrt_interval_join(ffrt_interval_t it)
{
    return 0;
}

inline FFRT_C_API int ffrt_interval_leave(ffrt_interval_t it)
{
    return 0;
}
#endif