// Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
#ifndef MOCK_FFRT_API_C_CONDITION_VARIABLE_H
#define MOCK_FFRT_API_C_CONDITION_VARIABLE_H

#include <time.h>
#include "type_def.h"
inline FFRT_C_API int ffrt_cond_init(ffrt_cond_t *cond, const ffrt_condattr_t *attr)
{
    return 0;
}

inline FFRT_C_API int ffrt_cond_signal(ffrt_cond_t *cond)
{
    return 0;
}

inline FFRT_C_API int ffrt_cond_broadcast(ffrt_cond_t *cond)
{
    return 0;
}

inline FFRT_C_API int ffrt_cond_wait(ffrt_cond_t *cond, ffrt_mutex_t *mutex)
{
    return 0;
}

inline FFRT_C_API int ffrt_cond_timedwait(ffrt_cond_t *cond, ffrt_mutex_t *mutex, const struct timespec *time_point)
{
    return 0;
}

inline FFRT_C_API int ffrt_cond_destroy(ffrt_cond_t *cond)
{
    return 0;
}

#endif