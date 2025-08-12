// Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
#ifndef MOCK_FFRT_API_C_MUTEX_H
#define MOCK_FFRT_API_C_MUTEX_H

#include "type_def.h"
inline FFRT_C_API int ffrt_mutexattr_init(ffrt_mutexattr_t *attr)
{
    return 0;
}

inline FFRT_C_API int ffrt_mutexattr_settype(ffrt_mutexattr_t *attr, int type)
{
    return 0;
}

inline FFRT_C_API int ffrt_mutexattr_gettype(ffrt_mutexattr_t *attr, int *type)
{
    return 0;
}

inline FFRT_C_API int ffrt_mutexattr_destroy(ffrt_mutexattr_t *attr)
{
    return 0;
}

inline FFRT_C_API int ffrt_mutex_init(ffrt_mutex_t *mutex, const ffrt_mutexattr_t *attr)
{
    return 0;
}

inline FFRT_C_API int ffrt_mutex_lock(ffrt_mutex_t *mutex)
{
    return 0;
}

inline FFRT_C_API int ffrt_mutex_unlock(ffrt_mutex_t *mutex)
{
    return 0;
}

inline FFRT_C_API int ffrt_mutex_trylock(ffrt_mutex_t *mutex)
{
    return 0;
}

inline FFRT_C_API int ffrt_mutex_destroy(ffrt_mutex_t *mutex)
{
    return 0;
}

#endif