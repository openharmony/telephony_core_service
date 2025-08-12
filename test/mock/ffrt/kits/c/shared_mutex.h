// Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
#ifndef MOCK_FFRT_API_C_SHARED_MUTEX_H
#define MOCK_FFRT_API_C_SHARED_MUTEX_H

#include "type_def.h"

inline FFRT_C_API int ffrt_rwlock_init(ffrt_rwlock_t *rwlock, const ffrt_rwlockattr_t *attr)
{
    return 0;
}

inline FFRT_C_API int ffrt_rwlock_wrlock(ffrt_rwlock_t *rwlock)
{
    return 0;
}

inline FFRT_C_API int ffrt_rwlock_trywrlock(ffrt_rwlock_t *rwlock)
{
    return 0;
}

inline FFRT_C_API int ffrt_rwlock_rdlock(ffrt_rwlock_t *rwlock)
{
    return 0;
}

inline FFRT_C_API int ffrt_rwlock_tryrdlock(ffrt_rwlock_t *rwlock)
{
    return 0;
}

inline FFRT_C_API int ffrt_rwlock_unlock(ffrt_rwlock_t *rwlock)
{
    return 0;
}

inline FFRT_C_API int ffrt_rwlock_destroy(ffrt_rwlock_t *rwlock)
{
    return 0;
}

#endif