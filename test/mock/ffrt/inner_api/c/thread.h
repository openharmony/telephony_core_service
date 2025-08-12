// Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
#ifndef MOCK_FFRT_API_C_THREAD_H
#define MOCK_FFRT_API_C_THREAD_H
#include "type_def_ext.h"

inline FFRT_C_API int ffrt_thread_create(
    ffrt_thread_t *thr, const ffrt_thread_attr_t *attr, void *(*func)(void *), void *arg)
{
    return 0;
}

inline FFRT_C_API int ffrt_thread_join(ffrt_thread_t thr, void **res)
{
    return 0;
}

inline FFRT_C_API int ffrt_thread_detach(ffrt_thread_t thr)
{
    return 0;
}
#endif