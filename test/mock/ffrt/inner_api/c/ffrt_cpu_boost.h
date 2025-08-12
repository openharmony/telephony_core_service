// Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
#ifndef MOCK_FFRT_CPU_BOOST_C_API_H
#define MOCK_FFRT_CPU_BOOST_C_API_H
#include "type_def_ext.h"

#define CPUBOOST_START_POINT 0
#define CPUBOOST_MAX_CNT 32

inline FFRT_C_API int ffrt_cpu_boost_start(int ctx_id)
{
    return 0;
}

inline FFRT_C_API int ffrt_cpu_boost_end(int ctx_id)
{
    return 0;
}

#endif  // FFRT_CPU_BOOST_C_API_H