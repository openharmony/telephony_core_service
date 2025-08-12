// Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
#ifndef MOCK_FFRT_API_CPP_DEADLINE_H
#define MOCK_FFRT_API_CPP_DEADLINE_H
#include <stdint.h>
#include "c/deadline.h"

namespace ffrt {
using interval = ffrt_interval_t;

static inline interval qos_interval_create(uint64_t deadline_us, qos qos_ = static_cast<int>(qos_deadline_request))
{
    return {};
}

static inline void qos_interval_destroy(interval it)
{}

static inline int qos_interval_begin(interval it)
{
    return 0;
}

static inline int qos_interval_update(interval it, uint64_t new_deadline_us)
{
    return 0;
}

static inline int qos_interval_end(interval it)
{
    return 0;
}

static inline int qos_interval_join(interval it)
{
    return 0;
}

static inline int qos_interval_leave(interval it)
{
    return 0;
}
};  // namespace ffrt

#endif