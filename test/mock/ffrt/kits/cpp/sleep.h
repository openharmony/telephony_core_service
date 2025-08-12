// Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
#ifndef MOCK_FFRT_API_CPP_SLEEP_H
#define MOCK_FFRT_API_CPP_SLEEP_H

#include <chrono>
#include "c/sleep.h"

namespace ffrt {

namespace this_task {

static inline void yield()
{}

template <class _Rep, class _Period>
inline void sleep_for(const std::chrono::duration<_Rep, _Period> &d)
{}

template <class _Clock, class _Duration>
inline void sleep_until(const std::chrono::time_point<_Clock, _Duration> &abs_time)
{}
}  // namespace this_task
}  // namespace ffrt

#endif