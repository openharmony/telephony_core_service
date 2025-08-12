// Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
#ifndef MOCK_FFRT_API_CPP_CONDITION_VARIABLE_H
#define MOCK_FFRT_API_CPP_CONDITION_VARIABLE_H

#include <chrono>
#include <mutex>
#include "mutex.h"
#include "c/condition_variable.h"

namespace ffrt {

enum class cv_status { no_timeout, timeout };

class condition_variable : public ffrt_cond_t {
public:
    condition_variable()
    {}

    ~condition_variable() noexcept
    {
    }

    condition_variable(const condition_variable &) = delete;

    condition_variable &operator=(const condition_variable &) = delete;

    template <typename Clock, typename Duration, typename Pred>
    bool wait_until(
        std::unique_lock<mutex> &lk, const std::chrono::time_point<Clock, Duration> &tp, Pred &&pred) noexcept
    {
        return true;
    }

    template <typename Clock, typename Duration>
    cv_status wait_until(std::unique_lock<mutex> &lk, const std::chrono::time_point<Clock, Duration> &tp) noexcept
    {
        return cv_status::timeout;
    }

    template <typename Rep, typename Period>
    cv_status wait_for(std::unique_lock<mutex> &lk, const std::chrono::duration<Rep, Period> &sleep_time) noexcept
    {
        return cv_status::timeout;
    }

    template <typename Rep, typename Period, typename Pred>
    bool wait_for(
        std::unique_lock<mutex> &lk, const std::chrono::duration<Rep, Period> &sleepTime, Pred &&pred) noexcept
    {
        return true;
    }

    template <typename Pred>
    void wait(std::unique_lock<mutex> &lk, Pred &&pred)
    {
    }

    void wait(std::unique_lock<mutex> &lk)
    {}

    void notify_one() noexcept
    {}

    void notify_all() noexcept
    {}

private:
    template <typename Rep, typename Period>
    cv_status _wait_for(std::unique_lock<mutex> &lk, const std::chrono::duration<Rep, Period> &dur) noexcept
    {
        return cv_status::timeout;
    }
};
}  // namespace ffrt

#endif