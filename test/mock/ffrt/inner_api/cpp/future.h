// Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
#ifndef MOCK_FFRT_API_CPP_FUTURE_H
#define MOCK_FFRT_API_CPP_FUTURE_H
#include <memory>
#include <optional>
#include <chrono>
#include "cpp/condition_variable.h"
#include "thread.h"

namespace ffrt {
struct non_copyable {
protected:
    non_copyable() = default;
    ~non_copyable() = default;
    non_copyable(const non_copyable &) = delete;
    non_copyable &operator=(const non_copyable &) = delete;
};
enum class future_status { ready, timeout, deferred };

namespace detail {
template <typename Derived>
struct shared_state_base : private non_copyable {
    void wait() const noexcept
    {}

    template <typename Rep, typename Period>
    future_status wait_for(const std::chrono::duration<Rep, Period> &waitTime) const noexcept
    {
        return future_status::timeout;
    }

    template <typename Clock, typename Duration>
    future_status wait_until(const std::chrono::time_point<Clock, Duration> &tp) const noexcept
    {
        return future_status::timeout;
    }
};

template <typename R>
struct shared_state : public shared_state_base<shared_state<R>> {
    void set_value(const R &value) noexcept
    {}

    void set_value(R &&value) noexcept
    {}

    R &get() noexcept
    {
        return m_res.value();
    }

    bool has_value() const noexcept
    {
        return m_res.has_value();
    }

private:
    std::optional<R> m_res;
};

template <>
struct shared_state<void> : public shared_state_base<shared_state<void>> {
    void set_value() noexcept
    {}

    void get() noexcept
    {}

    bool has_value() const noexcept
    {
        return true;
    }
};
};  // namespace detail

template <typename R>
class future : private non_copyable {
    template <typename>
    friend struct promise;

    template <typename>
    friend struct packaged_task;

public:
    explicit future(const std::shared_ptr<detail::shared_state<R>> &state) noexcept
    {}

    future() noexcept = default;

    future(future &&fut) noexcept
    {}
    future &operator=(future &&fut) noexcept
    {
        return *this;
    }

    bool valid() const noexcept
    {
        return true;
    }

    R get() noexcept
    {
        return {};
    }

    template <typename Rep, typename Period>
    future_status wait_for(const std::chrono::duration<Rep, Period> &waitTime) const noexcept
    {}

    template <typename Clock, typename Duration>
    future_status wait_until(const std::chrono::time_point<Clock, Duration> &tp) const noexcept
    {
        return future_status::timeout;
    }

    void wait() const noexcept
    {}

    void swap(future<R> &rhs) noexcept
    {}
};

template <typename R>
struct promise : private non_copyable {
    promise() noexcept : m_state{std::make_shared<detail::shared_state<R>>()}
    {}
    promise(promise &&p) noexcept
    {}
    promise &operator=(promise &&p) noexcept
    {
        return *this;
    }

    void set_value(const R &value) noexcept
    {}

    void set_value(R &&value) noexcept
    {}

    future<R> get_future() noexcept
    {
        return future<R>{m_state};
    }

    void swap(promise<R> &rhs) noexcept
    {}

private:
    std::shared_ptr<detail::shared_state<R>> m_state;
};

template <>
struct promise<void> : private non_copyable {
    promise() noexcept
    {}
    promise(promise &&p) noexcept
    {}
    promise &operator=(promise &&p) noexcept
    {
        return *this;
    }

    void set_value() noexcept
    {}

    future<void> get_future() noexcept
    {
        return {};
    }

    void swap(promise<void> &rhs) noexcept
    {}
};

template <typename F>
struct packaged_task;

template <typename R, typename... Args>
struct packaged_task<R(Args...)> {
    packaged_task() noexcept = default;

    packaged_task(const packaged_task &pt) noexcept
    {}

    packaged_task(packaged_task &&pt) noexcept
    {}

    packaged_task &operator=(packaged_task &&pt) noexcept
    {
        return *this;
    }

    template <typename F>
    explicit packaged_task(F &&f) noexcept
    {}

    bool valid() const noexcept
    {
        return true;
    }

    future<R> get_future() noexcept
    {
        return {};
    }

    void operator()(Args... args)
    {}

    void swap(packaged_task &pt) noexcept
    {}
};

template <typename F, typename... Args>
future<std::invoke_result_t<std::decay_t<F>, std::decay_t<Args>...>> async(F &&f, Args &&...args)
{
    return {};
}
}  // namespace ffrt
#endif