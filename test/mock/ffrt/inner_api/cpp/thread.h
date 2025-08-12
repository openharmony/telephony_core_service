// Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
#ifndef MOCK_FFRT_API_CPP_THREAD_H
#define MOCK_FFRT_API_CPP_THREAD_H
#include <memory>
#include "cpp/task.h"

namespace ffrt {
class thread {
public:
    thread() noexcept
    {}

    template <typename Fn, typename... Args,
        class = std::enable_if_t<!std::is_same_v<std::remove_cv_t<std::remove_reference_t<Fn>>, thread>>>
    explicit thread(const char *name, qos qos_, Fn &&fn, Args &&...args)
    {
    }

    template <typename Fn, typename... Args,
        class = std::enable_if_t<!std::is_same_v<std::remove_cv_t<std::remove_reference_t<Fn>>, thread>>>
    explicit thread(qos qos_, Fn &&fn, Args &&...args)
    {
    }

    template <class Fn, class... Args,
        class = std::enable_if_t<!std::is_same_v<std::remove_cv_t<std::remove_reference_t<Fn>>, thread>>,
        class = std::enable_if_t<!std::is_same_v<std::remove_cv_t<std::remove_reference_t<Fn>>, char *>>,
        class = std::enable_if_t<!std::is_same_v<std::remove_cv_t<std::remove_reference_t<Fn>>, qos>>>
    explicit thread(Fn &&fn, Args &&...args)
    {
    }

    thread(const thread &) = delete;
    thread &operator=(const thread &) = delete;

    thread(thread &&th) noexcept
    {}

    thread &operator=(thread &&th) noexcept
    {
        return *this;
    }

    bool joinable() const noexcept
    {
        return true;
    }

    void detach() noexcept
    {}

    void join() noexcept
    {
    }

    ~thread()
    {
    }
private:
    [[maybe_unused]] std::unique_ptr<task_handle> is_joinable;
};
}  // namespace ffrt
#endif