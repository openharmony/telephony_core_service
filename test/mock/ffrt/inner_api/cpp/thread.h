/*
 * Copyright (C) 2025-2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
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