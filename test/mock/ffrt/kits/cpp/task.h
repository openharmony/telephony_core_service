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
#ifndef MOCK_FFRT_API_CPP_TASK_H
#define MOCK_FFRT_API_CPP_TASK_H

#include <string>
#include <vector>
#include <functional>
#include "c/task.h"

namespace ffrt {

class task_attr : public ffrt_task_attr_t {
public:
#if __has_builtin(__builtin_FUNCTION)

    task_attr(const char *func = __builtin_FUNCTION())
    {}
#else

    task_attr()
    {}
#endif

    ~task_attr()
    {}

    task_attr(const task_attr &) = delete;

    task_attr &operator=(const task_attr &) = delete;

    inline task_attr &name(const char *name)
    {
        return *this;
    }

    inline const char *name() const
    {
        return nullptr;
    }

    inline task_attr &qos(qos qos_)
    {
        return *this;
    }

    inline int qos() const
    {
        return 0;
    }

    inline task_attr &delay(uint64_t delay_us)
    {
        return *this;
    }

    inline uint64_t delay() const
    {
        return 0;
    }

    inline task_attr &priority(ffrt_queue_priority_t prio)
    {
        return *this;
    }

    inline ffrt_queue_priority_t priority() const
    {
        return {};
    }

    inline task_attr &stack_size(uint64_t size)
    {
        return *this;
    }

    inline uint64_t stack_size() const
    {
        return 0;
    }

    inline task_attr &timeout(uint64_t timeout_us)
    {
        return *this;
    }

    inline uint64_t timeout() const
    {
        return 0;
    }
};

class task_handle {
public:
    task_handle()
    {}

    task_handle(ffrt_task_handle_t p)
    {}

    ~task_handle()
    {}

    task_handle(task_handle const &) = delete;

    task_handle &operator=(task_handle const &) = delete;

    task_handle(task_handle &&h)
    {}

    inline uint64_t get_id() const
    {
        return 0;
    }

    inline task_handle &operator=(task_handle &&h)
    {
        return *this;
    }

    inline operator void *() const
    {
        return nullptr;
    }
private:
    [[maybe_unused]] ffrt_task_handle_t p = nullptr;
};

struct dependence : ffrt_dependence_t {

    dependence(const void *d)
    {}

    dependence(const task_handle &h)
    {}

    dependence(const dependence &other)
    {}

    dependence(dependence &&other)
    {}

    dependence &operator=(const dependence &other)
    {
        return *this;
    }

    dependence &operator=(dependence &&other)
    {
        return *this;
    }

    ~dependence()
    {}
};

template <class T>
struct function {
    ffrt_function_header_t header;
    T closure;
};

template <class T>
void exec_function_wrapper(void *t)
{}

template <class T>
void destroy_function_wrapper(void *t)
{}

template <class T>
inline ffrt_function_header_t *create_function_wrapper(T &&func, ffrt_function_kind_t kind = ffrt_function_kind_general)
{
    return nullptr;
}

static inline void submit(std::function<void()> &&func, const task_attr &attr = {})
{}

static inline void submit(
    std::function<void()> &&func, std::initializer_list<dependence> in_deps, const task_attr &attr = {})
{}

static inline void submit(std::function<void()> &&func, std::initializer_list<dependence> in_deps,
    std::initializer_list<dependence> out_deps, const task_attr &attr = {})
{}

static inline void submit(
    std::function<void()> &&func, const std::vector<dependence> &in_deps, const task_attr &attr = {})
{}

static inline void submit(std::function<void()> &&func, const std::vector<dependence> &in_deps,
    const std::vector<dependence> &out_deps, const task_attr &attr = {})
{}

static inline void submit(const std::function<void()> &func, const task_attr &attr = {})
{}

static inline void submit(
    const std::function<void()> &func, std::initializer_list<dependence> in_deps, const task_attr &attr = {})
{}

static inline void submit(const std::function<void()> &func, std::initializer_list<dependence> in_deps,
    std::initializer_list<dependence> out_deps, const task_attr &attr = {})
{}

static inline void submit(
    const std::function<void()> &func, const std::vector<dependence> &in_deps, const task_attr &attr = {})
{}

static inline void submit(const std::function<void()> &func, const std::vector<dependence> &in_deps,
    const std::vector<dependence> &out_deps, const task_attr &attr = {})
{}

static inline task_handle submit_h(std::function<void()> &&func, const task_attr &attr = {})
{
    return {};
}

static inline task_handle submit_h(
    std::function<void()> &&func, std::initializer_list<dependence> in_deps, const task_attr &attr = {})
{
    return {};
}

static inline task_handle submit_h(std::function<void()> &&func, std::initializer_list<dependence> in_deps,
    std::initializer_list<dependence> out_deps, const task_attr &attr = {})
{
    return {};
}

static inline task_handle submit_h(
    std::function<void()> &&func, const std::vector<dependence> &in_deps, const task_attr &attr = {})
{
    return {};
}

static inline task_handle submit_h(std::function<void()> &&func, const std::vector<dependence> &in_deps,
    const std::vector<dependence> &out_deps, const task_attr &attr = {})
{
    return {};
}

static inline task_handle submit_h(const std::function<void()> &func, const task_attr &attr = {})
{
    return {};
}

static inline task_handle submit_h(
    const std::function<void()> &func, std::initializer_list<dependence> in_deps, const task_attr &attr = {})
{
    return {};
}

static inline task_handle submit_h(const std::function<void()> &func, std::initializer_list<dependence> in_deps,
    std::initializer_list<dependence> out_deps, const task_attr &attr = {})
{
    return {};
}

static inline task_handle submit_h(
    const std::function<void()> &func, const std::vector<dependence> &in_deps, const task_attr &attr = {})
{
    return {};
}

static inline task_handle submit_h(const std::function<void()> &func, const std::vector<dependence> &in_deps,
    const std::vector<dependence> &out_deps, const task_attr &attr = {})
{
    return {};
}

static inline void wait()
{}

static inline void wait(std::initializer_list<dependence> deps)
{}

static inline void wait(const std::vector<dependence> &deps)
{}

static inline ffrt_error_t set_worker_stack_size(qos qos_, size_t stack_size)
{
    return {};
}

namespace this_task {

static inline int update_qos(qos qos_)
{
    return 0;
}

static inline uint64_t get_id()
{
    return 0;
}
}  // namespace this_task
}  // namespace ffrt

#endif