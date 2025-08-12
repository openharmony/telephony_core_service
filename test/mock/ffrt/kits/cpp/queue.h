// Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
#ifndef MOCK_FFRT_API_CPP_QUEUE_H
#define MOCK_FFRT_API_CPP_QUEUE_H

#include "c/queue.h"
#include "task.h"

namespace ffrt {

enum queue_type {
    queue_serial = ffrt_queue_serial,
    queue_concurrent = ffrt_queue_concurrent,
    queue_max = ffrt_queue_max,
};

class queue_attr : public ffrt_queue_attr_t {
public:
    queue_attr()
    {}

    ~queue_attr()
    {}

    queue_attr(const queue_attr &) = delete;

    queue_attr &operator=(const queue_attr &) = delete;

    inline queue_attr &qos(qos qos_)
    {
        return *this;
    }

    inline int qos() const
    {
        return 0;
    }

    inline queue_attr &timeout(uint64_t timeout_us)
    {
        return *this;
    }

    inline uint64_t timeout() const
    {
        return 0;
    }

    inline queue_attr &callback(const std::function<void()> &func)
    {
        return *this;
    }

    inline ffrt_function_header_t *callback() const
    {
        return nullptr;
    }

    inline queue_attr &max_concurrency(const int max_concurrency)
    {
        return *this;
    }

    inline int max_concurrency() const
    {
        return 0;
    }

    inline queue_attr &thread_mode(bool mode)
    {
        return *this;
    }

    inline bool thread_mode() const
    {
        return true;
    }
};

class queue {
public:
    queue(const queue_type type, const char *name, const queue_attr &attr = {})
    {}

    queue(const char *name, const queue_attr &attr = {})
    {}

    ~queue()
    {}

    queue(const queue &) = delete;

    void operator=(const queue &) = delete;

    inline void submit(const std::function<void()> &func, const task_attr &attr = {})
    {}

    inline void submit(std::function<void()> &&func, const task_attr &attr = {})
    {}

    inline task_handle submit_h(const std::function<void()> &func, const task_attr &attr = {})
    {
        return {};
    }

    inline task_handle submit_h(std::function<void()> &&func, const task_attr &attr = {})
    {
        return {};
    }

    inline void submit_head(const std::function<void()> &func, const task_attr &attr = {})
    {}

    inline void submit_head(std::function<void()> &&func, const task_attr &attr = {})
    {}

    inline task_handle submit_head_h(const std::function<void()> &func, const task_attr &attr = {})
    {
        return {};
    }

    inline task_handle submit_head_h(std::function<void()> &&func, const task_attr &attr = {})
    {
        return {};
    }

    inline int cancel(const task_handle &handle)
    {
        return 0;
    }

    inline void wait(const task_handle &handle)
    {}

    inline uint64_t get_task_cnt()
    {
        return 0;
    }

    static inline queue *get_main_queue()
    {
        return nullptr;
    }

private:
    using QueueDeleter = void (*)(ffrt_queue_t);

    queue(ffrt_queue_t queue_handle, QueueDeleter deleter = nullptr)
    {}

    [[maybe_unused]] ffrt_queue_t queue_handle = nullptr; ///< Handle to the underlying queue.
    [[maybe_unused]] QueueDeleter deleter = nullptr;      ///< Function pointer used to delete or destroy the queue.
};
}  // namespace ffrt

#endif