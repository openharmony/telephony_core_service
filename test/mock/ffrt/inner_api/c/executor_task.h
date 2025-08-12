// Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
#ifndef MOCK_FFRT_API_C_EXECUTOR_TASK_H
#define MOCK_FFRT_API_C_EXECUTOR_TASK_H

#include <stdint.h>
#include <stdbool.h>
#include <sys/epoll.h>
#include "type_def_ext.h"
#include "c/timer.h"

typedef struct ffrt_executor_task {
    uintptr_t reserved[2];
    uintptr_t type;
    void *wq[2];
} ffrt_executor_task_t;

typedef enum {
    ffrt_normal_task = 0,
    ffrt_io_task = 1,
    ffrt_uv_task,
    ffrt_queue_task,
    ffrt_xpu_task,
    ffrt_invalid_task,
} ffrt_executor_task_type_t;

typedef void (*ffrt_executor_task_func)(ffrt_executor_task_t *data, ffrt_qos_t qos);

inline FFRT_C_API void ffrt_executor_task_register_func(ffrt_executor_task_func func, ffrt_executor_task_type_t type)
{}

inline FFRT_C_API void ffrt_executor_task_submit(ffrt_executor_task_t *task, const ffrt_task_attr_t *attr)
{}

inline FFRT_C_API int ffrt_executor_task_cancel(ffrt_executor_task_t *task, const ffrt_qos_t qos)
{
    return 0;
}

inline FFRT_C_API void ffrt_poller_wakeup(ffrt_qos_t qos)
{}

inline FFRT_C_API uint8_t ffrt_epoll_get_count(ffrt_qos_t qos)
{
    return 0;
}

inline FFRT_C_API ffrt_timer_query_t ffrt_timer_query(ffrt_qos_t qos, ffrt_timer_t handle)
{
    return {};
}

inline FFRT_C_API int ffrt_epoll_ctl(ffrt_qos_t qos, int op, int fd, uint32_t events, void *data, ffrt_poller_cb cb)
{
    return 0;
}

inline FFRT_C_API int ffrt_epoll_wait(ffrt_qos_t qos, struct epoll_event *events, int max_events, int timeout)
{
    return 0;
}

inline FFRT_C_API uint64_t ffrt_epoll_get_wait_time(void *taskHandle)
{
    return 0;
}

inline FFRT_C_API void ffrt_submit_coroutine(void *co, ffrt_coroutine_ptr_t exec, ffrt_function_t destroy,
    const ffrt_deps_t *in_deps, const ffrt_deps_t *out_deps, const ffrt_task_attr_t *attr)
{}

inline FFRT_C_API void ffrt_wake_coroutine(void *task)
{}

inline FFRT_C_API void *ffrt_get_current_task(void)
{
    return nullptr;
}

inline FFRT_C_API bool ffrt_get_current_coroutine_stack(void **stack_addr, size_t *size)
{
    return true;
}

inline FFRT_C_API void *ffrt_get_cur_task(void)
{
    return nullptr;
}

inline FFRT_C_API void ffrt_task_attr_set_local(ffrt_task_attr_t *attr, bool task_local)
{}

inline FFRT_C_API bool ffrt_task_attr_get_local(ffrt_task_attr_t *attr)
{
    return true;
}

inline FFRT_C_API pthread_t ffrt_task_get_tid(void *task_handle)
{
    return {};
}

inline FFRT_C_API uint64_t ffrt_get_cur_cached_task_id(void)
{
    return 0;
}
#endif