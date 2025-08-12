// Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
#ifndef MOCK_FFRT_API_C_QUEUE_H
#define MOCK_FFRT_API_C_QUEUE_H

#include <stdbool.h>
#include "type_def.h"

typedef enum {

    ffrt_queue_serial,

    ffrt_queue_concurrent,

    ffrt_queue_max
} ffrt_queue_type_t;

typedef void *ffrt_queue_t;
inline FFRT_C_API int ffrt_queue_attr_init(ffrt_queue_attr_t *attr)
{
    return 0;
}

inline FFRT_C_API void ffrt_queue_attr_destroy(ffrt_queue_attr_t *attr)
{}

inline FFRT_C_API void ffrt_queue_attr_set_qos(ffrt_queue_attr_t *attr, ffrt_qos_t qos)
{}

inline FFRT_C_API ffrt_qos_t ffrt_queue_attr_get_qos(const ffrt_queue_attr_t *attr)
{
    return {};
}

inline FFRT_C_API void ffrt_queue_attr_set_timeout(ffrt_queue_attr_t *attr, uint64_t timeout_us)
{}

inline FFRT_C_API uint64_t ffrt_queue_attr_get_timeout(const ffrt_queue_attr_t *attr)
{
    return 0;
}

inline FFRT_C_API void ffrt_queue_attr_set_callback(ffrt_queue_attr_t *attr, ffrt_function_header_t *f)
{}

inline FFRT_C_API ffrt_function_header_t *ffrt_queue_attr_get_callback(const ffrt_queue_attr_t *attr)
{
    return nullptr;
}

inline FFRT_C_API void ffrt_queue_attr_set_max_concurrency(ffrt_queue_attr_t *attr, const int max_concurrency)
{}

inline FFRT_C_API int ffrt_queue_attr_get_max_concurrency(const ffrt_queue_attr_t *attr)
{
    return 0;
}

inline FFRT_C_API void ffrt_queue_attr_set_thread_mode(ffrt_queue_attr_t *attr, bool mode)
{}

inline FFRT_C_API bool ffrt_queue_attr_get_thread_mode(const ffrt_queue_attr_t *attr)
{
    return true;
}

inline FFRT_C_API ffrt_queue_t ffrt_queue_create(
    ffrt_queue_type_t type, const char *name, const ffrt_queue_attr_t *attr)
{
    return {};
}

inline FFRT_C_API void ffrt_queue_destroy(ffrt_queue_t queue)
{}

inline FFRT_C_API void ffrt_queue_submit(ffrt_queue_t queue, ffrt_function_header_t *f, const ffrt_task_attr_t *attr)
{}

inline FFRT_C_API ffrt_task_handle_t ffrt_queue_submit_h(
    ffrt_queue_t queue, ffrt_function_header_t *f, const ffrt_task_attr_t *attr)
{
    return {};
}

inline FFRT_C_API void ffrt_queue_submit_f(
    ffrt_queue_t queue, ffrt_function_t func, void *arg, const ffrt_task_attr_t *attr)
{}

inline FFRT_C_API ffrt_task_handle_t ffrt_queue_submit_h_f(
    ffrt_queue_t queue, ffrt_function_t func, void *arg, const ffrt_task_attr_t *attr)
{
    return {};
}

inline FFRT_C_API void ffrt_queue_wait(ffrt_task_handle_t handle)
{}

inline FFRT_C_API int ffrt_queue_cancel(ffrt_task_handle_t handle)
{
    return 0;
}

inline FFRT_C_API ffrt_queue_t ffrt_get_main_queue(void)
{
    return {};
}

inline FFRT_C_API ffrt_queue_t ffrt_get_current_queue(void)
{
    return {};
}

inline FFRT_C_API uint64_t ffrt_queue_get_task_cnt(ffrt_queue_t queue)
{
    return 0;
}

inline FFRT_C_API void ffrt_queue_submit_head(
    ffrt_queue_t queue, ffrt_function_header_t *f, const ffrt_task_attr_t *attr)
{}

inline FFRT_C_API ffrt_task_handle_t ffrt_queue_submit_head_h(
    ffrt_queue_t queue, ffrt_function_header_t *f, const ffrt_task_attr_t *attr)
{
    return {};
}

#endif