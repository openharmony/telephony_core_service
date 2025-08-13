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
#ifndef MOCK_FFRT_API_C_TASK_H
#define MOCK_FFRT_API_C_TASK_H

#include <stdint.h>
#include "type_def.h"

inline FFRT_C_API int ffrt_task_attr_init(ffrt_task_attr_t *attr)
{
    return 0;
}

inline FFRT_C_API void ffrt_task_attr_set_name(ffrt_task_attr_t *attr, const char *name)
{}

inline FFRT_C_API const char *ffrt_task_attr_get_name(const ffrt_task_attr_t *attr)
{
    return nullptr;
}

inline FFRT_C_API void ffrt_task_attr_destroy(ffrt_task_attr_t *attr)
{}

inline FFRT_C_API void ffrt_task_attr_set_qos(ffrt_task_attr_t *attr, ffrt_qos_t qos)
{}

inline FFRT_C_API ffrt_qos_t ffrt_task_attr_get_qos(const ffrt_task_attr_t *attr)
{
    return {};
}

inline FFRT_C_API void ffrt_task_attr_set_delay(ffrt_task_attr_t *attr, uint64_t delay_us)
{}

inline FFRT_C_API uint64_t ffrt_task_attr_get_delay(const ffrt_task_attr_t *attr)
{
    return 0;
}

inline FFRT_C_API void ffrt_task_attr_set_queue_priority(ffrt_task_attr_t *attr, ffrt_queue_priority_t priority)
{}

inline FFRT_C_API ffrt_queue_priority_t ffrt_task_attr_get_queue_priority(const ffrt_task_attr_t *attr)
{
    return {};
}

inline FFRT_C_API void ffrt_task_attr_set_stack_size(ffrt_task_attr_t *attr, uint64_t size)
{}

inline FFRT_C_API uint64_t ffrt_task_attr_get_stack_size(const ffrt_task_attr_t *attr)
{
    return 0;
}

inline FFRT_C_API void ffrt_task_attr_set_timeout(ffrt_task_attr_t *attr, uint64_t timeout_us)
{}

inline FFRT_C_API uint64_t ffrt_task_attr_get_timeout(const ffrt_task_attr_t *attr)
{
    return 0;
}

inline FFRT_C_API int ffrt_this_task_update_qos(ffrt_qos_t qos)
{
    return 0;
}

inline FFRT_C_API ffrt_qos_t ffrt_this_task_get_qos(void)
{
    return {};
}

inline FFRT_C_API uint64_t ffrt_this_task_get_id(void)
{
    return 0;
}

inline FFRT_C_API void ffrt_submit_base(
    ffrt_function_header_t *f, const ffrt_deps_t *in_deps, const ffrt_deps_t *out_deps, const ffrt_task_attr_t *attr)
{}

inline FFRT_C_API ffrt_task_handle_t ffrt_submit_h_base(
    ffrt_function_header_t *f, const ffrt_deps_t *in_deps, const ffrt_deps_t *out_deps, const ffrt_task_attr_t *attr)
{
    return {};
}

inline FFRT_C_API void ffrt_submit_f(ffrt_function_t func, void *arg, const ffrt_deps_t *in_deps,
    const ffrt_deps_t *out_deps, const ffrt_task_attr_t *attr)
{}

inline FFRT_C_API ffrt_task_handle_t ffrt_submit_h_f(ffrt_function_t func, void *arg, const ffrt_deps_t *in_deps,
    const ffrt_deps_t *out_deps, const ffrt_task_attr_t *attr)
{
    return {};
}

inline FFRT_C_API uint32_t ffrt_task_handle_inc_ref(ffrt_task_handle_t handle)
{
    return 0;
}

inline FFRT_C_API uint32_t ffrt_task_handle_dec_ref(ffrt_task_handle_t handle)
{
    return 0;
}

inline FFRT_C_API void ffrt_task_handle_destroy(ffrt_task_handle_t handle)
{}

inline FFRT_C_API void ffrt_wait_deps(const ffrt_deps_t *deps)
{}

inline FFRT_C_API void ffrt_wait(void)
{}

inline FFRT_C_API ffrt_error_t ffrt_set_worker_stack_size(ffrt_qos_t qos, size_t stack_size)
{
    return {};
}

inline FFRT_C_API uint64_t ffrt_task_handle_get_id(ffrt_task_handle_t handle)
{
    return {};
}

#endif