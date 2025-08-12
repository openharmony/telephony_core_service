// Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
#ifndef MOCK_FFRT_INNER_API_C_TASK_H
#define MOCK_FFRT_INNER_API_C_TASK_H
#include <stdint.h>
#include <stdbool.h>
#include "type_def_ext.h"
inline FFRT_C_API int ffrt_skip(ffrt_task_handle_t handle)
{
    return 0;
}

inline FFRT_C_API int ffrt_set_cgroup_attr(ffrt_qos_t qos, ffrt_os_sched_attr *attr)
{
    return 0;
}

inline FFRT_C_API void ffrt_restore_qos_config(void)
{}

inline FFRT_C_API int ffrt_set_cpu_worker_max_num(ffrt_qos_t qos, uint32_t num)
{
    return 0;
}

inline FFRT_C_API void ffrt_task_attr_set_notify_worker(ffrt_task_attr_t *attr, bool notify)
{}

inline FFRT_C_API void ffrt_notify_workers(ffrt_qos_t qos, int number)
{}

inline FFRT_C_API int64_t ffrt_this_queue_get_id(void)
{
    return 0;
}

inline FFRT_C_API int ffrt_enable_worker_escape(uint64_t one_stage_interval_ms, uint64_t two_stage_interval_ms,
    uint64_t three_stage_interval_ms, uint64_t one_stage_worker_num, uint64_t two_stage_worker_num)
{
    return 0;
}

inline FFRT_C_API void ffrt_disable_worker_escape(void)
{}

inline FFRT_C_API void ffrt_set_sched_mode(ffrt_qos_t qos, ffrt_sched_mode mode)
{}

#endif