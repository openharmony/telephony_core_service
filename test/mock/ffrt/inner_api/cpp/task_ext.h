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
#ifndef MOCK_FFRT_INNER_API_CPP_TASK_H
#define MOCK_FFRT_INNER_API_CPP_TASK_H
#include <cstdint>
#include "c/task_ext.h"
#include "cpp/task.h"

namespace ffrt {

static inline int skip(task_handle &handle)
{
    return 0;
}

inline void sync_io(int fd)
{}

inline void set_trace_tag(const char *name)
{}

inline void clear_trace_tag()
{}

static inline int set_cgroup_attr(qos qos_, ffrt_os_sched_attr *attr)
{
    return 0;
}

static inline void restore_qos_config()
{}

static inline int set_cpu_worker_max_num(qos qos_, uint32_t num)
{
    return 0;
}

static inline void notify_workers(qos qos_, int number)
{}

static inline int64_t get_queue_id()
{
    return 0;
}

static inline int enable_worker_escape(uint64_t one_stage_interval_ms = 10, uint64_t two_stage_interval_ms = 100,
    uint64_t three_stage_interval_ms = 1000, uint64_t one_stage_worker_num = 128, uint64_t two_stage_worker_num = 256)
{
    return 0;
}

static inline void disable_worker_escape()
{}

}  // namespace ffrt
#endif