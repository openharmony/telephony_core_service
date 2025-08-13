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
#ifndef MOCK_FFRT_API_C_FFRT_DUMP_H
#define MOCK_FFRT_API_C_FFRT_DUMP_H
#include <stdint.h>
#include "type_def_ext.h"

#define MAX_TASK_NAME_LENGTH (64)
#define TASK_STAT_LENGTH (88)

typedef enum { DUMP_INFO_ALL = 0, DUMP_TASK_STATISTIC_INFO, DUMP_START_STAT, DUMP_STOP_STAT } ffrt_dump_cmd_t;

typedef struct ffrt_stat {
    char taskName[MAX_TASK_NAME_LENGTH];
    uint64_t funcPtr;
    uint64_t startTime;
    uint64_t endTime;
} ffrt_stat;

typedef void (*ffrt_task_timeout_cb)(uint64_t gid, const char *msg, uint32_t size);

inline FFRT_C_API int ffrt_dump(ffrt_dump_cmd_t cmd, char *buf, uint32_t len)
{
    return 0;
}

inline FFRT_C_API ffrt_task_timeout_cb ffrt_task_timeout_get_cb(void)
{
    return {};
}

inline FFRT_C_API void ffrt_task_timeout_set_cb(ffrt_task_timeout_cb cb)
{}

inline FFRT_C_API uint32_t ffrt_task_timeout_get_threshold(void)
{
    return 0;
}

inline FFRT_C_API void ffrt_task_timeout_set_threshold(uint32_t threshold_ms)
{}
#endif