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
#ifndef MOCK_FFRT_INNER_API_C_QUEUE_EXT_H
#define MOCK_FFRT_INNER_API_C_QUEUE_EXT_H

#include <stdbool.h>
#include "c/queue.h"

typedef enum {

    ffrt_queue_eventhandler_interactive = 3,
    ffrt_queue_eventhandler_adapter = 4,
    ffrt_queue_inner_max,
} ffrt_inner_queue_type_t;

typedef enum {

    ffrt_inner_queue_priority_vip = 0,

    ffrt_inner_queue_priority_immediate,

    ffrt_inner_queue_priority_high,

    ffrt_inner_queue_priority_low,

    ffrt_inner_queue_priority_idle,
} ffrt_inner_queue_priority_t;

inline FFRT_C_API bool ffrt_queue_has_task(ffrt_queue_t queue, const char *name)
{
    return true;
}

inline FFRT_C_API void ffrt_queue_cancel_all(ffrt_queue_t queue)
{}

inline FFRT_C_API void ffrt_queue_cancel_and_wait(ffrt_queue_t queue)
{}

inline FFRT_C_API int ffrt_queue_cancel_by_name(ffrt_queue_t queue, const char *name)
{
    return 0;
}

inline FFRT_C_API bool ffrt_queue_is_idle(ffrt_queue_t queue)
{
    return true;
}

inline FFRT_C_API int ffrt_queue_dump(ffrt_queue_t queue, const char *tag, char *buf, uint32_t len, bool history_info)
{
    return 0;
}

inline FFRT_C_API int ffrt_queue_size_dump(ffrt_queue_t queue, ffrt_inner_queue_priority_t priority)
{
    return 0;
}

inline FFRT_C_API void ffrt_queue_set_eventhandler(ffrt_queue_t queue, void *eventhandler)
{}

inline FFRT_C_API void *ffrt_get_current_queue_eventhandler(void)
{
    return {};
}

inline FFRT_C_API int ffrt_concurrent_queue_wait_all(ffrt_queue_t queue)
{
    return 0;
}

#endif