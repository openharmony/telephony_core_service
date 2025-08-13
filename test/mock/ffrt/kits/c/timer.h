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
#ifndef MOCK_FFRT_API_C_TIMER_H
#define MOCK_FFRT_API_C_TIMER_H

#include <stdbool.h>
#include "type_def.h"

inline FFRT_C_API ffrt_timer_t ffrt_timer_start(
    ffrt_qos_t qos, uint64_t timeout, void *data, ffrt_timer_cb cb, bool repeat)
{
    return {};
}

inline FFRT_C_API int ffrt_timer_stop(ffrt_qos_t qos, ffrt_timer_t handle)
{
    return 0;
}

#endif