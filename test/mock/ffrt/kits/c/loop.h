// Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
#ifndef MOCK_FFRT_API_C_LOOP_H
#define MOCK_FFRT_API_C_LOOP_H

#include <stdbool.h>
#include "type_def.h"
#include "queue.h"

typedef void *ffrt_loop_t;
inline FFRT_C_API ffrt_loop_t ffrt_loop_create(ffrt_queue_t queue)
{
    return {};
}

inline FFRT_C_API int ffrt_loop_destroy(ffrt_loop_t loop)
{
    return 0;
}

inline FFRT_C_API int ffrt_loop_run(ffrt_loop_t loop)
{
    return 0;
}

inline FFRT_C_API void ffrt_loop_stop(ffrt_loop_t loop)
{}

inline FFRT_C_API int ffrt_loop_epoll_ctl(
    ffrt_loop_t loop, int op, int fd, uint32_t events, void *data, ffrt_poller_cb cb)
{
    return 0;
}

inline FFRT_C_API ffrt_timer_t ffrt_loop_timer_start(
    ffrt_loop_t loop, uint64_t timeout, void *data, ffrt_timer_cb cb, bool repeat)
{
    return {};
}

inline FFRT_C_API int ffrt_loop_timer_stop(ffrt_loop_t loop, ffrt_timer_t handle)
{
    return 0;
}

#endif