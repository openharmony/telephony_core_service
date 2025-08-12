// Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
#ifndef MOCK_FFRT_INNER_API_C_TYPE_DEF_H
#define MOCK_FFRT_INNER_API_C_TYPE_DEF_H
#include <stdint.h>
#include "c/type_def.h"

#ifdef __cplusplus
#define FFRT_C_API
#else
#define FFRT_C_API
#endif

typedef enum {
    ffrt_qos_deadline_request = 4,
    ffrt_qos_user_interactive,
    ffrt_qos_max = ffrt_qos_user_interactive,
} ffrt_inner_qos_default_t;

typedef enum { ffrt_stack_protect_weak, ffrt_stack_protect_strong } ffrt_stack_protect_t;

typedef enum {
    ffrt_thread_attr_storage_size = 64,
} ffrt_inner_storage_size_t;

typedef struct {
    uint32_t storage[(ffrt_thread_attr_storage_size + sizeof(uint32_t) - 1) / sizeof(uint32_t)];
} ffrt_thread_attr_t;

#define MAX_CPUMAP_LENGTH 100
typedef struct {
    int shares;
    int latency_nice;
    int uclamp_min;
    int uclamp_max;
    int vip_prio;
    char cpumap[MAX_CPUMAP_LENGTH];
} ffrt_os_sched_attr;

typedef void *ffrt_thread_t;

typedef void *ffrt_interval_t;

typedef enum {
    ffrt_sys_event_type_read,
} ffrt_sys_event_type_t;

typedef enum { ffrt_sys_event_status_no_timeout, ffrt_sys_event_status_timeout } ffrt_sys_event_status_t;

typedef void *ffrt_sys_event_handle_t;

typedef void *ffrt_config_t;

typedef enum {
    ffrt_coroutine_stackless,
    ffrt_coroutine_with_stack,
} ffrt_coroutine_t;

typedef enum {
    ffrt_coroutine_pending = 0,
    ffrt_coroutine_ready = 1,
} ffrt_coroutine_ret_t;

typedef ffrt_coroutine_ret_t (*ffrt_coroutine_ptr_t)(void *);

typedef struct {
    int fd;
    void *data;
    void (*cb)(void *, uint32_t);
} ffrt_poller_t;

typedef enum {
    ffrt_timer_notfound = -1,
    ffrt_timer_not_executed = 0,
    ffrt_timer_executed = 1,
} ffrt_timer_query_t;

typedef enum {
    ffrt_sched_default_mode = 0,
    ffrt_sched_performance_mode,
    ffrt_sched_energy_saving_mode,
} ffrt_sched_mode;

#ifdef __cplusplus
namespace ffrt {
enum qos_inner_default {
    qos_deadline_request = ffrt_qos_deadline_request,
    qos_user_interactive = ffrt_qos_user_interactive,
    qos_max = ffrt_qos_max,
};

enum class stack_protect {
    weak = ffrt_stack_protect_weak,
    strong = ffrt_stack_protect_strong,
};

enum class sched_mode_type : uint8_t {
    sched_default_mode = ffrt_sched_default_mode,
    sched_performance_mode = ffrt_sched_performance_mode,
    sched_energy_saving_mode = ffrt_sched_energy_saving_mode,
};
}  // namespace ffrt
#endif
#endif