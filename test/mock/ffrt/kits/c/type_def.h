// Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
#ifndef MOCK_FFRT_API_C_TYPE_DEF_H
#define MOCK_FFRT_API_C_TYPE_DEF_H

#include <stdint.h>
#include <errno.h>

#ifdef __cplusplus
#define FFRT_C_API
#else
#define FFRT_C_API
#endif

typedef enum {

    ffrt_queue_priority_immediate = 0,

    ffrt_queue_priority_high,

    ffrt_queue_priority_low,

    ffrt_queue_priority_idle,
} ffrt_queue_priority_t;

typedef enum {

    ffrt_qos_inherit = -1,

    ffrt_qos_background,

    ffrt_qos_utility,

    ffrt_qos_default,

    ffrt_qos_user_initiated,
} ffrt_qos_default_t;

typedef int ffrt_qos_t;

typedef void (*ffrt_function_t)(void *);

typedef struct {

    ffrt_function_t exec;

    ffrt_function_t destroy;

    uint64_t reserve[2];
} ffrt_function_header_t;

typedef enum {

    ffrt_task_attr_storage_size = 128,

    ffrt_auto_managed_function_storage_size = 64 + sizeof(ffrt_function_header_t),

    ffrt_mutex_storage_size = 64,

    ffrt_cond_storage_size = 64,

    ffrt_queue_attr_storage_size = 128,

    ffrt_rwlock_storage_size = 64,

#if defined(__aarch64__)
    ffrt_fiber_storage_size = 22,
#elif defined(__arm__)
    ffrt_fiber_storage_size = 64,
#elif defined(__x86_64__)
    ffrt_fiber_storage_size = 8,
#else
#error "unsupported architecture"
#endif
} ffrt_storage_size_t;

typedef enum {

    ffrt_function_kind_general,

    ffrt_function_kind_queue,
} ffrt_function_kind_t;

typedef enum {

    ffrt_dependence_data,

    ffrt_dependence_task,
} ffrt_dependence_type_t;

typedef struct {

    ffrt_dependence_type_t type;

    const void *ptr;
} ffrt_dependence_t;

typedef struct {

    uint32_t len;

    const ffrt_dependence_t *items;
} ffrt_deps_t;

typedef struct {

    uint32_t storage[(ffrt_task_attr_storage_size + sizeof(uint32_t) - 1) / sizeof(uint32_t)];
} ffrt_task_attr_t;

typedef struct {

    uint32_t storage[(ffrt_queue_attr_storage_size + sizeof(uint32_t) - 1) / sizeof(uint32_t)];
} ffrt_queue_attr_t;

typedef void *ffrt_task_handle_t;

typedef enum {

    ffrt_error = -1,

    ffrt_success = 0,

    ffrt_error_nomem = ENOMEM,

    ffrt_error_timedout = ETIMEDOUT,

    ffrt_error_busy = EBUSY,

    ffrt_error_inval = EINVAL
} ffrt_error_t;

typedef struct {

    long storage;
} ffrt_condattr_t;

typedef struct {

    long storage;
} ffrt_mutexattr_t;

typedef struct {

    long storage;
} ffrt_rwlockattr_t;

typedef enum {

    ffrt_mutex_normal = 0,

    ffrt_mutex_recursive = 2,

    ffrt_mutex_default = ffrt_mutex_normal
} ffrt_mutex_type;

typedef struct {

    uint32_t storage[(ffrt_mutex_storage_size + sizeof(uint32_t) - 1) / sizeof(uint32_t)];
} ffrt_mutex_t;

typedef struct {

    uint32_t storage[(ffrt_rwlock_storage_size + sizeof(uint32_t) - 1) / sizeof(uint32_t)];
} ffrt_rwlock_t;

typedef struct {

    uint32_t storage[(ffrt_cond_storage_size + sizeof(uint32_t) - 1) / sizeof(uint32_t)];
} ffrt_cond_t;

typedef struct {

    uintptr_t storage[ffrt_fiber_storage_size];
} ffrt_fiber_t;

typedef void (*ffrt_poller_cb)(void *data, uint32_t event);

typedef void (*ffrt_timer_cb)(void *data);

typedef int ffrt_timer_t;

#ifdef __cplusplus
namespace ffrt {

enum qos_default {

    qos_inherit = ffrt_qos_inherit,

    qos_background = ffrt_qos_background,

    qos_utility = ffrt_qos_utility,

    qos_default = ffrt_qos_default,

    qos_user_initiated = ffrt_qos_user_initiated,
};

using qos = int;

}  // namespace ffrt

#endif
#endif