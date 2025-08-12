// Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
#ifndef MOCK_FFRT_API_FFRT_INNER_H
#define MOCK_FFRT_API_FFRT_INNER_H
#include "ffrt.h"
#ifdef __cplusplus
#include "c/ffrt_dump.h"
#include "c/queue_ext.h"
#include "cpp/thread.h"
#include "cpp/future.h"
#include "cpp/task_ext.h"
#include "cpp/deadline.h"
#include "cpp/qos_convert.h"
#else
#include "c/task_ext.h"
#include "c/queue_ext.h"
#include "c/thread.h"
#include "c/executor_task.h"
#include "c/ffrt_dump.h"
#include "c/deadline.h"
#include "c/ffrt_cpu_boost.h"
#include "c/ffrt_ipc.h"
#include "c/init.h"
#endif
#endif