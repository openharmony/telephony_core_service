// Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
#ifndef MOCK_FFRT_API_FFRT_H
#define MOCK_FFRT_API_FFRT_H
#ifdef __cplusplus
#include "cpp/task.h"
#include "cpp/mutex.h"
#include "cpp/shared_mutex.h"
#include "cpp/condition_variable.h"
#include "cpp/sleep.h"
#include "cpp/queue.h"
#include "c/timer.h"
#include "c/loop.h"
#include "c/fiber.h"
#else
#include "c/task.h"
#include "c/mutex.h"
#include "c/shared_mutex.h"
#include "c/condition_variable.h"
#include "c/sleep.h"
#include "c/queue.h"
#include "c/timer.h"
#include "c/loop.h"
#include "c/fiber.h"
#endif
#endif