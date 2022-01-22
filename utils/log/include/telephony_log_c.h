/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#ifndef TELEPHONY_LOG_C_H
#define TELEPHONY_LOG_C_H

#include <stddef.h>

#include "hilog/log.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifndef LOG_DOMAIN
#define LOG_DOMAIN 0xD002B01
#endif
#ifndef LOG_TAG
#define LOG_TAG "TelephonySubsystem"
#endif

#define OHOS_DEBUG
#ifndef OHOS_DEBUG
#define DECORATOR_HILOG(op, fmt, args...) \
    do {                                  \
        op(LOG_CORE, fmt, ##args);        \
    } while (0)
#else
// Gets the raw file name of the file.
// Its advantage is that it is executed only once __builtin_strrchr() function
inline const char *GetRawFileName(const char *path)
{
    const char *last = __builtin_strrchr(path, '/');
    return (last != NULL) ? (last + 1) : path;
}

#define DECORATOR_HILOG(op, fmt, args...)                                                                           \
    do {                                                                                                            \
        op(LOG_CORE, "[%{public}s-(%{public}s:%{public}d)] " fmt, __FUNCTION__, GetRawFileName(__FILE__), __LINE__, \
            ##args);                                                                                                \
    } while (0)
#endif

#define TELEPHONY_LOGE(fmt, args...) DECORATOR_HILOG(HILOG_ERROR, fmt, ##args)
#define TELEPHONY_LOGW(fmt, args...) DECORATOR_HILOG(HILOG_WARN, fmt, ##args)
#define TELEPHONY_LOGI(fmt, args...) DECORATOR_HILOG(HILOG_INFO, fmt, ##args)
#define TELEPHONY_LOGF(fmt, args...) DECORATOR_HILOG(HILOG_FATAL, fmt, ##args)

#ifdef __cplusplus
}
#endif

#endif // TELEPHONY_LOG_C_H
