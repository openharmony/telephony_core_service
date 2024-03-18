/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#ifndef OHOS_TELEPHONY_LOG_WRAPPER_H
#define OHOS_TELEPHONY_LOG_WRAPPER_H

#include <string>

#include "hilog/log.h"

namespace OHOS {
namespace Telephony {
#define CONFIG_HILOG
#ifdef CONFIG_HILOG

#ifndef TELEPHONY_LOG_TAG
#define TELEPHONY_LOG_TAG "TelephonySubsystem"
#endif

#ifndef TELEPHONY_LOG_FUNC_NAME
#define TELEPHONY_LOG_FUNC_NAME __func__
#endif

#define OHOS_DEBUG
#ifndef OHOS_DEBUG
#define TELEPHONY_LOGE(fmt, ...) \
    (void)HILOG_IMPL(LOG_CORE, LOG_ERROR, LOG_DOMAIN, TELEPHONY_LOG_TAG, fmt, ##__VA_ARGS__)
#define TELEPHONY_LOGW(fmt, ...) \
    (void)HILOG_IMPL(LOG_CORE, LOG_WARN, LOG_DOMAIN, TELEPHONY_LOG_TAG, fmt, ##__VA_ARGS__)
#define TELEPHONY_LOGI(fmt, ...) \
    (void)HILOG_IMPL(LOG_CORE, LOG_INFO, LOG_DOMAIN, TELEPHONY_LOG_TAG, fmt, ##__VA_ARGS__)
#define TELEPHONY_LOGF(fmt, ...) \
    (void)HILOG_IMPL(LOG_CORE, LOG_FATAL, LOG_DOMAIN, TELEPHONY_LOG_TAG, fmt, ##__VA_ARGS__)
#define TELEPHONY_LOGD(fmt, ...) \
    (void)HILOG_IMPL(LOG_CORE, LOG_DEBUG, LOG_DOMAIN, TELEPHONY_LOG_TAG, fmt, ##__VA_ARGS__)
#else
// Gets the raw file name of the file.
// This function is a function executed by the compiler, that is,
// it has been executed at compile time. When the program runs,
// it directly refers to the value calculated by this function
// and does not consume CPU for calculation.
inline constexpr const char *GetRawFileName(const char *path)
{
    char ch = '/';
    const char *start = path;
    // get the end of the string
    while (*start++) {
        ;
    }
    while (--start != path && *start != ch) {
        ;
    }

    return (*start == ch) ? ++start : path;
}

#define TELEPHONY_LOGE(fmt, ...)                                                                                      \
    (void)HILOG_IMPL(LOG_CORE, LOG_ERROR, LOG_DOMAIN, TELEPHONY_LOG_TAG, "[%{public}s-(%{public}s:%{public}d)] " fmt, \
    __FUNCTION__, GetRawFileName(__FILE__), __LINE__, ##__VA_ARGS__)
#define TELEPHONY_LOGW(fmt, ...)                                                                                     \
    (void)HILOG_IMPL(LOG_CORE, LOG_WARN, LOG_DOMAIN, TELEPHONY_LOG_TAG, "[%{public}s-(%{public}s:%{public}d)] " fmt, \
    __FUNCTION__, GetRawFileName(__FILE__), __LINE__, ##__VA_ARGS__)
#define TELEPHONY_LOGI(fmt, ...)                                                                                     \
    (void)HILOG_IMPL(LOG_CORE, LOG_INFO, LOG_DOMAIN, TELEPHONY_LOG_TAG, "[%{public}s-(%{public}s:%{public}d)] " fmt, \
    __FUNCTION__, GetRawFileName(__FILE__), __LINE__, ##__VA_ARGS__)
#define TELEPHONY_LOGF(fmt, ...)                                                                                      \
    (void)HILOG_IMPL(LOG_CORE, LOG_FATAL, LOG_DOMAIN, TELEPHONY_LOG_TAG, "[%{public}s-(%{public}s:%{public}d)] " fmt, \
    __FUNCTION__, GetRawFileName(__FILE__), __LINE__, ##__VA_ARGS__)
#define TELEPHONY_LOGD(fmt, ...)                                                                                      \
    (void)HILOG_IMPL(LOG_CORE, LOG_DEBUG, LOG_DOMAIN, TELEPHONY_LOG_TAG, "[%{public}s-(%{public}s:%{public}d)] " fmt, \
    __FUNCTION__, GetRawFileName(__FILE__), __LINE__, ##__VA_ARGS__)
#endif
#endif // CONFIG_HILOG
} // namespace Telephony
} // namespace OHOS
#endif // OHOS_TELEPHONY_LOG_WRAPPER_H
