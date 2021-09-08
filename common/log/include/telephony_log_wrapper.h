/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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
enum class TelephonyLogLevel {
    DEBUG = 0,
    INFO,
    WARN,
    ERROR,
    FATAL,
};

class TelephonyLogWrapper {
public:
    static bool JudgeLevel(const TelephonyLogLevel &level);

    static void SetLogLevel(const TelephonyLogLevel &level)
    {
        level_ = level;
    }

    static const TelephonyLogLevel &GetLogLevel()
    {
        return level_;
    }

    static std::string GetBriefFileName(const std::string &file);

private:
    static TelephonyLogLevel level_;
};

#define CONFIG_HILOG
#ifdef CONFIG_HILOG

#ifndef TELEPHONY_LOG_TAG
#define TELEPHONY_LOG_TAG "TelephonySubsystem"
#endif

static constexpr OHOS::HiviewDFX::HiLogLabel TELEPHONY_LABEL = {LOG_CORE, LOG_DOMAIN, TELEPHONY_LOG_TAG};

#define __TEL_FILENAME__ (__builtin_strrchr(__FILE__, '/') ? __builtin_strrchr(__FILE__, '/') + 1 : __FILE__)

#define OHOS_DEBUG
#ifndef OHOS_DEBUG
#define PRINT_LOG(op, fmt, ...) (void)OHOS::HiviewDFX::HiLog::op(TELEPHONY_LABEL, fmt, ##__VA_ARGS__)
#else
#define PRINT_LOG(op, fmt, ...)                                                                                  \
    (void)OHOS::HiviewDFX::HiLog::op(TELEPHONY_LABEL, "[%{public}s-(%{public}s:%{public}d)] " fmt, __FUNCTION__, \
        __TEL_FILENAME__, __LINE__, ##__VA_ARGS__)
#endif

#define TELEPHONY_LOGD(fmt, ...) PRINT_LOG(Debug, fmt, ##__VA_ARGS__)
#define TELEPHONY_LOGE(fmt, ...) PRINT_LOG(Error, fmt, ##__VA_ARGS__)
#define TELEPHONY_LOGW(fmt, ...) PRINT_LOG(Warn, fmt, ##__VA_ARGS__)
#define TELEPHONY_LOGI(fmt, ...) PRINT_LOG(Info, fmt, ##__VA_ARGS__)
#define TELEPHONY_LOGF(fmt, ...) PRINT_LOG(Fatal, fmt, ##__VA_ARGS__)

#else
#define TELEPHONY_LOGD(...)
#endif // CONFIG_HILOG
} // namespace Telephony
} // namespace OHOS
#endif // OHOS_TELEPHONY_LOG_WRAPPER_H