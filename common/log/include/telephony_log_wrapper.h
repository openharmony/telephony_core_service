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

#include "hilog/log.h"
#include <string>

namespace OHOS {
enum class TelephonyLogLevel {
    DEBUG = 0,
    INFO,
    WARN,
    ERROR,
    FATAL,
};

static constexpr OHOS::HiviewDFX::HiLogLabel TELEPHONY_LABEL = {LOG_CORE, LOG_DOMAIN, TELEPHONY_LOG_TAG};

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

#define PRINT_LOG(LEVEL, Level, fmt, ...)                                           \
    if (TelephonyLogWrapper::JudgeLevel(TelephonyLogLevel::LEVEL))                  \
    OHOS::HiviewDFX::HiLog::Level(TELEPHONY_LABEL, "[%{public}s(%{public}s)] " fmt, \
        TelephonyLogWrapper::GetBriefFileName(std::string(__FILE__)).c_str(), __FUNCTION__, ##__VA_ARGS__)

#define TELEPHONY_LOGD(fmt, ...) PRINT_LOG(DEBUG, Debug, fmt, ##__VA_ARGS__)
#define TELEPHONY_LOGI(fmt, ...) PRINT_LOG(INFO, Info, fmt, ##__VA_ARGS__)
#define TELEPHONY_LOGW(fmt, ...) PRINT_LOG(WARN, Warn, fmt, ##__VA_ARGS__)
#define TELEPHONY_LOGE(fmt, ...) PRINT_LOG(ERROR, Error, fmt, ##__VA_ARGS__)
#define TELEPHONY_LOGF(fmt, ...) PRINT_LOG(FATAL, Fatal, fmt, ##__VA_ARGS__)
} // namespace OHOS
#endif // OHOS_TELEPHONY_LOG_WRAPPER_H