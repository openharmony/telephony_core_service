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

#ifndef NETWORK_SEARCH_INCLUDE_NITZ_UPDATE_H
#define NETWORK_SEARCH_INCLUDE_NITZ_UPDATE_H

#include <memory>
#include "want.h"
#include "event_handler.h"

namespace OHOS {
namespace Telephony {
class NetworkSearchManager;
class NitzUpdate {
public:
    explicit NitzUpdate(std::weak_ptr<NetworkSearchManager> networkSearchManager);
    virtual ~NitzUpdate() = default;
    void ProcessNitzUpdate(const AppExecFwk::InnerEvent::Pointer &event);
    struct NetworkTime {
        int32_t year;
        int32_t month;
        int32_t day;
        int32_t hour;
        int32_t minute;
        int32_t second;
        int32_t offset;
    };

private:
    void ProcessTime(NetworkTime &networkTime);
    void ProcessTimeZone(NetworkTime &networkTime);
    void SaveTimeZone(std::string &timeZone);
    void SaveTime(std::string &time);
    bool IsAutoTimeZone();
    bool IsAutoTime();
    bool NitzParse(std::string &nitzStr, NetworkTime &networkTime);
    bool NitzTimeParse(std::string &strTimeSubs, NetworkTime &networkTime);
    void PublishCommonEvent(AAFwk::Want& want);
private:
    static const int32_t MAX_UPDATE_TIME = 5;
    std::weak_ptr<NetworkSearchManager> networkSearchManager_;
    const std::string KEY_AUTO_TIME_ZONE = "auto_timezone";
    const std::string KEY_AUTO_TIME = "auto_time";
    const std::string KEY_SYSTEM_TIMEZONE = "system_timezone";
    const std::string KEY_SYSTEM_TIME = "system_time";
    const uint32_t TIME_SPLIT_NUM = 3;
    const uint32_t TIMEZONE_SPLIT_NUM = 2;
    const uint32_t CST_YEAR = 1900;
    const uint32_t ONE_HOUR_TO_MINUTE = 60;
    const uint32_t ONE_HOUR_TO_SECOND = 3600;
    const uint32_t ONE_SECOND_TO_MILLISECOND = 1000;
    const uint32_t ONE_QUARTER_TO_MINUTE = 15;
    const uint32_t LOCATION_DAY_OR_SEC = 2;
    const int64_t lastUpdateTime_ = 0;
};
} // namespace Telephony
} // namespace OHOS
#endif // NETWORK_SEARCH_INCLUDE_NITZ_UPDATE_H