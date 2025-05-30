/*
 * Copyright (C) 2021-2024 Huawei Device Co., Ltd.
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

#include "event_handler.h"
#include "want.h"
#include "zone_util.h"

namespace OHOS {
namespace Telephony {
class NetworkSearchManager;
class NitzUpdate {
public:
    NitzUpdate(const std::weak_ptr<NetworkSearchManager> &networkSearchManager, int32_t slotId);
    virtual ~NitzUpdate() = default;
    void ProcessNitzUpdate(const AppExecFwk::InnerEvent::Pointer &event);
    void ProcessTimeZone();
    void AutoTimeChange();
    void AutoTimeZoneChange();
    void UpdateCountryCode(std::string &countryCode);
    struct NetworkTime {
        int32_t year = 0;
        int32_t month = 0;
        int32_t day = 0;
        int32_t hour = 0;
        int32_t minute = 0;
        int32_t second = 0;
        int32_t offset = 0;
        int32_t dst = 0;
    };

private:
    void ProcessTime(NetworkTime &networkTime);
    void SaveTimeZone(std::string &timeZone);
    void SaveTime(int64_t networkTime, int64_t offset);
    bool IsAutoTimeZone();
    bool IsAutoTime();
    bool NitzParse(std::string &nitzStr, NetworkTime &networkTime);
    bool NitzTimeParse(std::string &strTimeSubs, NetworkTime &networkTime);
    void PublishCommonEvent(AAFwk::Want &want);

private:
    std::weak_ptr<NetworkSearchManager> networkSearchManager_;
    static int64_t lastSystemTime_;
    int32_t slotId_ = 0;
    static int32_t offset_;
    static int64_t lastNetworkTime_;
    static int64_t lastOffsetTime_;
    static std::string timeZone_;
    int64_t nitzRecvTime_ = 0;
    Global::I18n::NITZData nitzData_ = {0};
};
} // namespace Telephony
} // namespace OHOS
#endif // NETWORK_SEARCH_INCLUDE_NITZ_UPDATE_H
