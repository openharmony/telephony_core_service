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
    NitzUpdate(std::weak_ptr<NetworkSearchManager> networkSearchManager, int32_t slotId);
    virtual ~NitzUpdate() = default;
    void ProcessNitzUpdate(const AppExecFwk::InnerEvent::Pointer &event);
    void ProcessTimeZone();
    void AutoTimeChange();
    void AutoTimeZoneChange();
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
    bool IsValidTime(int64_t networkTime);
    void SaveTimeZone(std::string &timeZone);
    void SaveTime(int64_t networkTime);
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
    static std::string timeZone_;
};
} // namespace Telephony
} // namespace OHOS
#endif // NETWORK_SEARCH_INCLUDE_NITZ_UPDATE_H