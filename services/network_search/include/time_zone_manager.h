/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

#ifndef NETWORK_SEARCH_INCLUDE_TIME_ZONE_MANAGER_H
#define NETWORK_SEARCH_INCLUDE_TIME_ZONE_MANAGER_H

#include "time_zone_updater.h"

namespace OHOS {
namespace Telephony {

class TimeZoneManager {
public:
    ~TimeZoneManager() = default;
    DISALLOW_COPY_AND_MOVE(TimeZoneManager);
    static TimeZoneManager &GetInstance();
    void Init(std::weak_ptr<NetworkSearchManager> networkSearchManager);
    bool UpdateLocationTimeZone(std::string &timeZone);
    void UpdateCountryCode(std::string &countryCode, int32_t slotId);
    void UpdateTimeZoneOffset(int32_t offset, int32_t slotId);
    void SendUpdateLocationRequest();
    void SendUpdateLocationCountryCodeRequest();

    bool IsRoaming();
    bool HasSimCard();
    int32_t GetCurrentLac();

private:
    TimeZoneManager();

private:
    std::weak_ptr<NetworkSearchManager> networkSearchManager_;
    std::shared_ptr<TimeZoneUpdater> timeZoneUpdater_ = nullptr;
    int32_t slotId_ = 0;
};
} // namespace Telephony
} // namespace OHOS
#endif // NETWORK_SEARCH_INCLUDE_TIME_ZONE_MANAGER_H