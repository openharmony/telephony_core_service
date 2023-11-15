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

#ifndef NETWORK_SEARCH_INCLUDE_TIME_ZONE_LOCATION_UPDATE_H
#define NETWORK_SEARCH_INCLUDE_TIME_ZONE_LOCATION_UPDATE_H

#ifdef ABILITY_LOCATION_SUPPORT
#include "i_locator_callback.h"
#include "iremote_stub.h"
#include "locator.h"
#endif
#include "time_zone_location_suggester.h"

namespace OHOS {
namespace Telephony {
class TimeZoneLocationUpdate : public std::enable_shared_from_this<TimeZoneLocationUpdate> {
public:
    explicit TimeZoneLocationUpdate(std::shared_ptr<TimeZoneLocationSuggester> locationSuggester);
    ~TimeZoneLocationUpdate();
    bool IsLocationEnabled();
    void StartPassiveUpdate();
    void StopPassiveUpdate();
    void RequestUpdate();
    void CancelUpdate();
    std::string GetIsoCountryCode();
#ifdef ABILITY_LOCATION_SUPPORT
    void LocationSwitchChange();
    void LocationReport(const std::unique_ptr<Location::Location> &location);

private:
    void RegisterLocationChange();
    void UnregisterLocationChange();
    void RegisterSwitchCallback();
    void UnregisterSwitchCallback();

private:
    class LocationCallback : public IRemoteStub<Location::ILocatorCallback> {
    public:
        explicit LocationCallback(std::shared_ptr<TimeZoneLocationUpdate> locationUpdate);
        virtual int OnRemoteRequest(
            uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override;
        void OnLocationReport(const std::unique_ptr<Location::Location> &location) override;
        void OnLocatingStatusChange(const int status) override;
        void OnErrorReport(const int errorCode) override;

    private:
        std::shared_ptr<TimeZoneLocationUpdate> locationUpdate_ = nullptr;
    };

    class SwitchCallback : public IRemoteStub<Location::ISwitchCallback> {
    public:
        explicit SwitchCallback(std::shared_ptr<TimeZoneLocationUpdate> locationUpdate);
        virtual int OnRemoteRequest(
            uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override;
        void OnSwitchChange(const int state) override;

    private:
        std::shared_ptr<TimeZoneLocationUpdate> locationUpdate_ = nullptr;
    };

private:
    std::shared_ptr<TimeZoneLocationSuggester> locationSuggester_ = nullptr;
    std::shared_ptr<Location::LocatorImpl> locatorImpl_ = nullptr;
    sptr<SwitchCallback> switchCallback_ = nullptr;
    sptr<LocationCallback> locatorCallback_ = nullptr;
    sptr<LocationCallback> registerCallback_ = nullptr;
    bool locationEnabled_ = false;
    bool needUpdate_ = false;
#endif
};
} // namespace Telephony
} // namespace OHOS
#endif // NETWORK_SEARCH_INCLUDE_TIME_ZONE_LOCATION_UPDATE_H