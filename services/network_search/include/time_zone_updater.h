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

#ifndef NETWORK_SEARCH_INCLUDE_TIME_ZONE_UPDATER_H
#define NETWORK_SEARCH_INCLUDE_TIME_ZONE_UPDATER_H

#include "common_event_subscriber.h"
#include "data_ability_observer_stub.h"
#include "event_handler.h"
#include "network_search_manager.h"
#include "system_ability_status_change_stub.h"
#include "time_zone_location_suggester.h"
#include "time_zone_location_update.h"

namespace OHOS {
namespace Telephony {
class TimeZoneUpdater : public AppExecFwk::EventHandler {
public:
    explicit TimeZoneUpdater(const std::shared_ptr<AppExecFwk::EventRunner> &runner);
    virtual ~TimeZoneUpdater();
    void ProcessEvent(const AppExecFwk::InnerEvent::Pointer &event) override;
    void Init();
    void UnInit();
    void UpdateCountryCode(std::string &countryCode, int32_t slotId);
    void UpdateTimeZoneOffset(int32_t offset, int32_t slotId);
    bool UpdateLocationTimeZone(std::string &timeZone);
    void SendUpdateLocationRequest();
    void SendUpdateLocationCountryCodeRequest();

private:
    void RegisterSetting();
    void UnRegisterSetting();
    void QuerySetting(Uri &uri, std::string &key, std::string &value);
    void StartEventSubscriber();
    void StopEventSubscriber();
    void RequestLocationUpdate();
    bool IsAutoTimeZone();
    bool IsAirplaneMode();
    bool IsScreenOn();
    bool IsLocationTimeZoneEnabled();
    std::string StringToLower(const std::string &str);
    bool IsMultiTimeZoneCountry(std::string &countryCode);
    void UpdateTelephonyTimeZone();
    void UpdateTelephonyTimeZone(std::string &countryCode);
    bool UpdateTelephonyTimeZone(int32_t offset);
    bool NeedUpdateLocationTimeZone(std::string &timeZone);
    bool IsTimeZoneMatchCountryCode(std::string &timeZone);
    bool SaveTimeZone(std::string &timeZone);
    void HandleAutoTimeZoneChange(const AppExecFwk::InnerEvent::Pointer &);
    void HandleAirplaneModeChange(const AppExecFwk::InnerEvent::Pointer &);
    void HandleLocationTimeOut(const AppExecFwk::InnerEvent::Pointer &);
    void HandleScreenOnEvent(const AppExecFwk::InnerEvent::Pointer &);
    void HandleCountryCodeChange(const AppExecFwk::InnerEvent::Pointer &);
    void HandleNetworkConnected(const AppExecFwk::InnerEvent::Pointer &);
    void HandleRequestLocationUpdate(const AppExecFwk::InnerEvent::Pointer &);
    void HandleRequestLocationCountryCode(const AppExecFwk::InnerEvent::Pointer &);

private:
    class AutoTimezoneObserver : public AAFwk::DataAbilityObserverStub {
    public:
        explicit AutoTimezoneObserver(std::shared_ptr<EventHandler> eventHandler);
        ~AutoTimezoneObserver() = default;
        void OnChange() override;

    private:
        std::shared_ptr<EventHandler> eventHandler_ = nullptr;
    };

    class AirplaneModeObserver : public AAFwk::DataAbilityObserverStub {
    public:
        explicit AirplaneModeObserver(std::shared_ptr<EventHandler> eventHandler);
        ~AirplaneModeObserver() = default;
        void OnChange() override;

    private:
        std::shared_ptr<EventHandler> eventHandler_ = nullptr;
    };

    class DeviceStateEventSubscriber : public EventFwk::CommonEventSubscriber {
    public:
        DeviceStateEventSubscriber(
            const EventFwk::CommonEventSubscribeInfo &info, std::shared_ptr<EventHandler> eventHandler);
        ~DeviceStateEventSubscriber() = default;
        void OnReceiveEvent(const EventFwk::CommonEventData &data) override;

    private:
        std::shared_ptr<EventHandler> eventHandler_ = nullptr;
    };

    class SystemAbilityStatusChangeListener : public OHOS::SystemAbilityStatusChangeStub {
    public:
        explicit SystemAbilityStatusChangeListener(std::shared_ptr<DeviceStateEventSubscriber> &eventSubscriber);
        ~SystemAbilityStatusChangeListener() = default;
        virtual void OnAddSystemAbility(int32_t systemAbilityId, const std::string &deviceId) override;
        virtual void OnRemoveSystemAbility(int32_t systemAbilityId, const std::string &deviceId) override;

    private:
        std::shared_ptr<DeviceStateEventSubscriber> eventSubscriber_ = nullptr;
    };

private:
    using TzHandlerFunc = void (TimeZoneUpdater::*)(const AppExecFwk::InnerEvent::Pointer &);
    std::map<uint32_t, TzHandlerFunc> memberFuncMap_;

    std::shared_ptr<TimeZoneLocationSuggester> locationSuggester_ = nullptr;
    std::shared_ptr<TimeZoneLocationUpdate> locationUpdate_ = nullptr;

    sptr<AutoTimezoneObserver> settingAutoTimezoneObserver_ = nullptr;
    sptr<AirplaneModeObserver> airplaneModeObserver_ = nullptr;
    std::shared_ptr<DeviceStateEventSubscriber> eventSubscriber_ = nullptr;
    sptr<ISystemAbilityStatusChange> statusChangeListener_ = nullptr;

    bool hasEventSubscriber_ = false;
    bool autoTimeZone_ = false;
    bool multiTimeZone_ = false;
    std::string countryCode_ = "";
    int32_t offset_ = 0;
    int32_t slotId_ = 0;
};
} // namespace Telephony
} // namespace OHOS
#endif // NETWORK_SEARCH_INCLUDE_TIME_ZONE_UPDATER_H