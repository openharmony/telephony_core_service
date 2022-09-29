/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#ifndef NETWORK_SEARCH_DEVICE_STATE_OBSERVER_H
#define NETWORK_SEARCH_DEVICE_STATE_OBSERVER_H

#include "common_event_subscriber.h"
#include "common_event_support.h"
#include "common_event_manager.h"
#include "device_state_handler.h"
#include "sharing_event_callback_stub.h"
#include "net_all_capabilities.h"
#include "net_supplier_info.h"
#include "system_ability_status_change_stub.h"

namespace OHOS {
namespace Telephony {
using CommonEventData = OHOS::EventFwk::CommonEventData;
using CommonEventManager = OHOS::EventFwk::CommonEventManager;
using CommonEventSubscribeInfo = OHOS::EventFwk::CommonEventSubscribeInfo;
using CommonEventSubscriber = OHOS::EventFwk::CommonEventSubscriber;
using CommonEventSupport = OHOS::EventFwk::CommonEventSupport;
using MatchingSkills = OHOS::EventFwk::MatchingSkills;
using NetBearType = OHOS::NetManagerStandard::NetBearType;
using NetConnState = OHOS::NetManagerStandard::NetConnState;

enum DeviceStateEventIntValue {
    COMMON_EVENT_CONNECTIVITY_CHANGE,
    COMMON_EVENT_SCREEN_ON,
    COMMON_EVENT_SCREEN_OFF,
    COMMON_EVENT_POWER_SAVE_MODE_CHANGED,
    COMMON_EVENT_DEVICE_IDLE_MODE_CHANGED,
    COMMON_EVENT_CHARGING,
    COMMON_EVENT_DISCHARGING,
    COMMON_EVENT_UNKNOWN,
};

class DeviceStateEventSubscriber : public CommonEventSubscriber {
public:
    explicit DeviceStateEventSubscriber(const CommonEventSubscribeInfo &info) : CommonEventSubscriber(info) {}
    ~DeviceStateEventSubscriber() = default;
    void OnReceiveEvent(const CommonEventData &data) override;
    void SetEventHandler(const std::shared_ptr<DeviceStateHandler> &deviceStateHandler);
    std::shared_ptr<DeviceStateHandler> GetEventHandler();
    void InitEventMap();

private:
    DeviceStateEventIntValue GetDeviceStateEventIntValue(std::string &event) const;

private:
    std::shared_ptr<DeviceStateHandler> deviceStateHandler_;
    std::map<std::string, DeviceStateEventIntValue> deviceStateEventMapIntValues_;
};

class SharingEventCallback : public NetManagerStandard::SharingEventCallbackStub {
public:
    explicit SharingEventCallback(const std::shared_ptr<DeviceStateHandler> &deviceStateHandler);
    ~SharingEventCallback() = default;
    void OnSharingStateChanged(const bool &isRunning) override;
    void OnInterfaceSharingStateChanged(const NetManagerStandard::SharingIfaceType &type, const std::string &iface,
        const NetManagerStandard::SharingIfaceState &state) override {}
    void OnSharingUpstreamChanged(const sptr<NetManagerStandard::NetHandle> netHandle) override {}

    private:
        std::shared_ptr<DeviceStateHandler> handler_ = nullptr;
};

class DeviceStateObserver {
public:
    DeviceStateObserver() = default;
    ~DeviceStateObserver() = default;
    void StartEventSubscriber(const std::shared_ptr<DeviceStateHandler> &deviceStateHandler);
    void StopEventSubscriber();

private:
    std::shared_ptr<DeviceStateEventSubscriber> subscriber_;
    sptr<NetManagerStandard::ISharingEventCallback> sharingEventCallback_ = nullptr;
    sptr<ISystemAbilityStatusChange> statusChangeListener_ = nullptr;

private:
    class SystemAbilityStatusChangeListener : public SystemAbilityStatusChangeStub {
    public:
        SystemAbilityStatusChangeListener(std::shared_ptr<DeviceStateEventSubscriber> &subscriber,
            sptr<NetManagerStandard::ISharingEventCallback> &callback);
        ~SystemAbilityStatusChangeListener() = default;
        virtual void OnAddSystemAbility(int32_t systemAbilityId, const std::string& deviceId) override;
        virtual void OnRemoveSystemAbility(int32_t systemAbilityId, const std::string& deviceId) override;

    private:
        std::shared_ptr<DeviceStateEventSubscriber> sub_ = nullptr;
        sptr<NetManagerStandard::ISharingEventCallback> callback_ = nullptr;
    };
};
} // namespace Telephony
} // namespace OHOS
#endif // NETWORK_SEARCH_DEVICE_STATE_OBSERVER_H
