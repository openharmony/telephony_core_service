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

#include "ffrt.h"
#include "common_event_subscriber.h"
#include "common_event_support.h"
#include "common_event_manager.h"
#include "device_state_handler.h"
#ifdef TETHER_NETWORKSHARE
#include "sharing_event_callback_stub.h"
#endif
#include "net_all_capabilities.h"
#include "net_supplier_info.h"
#include "system_ability_status_change_stub.h"
#include "core_service_common_event_callback.h"

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

class DeviceStateEventSubscriber : public CoreServiceCommonEventCallback {
public:
    DeviceStateEventSubscriber() = default;
    ~DeviceStateEventSubscriber() = default;
    std::shared_ptr<DeviceStateHandler> GetEventHandler();
    void OnScreenOn() override;
    void OnScreenOff() override;
    void OnCharging(uint32_t chargeType) override;
    void OnDischarging(uint32_t chargeType) override;
    void OnShutdown() override;
    void OnConnectivityChange(int32_t netType, int32_t netConnState) override;
    void OnPowerSaveModeChanged(uint32_t powerMode) override;

private:
    std::shared_ptr<DeviceStateHandler> deviceStateHandler_;
};

#ifdef TETHER_NETWORKSHARE
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
#endif

class DeviceStateObserver {
public:
    DeviceStateObserver() = default;
    ~DeviceStateObserver() = default;
    void StartEventSubscriber(const std::shared_ptr<DeviceStateHandler> &deviceStateHandler);
    void StopEventSubscriber();

private:
    std::shared_ptr<DeviceStateEventSubscriber> subscriber_;
#ifdef TETHER_NETWORKSHARE
    sptr<NetManagerStandard::ISharingEventCallback> sharingEventCallback_ = nullptr;
#endif
    sptr<ISystemAbilityStatusChange> statusChangeListener_ = nullptr;
    ffrt::mutex callbackMutex_;

private:
    class SystemAbilityStatusChangeListener : public SystemAbilityStatusChangeStub {
    public:
        #ifdef TETHER_NETWORKSHAR
        SystemAbilityStatusChangeListener(std::shared_ptr<DeviceStateEventSubscriber> &subscriber,
            sptr<NetManagerStandard::ISharingEventCallback> &callback);
        #else
        SystemAbilityStatusChangeListener(std::shared_ptr<DeviceStateEventSubscriber> &subscriber);
        #endif
        ~SystemAbilityStatusChangeListener() = default;
        virtual void OnAddSystemAbility(int32_t systemAbilityId, const std::string& deviceId) override;
        virtual void OnRemoveSystemAbility(int32_t systemAbilityId, const std::string& deviceId) override;

    private:
        std::shared_ptr<DeviceStateEventSubscriber> sub_ = nullptr;
#ifdef TETHER_NETWORKSHARE        
        sptr<NetManagerStandard::ISharingEventCallback> callback_ = nullptr;
#endif
    };
}; // namespace Telephony
}
