/*
 * Copyright (C) 2025-2025 Huawei Device Co., Ltd.
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

#ifndef CORE_SERVICE_COMMON_EVENT_HUB_H
#define CORE_SERVICE_COMMON_EVENT_HUB_H

#include <vector>
#include <string>
#include <memory>
#include <map>

#include "i_core_service_common_event_hub.h"
#include "core_service_common_event_callback.h"
#include "common_event_subscriber.h"
#include "ffrt.h"

namespace OHOS {
namespace Telephony {
class CoreServiceCommonEventHub : public ICoreServiceCommonEventHub,
                                  public std::enable_shared_from_this<CoreServiceCommonEventHub> {
public:
    CoreServiceCommonEventHub();
    ~CoreServiceCommonEventHub();
    void Init();
    void RegisterCallback(
        const std::shared_ptr<CoreServiceCommonEventCallback> &cb, const std::vector<TelCommonEvent> &events) override;
    void UnregisterCallback(const std::shared_ptr<CoreServiceCommonEventCallback> &cb) override;
    void OnReceiveEvent(const EventFwk::CommonEventData &data);

private:
    std::string EventToString(TelCommonEvent event);
    TelCommonEvent StringToEvent(const std::string &action);
    void InitHandlersFunc();
    void InitPermissions();
    std::shared_ptr<EventFwk::CommonEventSubscriber> Subscribe(TelCommonEvent event);
    void Unsubscribe(TelCommonEvent event);
    // Handler functions for various events
    void HandleRadioStateChange(const EventFwk::CommonEventData &data);
    void HandleDataShareReady(const EventFwk::CommonEventData &data);
    void HandleUserSwitched(const EventFwk::CommonEventData &data);
    void HandleSimStateChanged(const EventFwk::CommonEventData &data);
    void HandleBluetoothRemotedeviceNameUpdate(const EventFwk::CommonEventData &data);
    void HandleShutdown(const EventFwk::CommonEventData &data);
    void HandleScreenUnlocked(const EventFwk::CommonEventData &data);
    void HandleOperatorConfigChanged(const EventFwk::CommonEventData &data);
    void HandleNetworkStateChanged(const EventFwk::CommonEventData &data);
    void HandleCallStateChanged(const EventFwk::CommonEventData &data);
    void HandleSimCardDefaultDataSubscriptionChanged(const EventFwk::CommonEventData &data);
    void HandleScreenOn(const EventFwk::CommonEventData &data);
    void HandleScreenOff(const EventFwk::CommonEventData &data);
    void HandleConnectivityChange(const EventFwk::CommonEventData &data);
    void HandlePowerSaveModeChanged(const EventFwk::CommonEventData &data);
    void HandleCharging(const EventFwk::CommonEventData &data);
    void HandleDischarging(const EventFwk::CommonEventData &data);
    void HandleLocaleChanged(const EventFwk::CommonEventData &data);
    void HandleAirplaneModeChanged(const EventFwk::CommonEventData &data);
    void HandleSetPrimarySlotStatus(const EventFwk::CommonEventData &data);
    void HandleSecondMounted(const EventFwk::CommonEventData &data);
    void HandleBundleScanFinished(const EventFwk::CommonEventData &data);

private:
    class Subscriber : public EventFwk::CommonEventSubscriber {
    public:
        Subscriber(const EventFwk::CommonEventSubscribeInfo &subscriberInfo,
            std::weak_ptr<CoreServiceCommonEventHub> commonEventHub);
        void OnReceiveEvent(const EventFwk::CommonEventData &data) override;
        std::weak_ptr<CoreServiceCommonEventHub> commonEventHub_;
    };

    ffrt::shared_mutex callbacksMtx_;
    ffrt::shared_mutex subscribersMtx_;
    using HandlerFunc = std::function<void(const EventFwk::CommonEventData &)>;
    std::map<TelCommonEvent, HandlerFunc> actionHandlersMap_;
    std::map<TelCommonEvent, std::string> actionPermissionsMap_;
    std::map<TelCommonEvent, std::shared_ptr<EventFwk::CommonEventSubscriber>> subscribers_;
    std::map<TelCommonEvent, std::set<std::shared_ptr<CoreServiceCommonEventCallback>>> callbacks_;
};
}  // namespace Telephony
}  // namespace OHOS
#endif