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

#include "device_state_observer.h"

#include "telephony_log_wrapper.h"

namespace OHOS {
namespace Telephony {
const std::string NET_TYPE = "NetType";

void DeviceStateObserver::StartEventSubscriber(const std::shared_ptr<DeviceStateHandler> &deviceStateHandler)
{
    MatchingSkills matchingSkills;
    matchingSkills.AddEvent(CommonEventSupport::COMMON_EVENT_CONNECTIVITY_CHANGE);
    matchingSkills.AddEvent(CommonEventSupport::COMMON_EVENT_SCREEN_ON);
    matchingSkills.AddEvent(CommonEventSupport::COMMON_EVENT_SCREEN_OFF);
    matchingSkills.AddEvent(CommonEventSupport::COMMON_EVENT_POWER_SAVE_MODE_CHANGED);
    matchingSkills.AddEvent(CommonEventSupport::COMMON_EVENT_DEVICE_IDLE_MODE_CHANGED);
    matchingSkills.AddEvent(CommonEventSupport::COMMON_EVENT_CHARGING);
    matchingSkills.AddEvent(CommonEventSupport::COMMON_EVENT_DISCHARGING);
    matchingSkills.AddEvent(CommonEventSupport::COMMON_EVENT_WIFI_HOTSPOT_STATE);
    matchingSkills.AddEvent(CommonEventSupport::COMMON_EVENT_WIFI_AP_STA_JOIN);
    matchingSkills.AddEvent(CommonEventSupport::COMMON_EVENT_WIFI_AP_STA_LEAVE);
    CommonEventSubscribeInfo subscriberInfo(matchingSkills);
    subscriber_ = std::make_shared<DeviceStateEventSubscriber>(subscriberInfo);
    subscriber_->SetEventHandler(deviceStateHandler);
    subscriber_->InitEventMap();
    bool subscribeResult = CommonEventManager::SubscribeCommonEvent(subscriber_);
    TELEPHONY_LOGI("DeviceStateObserver::StartEventSubscriber subscribeResult = %{public}d", subscribeResult);
}

void DeviceStateObserver::StopEventSubscriber()
{
    if (subscriber_ == nullptr) {
        TELEPHONY_LOGE("DeviceStateObserver::StopEventSubscriber subscriber_ is nullptr");
        return;
    }
    bool subscribeResult = CommonEventManager::UnSubscribeCommonEvent(subscriber_);
    subscriber_ = nullptr;
    TELEPHONY_LOGI("DeviceStateObserver::StopEventSubscriber subscribeResult = %{public}d", subscribeResult);
}

void DeviceStateEventSubscriber::OnReceiveEvent(const CommonEventData &data)
{
    if (deviceStateHandler_ == nullptr) {
        TELEPHONY_LOGE("DeviceStateEventSubscriber::OnReceiveEvent: networkSearchHandler_ is nullptr");
        return;
    }
    std::string action = data.GetWant().GetAction();
    TELEPHONY_LOGI("DeviceStateEventSubscriber::OnReceiveEvent: action = %{public}s", action.c_str());
    switch (GetDeviceStateEventIntValue(action)) {
        case COMMON_EVENT_CONNECTIVITY_CHANGE:
            if (data.GetWant().GetIntParam(NET_TYPE, NetBearType::BEARER_DEFAULT) == NetBearType::BEARER_WIFI) {
                bool isWifiConnected = data.GetCode() == NetConnState::NET_CONN_STATE_CONNECTED;
                deviceStateHandler_->ProcessWifiState(isWifiConnected);
                TELEPHONY_LOGI("DeviceStateEventSubscriber:: wifi %{public}s",
                    isWifiConnected ? "connected" : "no connected");
            }
            break;
        case COMMON_EVENT_SCREEN_ON:
            deviceStateHandler_->ProcessScreenDisplay(true);
            break;
        case COMMON_EVENT_SCREEN_OFF:
            deviceStateHandler_->ProcessScreenDisplay(false);
            break;
        case COMMON_EVENT_POWER_SAVE_MODE_CHANGED:
            deviceStateHandler_->ProcessPowerSaveMode(true);
            break;
        case COMMON_EVENT_DEVICE_IDLE_MODE_CHANGED:
            deviceStateHandler_->ProcessPowerSaveMode(false);
            break;
        case COMMON_EVENT_CHARGING:
            deviceStateHandler_->ProcessChargingState(true);
            break;
        case COMMON_EVENT_DISCHARGING:
            deviceStateHandler_->ProcessChargingState(false);
            break;
        case COMMON_EVENT_WIFI_HOTSPOT_STATE:
        case COMMON_EVENT_WIFI_AP_STA_JOIN:
        case COMMON_EVENT_WIFI_AP_STA_LEAVE:
            break;
        default:
            break;
    }
}

void DeviceStateEventSubscriber::SetEventHandler(const std::shared_ptr<DeviceStateHandler> &deviceStateHandler)
{
    deviceStateHandler_ = deviceStateHandler;
}

DeviceStateEventIntValue DeviceStateEventSubscriber::GetDeviceStateEventIntValue(std::string &event) const
{
    auto iter = deviceStateEventMapIntValues_.find(event);
    if (iter == deviceStateEventMapIntValues_.end()) {
        return COMMON_EVENT_UNKNOWN;
    }
    return iter->second;
}

void DeviceStateEventSubscriber::InitEventMap()
{
    deviceStateEventMapIntValues_ = {
        {CommonEventSupport::COMMON_EVENT_CONNECTIVITY_CHANGE, COMMON_EVENT_CONNECTIVITY_CHANGE},
        {CommonEventSupport::COMMON_EVENT_SCREEN_ON, COMMON_EVENT_SCREEN_ON},
        {CommonEventSupport::COMMON_EVENT_SCREEN_OFF, COMMON_EVENT_SCREEN_OFF},
        {CommonEventSupport::COMMON_EVENT_POWER_SAVE_MODE_CHANGED, COMMON_EVENT_POWER_SAVE_MODE_CHANGED},
        {CommonEventSupport::COMMON_EVENT_DEVICE_IDLE_MODE_CHANGED, COMMON_EVENT_DEVICE_IDLE_MODE_CHANGED},
        {CommonEventSupport::COMMON_EVENT_CHARGING, COMMON_EVENT_CHARGING},
        {CommonEventSupport::COMMON_EVENT_DISCHARGING, COMMON_EVENT_DISCHARGING},
        {CommonEventSupport::COMMON_EVENT_WIFI_HOTSPOT_STATE, COMMON_EVENT_WIFI_HOTSPOT_STATE},
        {CommonEventSupport::COMMON_EVENT_WIFI_AP_STA_JOIN, COMMON_EVENT_WIFI_AP_STA_JOIN},
        {CommonEventSupport::COMMON_EVENT_WIFI_AP_STA_LEAVE, COMMON_EVENT_WIFI_AP_STA_LEAVE},
    };
}
} // namespace Telephony
} // namespace OHOS