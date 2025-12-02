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
#include "core_service_common_event_hub.h"

#include <shared_mutex>

#include "common_event_manager.h"
#include "common_event_support.h"
#include "telephony_log_wrapper.h"

namespace OHOS {
namespace Telephony {
//
constexpr const char *PERMISSION_PUBLISH_SYSTEM_COMMON_EVENT = "ohos.permission.PUBLISH_SYSTEM_COMMON_EVENT";

CoreServiceCommonEventHub::Subscriber::Subscriber(
    const EventFwk::CommonEventSubscribeInfo &subscriberInfo, std::weak_ptr<CoreServiceCommonEventHub> commonEventHub)
    : EventFwk::CommonEventSubscriber(subscriberInfo), commonEventHub_(commonEventHub)
{}

void CoreServiceCommonEventHub::Subscriber::OnReceiveEvent(const EventFwk::CommonEventData &data)
{
    auto commonEventHub = commonEventHub_.lock();
    if (commonEventHub != nullptr) {
        ffrt::submit([=]() { commonEventHub->OnReceiveEvent(data); });
    }
}

void CoreServiceCommonEventHub::Init()
{
    InitHandlersFunc();
    InitPermissions();
}

CoreServiceCommonEventHub::CoreServiceCommonEventHub()
{}

CoreServiceCommonEventHub::~CoreServiceCommonEventHub()
{
    for (const auto &subscriber : subscribers_) {
        EventFwk::CommonEventManager::UnSubscribeCommonEvent(subscriber.second);
    }
}

namespace {
const std::map<TelCommonEvent, std::string> EVENT_TO_COMMON_EVENT_MAP = {
    {TelCommonEvent::RADIO_STATE_CHANGE, EventFwk::CommonEventSupport::COMMON_EVENT_RADIO_STATE_CHANGE},
    {TelCommonEvent::DATA_SHARE_READY, EventFwk::CommonEventSupport::COMMON_EVENT_DATA_SHARE_READY},
    {TelCommonEvent::USER_SWITCHED, EventFwk::CommonEventSupport::COMMON_EVENT_USER_SWITCHED},
    {TelCommonEvent::SIM_STATE_CHANGED, EventFwk::CommonEventSupport::COMMON_EVENT_SIM_STATE_CHANGED},
    {TelCommonEvent::BLUETOOTH_REMOTEDEVICE_NAME_UPDATE,
        EventFwk::CommonEventSupport::COMMON_EVENT_BLUETOOTH_REMOTEDEVICE_NAME_UPDATE},
    {TelCommonEvent::SHUTDOWN, EventFwk::CommonEventSupport::COMMON_EVENT_SHUTDOWN},
    {TelCommonEvent::SCREEN_UNLOCKED, EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_UNLOCKED},
    {TelCommonEvent::SPECIAL_CODE, EventFwk::CommonEventSupport::COMMON_EVENT_SPECIAL_CODE},
    {TelCommonEvent::OPERATOR_CONFIG_CHANGED, EventFwk::CommonEventSupport::COMMON_EVENT_OPERATOR_CONFIG_CHANGED},
    {TelCommonEvent::NETWORK_STATE_CHANGED, EventFwk::CommonEventSupport::COMMON_EVENT_NETWORK_STATE_CHANGED},
    {TelCommonEvent::CALL_STATE_CHANGED, EventFwk::CommonEventSupport::COMMON_EVENT_CALL_STATE_CHANGED},
    {TelCommonEvent::SIM_CARD_DEFAULT_DATA_SUBSCRIPTION_CHANGED,
        EventFwk::CommonEventSupport::COMMON_EVENT_SIM_CARD_DEFAULT_DATA_SUBSCRIPTION_CHANGED},
    {TelCommonEvent::SCREEN_ON, EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_ON},
    {TelCommonEvent::SCREEN_OFF, EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_OFF},
    {TelCommonEvent::CONNECTIVITY_CHANGE, EventFwk::CommonEventSupport::COMMON_EVENT_CONNECTIVITY_CHANGE},
    {TelCommonEvent::POWER_SAVE_MODE_CHANGED, EventFwk::CommonEventSupport::COMMON_EVENT_POWER_SAVE_MODE_CHANGED},
    {TelCommonEvent::CHARGING, EventFwk::CommonEventSupport::COMMON_EVENT_CHARGING},
    {TelCommonEvent::DISCHARGING, EventFwk::CommonEventSupport::COMMON_EVENT_DISCHARGING},
    {TelCommonEvent::LOCALE_CHANGED, EventFwk::CommonEventSupport::COMMON_EVENT_LOCALE_CHANGED},
    {TelCommonEvent::AIRPLANE_MODE_CHANGED, EventFwk::CommonEventSupport::COMMON_EVENT_AIRPLANE_MODE_CHANGED},
    {TelCommonEvent::SET_PRIMARY_SLOT_STATUS, EventFwk::CommonEventSupport::COMMON_EVENT_SET_PRIMARY_SLOT_STATUS},
    {TelCommonEvent::SECOND_MOUNTED, EventFwk::CommonEventSupport::COMMON_EVENT_SECOND_MOUNTED},
    {TelCommonEvent::BUNDLE_SCAN_FINISHED, EventFwk::CommonEventSupport::COMMON_EVENT_BUNDLE_SCAN_FINISHED}};
}  // namespace

std::string CoreServiceCommonEventHub::EventToString(TelCommonEvent event)
{
    std::string result;
    auto it = EVENT_TO_COMMON_EVENT_MAP.find(event);
    if (it != EVENT_TO_COMMON_EVENT_MAP.end()) {
        result = it->second;
    }
    return result;
}

TelCommonEvent CoreServiceCommonEventHub::StringToEvent(const std::string &action)
{
    for (const auto &pair : EVENT_TO_COMMON_EVENT_MAP) {
        if (pair.second == action) {
            return pair.first;
        }
    }
    return TelCommonEvent::UNKNOWN_ENENT;
}

void CoreServiceCommonEventHub::InitHandlersFunc()
{
    actionHandlersMap_ = {
        {TelCommonEvent::RADIO_STATE_CHANGE,
            [this](const EventFwk::CommonEventData &data) { HandleRadioStateChange(data); }},
        {TelCommonEvent::DATA_SHARE_READY,
            [this](const EventFwk::CommonEventData &data) { HandleDataShareReady(data); }},
        {TelCommonEvent::USER_SWITCHED, [this](const EventFwk::CommonEventData &data) { HandleUserSwitched(data); }},
        {TelCommonEvent::SIM_STATE_CHANGED,
            [this](const EventFwk::CommonEventData &data) { HandleSimStateChanged(data); }},
        {TelCommonEvent::BLUETOOTH_REMOTEDEVICE_NAME_UPDATE,
            [this](const EventFwk::CommonEventData &data) { HandleBluetoothRemotedeviceNameUpdate(data); }},
        {TelCommonEvent::SHUTDOWN, [this](const EventFwk::CommonEventData &data) { HandleShutdown(data); }},
        {TelCommonEvent::SCREEN_UNLOCKED,
            [this](const EventFwk::CommonEventData &data) { HandleScreenUnlocked(data); }},
        {TelCommonEvent::OPERATOR_CONFIG_CHANGED,
            [this](const EventFwk::CommonEventData &data) { HandleOperatorConfigChanged(data); }},
        {TelCommonEvent::NETWORK_STATE_CHANGED,
            [this](const EventFwk::CommonEventData &data) { HandleNetworkStateChanged(data); }},
        {TelCommonEvent::CALL_STATE_CHANGED,
            [this](const EventFwk::CommonEventData &data) { HandleCallStateChanged(data); }},
        {TelCommonEvent::SIM_CARD_DEFAULT_DATA_SUBSCRIPTION_CHANGED,
            [this](const EventFwk::CommonEventData &data) { HandleSimCardDefaultDataSubscriptionChanged(data); }},
        {TelCommonEvent::SCREEN_ON, [this](const EventFwk::CommonEventData &data) { HandleScreenOn(data); }},
        {TelCommonEvent::SCREEN_OFF, [this](const EventFwk::CommonEventData &data) { HandleScreenOff(data); }},
        {TelCommonEvent::CONNECTIVITY_CHANGE,
            [this](const EventFwk::CommonEventData &data) { HandleConnectivityChange(data); }},
        {TelCommonEvent::POWER_SAVE_MODE_CHANGED,
            [this](const EventFwk::CommonEventData &data) { HandlePowerSaveModeChanged(data); }},
        {TelCommonEvent::CHARGING, [this](const EventFwk::CommonEventData &data) { HandleCharging(data); }},
        {TelCommonEvent::DISCHARGING, [this](const EventFwk::CommonEventData &data) { HandleDischarging(data); }},
        {TelCommonEvent::LOCALE_CHANGED, [this](const EventFwk::CommonEventData &data) { HandleLocaleChanged(data); }},
        {TelCommonEvent::AIRPLANE_MODE_CHANGED,
            [this](const EventFwk::CommonEventData &data) { HandleAirplaneModeChanged(data); }},
        {TelCommonEvent::SET_PRIMARY_SLOT_STATUS,
            [this](const EventFwk::CommonEventData &data) { HandleSetPrimarySlotStatus(data); }},
        {TelCommonEvent::SECOND_MOUNTED, [this](const EventFwk::CommonEventData &data) { HandleSecondMounted(data); }},
        {TelCommonEvent::BUNDLE_SCAN_FINISHED,
            [this](const EventFwk::CommonEventData &data) { HandleBundleScanFinished(data); }},
    };
}

void CoreServiceCommonEventHub::InitPermissions()
{
    actionPermissionsMap_[TelCommonEvent::DATA_SHARE_READY] = PERMISSION_PUBLISH_SYSTEM_COMMON_EVENT;
}

std::shared_ptr<EventFwk::CommonEventSubscriber> CoreServiceCommonEventHub::Subscribe(TelCommonEvent eventEnum)
{
    if (eventEnum == TelCommonEvent::UNKNOWN_ENENT) {
        TELEPHONY_LOGW("CoreServiceCommonEventHub Subscribe: unknown event");
        return nullptr;
    }

    std::string eventStr = EventToString(eventEnum);

    EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent(eventStr);

    EventFwk::CommonEventSubscribeInfo subscriberInfo(matchingSkills);
    subscriberInfo.SetThreadMode(EventFwk::CommonEventSubscribeInfo::COMMON);

    auto permIt = actionPermissionsMap_.find(eventEnum);
    if (permIt != actionPermissionsMap_.end()) {
        subscriberInfo.SetPermission(permIt->second);
    }

    auto subscriber = std::make_shared<Subscriber>(subscriberInfo, weak_from_this());
    bool subscribeResult = EventFwk::CommonEventManager::SubscribeCommonEvent(subscriber);
    if (!subscribeResult) {
        TELEPHONY_LOGE("CoreServiceCommonEventHub Subscribe failed, event = %{public}s", eventStr.c_str());
        return nullptr;
    }

    TELEPHONY_LOGI("CoreServiceCommonEventHub Subscribe success, event = %{public}s", eventStr.c_str());
    return subscriber;
}

void CoreServiceCommonEventHub::Unsubscribe(TelCommonEvent eventEnum)
{
    if (eventEnum == TelCommonEvent::UNKNOWN_ENENT) {
        TELEPHONY_LOGE("Unsubscribe: unknown event");
        return;
    }

    std::shared_ptr<EventFwk::CommonEventSubscriber> subscriber;
    {
        std::shared_lock<ffrt::shared_mutex> subscribersLock(subscribersMtx_);
        auto it = subscribers_.find(eventEnum);
        if (it == subscribers_.end()) {
            TELEPHONY_LOGE("Unsubscribe: no subscriber for event");
            return;
        }
        subscriber = it->second;
    }  // 解锁，外部调用前不持锁

    bool unsubscribeResult = EventFwk::CommonEventManager::UnSubscribeCommonEvent(subscriber);
    TELEPHONY_LOGI(
        "Unsubscribe event = %{public}d, result = %{public}d", static_cast<int>(eventEnum), unsubscribeResult);
}

void CoreServiceCommonEventHub::RegisterCallback(
    const std::shared_ptr<CoreServiceCommonEventCallback> &cb, const std::vector<TelCommonEvent> &events)
{
    if (cb == nullptr) {
        TELEPHONY_LOGW("RegisterCallback: callback is null");
        return;
    }

    // Step 1: 先确定哪些事件需要订阅
    std::vector<TelCommonEvent> needSubscribe;
    {
        std::shared_lock<ffrt::shared_mutex> subscribersLock(subscribersMtx_);
        for (auto event : events) {
            if (subscribers_.find(event) == subscribers_.end()) {
                needSubscribe.push_back(event);
            }
        }
    }

    // Step 2: 在无锁状态下调用外部订阅逻辑
    std::unordered_map<TelCommonEvent, std::shared_ptr<EventFwk::CommonEventSubscriber>> newSubscribers;
    for (auto event : needSubscribe) {
        auto subscriber = Subscribe(event);
        if (subscriber != nullptr) {
            TELEPHONY_LOGI("CoreServiceCommonEventHub RegisterCallback: subscribed event %{public}d successfully",
                static_cast<int>(event));
            newSubscribers[event] = subscriber;
        } else {
            TELEPHONY_LOGE("CoreServiceCommonEventHub RegisterCallback failed: subscribe event %{public}d failed",
                static_cast<int>(event));
        }
    }

    // Step 3: 更新 subscribers_
    for (auto &[event, subscriber] : newSubscribers) {
        std::unique_lock<ffrt::shared_mutex> subscribersLock(subscribersMtx_);
        subscribers_[event] = subscriber;
    }

    // Step 4: 更新 callbacks_
    for (auto event : events) {
        std::unique_lock<ffrt::shared_mutex> callbacksLock(callbacksMtx_);
        callbacks_[event].insert(cb);
    }
}

void CoreServiceCommonEventHub::UnregisterCallback(const std::shared_ptr<CoreServiceCommonEventCallback> &cb)
{
    if (cb == nullptr) {
        TELEPHONY_LOGE("UnregisterCallback: callback is null");
        return;
    }

    std::vector<TelCommonEvent> needUnsubscribe;

    // Step 1: 清理 callbacks_
    {
        std::unique_lock<ffrt::shared_mutex> callbacksLock(callbacksMtx_);
        for (auto it = callbacks_.begin(); it != callbacks_.end();) {
            it->second.erase(cb);
            if (it->second.empty()) {
                needUnsubscribe.push_back(it->first);
                it = callbacks_.erase(it);
            } else {
                ++it;
            }
        }
    }

    // Step 2: 外部注销
    for (auto event : needUnsubscribe) {
        Unsubscribe(event);
    }

    // Step 3: 清理 subscribers_
    {
        std::unique_lock<ffrt::shared_mutex> subscribersLock(subscribersMtx_);
        for (auto event : needUnsubscribe) {
            subscribers_.erase(event);
        }
    }
}

void CoreServiceCommonEventHub::OnReceiveEvent(const EventFwk::CommonEventData &data)
{
    const std::string &action = data.GetWant().GetAction();
    TelCommonEvent eventEnum = StringToEvent(action);
    if (eventEnum == TelCommonEvent::UNKNOWN_ENENT) {
        TELEPHONY_LOGW("OnReceiveEvent: unknown event %{public}s", action.c_str());
        return;
    }

    TELEPHONY_LOGI(
        "OnReceiveEvent: event enum = %{public}d, action = %{public}s", static_cast<int>(eventEnum), action.c_str());

    auto it = actionHandlersMap_.find(eventEnum);
    if (it != actionHandlersMap_.end() && it->second != nullptr) {
        it->second(data);
    }
}

// ================= Handlers =================
void CoreServiceCommonEventHub::HandleRadioStateChange(const EventFwk::CommonEventData &data)
{
    const EventFwk::Want &want = data.GetWant();
    int32_t slotId = want.GetIntParam("slotId", 0);
    int32_t state = want.GetIntParam("state", 0);

    std::shared_lock<ffrt::shared_mutex> lock(callbacksMtx_);
    auto it = callbacks_.find(TelCommonEvent::RADIO_STATE_CHANGE);
    if (it != callbacks_.end()) {
        for (const auto &cb : it->second) {
            cb->OnRadioStateChange(slotId, state);
        }
    }
}

void CoreServiceCommonEventHub::HandleDataShareReady(const EventFwk::CommonEventData &)
{
    std::shared_lock<ffrt::shared_mutex> lock(callbacksMtx_);
    auto it = callbacks_.find(TelCommonEvent::DATA_SHARE_READY);
    if (it != callbacks_.end()) {
        for (const auto &cb : it->second) {
            cb->OnDataShareReady();
        }
    }
}

void CoreServiceCommonEventHub::HandleUserSwitched(const EventFwk::CommonEventData &data)
{
    int32_t userId = data.GetCode();
    std::shared_lock<ffrt::shared_mutex> lock(callbacksMtx_);
    auto it = callbacks_.find(TelCommonEvent::USER_SWITCHED);
    if (it != callbacks_.end()) {
        for (const auto &cb : it->second) {
            cb->OnUserSwitched(userId);
        }
    }
}

void CoreServiceCommonEventHub::HandleSimStateChanged(const EventFwk::CommonEventData &data)
{
    const EventFwk::Want &want = data.GetWant();
    int32_t slotId = want.GetIntParam("slotId", 0);
    int32_t simType = want.GetIntParam("simType", 0);
    int32_t simState = want.GetIntParam("simState", 0);
    int32_t lockReason = want.GetIntParam("lockReason", 0);

    std::shared_lock<ffrt::shared_mutex> lock(callbacksMtx_);
    auto it = callbacks_.find(TelCommonEvent::SIM_STATE_CHANGED);
    if (it != callbacks_.end()) {
        for (const auto &cb : it->second) {
            cb->OnSimStateChanged(slotId, simType, simState, lockReason);
        }
    }
}

void CoreServiceCommonEventHub::HandleBluetoothRemotedeviceNameUpdate(const EventFwk::CommonEventData &data)
{
    const EventFwk::Want &want = data.GetWant();
    std::string deviceAddr = want.GetStringParam("deviceAddr");
    std::string remoteName = want.GetStringParam("remoteName");

    std::shared_lock<ffrt::shared_mutex> lock(callbacksMtx_);
    auto it = callbacks_.find(TelCommonEvent::BLUETOOTH_REMOTEDEVICE_NAME_UPDATE);
    if (it != callbacks_.end()) {
        for (const auto &cb : it->second) {
            cb->OnBluetoothRemoteDeviceNameUpdate(deviceAddr, remoteName);
        }
    }
}

void CoreServiceCommonEventHub::HandleShutdown(const EventFwk::CommonEventData &)
{
    std::shared_lock<ffrt::shared_mutex> lock(callbacksMtx_);
    auto it = callbacks_.find(TelCommonEvent::SHUTDOWN);
    if (it != callbacks_.end()) {
        for (const auto &cb : it->second) {
            cb->OnShutdown();
        }
    }
}

void CoreServiceCommonEventHub::HandleScreenUnlocked(const EventFwk::CommonEventData &)
{
    std::shared_lock<ffrt::shared_mutex> lock(callbacksMtx_);
    auto it = callbacks_.find(TelCommonEvent::SCREEN_UNLOCKED);
    if (it != callbacks_.end()) {
        for (const auto &cb : it->second) {
            cb->OnScreenUnlocked();
        }
    }
}

void CoreServiceCommonEventHub::HandleOperatorConfigChanged(const EventFwk::CommonEventData &data)
{
    const EventFwk::Want &want = data.GetWant();
    int32_t slotId = want.GetIntParam("slotId", 0);
    int32_t state = want.GetIntParam("state", 0);

    std::shared_lock<ffrt::shared_mutex> lock(callbacksMtx_);
    auto it = callbacks_.find(TelCommonEvent::OPERATOR_CONFIG_CHANGED);
    if (it != callbacks_.end()) {
        for (const auto &cb : it->second) {
            cb->OnOperatorConfigChanged(slotId, state);
        }
    }
}

void CoreServiceCommonEventHub::HandleNetworkStateChanged(const EventFwk::CommonEventData &data)
{
    const EventFwk::Want &want = data.GetWant();
    int32_t slotId = want.GetIntParam("slotId", 0);
    std::string networkState = want.GetStringParam("networkState");

    std::shared_lock<ffrt::shared_mutex> lock(callbacksMtx_);
    auto it = callbacks_.find(TelCommonEvent::NETWORK_STATE_CHANGED);
    if (it != callbacks_.end()) {
        for (const auto &cb : it->second) {
            cb->OnNetworkStateChanged(slotId, networkState);
        }
    }
}

void CoreServiceCommonEventHub::HandleCallStateChanged(const EventFwk::CommonEventData &data)
{
    const EventFwk::Want &want = data.GetWant();
    int32_t slotId = want.GetIntParam("slotId", 0);
    int32_t state = want.GetIntParam("state", 0);

    std::shared_lock<ffrt::shared_mutex> lock(callbacksMtx_);
    auto it = callbacks_.find(TelCommonEvent::CALL_STATE_CHANGED);
    if (it != callbacks_.end()) {
        for (const auto &cb : it->second) {
            cb->OnCallStateChanged(slotId, state);
        }
    }
}

void CoreServiceCommonEventHub::HandleSimCardDefaultDataSubscriptionChanged(const EventFwk::CommonEventData &data)
{
    const EventFwk::Want &want = data.GetWant();
    int32_t simId = want.GetIntParam("simId", 0);

    std::shared_lock<ffrt::shared_mutex> lock(callbacksMtx_);
    auto it = callbacks_.find(TelCommonEvent::SIM_CARD_DEFAULT_DATA_SUBSCRIPTION_CHANGED);
    if (it != callbacks_.end()) {
        for (const auto &cb : it->second) {
            cb->OnSimCardDefaultDataSubscriptionChanged(simId);
        }
    }
}

void CoreServiceCommonEventHub::HandleScreenOn(const EventFwk::CommonEventData &)
{
    std::shared_lock<ffrt::shared_mutex> lock(callbacksMtx_);
    auto it = callbacks_.find(TelCommonEvent::SCREEN_ON);
    if (it != callbacks_.end()) {
        for (const auto &cb : it->second) {
            cb->OnScreenOn();
        }
    }
}

void CoreServiceCommonEventHub::HandleScreenOff(const EventFwk::CommonEventData &)
{
    std::shared_lock<ffrt::shared_mutex> lock(callbacksMtx_);
    auto it = callbacks_.find(TelCommonEvent::SCREEN_OFF);
    if (it != callbacks_.end()) {
        for (const auto &cb : it->second) {
            cb->OnScreenOff();
        }
    }
}

void CoreServiceCommonEventHub::HandleConnectivityChange(const EventFwk::CommonEventData &data)
{
    const EventFwk::Want &want = data.GetWant();
    int32_t netType = want.GetIntParam("NetType", 0);
    int32_t netConnState = data.GetCode();

    std::shared_lock<ffrt::shared_mutex> lock(callbacksMtx_);
    auto it = callbacks_.find(TelCommonEvent::CONNECTIVITY_CHANGE);
    if (it != callbacks_.end()) {
        for (const auto &cb : it->second) {
            cb->OnConnectivityChange(netType, netConnState);
        }
    }
}

void CoreServiceCommonEventHub::HandlePowerSaveModeChanged(const EventFwk::CommonEventData &data)
{
    uint32_t powerMode = static_cast<uint32_t>(data.GetCode());

    std::shared_lock<ffrt::shared_mutex> lock(callbacksMtx_);
    auto it = callbacks_.find(TelCommonEvent::POWER_SAVE_MODE_CHANGED);
    if (it != callbacks_.end()) {
        for (const auto &cb : it->second) {
            cb->OnPowerSaveModeChanged(powerMode);
        }
    }
}

void CoreServiceCommonEventHub::HandleCharging(const EventFwk::CommonEventData &data)
{
    const EventFwk::Want &want = data.GetWant();
    uint32_t chargeType = static_cast<uint32_t>(want.GetIntParam("chargeType", 0));

    std::shared_lock<ffrt::shared_mutex> lock(callbacksMtx_);
    auto it = callbacks_.find(TelCommonEvent::CHARGING);
    if (it != callbacks_.end()) {
        for (const auto &cb : it->second) {
            cb->OnCharging(chargeType);
        }
    }
}

void CoreServiceCommonEventHub::HandleDischarging(const EventFwk::CommonEventData &data)
{
    const EventFwk::Want &want = data.GetWant();
    uint32_t chargeType = static_cast<uint32_t>(want.GetIntParam("chargeType", 0));

    std::shared_lock<ffrt::shared_mutex> lock(callbacksMtx_);
    auto it = callbacks_.find(TelCommonEvent::DISCHARGING);
    if (it != callbacks_.end()) {
        for (const auto &cb : it->second) {
            cb->OnDischarging(chargeType);
        }
    }
}

void CoreServiceCommonEventHub::HandleLocaleChanged(const EventFwk::CommonEventData &)
{
    std::shared_lock<ffrt::shared_mutex> lock(callbacksMtx_);
    auto it = callbacks_.find(TelCommonEvent::LOCALE_CHANGED);
    if (it != callbacks_.end()) {
        for (const auto &cb : it->second) {
            cb->OnLocaleChanged();
        }
    }
}

void CoreServiceCommonEventHub::HandleAirplaneModeChanged(const EventFwk::CommonEventData &data)
{
    auto code = data.GetCode();

    std::shared_lock<ffrt::shared_mutex> lock(callbacksMtx_);
    auto it = callbacks_.find(TelCommonEvent::AIRPLANE_MODE_CHANGED);
    if (it != callbacks_.end()) {
        for (const auto &cb : it->second) {
            cb->OnAirplaneModeChanged(static_cast<bool>(code));
        }
    }
}

void CoreServiceCommonEventHub::HandleSetPrimarySlotStatus(const EventFwk::CommonEventData &data)
{
    const EventFwk::Want &want = data.GetWant();
    bool setDone = want.GetBoolParam("setDone", false);

    std::shared_lock<ffrt::shared_mutex> lock(callbacksMtx_);
    auto it = callbacks_.find(TelCommonEvent::SET_PRIMARY_SLOT_STATUS);
    if (it != callbacks_.end()) {
        for (const auto &cb : it->second) {
            cb->OnSetPrimarySlotStatus(setDone);
        }
    }
}

void CoreServiceCommonEventHub::HandleSecondMounted(const EventFwk::CommonEventData &)
{
    std::shared_lock<ffrt::shared_mutex> lock(callbacksMtx_);
    auto it = callbacks_.find(TelCommonEvent::SECOND_MOUNTED);
    if (it != callbacks_.end()) {
        for (const auto &cb : it->second) {
            cb->OnSecondMounted();
        }
    }
}

void CoreServiceCommonEventHub::HandleBundleScanFinished(const EventFwk::CommonEventData &)
{
    std::shared_lock<ffrt::shared_mutex> lock(callbacksMtx_);
    auto it = callbacks_.find(TelCommonEvent::BUNDLE_SCAN_FINISHED);
    if (it != callbacks_.end()) {
        for (const auto &cb : it->second) {
            cb->OnBundleScanFinished();
        }
    }
}

}  // namespace Telephony
}  // namespace OHOS