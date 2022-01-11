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

#include "sim_state_tracker.h"
#include "observer_handler.h"

namespace OHOS {
namespace Telephony {
SimStateTracker::SimStateTracker(const std::shared_ptr<AppExecFwk::EventRunner> &runner,
    std::shared_ptr<ISimFileManager> simFileManager)
    : AppExecFwk::EventHandler(runner), simFileManager_(simFileManager)
{
    if (simFileManager == nullptr) {
        TELEPHONY_LOGE("can not make OperatorConf");
    }
    operatorConf_ = std::make_unique<OperatorConf>(simFileManager);
}

SimStateTracker::~SimStateTracker()
{
    UnRegisterForIccLoaded();
}

bool SimStateTracker::GetOperatorConfigs(int32_t slotId, OperatorConfig &poc)
{
    TELEPHONY_LOGI("SimStateTracker::GetOperatorConfigs");
    // if we already have the data get from local
    if (conf_.configValue.size() > 0) {
        TELEPHONY_LOGI("SimStateTracker::GetOperatorConfigs from cache");
        auto valueIt = conf_.configValue.begin();
        while (valueIt != conf_.configValue.end()) {
            poc.configValue.emplace(
                std::pair<std::u16string, std::u16string>(valueIt->first, valueIt->second));
            valueIt++;
        }
        return true;
    }
    // or we need to get data now
    if (operatorConf_ == nullptr) {
        TELEPHONY_LOGE("SimStateTracker::GetOperatorConfigs operatorConf_ is null");
        return false;
    }
    TELEPHONY_LOGI("SimStateTracker::GetOperatorConfigs from new");
    if (!operatorConf_->GetOperatorConfigs(slotId, conf_)) {
        TELEPHONY_LOGE("SimStateTracker::GetOperatorConfigs can not get from xml");
        return false;
    }
    auto valueIt = conf_.configValue.begin();
    while (valueIt != conf_.configValue.end()) {
        poc.configValue.emplace(
            std::pair<std::u16string, std::u16string>(valueIt->first, valueIt->second));
        valueIt++;
    }
    return AnnounceOperatorConfigChanged();
}

bool SimStateTracker::AnnounceOperatorConfigChanged()
{
    AAFwk::Want want;
    want.SetAction(COMMON_EVENT_TELEPHONY_OPERATOR_CONFIG_CHANGED);
    std::string eventData(OPERATOR_CONFIG_CHANGED);
    EventFwk::CommonEventData data;
    data.SetWant(want);
    data.SetData(eventData);
    EventFwk::CommonEventPublishInfo publishInfo;
    publishInfo.SetOrdered(true);
    bool publishResult = EventFwk::CommonEventManager::PublishCommonEvent(data, publishInfo, nullptr);
    TELEPHONY_LOGI("SimStateTracker::PublishSimFileEvent end###publishResult = %{public}d\n", publishResult);
    return publishResult;
}

void SimStateTracker::ProcessEvent(const AppExecFwk::InnerEvent::Pointer &event)
{
    if (event == nullptr) {
        TELEPHONY_LOGE("start ProcessEvent but event is null!");
        return;
    }
    auto eventCode = event->GetInnerEventId();
    switch (eventCode) {
        case ObserverHandler::RADIO_SIM_RECORDS_LOADED:
            TELEPHONY_LOGI("SimStateTracker::Refresh config");
            conf_.configValue.clear();
            GetOperatorConfigs(CoreManager::DEFAULT_SLOT_ID, conf_);
            break;
        default:
            break;
    }
}

bool SimStateTracker::RegisterForIccLoaded()
{
    TELEPHONY_LOGI("SimStateTracker::RegisterForIccLoaded");
    if (simFileManager_ == nullptr) {
        TELEPHONY_LOGE("SimStateTracker::can not get SimFileManager");
        return false;
    }
    simFileManager_->RegisterCoreNotify(shared_from_this(), ObserverHandler::RADIO_SIM_RECORDS_LOADED);
    return true;
}

bool SimStateTracker::UnRegisterForIccLoaded()
{
    TELEPHONY_LOGI("SimStateTracker::UnRegisterForIccLoaded");
    if (simFileManager_ == nullptr) {
        TELEPHONY_LOGE("SimStateTracker::can not get SimFileManager");
        return false;
    }
    simFileManager_->UnRegisterCoreNotify(shared_from_this(), ObserverHandler::RADIO_SIM_RECORDS_LOADED);
    return true;
}
} // namespace Telephony
} // namespace OHOS