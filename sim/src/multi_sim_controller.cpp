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

#include "multi_sim_controller.h"
#include "string_ex.h"

namespace OHOS {
namespace Telephony {
MultiSimController::MultiSimController()
{
    // fixme this is test program should be delete
    operationInfoOne_.Init(CoreManager::DEFAULT_SLOT_ID);
}

MultiSimController::~MultiSimController() {}

std::shared_ptr<Core> MultiSimController::GetCoreInstance(int32_t slotIndex)
{
    return CoreManager::GetInstance().getCore(slotIndex);
}

bool MultiSimController::GetListFromDataBase()
{
    // fixme get the list from DB and pick all rows to refresh local list test with constant list
    if (dataList_.size() > 0) {
        dataList_.clear();
    }
    dataList_.emplace_back(operationInfoOne_);
    return true;
}

bool MultiSimController::RefreshIccAccountInfoList()
{
    if (GetListFromDataBase()) {
        std::list<IccAccountInfo>::iterator it = dataList_.begin();
        if (iccAccountInfoList_.size() > 0) {
            iccAccountInfoList_.clear();
        }
        while (it != dataList_.end()) {
            iccAccountInfoList_.emplace_back(*it);
            it++;
        }
        return true;
    } else {
        TELEPHONY_LOGE("MultiSimController::RefreshIccAccountInfoList get Data Base failed");
        return false;
    }
}

int32_t MultiSimController::GetDefaultVoiceSlotId()
{
    // get data from Settings
    TELEPHONY_LOGD("MultiSimController::GetDefaultVoiceSlotId");
    return defaultVoiceSlotId_;
}

bool MultiSimController::SetDefaultVoiceSlotId(int32_t subId)
{
    // set data to Settings and send broad cast
    TELEPHONY_LOGD("MultiSimController::SetDefaultVoiceSlotId subId = %d", subId);
    defaultVoiceSlotId_ = subId; // fixme this is test program
    AnnounceDefaultVoiceSlotIdChanged(subId);
    return true;
}

int32_t MultiSimController::GetDefaultSmsSlotId()
{
    // get data from Settings
    TELEPHONY_LOGD("MultiSimController::GetDefaultSmsSlotId");
    return defaultSmsSlotId_; // fixme this is test program
}

bool MultiSimController::SetDefaultSmsSlotId(int32_t subId)
{
    // set data to Settings and send broad cast
    TELEPHONY_LOGD("MultiSimController::SetDefaultSmsSlotId subId = %d", subId);
    defaultSmsSlotId_ = subId; // fixme this is test program
    AnnounceDefaultSmsSlotIdChanged(subId);
    return true;
}

bool MultiSimController::AnnounceDefaultVoiceSlotIdChanged(int32_t subId)
{
    AAFwk::Want want;
    want.SetParam(PARAM_SUBID, subId);
    want.SetAction(DEFAULT_VOICE_SLOTID_CHANGE_ACTION);
    int32_t eventCode = EVENT_CODE;
    std::string eventData(DEFAULT_VOICE_SLOT_CHANGED);
    return PublishSimFileEvent(want, eventCode, eventData);
}

bool MultiSimController::AnnounceDefaultSmsSlotIdChanged(int32_t subId)
{
    AAFwk::Want want;
    want.SetParam(PARAM_SUBID, subId);
    want.SetAction(DEFAULT_SMS_SLOTID_CHANGE_ACTION);
    int32_t eventCode = EVENT_CODE;
    std::string eventData(DEFAULT_SMS_SLOT_CHANGED);
    return PublishSimFileEvent(want, eventCode, eventData);
}

bool MultiSimController::PublishSimFileEvent(const AAFwk::Want &want, int eventCode, const std::string &eventData)
{
    EventFwk::CommonEventData data;
    data.SetWant(want);
    data.SetCode(eventCode);
    data.SetData(eventData);
    EventFwk::CommonEventPublishInfo publishInfo;
    publishInfo.SetOrdered(true);
    bool publishResult = EventFwk::CommonEventManager::PublishCommonEvent(data, publishInfo, nullptr);
    TELEPHONY_LOGD("MultiSimController::PublishSimFileEvent end###publishResult = %{public}d\n", publishResult);
    return publishResult;
}
} // namespace Telephony
} // namespace OHOS
