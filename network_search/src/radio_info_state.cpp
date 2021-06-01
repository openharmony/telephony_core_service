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

#include "radio_info_state.h"
#include "network_search_manager.h"
namespace OHOS {
RadioInfoState::RadioInfoState() {}

RadioInfoState::RadioInfoState(std::shared_ptr<NetworkSearchManager> const &networkSearchManager)
    : networkSearchManager_(networkSearchManager)
{}

void RadioInfoState::ProcessRadioChange()
{
    SetToTheSuitableState();
}

void RadioInfoState::SetToTheSuitableState()
{
    ModemPowerState rdState = networkSearchManager_->GetRilHRilRadioState();
    switch (rdState) {
        case CORE_SERVICE_POWER_OFF: {
            networkSearchManager_->SetHRilRadioState(true);
        } break;
        case CORE_SERVICE_POWER_NOT_AVAILABLE: {
            auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_POWER);
            PhoneManager ::GetInstance().phone_[1]->rilManager_->ShutDown(event);
        } break;
        default:
            break;
    }
}
} // namespace OHOS
