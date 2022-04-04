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

#ifndef NETWORK_SEARCH_INCLUDE_RADIO_INFO_H
#define NETWORK_SEARCH_INCLUDE_RADIO_INFO_H

#include <memory>
#include "event_handler.h"
#include "network_state.h"
namespace OHOS {
namespace Telephony {
class NetworkSearchManager;
class RadioInfo {
public:
    RadioInfo(std::weak_ptr<NetworkSearchManager> networkSearchManager, int32_t slotId);
    virtual ~RadioInfo() = default;
    void ProcessGetRadioState(const AppExecFwk::InnerEvent::Pointer &event) const;
    void ProcessSetRadioState(const AppExecFwk::InnerEvent::Pointer &event) const;
    void ProcessGetImei(const AppExecFwk::InnerEvent::Pointer &event) const;
    void ProcessGetMeid(const AppExecFwk::InnerEvent::Pointer &event) const;
    void ProcessGetRadioCapability(const AppExecFwk::InnerEvent::Pointer &event) const;
    void UpdatePhone(RadioTech csRadioTech);
    void SetPhoneType(PhoneType phoneType);
    PhoneType GetPhoneType() const;
    void ProcessVoiceTechChange(const AppExecFwk::InnerEvent::Pointer &event);
    void AirplaneModeChange();
private:
    PhoneType RadioTechToPhoneType(RadioTech radioTech) const;
    PhoneType phoneType_ = PhoneType::PHONE_TYPE_IS_NONE;
    std::weak_ptr<NetworkSearchManager> networkSearchManager_;
    int32_t slotId_ = 0;
};
} // namespace Telephony
} // namespace OHOS
#endif // NETWORK_SEARCH_INCLUDE_RADIO_INFO_H
