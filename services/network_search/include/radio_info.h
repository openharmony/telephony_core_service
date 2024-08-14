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
#include "tel_ril_types.h"
#include "tel_ril_modem_parcel.h"
#include "message_parcel.h"
#include "network_state.h"
#include "telephony_types.h"
#include "telephony_ext_wrapper.h"

namespace OHOS {
namespace Telephony {
class NetworkSearchManager;
class RadioInfo {
public:
    RadioInfo(std::weak_ptr<NetworkSearchManager> networkSearchManager, int32_t slotId);
    virtual ~RadioInfo() = default;
    void ProcessGetRadioState(const AppExecFwk::InnerEvent::Pointer &event) const;
    void ProcessSetRadioState(const AppExecFwk::InnerEvent::Pointer &event) const;
    void RadioFirstPowerOn(std::shared_ptr<NetworkSearchManager> &nsm, ModemPowerState radioState) const;
    void ProcessGetImei(const AppExecFwk::InnerEvent::Pointer &event) const;
    void ProcessGetImeiSv(const AppExecFwk::InnerEvent::Pointer &event) const;
    void ProcessGetMeid(const AppExecFwk::InnerEvent::Pointer &event) const;
    void UpdatePhone(RadioTech csRadioTech, const RadioTech &psRadioTech);
    void SetPhoneType(PhoneType phoneType);
    PhoneType GetPhoneType() const;
    void ProcessVoiceTechChange(const AppExecFwk::InnerEvent::Pointer &event);
    void AirplaneModeChange();
    int32_t ProcessGetBasebandVersion(const AppExecFwk::InnerEvent::Pointer &event) const;
    int32_t ProcessSetNrOptionMode(const AppExecFwk::InnerEvent::Pointer &event) const;
    int32_t ProcessGetNrOptionMode(const AppExecFwk::InnerEvent::Pointer &event) const;
    int32_t ProcessGetRrcConnectionState(const AppExecFwk::InnerEvent::Pointer &event) const;

private:
    PhoneType RadioTechToPhoneType(RadioTech csRadioTech, const RadioTech &psRadioTech) const;
    bool WriteRadioStateResponseInfo(
        int64_t &index, MessageParcel &data, bool result, std::shared_ptr<RadioResponseInfo> &responseInfo) const;
    bool WriteRadioStateObject(
        int64_t &index, MessageParcel &data, bool result, std::unique_ptr<RadioStateInfo> &object) const;
    void UpdateInfoOfSetRadioState(ModemPowerState &radioState, bool result, MessageParcel &data, int64_t index) const;
    void SetRadioOnIfNeeded();
    PhoneType phoneType_ = PhoneType::PHONE_TYPE_IS_NONE;
    std::weak_ptr<NetworkSearchManager> networkSearchManager_;
    int32_t slotId_ = 0;
};
} // namespace Telephony
} // namespace OHOS
#endif // NETWORK_SEARCH_INCLUDE_RADIO_INFO_H
