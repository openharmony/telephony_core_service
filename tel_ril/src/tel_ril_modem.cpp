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
#include "tel_ril_modem.h"
#include "hril_modem_parcel.h"

namespace OHOS {
void TelRilModem::AddHandlerToMap()
{
    // indication
    memberFuncMap_[HNOTI_MODEM_RADIO_STATE_UPDATED] = &TelRilModem::RadioStateUpdated;
    // reponse
    memberFuncMap_[HREQ_MODEM_SET_RADIO_POWER] = &TelRilModem::SetRadioPowerResponse;
}

TelRilModem::TelRilModem(sptr<IRemoteObject> cellularRadio, std::shared_ptr<ObserverHandler> observerHandler)
    : TelRilBase(cellularRadio, observerHandler)
{
    AddHandlerToMap();
}

bool TelRilModem::IsCommonRespOrNotify(uint32_t code)
{
    return IsCommonResponse(code) || IsCommonNotification(code);
}
void TelRilModem::ProcessCommonRespOrNotify(uint32_t code, OHOS::MessageParcel &data)
{
    TELEPHONY_INFO_LOG(
        "TelRilModem ProcessCommonRespOrNotify code:%{public}u, GetDataSize:%{public}zu", code, data.GetDataSize());
    auto itFunc = memberFuncMap_.find(code);
    if (itFunc != memberFuncMap_.end()) {
        auto memberFunc = itFunc->second;
        if (memberFunc != nullptr) {
            (this->*memberFunc)(data);
        }
    }
}

bool TelRilModem::IsCommonResponse(uint32_t code)
{
    return code >= HREQ_COMMON_BASE;
}

bool TelRilModem::IsCommonNotification(uint32_t code)
{
    return code >= HREQ_COMMON_BASE;
}

void TelRilModem::SetModemRadioPower(bool on, const AppExecFwk::InnerEvent::Pointer &response)
{
    TELEPHONY_INFO_LOG("TelRilModem SetModemRadioPower  on: %{public}d", on);
    if (cellularRadio_ != nullptr) {
        std::shared_ptr<TelRilRequest> telRilRequest = CreateTelRilRequest(HREQ_MODEM_SET_RADIO_POWER, response);
        if (telRilRequest == nullptr) {
            TELEPHONY_DEBUG_LOG("SetModemRadioPower:telRilRequest is nullptr");
            return;
        }
        OHOS::MessageParcel wData;
        UniInfo universalInfo;
        universalInfo.serial = telRilRequest->serialId_;
        universalInfo.flag = on;
        universalInfo.Marshalling(wData);
        int ret = SendBufferEvent(HREQ_MODEM_SET_RADIO_POWER, wData);
        TELEPHONY_INFO_LOG("HREQ_MODEM_SET_RADIO_POWER ret %{public}d", ret);
    }
}

void TelRilModem::SetRadioPowerResponse(OHOS::MessageParcel &data)
{
    TELEPHONY_INFO_LOG("TelRilModem SetRadioPowerResponse --> ");
    const size_t readSpSize = sizeof(struct HRilRadioResponseInfo);
    const uint8_t *spBuffer = data.ReadUnpadBuffer(readSpSize);
    if (spBuffer == nullptr) {
        TELEPHONY_ERR_LOG("TelRilModem SetRadioPowerResponse read spBuffer failed");
        return;
    }
    const struct HRilRadioResponseInfo *radioResponseInfo =
        reinterpret_cast<const struct HRilRadioResponseInfo *>(spBuffer);
    if (radioResponseInfo == nullptr) {
        TELEPHONY_ERR_LOG("ERROR : SetRadioPowerResponse --> radioResponseInfo == nullptr !!!");
        return;
    }
    TELEPHONY_DEBUG_LOG(
        "SetRadioPowerResponse serial:%{public}d, error:%{public}d, "
        "type:%{public}d",
        radioResponseInfo->serial, radioResponseInfo->error, radioResponseInfo->type);
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(*radioResponseInfo);
    TELEPHONY_DEBUG_LOG("SetRadioPowerResponse serialId_:%{public}d, requestId_:%{public}d,",
        telRilRequest->serialId_, telRilRequest->requestId_);
    if (telRilRequest != nullptr && telRilRequest->pointer_ != nullptr) {
        if (radioResponseInfo->error == HRilErrType::NONE) {
            std::shared_ptr<OHOS::AppExecFwk::EventHandler> handler = telRilRequest->pointer_->GetOwner();
            if (handler == nullptr) {
                TELEPHONY_WARNING_LOG("WARNNING : SetRadioPowerResponse --> handler == nullptr !!!");
                return;
            }
            uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
            TELEPHONY_DEBUG_LOG("SetRadioPowerResponse eventId:%{public}d", eventId);
            handler->SendEvent(eventId);
        }

        if (radioResponseInfo->type == HRilResponseType::HRIL_RESP_ACK_NEED) {
            SendRespOrNotiAck();
        }
    }
}

ModemPowerState TelRilModem::GetRadioState()
{
    TELEPHONY_INFO_LOG("RilManager GetRadioState->");
    return radioState_;
}

ModemPowerState TelRilModem::GetRadioStatusFromInt(int32_t statusInt)
{
    ModemPowerState state = ModemPowerState::CORE_SERVICE_POWER_NOT_AVAILABLE;
    switch (statusInt) {
        case (int32_t)HRilRadioState::HRIL_RADIO_POWER_STATE_OFF:
            state = ModemPowerState::CORE_SERVICE_POWER_OFF;
            break;
        case (int32_t)HRilRadioState::HRIL_RADIO_POWER_STATE_UNAVAILABLE:
            state = ModemPowerState::CORE_SERVICE_POWER_NOT_AVAILABLE;
            break;
        case (int32_t)HRilRadioState::HRIL_RADIO_POWER_STATE_ON:
            state = ModemPowerState::CORE_SERVICE_POWER_ON;
            break;
        default:
            TELEPHONY_ERR_LOG(
                "TelRilModem GetRadioStatusFromInt Unrecognized HRilRadioState: %{public}d", statusInt);
    }
    return state;
}

void TelRilModem::RadioStateUpdated(OHOS::MessageParcel &data)
{
    int32_t radioState = data.ReadInt32();
    int32_t indicationType = data.ReadInt32();
    if (cellularRadio_ != nullptr) {
        RilProcessIndication(indicationType);
        ModemPowerState ModemPowerState = GetRadioStatusFromInt(radioState);

        TELEPHONY_INFO_LOG("TelRilModem RadioStateUpdate radioState:%{public}d, ModemPowerState:%{public}d",
            radioState, ModemPowerState);
        SetRadioPower(ModemPowerState);
    }
}
bool IsRadioOn(ModemPowerState state)
{
    return state == CORE_SERVICE_POWER_ON;
}

bool IsRadioAvailable(ModemPowerState state)
{
    return state != CORE_SERVICE_POWER_NOT_AVAILABLE;
}
void TelRilModem::SetRadioPower(ModemPowerState radioState)
{
    ModemPowerState oldRadioState = radioState_;
    radioState_ = radioState;

    if (oldRadioState == radioState_) {
        // no state transition
        return;
    }
    if (observerHandler_ != nullptr) {
        observerHandler_->NotifyObserver(ObserverHandler::RADIO_STATE_CHANGED);
        if (IsRadioAvailable(radioState_) && !IsRadioAvailable(oldRadioState)) {
            observerHandler_->NotifyObserver(ObserverHandler::RADIO_AVAIL);
        }
        if (!IsRadioOn(radioState_)) {
            if (IsRadioAvailable(oldRadioState)) {
                observerHandler_->NotifyObserver(ObserverHandler::RADIO_NOT_AVAIL);
            }
        } else {
            if (!IsRadioOn(oldRadioState) == false) {
                observerHandler_->NotifyObserver(ObserverHandler::RADIO_ON);
            }
        }
        if ((!IsRadioOn(radioState_) || !IsRadioAvailable(radioState_)) &&
            !((!IsRadioOn(oldRadioState) || !IsRadioAvailable(oldRadioState)))) {
            observerHandler_->NotifyObserver(ObserverHandler::RADIO_OFF_OR_NOT_AVAIL);
        }
    }
}
} // namespace OHOS
