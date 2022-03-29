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

#include "hril_notification.h"
#include "hril_request.h"
#include "radio_event.h"

namespace OHOS {
namespace Telephony {
void TelRilModem::AddHandlerToMap()
{
    // indication
    memberFuncMap_[HNOTI_MODEM_RADIO_STATE_UPDATED] = &TelRilModem::RadioStateUpdated;
    memberFuncMap_[HNOTI_MODEM_VOICE_TECH_UPDATED] = &TelRilModem::VoiceRadioTechUpdated;
    // response
    memberFuncMap_[HREQ_MODEM_SET_RADIO_STATUS] = &TelRilModem::SetRadioStateResponse;
    memberFuncMap_[HREQ_MODEM_GET_RADIO_STATUS] = &TelRilModem::GetRadioStateResponse;
    memberFuncMap_[HREQ_MODEM_GET_IMEI] = &TelRilModem::GetImeiResponse;
    memberFuncMap_[HREQ_MODEM_GET_MEID] = &TelRilModem::GetMeidResponse;
    memberFuncMap_[HREQ_MODEM_GET_VOICE_RADIO] = &TelRilModem::GetVoiceRadioTechnologyResponse;
}

TelRilModem::TelRilModem(int32_t slotId, sptr<IRemoteObject> cellularRadio,
    std::shared_ptr<ObserverHandler> observerHandler, std::shared_ptr<TelRilHandler> handler)
    : TelRilBase(slotId, cellularRadio, observerHandler, handler)
{
    AddHandlerToMap();
}

bool TelRilModem::IsCommonRespOrNotify(uint32_t code)
{
    return IsCommonResponse(code) || IsCommonNotification(code);
}

bool TelRilModem::IsCommonResponse(uint32_t code)
{
    return code >= HREQ_COMMON_BASE;
}

bool TelRilModem::IsCommonNotification(uint32_t code)
{
    return code >= HREQ_COMMON_BASE;
}

int32_t TelRilModem::SetRadioStateResponse(MessageParcel &data)
{
    auto sendData = [](UserEvent &userEvent) -> int32_t {
        std::unique_ptr<HRilRadioStateInfo> radioState = std::make_unique<HRilRadioStateInfo>();
        radioState->flag = userEvent.telRilRequest_.pointer_->GetParam();
        radioState->state = (int32_t)(userEvent.radioResponseInfo_.error);
        return userEvent.handler_.SendEvent(userEvent.eventId_, radioState);
    };
    return Response(TELEPHONY_LOG_FUNC_NAME, data, (UserSendEvent)sendData);
}

int32_t TelRilModem::GetRadioStateResponse(MessageParcel &data)
{
    auto sendData = [](UserEvent &userEvent) -> int32_t {
        std::shared_ptr<HRilInt32Parcel> state = std::make_shared<HRilInt32Parcel>();
        state->ReadFromParcel(userEvent.data_);

        std::unique_ptr<HRilRadioStateInfo> radioState = std::make_unique<HRilRadioStateInfo>();
        radioState->flag = userEvent.telRilRequest_.pointer_->GetParam();
        radioState->state = state->data;
        return userEvent.handler_.SendEvent(userEvent.eventId_, radioState);
    };
    return Response(TELEPHONY_LOG_FUNC_NAME, data, (UserSendEvent)sendData);
}

int32_t TelRilModem::SetRadioState(int32_t fun, int32_t rst, const AppExecFwk::InnerEvent::Pointer &response)
{
    return Request(TELEPHONY_LOG_FUNC_NAME, response, (uint32_t)HREQ_MODEM_SET_RADIO_STATUS, fun, rst);
}

int32_t TelRilModem::GetRadioState(const AppExecFwk::InnerEvent::Pointer &response)
{
    return Request(TELEPHONY_LOG_FUNC_NAME, response, (uint32_t)HREQ_MODEM_GET_RADIO_STATUS);
}

int32_t TelRilModem::GetImei(const AppExecFwk::InnerEvent::Pointer &response)
{
    return Request(TELEPHONY_LOG_FUNC_NAME, response, (uint32_t)HREQ_MODEM_GET_IMEI);
}

int32_t TelRilModem::GetMeid(const AppExecFwk::InnerEvent::Pointer &response)
{
    return Request(TELEPHONY_LOG_FUNC_NAME, response, (uint32_t)HREQ_MODEM_GET_MEID);
}

int32_t TelRilModem::GetVoiceRadioTechnology(const AppExecFwk::InnerEvent::Pointer &response)
{
    return Request(TELEPHONY_LOG_FUNC_NAME, response, (uint32_t)HREQ_MODEM_GET_VOICE_RADIO);
}

int32_t TelRilModem::GetImeiResponse(MessageParcel &data)
{
    return Response<HRilStringParcel>(TELEPHONY_LOG_FUNC_NAME, data);
}

int32_t TelRilModem::GetMeidResponse(MessageParcel &data)
{
    return Response<HRilStringParcel>(TELEPHONY_LOG_FUNC_NAME, data);
}

int32_t TelRilModem::GetVoiceRadioTechnologyResponse(MessageParcel &data)
{
    return Response<VoiceRadioTechnology>(TELEPHONY_LOG_FUNC_NAME, data);
}

int32_t TelRilModem::RadioStateUpdated(MessageParcel &data)
{
    return Notify<HRilInt32Parcel>(TELEPHONY_LOG_FUNC_NAME, data, RadioEvent::RADIO_STATE_CHANGED);
}

int32_t TelRilModem::VoiceRadioTechUpdated(MessageParcel &data)
{
    return Notify<VoiceRadioTechnology>(TELEPHONY_LOG_FUNC_NAME, data, RadioEvent::RADIO_VOICE_TECH_CHANGED);
}
} // namespace Telephony
} // namespace OHOS