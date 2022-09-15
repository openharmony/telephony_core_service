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
#include "want.h"
#include "common_event_manager.h"
#include "common_event_support.h"

namespace OHOS {
namespace Telephony {
TelRilModem::TelRilModem(int32_t slotId, sptr<IRemoteObject> cellularRadio, sptr<HDI::Ril::V1_0::IRil> rilInterface,
    std::shared_ptr<ObserverHandler> observerHandler, std::shared_ptr<TelRilHandler> handler)
    : TelRilBase(slotId, cellularRadio, rilInterface, observerHandler, handler)
{}

int32_t TelRilModem::SetRadioStateResponse(const HDI::Ril::V1_0::RilRadioResponseInfo &responseInfo)
{
    auto getDataFunc = [&responseInfo](std::shared_ptr<TelRilRequest> telRilRequest) {
        std::unique_ptr<HRilRadioStateInfo> radioState = std::make_unique<HRilRadioStateInfo>();
        radioState->flag = telRilRequest->pointer_->GetParam();
        radioState->state = static_cast<int32_t>(responseInfo.error);
        return radioState;
    };
    return Response<std::unique_ptr<HRilRadioStateInfo>>(TELEPHONY_LOG_FUNC_NAME, responseInfo, getDataFunc);
}

int32_t TelRilModem::GetRadioStateResponse(const HDI::Ril::V1_0::RilRadioResponseInfo &responseInfo, int32_t state)
{
    auto getDataFunc = [state](std::shared_ptr<TelRilRequest> telRilRequest) {
        std::unique_ptr<HRilRadioStateInfo> radioState = std::make_unique<HRilRadioStateInfo>();
        radioState->flag = telRilRequest->pointer_->GetParam();
        radioState->state = state;
        return radioState;
    };
    return Response<std::unique_ptr<HRilRadioStateInfo>>(TELEPHONY_LOG_FUNC_NAME, responseInfo, getDataFunc);
}

int32_t TelRilModem::ShutDown(const AppExecFwk::InnerEvent::Pointer &response)
{
    return Request(TELEPHONY_LOG_FUNC_NAME, response, HREQ_MODEM_SHUT_DOWN, &HDI::Ril::V1_0::IRil::ShutDown);
}

int32_t TelRilModem::SetRadioState(int32_t fun, int32_t rst, const AppExecFwk::InnerEvent::Pointer &response)
{
    return Request(
        TELEPHONY_LOG_FUNC_NAME, response, HREQ_MODEM_SET_RADIO_STATUS, &HDI::Ril::V1_0::IRil::SetRadioState, fun, rst);
}

int32_t TelRilModem::GetRadioState(const AppExecFwk::InnerEvent::Pointer &response)
{
    return Request(
        TELEPHONY_LOG_FUNC_NAME, response, HREQ_MODEM_GET_RADIO_STATUS, &HDI::Ril::V1_0::IRil::GetRadioState);
}

int32_t TelRilModem::GetImei(const AppExecFwk::InnerEvent::Pointer &response)
{
    return Request(TELEPHONY_LOG_FUNC_NAME, response, HREQ_MODEM_GET_IMEI, &HDI::Ril::V1_0::IRil::GetImei);
}

int32_t TelRilModem::GetMeid(const AppExecFwk::InnerEvent::Pointer &response)
{
    return Request(TELEPHONY_LOG_FUNC_NAME, response, HREQ_MODEM_GET_MEID, &HDI::Ril::V1_0::IRil::GetMeid);
}

int32_t TelRilModem::GetVoiceRadioTechnology(const AppExecFwk::InnerEvent::Pointer &response)
{
    return Request(
        TELEPHONY_LOG_FUNC_NAME, response, HREQ_MODEM_GET_VOICE_RADIO, &HDI::Ril::V1_0::IRil::GetVoiceRadioTechnology);
}

int32_t TelRilModem::GetBasebandVersion(const AppExecFwk::InnerEvent::Pointer &response)
{
    return Request(
        TELEPHONY_LOG_FUNC_NAME, response, HREQ_MODEM_GET_BASEBAND_VERSION, &HDI::Ril::V1_0::IRil::GetBasebandVersion);
}

int32_t TelRilModem::ShutDownResponse(const HDI::Ril::V1_0::RilRadioResponseInfo responseInfo)
{
    return Response(TELEPHONY_LOG_FUNC_NAME, responseInfo);
}

int32_t TelRilModem::GetImeiResponse(const HDI::Ril::V1_0::RilRadioResponseInfo &responseInfo, const std::string &imei)
{
    return Response<HRilStringParcel>(TELEPHONY_LOG_FUNC_NAME, responseInfo, std::make_shared<HRilStringParcel>(imei));
}

int32_t TelRilModem::GetMeidResponse(const HDI::Ril::V1_0::RilRadioResponseInfo &responseInfo, const std::string &meid)
{
    return Response<HRilStringParcel>(TELEPHONY_LOG_FUNC_NAME, responseInfo, std::make_shared<HRilStringParcel>(meid));
}

int32_t TelRilModem::GetVoiceRadioTechnologyResponse(const HDI::Ril::V1_0::RilRadioResponseInfo &responseInfo,
    const HDI::Ril::V1_0::VoiceRadioTechnology &voiceRadioTechnology)
{
    std::shared_ptr<VoiceRadioTechnology> mVoiceRadioTechnology = std::make_shared<VoiceRadioTechnology>();
    BuildVoiceRadioTechnology(voiceRadioTechnology, mVoiceRadioTechnology);
    return Response<VoiceRadioTechnology>(TELEPHONY_LOG_FUNC_NAME, responseInfo, mVoiceRadioTechnology);
}

int32_t TelRilModem::GetBasebandVersionResponse(
    const HDI::Ril::V1_0::RilRadioResponseInfo &responseInfo, const std::string &basebandVersion)
{
    return Response<HRilStringParcel>(
        TELEPHONY_LOG_FUNC_NAME, responseInfo, std::make_shared<HRilStringParcel>(basebandVersion));
}

int32_t TelRilModem::RadioStateUpdated(int32_t state)
{
    AAFwk::Want want;
    want.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_RADIO_STATE_CHANGE);
    EventFwk::CommonEventData commonEventData;
    commonEventData.SetWant(want);
    EventFwk::CommonEventPublishInfo publishInfo;
    bool retsult = EventFwk::CommonEventManager::PublishCommonEvent(commonEventData, publishInfo, nullptr);
    TELEPHONY_LOGI("publish modem subscribed event result : %{public}d", retsult);
    return Notify<HRilInt32Parcel>(
        TELEPHONY_LOG_FUNC_NAME, std::make_shared<HRilInt32Parcel>(state), RadioEvent::RADIO_STATE_CHANGED);
}

int32_t TelRilModem::VoiceRadioTechUpdated(const HDI::Ril::V1_0::VoiceRadioTechnology &voiceRadioTechnology)
{
    std::shared_ptr<VoiceRadioTechnology> mVoiceRadioTechnology = std::make_shared<VoiceRadioTechnology>();
    BuildVoiceRadioTechnology(voiceRadioTechnology, mVoiceRadioTechnology);
    return Notify<VoiceRadioTechnology>(
        TELEPHONY_LOG_FUNC_NAME, mVoiceRadioTechnology, RadioEvent::RADIO_VOICE_TECH_CHANGED);
}

void TelRilModem::BuildVoiceRadioTechnology(const HDI::Ril::V1_0::VoiceRadioTechnology &voiceRadioTechnology,
    std::shared_ptr<VoiceRadioTechnology> &mVoiceRadioTechnology)
{
    if (mVoiceRadioTechnology == nullptr) {
        return;
    }
    mVoiceRadioTechnology->srvStatus = static_cast<HRilSrvStatus>(voiceRadioTechnology.srvStatus);
    mVoiceRadioTechnology->srvDomain = static_cast<HRilSrvDomain>(voiceRadioTechnology.srvDomain);
    mVoiceRadioTechnology->roamStatus = static_cast<HRilRoamStatus>(voiceRadioTechnology.roamStatus);
    mVoiceRadioTechnology->simStatus = static_cast<HRilSimStatus>(voiceRadioTechnology.simStatus);
    mVoiceRadioTechnology->lockStatus = static_cast<HRilSimLockStatus>(voiceRadioTechnology.lockStatus);
    mVoiceRadioTechnology->sysMode = static_cast<HRilSysMode>(voiceRadioTechnology.sysMode);
    mVoiceRadioTechnology->sysModeName = voiceRadioTechnology.sysModeName;
    mVoiceRadioTechnology->actType = static_cast<HRilRadioTech>(voiceRadioTechnology.actType);
    mVoiceRadioTechnology->actName = voiceRadioTechnology.actName;
}
} // namespace Telephony
} // namespace OHOS
