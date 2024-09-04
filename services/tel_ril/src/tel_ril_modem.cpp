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

#include "common_event_manager.h"
#include "common_event_support.h"
#include "radio_event.h"
#include "want.h"

namespace OHOS {
namespace Telephony {
constexpr int32_t STATE_NV_REFREASH_FINNISHED = 1;

TelRilModem::TelRilModem(int32_t slotId, sptr<HDI::Ril::V1_3::IRil> rilInterface,
    std::shared_ptr<ObserverHandler> observerHandler, std::shared_ptr<TelRilHandler> handler)
    : TelRilBase(slotId, rilInterface, observerHandler, handler)
{}

int32_t TelRilModem::SetRadioStateResponse(const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo)
{
    auto getDataFunc = [&responseInfo](std::shared_ptr<TelRilRequest> telRilRequest) {
        std::unique_ptr<RadioStateInfo> radioState = std::make_unique<RadioStateInfo>();
        radioState->flag = telRilRequest->pointer_->GetParam();
        radioState->state = static_cast<int32_t>(responseInfo.error);
        return radioState;
    };
    return Response<std::unique_ptr<RadioStateInfo>>(TELEPHONY_LOG_FUNC_NAME, responseInfo, getDataFunc);
}

int32_t TelRilModem::GetRadioStateResponse(const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo, int32_t state)
{
    auto getDataFunc = [state](std::shared_ptr<TelRilRequest> telRilRequest) {
        std::unique_ptr<RadioStateInfo> radioState = std::make_unique<RadioStateInfo>();
        radioState->flag = telRilRequest->pointer_->GetParam();
        radioState->state = state;
        return radioState;
    };
    return Response<std::unique_ptr<RadioStateInfo>>(TELEPHONY_LOG_FUNC_NAME, responseInfo, getDataFunc);
}

int32_t TelRilModem::ShutDown(const AppExecFwk::InnerEvent::Pointer &response)
{
    return Request(TELEPHONY_LOG_FUNC_NAME, response, &HDI::Ril::V1_1::IRil::ShutDown);
}

int32_t TelRilModem::SetRadioState(int32_t fun, int32_t rst, const AppExecFwk::InnerEvent::Pointer &response)
{
    return Request(TELEPHONY_LOG_FUNC_NAME, response, &HDI::Ril::V1_1::IRil::SetRadioState, fun, rst);
}

int32_t TelRilModem::GetRadioState(const AppExecFwk::InnerEvent::Pointer &response)
{
    return Request(TELEPHONY_LOG_FUNC_NAME, response, &HDI::Ril::V1_1::IRil::GetRadioState);
}

int32_t TelRilModem::GetImei(const AppExecFwk::InnerEvent::Pointer &response)
{
    return Request(TELEPHONY_LOG_FUNC_NAME, response, &HDI::Ril::V1_1::IRil::GetImei);
}

int32_t TelRilModem::GetImeiSv(const AppExecFwk::InnerEvent::Pointer &response)
{
    return Request(TELEPHONY_LOG_FUNC_NAME, response, &HDI::Ril::V1_3::IRil::GetImeiSv);
}

int32_t TelRilModem::GetMeid(const AppExecFwk::InnerEvent::Pointer &response)
{
    return Request(TELEPHONY_LOG_FUNC_NAME, response, &HDI::Ril::V1_1::IRil::GetMeid);
}

int32_t TelRilModem::GetVoiceRadioTechnology(const AppExecFwk::InnerEvent::Pointer &response)
{
    return Request(TELEPHONY_LOG_FUNC_NAME, response, &HDI::Ril::V1_1::IRil::GetVoiceRadioTechnology);
}

int32_t TelRilModem::GetBasebandVersion(const AppExecFwk::InnerEvent::Pointer &response)
{
    return Request(TELEPHONY_LOG_FUNC_NAME, response, &HDI::Ril::V1_1::IRil::GetBasebandVersion);
}

int32_t TelRilModem::ShutDownResponse(const HDI::Ril::V1_1::RilRadioResponseInfo responseInfo)
{
    return Response(TELEPHONY_LOG_FUNC_NAME, responseInfo);
}

int32_t TelRilModem::GetImeiResponse(const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo, const std::string &imei)
{
    return Response<StringParcel>(TELEPHONY_LOG_FUNC_NAME, responseInfo, std::make_shared<StringParcel>(imei));
}

int32_t TelRilModem::GetImeiSvResponse(
    const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo, const std::string &imeiSv)
{
    return Response<StringParcel>(TELEPHONY_LOG_FUNC_NAME, responseInfo, std::make_shared<StringParcel>(imeiSv));
}

int32_t TelRilModem::GetMeidResponse(const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo, const std::string &meid)
{
    return Response<StringParcel>(TELEPHONY_LOG_FUNC_NAME, responseInfo, std::make_shared<StringParcel>(meid));
}

int32_t TelRilModem::GetVoiceRadioTechnologyResponse(const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo,
    const HDI::Ril::V1_1::VoiceRadioTechnology &voiceRadioTechnology)
{
    std::shared_ptr<VoiceRadioTechnology> mVoiceRadioTechnology = std::make_shared<VoiceRadioTechnology>();
    BuildVoiceRadioTechnology(voiceRadioTechnology, mVoiceRadioTechnology);
    return Response<VoiceRadioTechnology>(TELEPHONY_LOG_FUNC_NAME, responseInfo, mVoiceRadioTechnology);
}

int32_t TelRilModem::GetBasebandVersionResponse(
    const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo, const std::string &basebandVersion)
{
    return Response<StringParcel>(
        TELEPHONY_LOG_FUNC_NAME, responseInfo, std::make_shared<StringParcel>(basebandVersion));
}

int32_t TelRilModem::OnRilAdapterHostDied()
{
    int32_t result = Notify(TELEPHONY_LOG_FUNC_NAME, RadioEvent::RADIO_RIL_ADAPTER_HOST_DIED);
    if (result == TELEPHONY_ERR_SUCCESS) {
        TELEPHONY_LOGI("Notify RIL died successfully.");
        result = RadioStateUpdated(ModemPowerState::CORE_SERVICE_POWER_NOT_AVAILABLE);
    }
    return result;
}

int32_t TelRilModem::RadioStateUpdated(int32_t state)
{
    AAFwk::Want want;
    want.SetParam("slotId", slotId_);
    want.SetParam("radioState", state);
    want.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_RADIO_STATE_CHANGE);
    EventFwk::CommonEventData commonEventData;
    commonEventData.SetWant(want);
    EventFwk::CommonEventPublishInfo publishInfo;
    bool result = EventFwk::CommonEventManager::PublishCommonEvent(commonEventData, publishInfo, nullptr);
    TELEPHONY_LOGD("publish modem subscribed event result : %{public}d", result);
    return Notify<Int32Parcel>(
        TELEPHONY_LOG_FUNC_NAME, std::make_shared<Int32Parcel>(state), RadioEvent::RADIO_STATE_CHANGED);
}

int32_t TelRilModem::VoiceRadioTechUpdated(const HDI::Ril::V1_1::VoiceRadioTechnology &voiceRadioTechnology)
{
    std::shared_ptr<VoiceRadioTechnology> mVoiceRadioTechnology = std::make_shared<VoiceRadioTechnology>();
    BuildVoiceRadioTechnology(voiceRadioTechnology, mVoiceRadioTechnology);
    return Notify<VoiceRadioTechnology>(
        TELEPHONY_LOG_FUNC_NAME, mVoiceRadioTechnology, RadioEvent::RADIO_VOICE_TECH_CHANGED);
}

int32_t TelRilModem::DsdsModeUpdated(int32_t mode)
{
    return Notify<Int32Parcel>(
        TELEPHONY_LOG_FUNC_NAME, std::make_shared<Int32Parcel>(mode), RadioEvent::RADIO_DSDS_MODE_CHANGED);
}

int32_t TelRilModem::NcfgFinishedResult(int32_t state)
{
    if (state == STATE_NV_REFREASH_FINNISHED) {
        return Notify<Int32Parcel>(
            TELEPHONY_LOG_FUNC_NAME, std::make_shared<Int32Parcel>(state), RadioEvent::RADIO_NV_REFRESH_FINISHED);
    }
    return TELEPHONY_ERR_SUCCESS;
}

int32_t TelRilModem::RestartRildNvMatch(int32_t state)
{
    return Notify<Int32Parcel>(
        TELEPHONY_LOG_FUNC_NAME, std::make_shared<Int32Parcel>(state), RadioEvent::RADIO_DSDS_MODE_CHANGED);
}

void TelRilModem::BuildVoiceRadioTechnology(const HDI::Ril::V1_1::VoiceRadioTechnology &voiceRadioTechnology,
    std::shared_ptr<VoiceRadioTechnology> &mVoiceRadioTechnology)
{
    if (mVoiceRadioTechnology == nullptr) {
        return;
    }
    mVoiceRadioTechnology->srvStatus = static_cast<SrvStatus>(voiceRadioTechnology.srvStatus);
    mVoiceRadioTechnology->srvDomain = static_cast<SrvDomain>(voiceRadioTechnology.srvDomain);
    mVoiceRadioTechnology->roamStatus = static_cast<RoamStatus>(voiceRadioTechnology.roamStatus);
    mVoiceRadioTechnology->simStatus = static_cast<SimStatus>(voiceRadioTechnology.simStatus);
    mVoiceRadioTechnology->lockStatus = static_cast<SimLockStatus>(voiceRadioTechnology.lockStatus);
    mVoiceRadioTechnology->sysMode = static_cast<SysMode>(voiceRadioTechnology.sysMode);
    mVoiceRadioTechnology->sysModeName = voiceRadioTechnology.sysModeName;
    mVoiceRadioTechnology->actType = static_cast<TelRilRadioTech>(voiceRadioTechnology.actType);
    mVoiceRadioTechnology->actName = voiceRadioTechnology.actName;
}
} // namespace Telephony
} // namespace OHOS
