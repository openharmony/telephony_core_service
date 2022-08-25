/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#include "tel_ril_callback.h"

namespace OHOS {
namespace Telephony {
TelRilCallback::TelRilCallback(std::shared_ptr<TelRilManager> telRilManager) : telRilManager_(telRilManager) {}

// Call
int32_t TelRilCallback::SetEmergencyCallListResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo)
{
    return TaskSchedule(
        responseInfo.slotId, &TelRilManager::GetTelRilCall, &TelRilCall::SetEmergencyCallListResponse, responseInfo);
}

int32_t TelRilCallback::GetEmergencyCallListResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo,
    const HDI::Ril::V1_0::IEmergencyInfoList &emergencyInfoList)
{
    return TaskSchedule(responseInfo.slotId, &TelRilManager::GetTelRilCall, &TelRilCall::GetEmergencyCallListResponse,
        responseInfo, emergencyInfoList);
}

int32_t TelRilCallback::CallEmergencyNotice(int32_t slotId, const HDI::Ril::V1_0::IEmergencyInfoList &emergencyInfoList)
{
    return TaskSchedule(slotId, &TelRilManager::GetTelRilCall, &TelRilCall::CallEmergencyNotice, emergencyInfoList);
}

int32_t TelRilCallback::CallStateUpdated(int32_t slotId, int32_t type)
{
    return TaskSchedule(slotId, &TelRilManager::GetTelRilCall, &TelRilCall::CallStateUpdated, type);
}

int32_t TelRilCallback::CallRingbackVoiceNotice(int32_t slotId, const HDI::Ril::V1_0::IRingbackVoice &ringbackVoice)
{
    return TaskSchedule(slotId, &TelRilManager::GetTelRilCall, &TelRilCall::CallRingbackVoiceNotice, ringbackVoice);
}

int32_t TelRilCallback::CallSrvccStatusNotice(int32_t slotId, const HDI::Ril::V1_0::ISrvccStatus &srvccStatus)
{
    return TaskSchedule(slotId, &TelRilManager::GetTelRilCall, &TelRilCall::CallSrvccStatusNotice, srvccStatus);
}

int32_t TelRilCallback::CallUssdNotice(int32_t slotId, const HDI::Ril::V1_0::IUssdNoticeInfo &ussdNoticeInfo)
{
    return TaskSchedule(slotId, &TelRilManager::GetTelRilCall, &TelRilCall::CallUssdNotice, ussdNoticeInfo);
}

int32_t TelRilCallback::CallSsNotice(int32_t slotId, const HDI::Ril::V1_0::ISsNoticeInfo &ssNoticeInfo)
{
    return TaskSchedule(slotId, &TelRilManager::GetTelRilCall, &TelRilCall::CallSsNotice, ssNoticeInfo);
}

int32_t TelRilCallback::GetCallListResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo,
    const HDI::Ril::V1_0::ICallInfoList &callList)
{
    return TaskSchedule(responseInfo.slotId, &TelRilManager::GetTelRilCall, &TelRilCall::GetCallListResponse,
        responseInfo, callList);
}

int32_t TelRilCallback::DialResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo)
{
    return TaskSchedule(
        responseInfo.slotId, &TelRilManager::GetTelRilCall, &TelRilCall::DialResponse, responseInfo);
}

int32_t TelRilCallback::HangupResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo)
{
    return TaskSchedule(
        responseInfo.slotId, &TelRilManager::GetTelRilCall, &TelRilCall::HangupResponse, responseInfo);
}

int32_t TelRilCallback::RejectResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo)
{
    return TaskSchedule(
        responseInfo.slotId, &TelRilManager::GetTelRilCall, &TelRilCall::RejectResponse, responseInfo);
}

int32_t TelRilCallback::AnswerResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo)
{
    return TaskSchedule(
        responseInfo.slotId, &TelRilManager::GetTelRilCall, &TelRilCall::AnswerResponse, responseInfo);
}

int32_t TelRilCallback::HoldCallResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo)
{
    return TaskSchedule(
        responseInfo.slotId, &TelRilManager::GetTelRilCall, &TelRilCall::HoldCallResponse, responseInfo);
}

int32_t TelRilCallback::UnHoldCallResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo)
{
    return TaskSchedule(
        responseInfo.slotId, &TelRilManager::GetTelRilCall, &TelRilCall::UnHoldCallResponse, responseInfo);
}

int32_t TelRilCallback::SwitchCallResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo)
{
    return TaskSchedule(
        responseInfo.slotId, &TelRilManager::GetTelRilCall, &TelRilCall::SwitchCallResponse, responseInfo);
}

int32_t TelRilCallback::GetClipResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo,
    const HDI::Ril::V1_0::IGetClipResult &getClipResult)
{
    return TaskSchedule(responseInfo.slotId, &TelRilManager::GetTelRilCall, &TelRilCall::GetClipResponse,
        responseInfo, getClipResult);
}

int32_t TelRilCallback::SetClipResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo)
{
    return TaskSchedule(
        responseInfo.slotId, &TelRilManager::GetTelRilCall, &TelRilCall::SetClipResponse, responseInfo);
}

int32_t TelRilCallback::CombineConferenceResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo)
{
    return TaskSchedule(
        responseInfo.slotId, &TelRilManager::GetTelRilCall, &TelRilCall::CombineConferenceResponse, responseInfo);
}

int32_t TelRilCallback::SeparateConferenceResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo)
{
    return TaskSchedule(
        responseInfo.slotId, &TelRilManager::GetTelRilCall, &TelRilCall::SeparateConferenceResponse, responseInfo);
}

int32_t TelRilCallback::CallSupplementResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo)
{
    return TaskSchedule(
        responseInfo.slotId, &TelRilManager::GetTelRilCall, &TelRilCall::CallSupplementResponse, responseInfo);
}

int32_t TelRilCallback::GetCallWaitingResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo,
    const HDI::Ril::V1_0::ICallWaitResult &callWaitResult)
{
    return TaskSchedule(responseInfo.slotId, &TelRilManager::GetTelRilCall, &TelRilCall::GetCallWaitingResponse,
        responseInfo, callWaitResult);
}

int32_t TelRilCallback::SetCallWaitingResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo)
{
    return TaskSchedule(
        responseInfo.slotId, &TelRilManager::GetTelRilCall, &TelRilCall::SetCallWaitingResponse, responseInfo);
}

int32_t TelRilCallback::GetCallTransferInfoResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo,
    const HDI::Ril::V1_0::ICallForwardQueryInfoList &cFQueryList)
{
    return TaskSchedule(responseInfo.slotId, &TelRilManager::GetTelRilCall, &TelRilCall::GetCallTransferInfoResponse,
        responseInfo, cFQueryList);
}

int32_t TelRilCallback::SetCallTransferInfoResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo)
{
    return TaskSchedule(
        responseInfo.slotId, &TelRilManager::GetTelRilCall, &TelRilCall::SetCallTransferInfoResponse, responseInfo);
}

int32_t TelRilCallback::GetCallRestrictionResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo,
    const HDI::Ril::V1_0::ICallRestrictionResult &result)
{
    return TaskSchedule(responseInfo.slotId, &TelRilManager::GetTelRilCall, &TelRilCall::GetCallRestrictionResponse,
        responseInfo, result);
}

int32_t TelRilCallback::SetCallRestrictionResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo)
{
    return TaskSchedule(
        responseInfo.slotId, &TelRilManager::GetTelRilCall, &TelRilCall::SetCallRestrictionResponse, responseInfo);
}

int32_t TelRilCallback::GetClirResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo,
    const HDI::Ril::V1_0::IGetClirResult &getClirResult)
{
    return TaskSchedule(responseInfo.slotId, &TelRilManager::GetTelRilCall, &TelRilCall::GetClirResponse,
        responseInfo, getClirResult);
}

int32_t TelRilCallback::SetClirResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo)
{
    return TaskSchedule(
        responseInfo.slotId, &TelRilManager::GetTelRilCall, &TelRilCall::SetClirResponse, responseInfo);
}

int32_t TelRilCallback::StartDtmfResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo)
{
    return TaskSchedule(
        responseInfo.slotId, &TelRilManager::GetTelRilCall, &TelRilCall::StartDtmfResponse, responseInfo);
}

int32_t TelRilCallback::SendDtmfResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo)
{
    return TaskSchedule(
        responseInfo.slotId, &TelRilManager::GetTelRilCall, &TelRilCall::SendDtmfResponse, responseInfo);
}

int32_t TelRilCallback::StopDtmfResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo)
{
    return TaskSchedule(
        responseInfo.slotId, &TelRilManager::GetTelRilCall, &TelRilCall::StopDtmfResponse, responseInfo);
}

int32_t TelRilCallback::GetCallPreferenceModeResponse(
    const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo, int32_t mode)
{
    return TaskSchedule(responseInfo.slotId, &TelRilManager::GetTelRilCall,
        &TelRilCall::GetCallPreferenceModeResponse, responseInfo, mode);
}

int32_t TelRilCallback::SetCallPreferenceModeResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo)
{
    return TaskSchedule(
        responseInfo.slotId, &TelRilManager::GetTelRilCall, &TelRilCall::SetCallPreferenceModeResponse, responseInfo);
}

int32_t TelRilCallback::SetUssdResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo)
{
    return TaskSchedule(
        responseInfo.slotId, &TelRilManager::GetTelRilCall, &TelRilCall::SetUssdResponse, responseInfo);
}

int32_t TelRilCallback::GetUssdResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo, int32_t cusd)
{
    return TaskSchedule(
        responseInfo.slotId, &TelRilManager::GetTelRilCall, &TelRilCall::GetUssdResponse, responseInfo, cusd);
}

int32_t TelRilCallback::SetMuteResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo)
{
    return TaskSchedule(
        responseInfo.slotId, &TelRilManager::GetTelRilCall, &TelRilCall::SetMuteResponse, responseInfo);
}

int32_t TelRilCallback::GetMuteResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo, int32_t mute)
{
    return TaskSchedule(
        responseInfo.slotId, &TelRilManager::GetTelRilCall, &TelRilCall::GetMuteResponse, responseInfo, mute);
}

int32_t TelRilCallback::GetCallFailReasonResponse(
    const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo, int32_t callFail)
{
    return TaskSchedule(responseInfo.slotId, &TelRilManager::GetTelRilCall, &TelRilCall::GetCallFailReasonResponse,
        responseInfo, callFail);
}

int32_t TelRilCallback::SetBarringPasswordResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo)
{
    return TaskSchedule(
        responseInfo.slotId, &TelRilManager::GetTelRilCall, &TelRilCall::SetBarringPasswordResponse, responseInfo);
}

// Data
int32_t TelRilCallback::PdpContextListUpdated(
    int32_t slotId, const HDI::Ril::V1_0::IDataCallResultList &dataCallResultList)
{
    return TaskSchedule(slotId, &TelRilManager::GetTelRilData, &TelRilData::PdpContextListUpdated, dataCallResultList);
}

int32_t TelRilCallback::ActivatePdpContextResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo,
    const HDI::Ril::V1_0::ISetupDataCallResultInfo &setupDataCallResultInfo)
{
    return TaskSchedule(responseInfo.slotId, &TelRilManager::GetTelRilData, &TelRilData::ActivatePdpContextResponse,
        responseInfo, setupDataCallResultInfo);
}

int32_t TelRilCallback::DeactivatePdpContextResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo)
{
    return TaskSchedule(
        responseInfo.slotId, &TelRilManager::GetTelRilData, &TelRilData::DeactivatePdpContextResponse, responseInfo);
}

int32_t TelRilCallback::GetPdpContextListResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo,
    const HDI::Ril::V1_0::IDataCallResultList &dataCallResultList)
{
    return TaskSchedule(responseInfo.slotId, &TelRilManager::GetTelRilData, &TelRilData::GetPdpContextListResponse,
        responseInfo, dataCallResultList);
}

int32_t TelRilCallback::SetInitApnInfoResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo)
{
    return TaskSchedule(
        responseInfo.slotId, &TelRilManager::GetTelRilData, &TelRilData::SetInitApnInfoResponse, responseInfo);
}

int32_t TelRilCallback::SetLinkBandwidthReportingRuleResponse(
    const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo)
{
    return TaskSchedule(responseInfo.slotId, &TelRilManager::GetTelRilData,
        &TelRilData::SetLinkBandwidthReportingRuleResponse, responseInfo);
}

int32_t TelRilCallback::GetLinkBandwidthInfoResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo,
    const HDI::Ril::V1_0::IDataLinkBandwidthInfo &dataLinkBandwidthInfo)
{
    return TaskSchedule(responseInfo.slotId, &TelRilManager::GetTelRilData, &TelRilData::GetLinkBandwidthInfoResponse,
        responseInfo, dataLinkBandwidthInfo);
}

int32_t TelRilCallback::SetDataPermittedResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo)
{
    return TaskSchedule(
        responseInfo.slotId, &TelRilManager::GetTelRilData, &TelRilData::SetDataPermittedResponse, responseInfo);
}

int32_t TelRilCallback::RadioStateUpdated(int32_t slotId, int32_t state)
{
    return TaskSchedule(slotId, &TelRilManager::GetTelRilModem, &TelRilModem::RadioStateUpdated, state);
}

int32_t TelRilCallback::VoiceRadioTechUpdated(
    int32_t slotId, const HDI::Ril::V1_0::IVoiceRadioTechnology &voiceRadioTechnology)
{
    return TaskSchedule(
        slotId, &TelRilManager::GetTelRilModem, &TelRilModem::VoiceRadioTechUpdated, voiceRadioTechnology);
}

int32_t TelRilCallback::ShutDownResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo)
{
    return TaskSchedule(
        responseInfo.slotId, &TelRilManager::GetTelRilModem, &TelRilModem::ShutDownResponse, responseInfo);
}

int32_t TelRilCallback::SetRadioStateResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo)
{
    return TaskSchedule(
        responseInfo.slotId, &TelRilManager::GetTelRilModem, &TelRilModem::SetRadioStateResponse, responseInfo);
}

int32_t TelRilCallback::GetRadioStateResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo, int32_t state)
{
    return TaskSchedule(
        responseInfo.slotId, &TelRilManager::GetTelRilModem, &TelRilModem::GetRadioStateResponse, responseInfo, state);
}

int32_t TelRilCallback::GetImeiResponse(
    const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo, const std::string &imei)
{
    return TaskSchedule(
        responseInfo.slotId, &TelRilManager::GetTelRilModem, &TelRilModem::GetImeiResponse, responseInfo, imei);
}

int32_t TelRilCallback::GetMeidResponse(
    const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo, const std::string &meid)
{
    return TaskSchedule(
        responseInfo.slotId, &TelRilManager::GetTelRilModem, &TelRilModem::GetMeidResponse, responseInfo, meid);
}

int32_t TelRilCallback::GetVoiceRadioTechnologyResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo,
    const HDI::Ril::V1_0::IVoiceRadioTechnology &voiceRadioTechnology)
{
    return TaskSchedule(responseInfo.slotId, &TelRilManager::GetTelRilModem,
        &TelRilModem::GetVoiceRadioTechnologyResponse, responseInfo, voiceRadioTechnology);
}

int32_t TelRilCallback::GetBasebandVersionResponse(
    const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo, const std::string &basebandVersion)
{
    return TaskSchedule(responseInfo.slotId, &TelRilManager::GetTelRilModem, &TelRilModem::GetBasebandVersionResponse,
        responseInfo, basebandVersion);
}

int32_t TelRilCallback::SimStateUpdated(int32_t slotId)
{
    return TaskSchedule(slotId, &TelRilManager::GetTelRilSim, &TelRilSim::SimStateUpdated);
}

int32_t TelRilCallback::SimStkSessionEndNotify(int32_t slotId)
{
    return TaskSchedule(slotId, &TelRilManager::GetTelRilSim, &TelRilSim::SimStkSessionEndNotify);
}

int32_t TelRilCallback::SimStkProactiveNotify(int32_t slotId, const std::string &response)
{
    return TaskSchedule(slotId, &TelRilManager::GetTelRilSim, &TelRilSim::SimStkProactiveNotify, response);
}

int32_t TelRilCallback::SimStkAlphaNotify(int32_t slotId, const std::string &response)
{
    return TaskSchedule(slotId, &TelRilManager::GetTelRilSim, &TelRilSim::SimStkAlphaNotify, response);
}

int32_t TelRilCallback::SimStkEventNotify(int32_t slotId, const std::string &response)
{
    return TaskSchedule(slotId, &TelRilManager::GetTelRilSim, &TelRilSim::SimStkEventNotify, response);
}

int32_t TelRilCallback::SimStkCallSetupNotify(int32_t slotId)
{
    return TaskSchedule(slotId, &TelRilManager::GetTelRilSim, &TelRilSim::SimStkCallSetupNotify);
}

int32_t TelRilCallback::SimRefreshNotify(int32_t slotId)
{
    return TaskSchedule(slotId, &TelRilManager::GetTelRilSim, &TelRilSim::SimRefreshNotify);
}

int32_t TelRilCallback::GetSimIOResponse(
    const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo, const HDI::Ril::V1_0::IIccIoResultInfo &result)
{
    return TaskSchedule(
        responseInfo.slotId, &TelRilManager::GetTelRilSim, &TelRilSim::GetSimIOResponse, responseInfo, result);
}

int32_t TelRilCallback::GetSimStatusResponse(
    const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo, const HDI::Ril::V1_0::ICardStatusInfo &result)
{
    return TaskSchedule(
        responseInfo.slotId, &TelRilManager::GetTelRilSim, &TelRilSim::GetSimStatusResponse, responseInfo, result);
}

int32_t TelRilCallback::GetImsiResponse(
    const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo, const std::string &response)
{
    return TaskSchedule(
        responseInfo.slotId, &TelRilManager::GetTelRilSim, &TelRilSim::GetImsiResponse, responseInfo, response);
}

int32_t TelRilCallback::GetSimLockStatusResponse(
    const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo, int32_t simLockStatus)
{
    return TaskSchedule(responseInfo.slotId, &TelRilManager::GetTelRilSim, &TelRilSim::GetSimLockStatusResponse,
        responseInfo, simLockStatus);
}

int32_t TelRilCallback::SetSimLockResponse(
    const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo, const HDI::Ril::V1_0::ILockStatusResp &lockStatus)
{
    return TaskSchedule(
        responseInfo.slotId, &TelRilManager::GetTelRilSim, &TelRilSim::SetSimLockResponse, responseInfo, lockStatus);
}

int32_t TelRilCallback::ChangeSimPasswordResponse(
    const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo, const HDI::Ril::V1_0::ILockStatusResp &lockStatus)
{
    return TaskSchedule(responseInfo.slotId, &TelRilManager::GetTelRilSim, &TelRilSim::ChangeSimPasswordResponse,
        responseInfo, lockStatus);
}

int32_t TelRilCallback::UnlockPinResponse(
    const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo, const HDI::Ril::V1_0::ILockStatusResp &lockStatus)
{
    return TaskSchedule(
        responseInfo.slotId, &TelRilManager::GetTelRilSim, &TelRilSim::UnlockPinResponse, responseInfo, lockStatus);
}

int32_t TelRilCallback::UnlockPukResponse(
    const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo, const HDI::Ril::V1_0::ILockStatusResp &lockStatus)
{
    return TaskSchedule(
        responseInfo.slotId, &TelRilManager::GetTelRilSim, &TelRilSim::UnlockPukResponse, responseInfo, lockStatus);
}

int32_t TelRilCallback::UnlockPin2Response(
    const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo, const HDI::Ril::V1_0::ILockStatusResp &lockStatus)
{
    return TaskSchedule(
        responseInfo.slotId, &TelRilManager::GetTelRilSim, &TelRilSim::UnlockPin2Response, responseInfo, lockStatus);
}

int32_t TelRilCallback::UnlockPuk2Response(
    const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo, const HDI::Ril::V1_0::ILockStatusResp &lockStatus)
{
    return TaskSchedule(
        responseInfo.slotId, &TelRilManager::GetTelRilSim, &TelRilSim::UnlockPuk2Response, responseInfo, lockStatus);
}

int32_t TelRilCallback::SetActiveSimResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo)
{
    return TaskSchedule(
        responseInfo.slotId, &TelRilManager::GetTelRilSim, &TelRilSim::SetActiveSimResponse, responseInfo);
}

int32_t TelRilCallback::SimStkSendTerminalResponseResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo)
{
    return TaskSchedule(responseInfo.slotId, &TelRilManager::GetTelRilSim,
        &TelRilSim::SimStkSendTerminalResponseResponse, responseInfo);
}

int32_t TelRilCallback::SimStkSendEnvelopeResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo)
{
    return TaskSchedule(
        responseInfo.slotId, &TelRilManager::GetTelRilSim, &TelRilSim::SimStkSendEnvelopeResponse, responseInfo);
}

int32_t TelRilCallback::SimStkSendCallSetupRequestResultResponse(
    const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo)
{
    return TaskSchedule(responseInfo.slotId, &TelRilManager::GetTelRilSim,
        &TelRilSim::SimStkSendCallSetupRequestResultResponse, responseInfo);
}

int32_t TelRilCallback::SimStkIsReadyResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo)
{
    return TaskSchedule(
        responseInfo.slotId, &TelRilManager::GetTelRilSim, &TelRilSim::SimStkIsReadyResponse, responseInfo);
}

int32_t TelRilCallback::SetRadioProtocolResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo,
    const HDI::Ril::V1_0::ISimProtocolResponse &pSimProtocol)
{
    return TaskSchedule(responseInfo.slotId, &TelRilManager::GetTelRilSim, &TelRilSim::SetRadioProtocolResponse,
        responseInfo, pSimProtocol);
}

int32_t TelRilCallback::SimOpenLogicalChannelResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo,
    const HDI::Ril::V1_0::IOpenLogicalChannelResponse &pOpenLogicalChannelResponse)
{
    return TaskSchedule(responseInfo.slotId, &TelRilManager::GetTelRilSim, &TelRilSim::SimOpenLogicalChannelResponse,
        responseInfo, pOpenLogicalChannelResponse);
}

int32_t TelRilCallback::SimCloseLogicalChannelResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo)
{
    return TaskSchedule(
        responseInfo.slotId, &TelRilManager::GetTelRilSim, &TelRilSim::SimCloseLogicalChannelResponse, responseInfo);
}

int32_t TelRilCallback::SimTransmitApduLogicalChannelResponse(
    const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo, const HDI::Ril::V1_0::IIccIoResultInfo &result)
{
    return TaskSchedule(responseInfo.slotId, &TelRilManager::GetTelRilSim,
        &TelRilSim::SimTransmitApduLogicalChannelResponse, responseInfo, result);
}

int32_t TelRilCallback::SimTransmitApduBasicChannelResponse(
    const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo, const HDI::Ril::V1_0::IIccIoResultInfo &result)
{
    return TaskSchedule(responseInfo.slotId, &TelRilManager::GetTelRilSim,
        &TelRilSim::SimTransmitApduBasicChannelResponse, responseInfo, result);
}

int32_t TelRilCallback::SimAuthenticationResponse(
    const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo, const HDI::Ril::V1_0::IIccIoResultInfo &result)
{
    return TaskSchedule(
        responseInfo.slotId, &TelRilManager::GetTelRilSim, &TelRilSim::SimAuthenticationResponse, responseInfo, result);
}

int32_t TelRilCallback::UnlockSimLockResponse(
    const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo, const HDI::Ril::V1_0::ILockStatusResp &lockStatus)
{
    return TaskSchedule(
        responseInfo.slotId, &TelRilManager::GetTelRilSim, &TelRilSim::UnlockSimLockResponse, responseInfo, lockStatus);
}
} // namespace Telephony
} // namespace OHOS