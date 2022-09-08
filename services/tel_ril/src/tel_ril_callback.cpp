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

int32_t TelRilCallback::SimRadioProtocolUpdated(int32_t slotId, const HDI::Ril::V1_0::IRadioProtocol &radioProtocol)
{
    return TaskSchedule(slotId, &TelRilManager::GetTelRilSim, &TelRilSim::SimRadioProtocolUpdated, radioProtocol);
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

int32_t TelRilCallback::GetRadioProtocolResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo,
    const HDI::Ril::V1_0::IRadioProtocol &radioProtocol)
{
    return TaskSchedule(responseInfo.slotId, &TelRilManager::GetTelRilSim, &TelRilSim::GetRadioProtocolResponse,
        responseInfo, radioProtocol);
}

int32_t TelRilCallback::SetRadioProtocolResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo,
    const HDI::Ril::V1_0::IRadioProtocol &radioProtocol)
{
    return TaskSchedule(responseInfo.slotId, &TelRilManager::GetTelRilSim, &TelRilSim::SetRadioProtocolResponse,
        responseInfo, radioProtocol);
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

// Network
int32_t TelRilCallback::NetworkCsRegStatusUpdated(
    int32_t slotId, const HDI::Ril::V1_0::ICsRegStatusInfo &csRegStatusInfo)
{
    return TaskSchedule(
        slotId, &TelRilManager::GetTelRilNetwork, &TelRilNetwork::NetworkCsRegStatusUpdated, csRegStatusInfo);
}

int32_t TelRilCallback::NetworkPsRegStatusUpdated(
    int32_t slotId, const HDI::Ril::V1_0::IPsRegStatusInfo &psRegStatusInfo)
{
    return TaskSchedule(
        slotId, &TelRilManager::GetTelRilNetwork, &TelRilNetwork::NetworkPsRegStatusUpdated, psRegStatusInfo);
}

int32_t TelRilCallback::SignalStrengthUpdated(int32_t slotId, const HDI::Ril::V1_0::IRssi &rssi)
{
    return TaskSchedule(slotId, &TelRilManager::GetTelRilNetwork, &TelRilNetwork::SignalStrengthUpdated, rssi);
}

int32_t TelRilCallback::NetworkTimeZoneUpdated(int32_t slotId, const std::string &timeZoneStr)
{
    return TaskSchedule(slotId, &TelRilManager::GetTelRilNetwork, &TelRilNetwork::NetworkTimeZoneUpdated, timeZoneStr);
}

int32_t TelRilCallback::NetworkTimeUpdated(int32_t slotId, const std::string &timeStr)
{
    return TaskSchedule(slotId, &TelRilManager::GetTelRilNetwork, &TelRilNetwork::NetworkTimeUpdated, timeStr);
}

int32_t TelRilCallback::NetworkPhyChnlCfgUpdated(
    int32_t slotId, const HDI::Ril::V1_0::IChannelConfigInfoList &channelConfigInfoList)
{
    return TaskSchedule(
        slotId, &TelRilManager::GetTelRilNetwork, &TelRilNetwork::NetworkPhyChnlCfgUpdated, channelConfigInfoList);
}

int32_t TelRilCallback::NetworkCurrentCellUpdated(
    int32_t slotId, const HDI::Ril::V1_0::ICellListCurrentInfo &cellListCurrentInfo)
{
    return TaskSchedule(
        slotId, &TelRilManager::GetTelRilNetwork, &TelRilNetwork::NetworkCurrentCellUpdated, cellListCurrentInfo);
}

int32_t TelRilCallback::GetSignalStrengthResponse(
    const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo, const HDI::Ril::V1_0::IRssi &rssi)
{
    return TaskSchedule(responseInfo.slotId, &TelRilManager::GetTelRilNetwork,
        &TelRilNetwork::GetSignalStrengthResponse, responseInfo, rssi);
}

int32_t TelRilCallback::GetCsRegStatusResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo,
    const HDI::Ril::V1_0::ICsRegStatusInfo &csRegStatusInfo)
{
    return TaskSchedule(responseInfo.slotId, &TelRilManager::GetTelRilNetwork,
        &TelRilNetwork::GetCsRegStatusResponse, responseInfo, csRegStatusInfo);
}

int32_t TelRilCallback::GetPsRegStatusResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo,
    const HDI::Ril::V1_0::IPsRegStatusInfo &psRegStatusInfo)
{
    return TaskSchedule(responseInfo.slotId, &TelRilManager::GetTelRilNetwork,
        &TelRilNetwork::GetPsRegStatusResponse, responseInfo, psRegStatusInfo);
}

int32_t TelRilCallback::GetOperatorInfoResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo,
    const HDI::Ril::V1_0::IOperatorInfo &operatorInfo)
{
    return TaskSchedule(responseInfo.slotId, &TelRilManager::GetTelRilNetwork,
        &TelRilNetwork::GetOperatorInfoResponse, responseInfo, operatorInfo);
}

int32_t TelRilCallback::GetNetworkSearchInformationResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo,
    const HDI::Ril::V1_0::IAvailableNetworkList &availableNetworkList)
{
    return TaskSchedule(responseInfo.slotId, &TelRilManager::GetTelRilNetwork,
        &TelRilNetwork::GetNetworkSearchInformationResponse, responseInfo, availableNetworkList);
}

int32_t TelRilCallback::GetNetworkSelectionModeResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo,
    const HDI::Ril::V1_0::ISetNetworkModeInfo &setNetworkModeInfo)
{
    return TaskSchedule(responseInfo.slotId, &TelRilManager::GetTelRilNetwork,
        &TelRilNetwork::GetNetworkSelectionModeResponse, responseInfo, setNetworkModeInfo);
}

int32_t TelRilCallback::SetNetworkSelectionModeResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo)
{
    return TaskSchedule(responseInfo.slotId, &TelRilManager::GetTelRilNetwork,
        &TelRilNetwork::SetNetworkSelectionModeResponse, responseInfo);
}

int32_t TelRilCallback::GetNeighboringCellInfoListResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo,
    const HDI::Ril::V1_0::ICellListNearbyInfo &cellInfoList)
{
    return TaskSchedule(responseInfo.slotId, &TelRilManager::GetTelRilNetwork,
        &TelRilNetwork::GetNeighboringCellInfoListResponse, responseInfo, cellInfoList);
}

int32_t TelRilCallback::GetCurrentCellInfoResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo,
    const HDI::Ril::V1_0::ICellListCurrentInfo &cellInfoList)
{
    return TaskSchedule(responseInfo.slotId, &TelRilManager::GetTelRilNetwork,
        &TelRilNetwork::GetCurrentCellInfoResponse, responseInfo, cellInfoList);
}

int32_t TelRilCallback::SetPreferredNetworkResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo)
{
    return TaskSchedule(responseInfo.slotId, &TelRilManager::GetTelRilNetwork,
        &TelRilNetwork::SetPreferredNetworkResponse, responseInfo);
}

int32_t TelRilCallback::GetPreferredNetworkResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo,
    const HDI::Ril::V1_0::IPreferredNetworkTypeInfo &preferredNetworkTypeInfo)
{
    return TaskSchedule(responseInfo.slotId, &TelRilManager::GetTelRilNetwork,
        &TelRilNetwork::GetPreferredNetworkResponse, responseInfo, preferredNetworkTypeInfo);
}

int32_t TelRilCallback::GetPhysicalChannelConfigResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo,
    const HDI::Ril::V1_0::IChannelConfigInfoList &channelConfigInfoList)
{
    return TaskSchedule(responseInfo.slotId, &TelRilManager::GetTelRilNetwork,
        &TelRilNetwork::GetPhysicalChannelConfigResponse, responseInfo, channelConfigInfoList);
}

int32_t TelRilCallback::SetLocateUpdatesResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo)
{
    return TaskSchedule(responseInfo.slotId, &TelRilManager::GetTelRilNetwork,
        &TelRilNetwork::SetLocateUpdatesResponse, responseInfo);
}

int32_t TelRilCallback::SetNotificationFilterResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo)
{
    return TaskSchedule(responseInfo.slotId, &TelRilManager::GetTelRilNetwork,
        &TelRilNetwork::SetNotificationFilterResponse, responseInfo);
}

int32_t TelRilCallback::SetDeviceStateResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo)
{
    return TaskSchedule(responseInfo.slotId, &TelRilManager::GetTelRilNetwork,
        &TelRilNetwork::SetDeviceStateResponse, responseInfo);
}

int32_t TelRilCallback::NewSmsNotify(int32_t slotId, const HDI::Ril::V1_0::ISmsMessageInfo &smsMessageInfo)
{
    return TaskSchedule(slotId, &TelRilManager::GetTelRilSms, &TelRilSms::NewSmsNotify, smsMessageInfo);
}

int32_t TelRilCallback::NewCdmaSmsNotify(int32_t slotId, const HDI::Ril::V1_0::ISmsMessageInfo &smsMessageInfo)
{
    return TaskSchedule(slotId, &TelRilManager::GetTelRilSms, &TelRilSms::NewCdmaSmsNotify, smsMessageInfo);
}

int32_t TelRilCallback::SmsStatusReportNotify(int32_t slotId, const HDI::Ril::V1_0::ISmsMessageInfo &smsMessageInfo)
{
    return TaskSchedule(slotId, &TelRilManager::GetTelRilSms, &TelRilSms::SmsStatusReportNotify, smsMessageInfo);
}

int32_t TelRilCallback::NewSmsStoredOnSimNotify(int32_t slotId, int32_t recordNumber, int32_t indicationType)
{
    return TaskSchedule(
        slotId, &TelRilManager::GetTelRilSms, &TelRilSms::NewSmsStoredOnSimNotify, recordNumber, indicationType);
}

int32_t TelRilCallback::CBConfigNotify(
    int32_t slotId, const HDI::Ril::V1_0::ICBConfigReportInfo &cellBroadConfigReportInfo)
{
    return TaskSchedule(slotId, &TelRilManager::GetTelRilSms, &TelRilSms::CBConfigNotify, cellBroadConfigReportInfo);
}

int32_t TelRilCallback::SendGsmSmsResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo,
    const HDI::Ril::V1_0::ISendSmsResultInfo &sendSmsResultInfo)
{
    return TaskSchedule(responseInfo.slotId, &TelRilManager::GetTelRilSms, &TelRilSms::SendGsmSmsResponse, responseInfo,
        sendSmsResultInfo);
}

int32_t TelRilCallback::SendCdmaSmsResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo,
    const HDI::Ril::V1_0::ISendSmsResultInfo &sendSmsResultInfo)
{
    return TaskSchedule(responseInfo.slotId, &TelRilManager::GetTelRilSms, &TelRilSms::SendCdmaSmsResponse,
        responseInfo, sendSmsResultInfo);
}

int32_t TelRilCallback::AddSimMessageResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo)
{
    return TaskSchedule(
        responseInfo.slotId, &TelRilManager::GetTelRilSms, &TelRilSms::AddSimMessageResponse, responseInfo);
}

int32_t TelRilCallback::DelSimMessageResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo)
{
    return TaskSchedule(
        responseInfo.slotId, &TelRilManager::GetTelRilSms, &TelRilSms::DelSimMessageResponse, responseInfo);
}

int32_t TelRilCallback::UpdateSimMessageResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo)
{
    return TaskSchedule(
        responseInfo.slotId, &TelRilManager::GetTelRilSms, &TelRilSms::UpdateSimMessageResponse, responseInfo);
}

int32_t TelRilCallback::AddCdmaSimMessageResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo)
{
    return TaskSchedule(
        responseInfo.slotId, &TelRilManager::GetTelRilSms, &TelRilSms::AddCdmaSimMessageResponse, responseInfo);
}

int32_t TelRilCallback::DelCdmaSimMessageResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo)
{
    return TaskSchedule(
        responseInfo.slotId, &TelRilManager::GetTelRilSms, &TelRilSms::DelCdmaSimMessageResponse, responseInfo);
}

int32_t TelRilCallback::UpdateCdmaSimMessageResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo)
{
    return TaskSchedule(
        responseInfo.slotId, &TelRilManager::GetTelRilSms, &TelRilSms::UpdateCdmaSimMessageResponse, responseInfo);
}

int32_t TelRilCallback::SetSmscAddrResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo)
{
    return TaskSchedule(
        responseInfo.slotId, &TelRilManager::GetTelRilSms, &TelRilSms::SetSmscAddrResponse, responseInfo);
}

int32_t TelRilCallback::GetSmscAddrResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo,
    const HDI::Ril::V1_0::IServiceCenterAddress &serviceCenterAddress)
{
    return TaskSchedule(responseInfo.slotId, &TelRilManager::GetTelRilSms, &TelRilSms::GetSmscAddrResponse,
        responseInfo, serviceCenterAddress);
}

int32_t TelRilCallback::SetCBConfigResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo)
{
    return TaskSchedule(
        responseInfo.slotId, &TelRilManager::GetTelRilSms, &TelRilSms::SetCBConfigResponse, responseInfo);
}

int32_t TelRilCallback::GetCBConfigResponse(
    const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo, const HDI::Ril::V1_0::ICBConfigInfo &cellBroadcastInfo)
{
    return TaskSchedule(responseInfo.slotId, &TelRilManager::GetTelRilSms, &TelRilSms::GetCBConfigResponse,
        responseInfo, cellBroadcastInfo);
}

int32_t TelRilCallback::SetCdmaCBConfigResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo)
{
    return TaskSchedule(
        responseInfo.slotId, &TelRilManager::GetTelRilSms, &TelRilSms::SetCdmaCBConfigResponse, responseInfo);
}

int32_t TelRilCallback::GetCdmaCBConfigResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo,
    const HDI::Ril::V1_0::ICdmaCBConfigInfo &cdmaCBConfigInfo)
{
    return TaskSchedule(responseInfo.slotId, &TelRilManager::GetTelRilSms, &TelRilSms::GetCdmaCBConfigResponse,
        responseInfo, cdmaCBConfigInfo);
}

int32_t TelRilCallback::SendSmsMoreModeResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo,
    const HDI::Ril::V1_0::ISendSmsResultInfo &sendSmsResultInfo)
{
    return TaskSchedule(responseInfo.slotId, &TelRilManager::GetTelRilSms, &TelRilSms::SendSmsMoreModeResponse,
        responseInfo, sendSmsResultInfo);
}

int32_t TelRilCallback::SendSmsAckResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo)
{
    return TaskSchedule(
        responseInfo.slotId, &TelRilManager::GetTelRilSms, &TelRilSms::SendSmsAckResponse, responseInfo);
}
} // namespace Telephony
} // namespace OHOS