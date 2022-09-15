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
int32_t TelRilCallback::SetEmergencyCallListResponse(const HDI::Ril::V1_0::RilRadioResponseInfo &responseInfo)
{
    return Response(responseInfo, &TelRilManager::GetTelRilCall, &TelRilCall::SetEmergencyCallListResponse);
}

int32_t TelRilCallback::GetEmergencyCallListResponse(const HDI::Ril::V1_0::RilRadioResponseInfo &responseInfo,
    const HDI::Ril::V1_0::EmergencyInfoList &emergencyInfoList)
{
    return Response(
        responseInfo, &TelRilManager::GetTelRilCall, &TelRilCall::GetEmergencyCallListResponse, emergencyInfoList);
}

int32_t TelRilCallback::CallEmergencyNotice(const HDI::Ril::V1_0::RilRadioResponseInfo &responseInfo,
    const HDI::Ril::V1_0::EmergencyInfoList &emergencyInfoList)
{
    return Notify(responseInfo, &TelRilManager::GetTelRilCall, &TelRilCall::CallEmergencyNotice, emergencyInfoList);
}

int32_t TelRilCallback::CallStateUpdated(const HDI::Ril::V1_0::RilRadioResponseInfo &responseInfo)
{
    return Notify(responseInfo, &TelRilManager::GetTelRilCall, &TelRilCall::CallStateUpdated);
}

int32_t TelRilCallback::CallRingbackVoiceNotice(
    const HDI::Ril::V1_0::RilRadioResponseInfo &responseInfo, const HDI::Ril::V1_0::RingbackVoice &ringbackVoice)
{
    return Notify(responseInfo, &TelRilManager::GetTelRilCall, &TelRilCall::CallRingbackVoiceNotice, ringbackVoice);
}

int32_t TelRilCallback::CallSrvccStatusNotice(
    const HDI::Ril::V1_0::RilRadioResponseInfo &responseInfo, const HDI::Ril::V1_0::SrvccStatus &srvccStatus)
{
    return Notify(responseInfo, &TelRilManager::GetTelRilCall, &TelRilCall::CallSrvccStatusNotice, srvccStatus);
}

int32_t TelRilCallback::CallUssdNotice(
    const HDI::Ril::V1_0::RilRadioResponseInfo &responseInfo, const HDI::Ril::V1_0::UssdNoticeInfo &ussdNoticeInfo)
{
    return Notify(responseInfo, &TelRilManager::GetTelRilCall, &TelRilCall::CallUssdNotice, ussdNoticeInfo);
}

int32_t TelRilCallback::CallSsNotice(
    const HDI::Ril::V1_0::RilRadioResponseInfo &responseInfo, const HDI::Ril::V1_0::SsNoticeInfo &ssNoticeInfo)
{
    return Notify(responseInfo, &TelRilManager::GetTelRilCall, &TelRilCall::CallSsNotice, ssNoticeInfo);
}

int32_t TelRilCallback::GetCallListResponse(
    const HDI::Ril::V1_0::RilRadioResponseInfo &responseInfo, const HDI::Ril::V1_0::CallInfoList &callList)
{
    return Response(responseInfo, &TelRilManager::GetTelRilCall, &TelRilCall::GetCallListResponse, callList);
}

int32_t TelRilCallback::DialResponse(const HDI::Ril::V1_0::RilRadioResponseInfo &responseInfo)
{
    return Response(responseInfo, &TelRilManager::GetTelRilCall, &TelRilCall::DialResponse);
}

int32_t TelRilCallback::HangupResponse(const HDI::Ril::V1_0::RilRadioResponseInfo &responseInfo)
{
    return Response(responseInfo, &TelRilManager::GetTelRilCall, &TelRilCall::HangupResponse);
}

int32_t TelRilCallback::RejectResponse(const HDI::Ril::V1_0::RilRadioResponseInfo &responseInfo)
{
    return Response(responseInfo, &TelRilManager::GetTelRilCall, &TelRilCall::RejectResponse);
}

int32_t TelRilCallback::AnswerResponse(const HDI::Ril::V1_0::RilRadioResponseInfo &responseInfo)
{
    return Response(responseInfo, &TelRilManager::GetTelRilCall, &TelRilCall::AnswerResponse);
}

int32_t TelRilCallback::HoldCallResponse(const HDI::Ril::V1_0::RilRadioResponseInfo &responseInfo)
{
    return Response(responseInfo, &TelRilManager::GetTelRilCall, &TelRilCall::HoldCallResponse);
}

int32_t TelRilCallback::UnHoldCallResponse(const HDI::Ril::V1_0::RilRadioResponseInfo &responseInfo)
{
    return Response(responseInfo, &TelRilManager::GetTelRilCall, &TelRilCall::UnHoldCallResponse);
}

int32_t TelRilCallback::SwitchCallResponse(const HDI::Ril::V1_0::RilRadioResponseInfo &responseInfo)
{
    return Response(responseInfo, &TelRilManager::GetTelRilCall, &TelRilCall::SwitchCallResponse);
}

int32_t TelRilCallback::GetClipResponse(
    const HDI::Ril::V1_0::RilRadioResponseInfo &responseInfo, const HDI::Ril::V1_0::GetClipResult &getClipResult)
{
    return Response(responseInfo, &TelRilManager::GetTelRilCall, &TelRilCall::GetClipResponse, getClipResult);
}

int32_t TelRilCallback::SetClipResponse(const HDI::Ril::V1_0::RilRadioResponseInfo &responseInfo)
{
    return Response(responseInfo, &TelRilManager::GetTelRilCall, &TelRilCall::SetClipResponse);
}

int32_t TelRilCallback::CombineConferenceResponse(const HDI::Ril::V1_0::RilRadioResponseInfo &responseInfo)
{
    return Response(responseInfo, &TelRilManager::GetTelRilCall, &TelRilCall::CombineConferenceResponse);
}

int32_t TelRilCallback::SeparateConferenceResponse(const HDI::Ril::V1_0::RilRadioResponseInfo &responseInfo)
{
    return Response(responseInfo, &TelRilManager::GetTelRilCall, &TelRilCall::SeparateConferenceResponse);
}

int32_t TelRilCallback::CallSupplementResponse(const HDI::Ril::V1_0::RilRadioResponseInfo &responseInfo)
{
    return Response(responseInfo, &TelRilManager::GetTelRilCall, &TelRilCall::CallSupplementResponse);
}

int32_t TelRilCallback::GetCallWaitingResponse(
    const HDI::Ril::V1_0::RilRadioResponseInfo &responseInfo, const HDI::Ril::V1_0::CallWaitResult &callWaitResult)
{
    return Response(responseInfo, &TelRilManager::GetTelRilCall, &TelRilCall::GetCallWaitingResponse, callWaitResult);
}

int32_t TelRilCallback::SetCallWaitingResponse(const HDI::Ril::V1_0::RilRadioResponseInfo &responseInfo)
{
    return Response(responseInfo, &TelRilManager::GetTelRilCall, &TelRilCall::SetCallWaitingResponse);
}

int32_t TelRilCallback::GetCallTransferInfoResponse(const HDI::Ril::V1_0::RilRadioResponseInfo &responseInfo,
    const HDI::Ril::V1_0::CallForwardQueryInfoList &cFQueryList)
{
    return Response(responseInfo, &TelRilManager::GetTelRilCall, &TelRilCall::GetCallTransferInfoResponse, cFQueryList);
}

int32_t TelRilCallback::SetCallTransferInfoResponse(const HDI::Ril::V1_0::RilRadioResponseInfo &responseInfo)
{
    return Response(responseInfo, &TelRilManager::GetTelRilCall, &TelRilCall::SetCallTransferInfoResponse);
}

int32_t TelRilCallback::GetCallRestrictionResponse(
    const HDI::Ril::V1_0::RilRadioResponseInfo &responseInfo, const HDI::Ril::V1_0::CallRestrictionResult &result)
{
    return Response(responseInfo, &TelRilManager::GetTelRilCall, &TelRilCall::GetCallRestrictionResponse, result);
}

int32_t TelRilCallback::SetCallRestrictionResponse(const HDI::Ril::V1_0::RilRadioResponseInfo &responseInfo)
{
    return Response(responseInfo, &TelRilManager::GetTelRilCall, &TelRilCall::SetCallRestrictionResponse);
}

int32_t TelRilCallback::GetClirResponse(
    const HDI::Ril::V1_0::RilRadioResponseInfo &responseInfo, const HDI::Ril::V1_0::GetClirResult &getClirResult)
{
    return Response(responseInfo, &TelRilManager::GetTelRilCall, &TelRilCall::GetClirResponse, getClirResult);
}

int32_t TelRilCallback::SetClirResponse(const HDI::Ril::V1_0::RilRadioResponseInfo &responseInfo)
{
    return Response(responseInfo, &TelRilManager::GetTelRilCall, &TelRilCall::SetClirResponse);
}

int32_t TelRilCallback::StartDtmfResponse(const HDI::Ril::V1_0::RilRadioResponseInfo &responseInfo)
{
    return Response(responseInfo, &TelRilManager::GetTelRilCall, &TelRilCall::StartDtmfResponse);
}

int32_t TelRilCallback::SendDtmfResponse(const HDI::Ril::V1_0::RilRadioResponseInfo &responseInfo)
{
    return Response(responseInfo, &TelRilManager::GetTelRilCall, &TelRilCall::SendDtmfResponse);
}

int32_t TelRilCallback::StopDtmfResponse(const HDI::Ril::V1_0::RilRadioResponseInfo &responseInfo)
{
    return Response(responseInfo, &TelRilManager::GetTelRilCall, &TelRilCall::StopDtmfResponse);
}

int32_t TelRilCallback::GetCallPreferenceModeResponse(
    const HDI::Ril::V1_0::RilRadioResponseInfo &responseInfo, int32_t mode)
{
    return Response(responseInfo, &TelRilManager::GetTelRilCall, &TelRilCall::GetCallPreferenceModeResponse, mode);
}

int32_t TelRilCallback::SetCallPreferenceModeResponse(const HDI::Ril::V1_0::RilRadioResponseInfo &responseInfo)
{
    return Response(responseInfo, &TelRilManager::GetTelRilCall, &TelRilCall::SetCallPreferenceModeResponse);
}

int32_t TelRilCallback::SetUssdResponse(const HDI::Ril::V1_0::RilRadioResponseInfo &responseInfo)
{
    return Response(responseInfo, &TelRilManager::GetTelRilCall, &TelRilCall::SetUssdResponse);
}

int32_t TelRilCallback::GetUssdResponse(const HDI::Ril::V1_0::RilRadioResponseInfo &responseInfo, int32_t cusd)
{
    return Response(responseInfo, &TelRilManager::GetTelRilCall, &TelRilCall::GetUssdResponse, cusd);
}

int32_t TelRilCallback::SetMuteResponse(const HDI::Ril::V1_0::RilRadioResponseInfo &responseInfo)
{
    return Response(responseInfo, &TelRilManager::GetTelRilCall, &TelRilCall::SetMuteResponse);
}

int32_t TelRilCallback::GetMuteResponse(const HDI::Ril::V1_0::RilRadioResponseInfo &responseInfo, int32_t mute)
{
    return Response(responseInfo, &TelRilManager::GetTelRilCall, &TelRilCall::GetMuteResponse, mute);
}

int32_t TelRilCallback::GetCallFailReasonResponse(
    const HDI::Ril::V1_0::RilRadioResponseInfo &responseInfo, int32_t callFail)
{
    return Response(responseInfo, &TelRilManager::GetTelRilCall, &TelRilCall::GetCallFailReasonResponse, callFail);
}

int32_t TelRilCallback::SetBarringPasswordResponse(const HDI::Ril::V1_0::RilRadioResponseInfo &responseInfo)
{
    return Response(responseInfo, &TelRilManager::GetTelRilCall, &TelRilCall::SetBarringPasswordResponse);
}

// Data
int32_t TelRilCallback::PdpContextListUpdated(const HDI::Ril::V1_0::RilRadioResponseInfo &responseInfo,
    const HDI::Ril::V1_0::DataCallResultList &dataCallResultList)
{
    return Notify(responseInfo, &TelRilManager::GetTelRilData, &TelRilData::PdpContextListUpdated, dataCallResultList);
}

int32_t TelRilCallback::ActivatePdpContextResponse(const HDI::Ril::V1_0::RilRadioResponseInfo &responseInfo,
    const HDI::Ril::V1_0::SetupDataCallResultInfo &setupDataCallResultInfo)
{
    return Response(
        responseInfo, &TelRilManager::GetTelRilData, &TelRilData::ActivatePdpContextResponse, setupDataCallResultInfo);
}

int32_t TelRilCallback::DeactivatePdpContextResponse(const HDI::Ril::V1_0::RilRadioResponseInfo &responseInfo)
{
    return Response(responseInfo, &TelRilManager::GetTelRilData, &TelRilData::DeactivatePdpContextResponse);
}

int32_t TelRilCallback::GetPdpContextListResponse(const HDI::Ril::V1_0::RilRadioResponseInfo &responseInfo,
    const HDI::Ril::V1_0::DataCallResultList &dataCallResultList)
{
    return Response(
        responseInfo, &TelRilManager::GetTelRilData, &TelRilData::GetPdpContextListResponse, dataCallResultList);
}

int32_t TelRilCallback::SetInitApnInfoResponse(const HDI::Ril::V1_0::RilRadioResponseInfo &responseInfo)
{
    return Response(responseInfo, &TelRilManager::GetTelRilData, &TelRilData::SetInitApnInfoResponse);
}

int32_t TelRilCallback::SetLinkBandwidthReportingRuleResponse(const HDI::Ril::V1_0::RilRadioResponseInfo &responseInfo)
{
    return Response(responseInfo, &TelRilManager::GetTelRilData, &TelRilData::SetLinkBandwidthReportingRuleResponse);
}

int32_t TelRilCallback::GetLinkBandwidthInfoResponse(const HDI::Ril::V1_0::RilRadioResponseInfo &responseInfo,
    const HDI::Ril::V1_0::DataLinkBandwidthInfo &dataLinkBandwidthInfo)
{
    return Response(
        responseInfo, &TelRilManager::GetTelRilData, &TelRilData::GetLinkBandwidthInfoResponse, dataLinkBandwidthInfo);
}

int32_t TelRilCallback::SetDataPermittedResponse(const HDI::Ril::V1_0::RilRadioResponseInfo &responseInfo)
{
    return Response(responseInfo, &TelRilManager::GetTelRilData, &TelRilData::SetDataPermittedResponse);
}

int32_t TelRilCallback::RadioStateUpdated(const HDI::Ril::V1_0::RilRadioResponseInfo &responseInfo, int32_t state)
{
    return Notify(responseInfo, &TelRilManager::GetTelRilModem, &TelRilModem::RadioStateUpdated, state);
}

int32_t TelRilCallback::VoiceRadioTechUpdated(const HDI::Ril::V1_0::RilRadioResponseInfo &responseInfo,
    const HDI::Ril::V1_0::VoiceRadioTechnology &voiceRadioTechnology)
{
    return Notify(
        responseInfo, &TelRilManager::GetTelRilModem, &TelRilModem::VoiceRadioTechUpdated, voiceRadioTechnology);
}

int32_t TelRilCallback::ShutDownResponse(const HDI::Ril::V1_0::RilRadioResponseInfo &responseInfo)
{
    return Response(responseInfo, &TelRilManager::GetTelRilModem, &TelRilModem::ShutDownResponse);
}

int32_t TelRilCallback::SetRadioStateResponse(const HDI::Ril::V1_0::RilRadioResponseInfo &responseInfo)
{
    return Response(responseInfo, &TelRilManager::GetTelRilModem, &TelRilModem::SetRadioStateResponse);
}

int32_t TelRilCallback::GetRadioStateResponse(const HDI::Ril::V1_0::RilRadioResponseInfo &responseInfo, int32_t state)
{
    return Response(responseInfo, &TelRilManager::GetTelRilModem, &TelRilModem::GetRadioStateResponse, state);
}

int32_t TelRilCallback::GetImeiResponse(
    const HDI::Ril::V1_0::RilRadioResponseInfo &responseInfo, const std::string &imei)
{
    return Response(responseInfo, &TelRilManager::GetTelRilModem, &TelRilModem::GetImeiResponse, imei);
}

int32_t TelRilCallback::GetMeidResponse(
    const HDI::Ril::V1_0::RilRadioResponseInfo &responseInfo, const std::string &meid)
{
    return Response(responseInfo, &TelRilManager::GetTelRilModem, &TelRilModem::GetMeidResponse, meid);
}

int32_t TelRilCallback::GetVoiceRadioTechnologyResponse(const HDI::Ril::V1_0::RilRadioResponseInfo &responseInfo,
    const HDI::Ril::V1_0::VoiceRadioTechnology &voiceRadioTechnology)
{
    return Response(responseInfo, &TelRilManager::GetTelRilModem, &TelRilModem::GetVoiceRadioTechnologyResponse,
        voiceRadioTechnology);
}

int32_t TelRilCallback::GetBasebandVersionResponse(
    const HDI::Ril::V1_0::RilRadioResponseInfo &responseInfo, const std::string &basebandVersion)
{
    return Response(
        responseInfo, &TelRilManager::GetTelRilModem, &TelRilModem::GetBasebandVersionResponse, basebandVersion);
}

int32_t TelRilCallback::SimStateUpdated(const HDI::Ril::V1_0::RilRadioResponseInfo &responseInfo)
{
    return Notify(responseInfo, &TelRilManager::GetTelRilSim, &TelRilSim::SimStateUpdated);
}

int32_t TelRilCallback::SimStkSessionEndNotify(const HDI::Ril::V1_0::RilRadioResponseInfo &responseInfo)
{
    return Notify(responseInfo, &TelRilManager::GetTelRilSim, &TelRilSim::SimStkSessionEndNotify);
}

int32_t TelRilCallback::SimStkProactiveNotify(
    const HDI::Ril::V1_0::RilRadioResponseInfo &responseInfo, const std::string &response)
{
    return Notify(responseInfo, &TelRilManager::GetTelRilSim, &TelRilSim::SimStkProactiveNotify, response);
}

int32_t TelRilCallback::SimStkAlphaNotify(
    const HDI::Ril::V1_0::RilRadioResponseInfo &responseInfo, const std::string &response)
{
    return Notify(responseInfo, &TelRilManager::GetTelRilSim, &TelRilSim::SimStkAlphaNotify, response);
}

int32_t TelRilCallback::SimStkEventNotify(
    const HDI::Ril::V1_0::RilRadioResponseInfo &responseInfo, const std::string &response)
{
    return Notify(responseInfo, &TelRilManager::GetTelRilSim, &TelRilSim::SimStkEventNotify, response);
}

int32_t TelRilCallback::SimStkCallSetupNotify(const HDI::Ril::V1_0::RilRadioResponseInfo &responseInfo)
{
    return Notify(responseInfo, &TelRilManager::GetTelRilSim, &TelRilSim::SimStkCallSetupNotify);
}

int32_t TelRilCallback::SimRefreshNotify(const HDI::Ril::V1_0::RilRadioResponseInfo &responseInfo)
{
    return Notify(responseInfo, &TelRilManager::GetTelRilSim, &TelRilSim::SimRefreshNotify);
}

int32_t TelRilCallback::SimRadioProtocolUpdated(
    const HDI::Ril::V1_0::RilRadioResponseInfo &responseInfo, const HDI::Ril::V1_0::RadioProtocol &radioProtocol)
{
    return Notify(responseInfo, &TelRilManager::GetTelRilSim, &TelRilSim::SimRadioProtocolUpdated, radioProtocol);
}

int32_t TelRilCallback::GetSimIOResponse(
    const HDI::Ril::V1_0::RilRadioResponseInfo &responseInfo, const HDI::Ril::V1_0::IccIoResultInfo &result)
{
    return Response(responseInfo, &TelRilManager::GetTelRilSim, &TelRilSim::GetSimIOResponse, result);
}

int32_t TelRilCallback::GetSimStatusResponse(
    const HDI::Ril::V1_0::RilRadioResponseInfo &responseInfo, const HDI::Ril::V1_0::CardStatusInfo &result)
{
    return Response(responseInfo, &TelRilManager::GetTelRilSim, &TelRilSim::GetSimStatusResponse, result);
}

int32_t TelRilCallback::GetImsiResponse(
    const HDI::Ril::V1_0::RilRadioResponseInfo &responseInfo, const std::string &response)
{
    return Response(responseInfo, &TelRilManager::GetTelRilSim, &TelRilSim::GetImsiResponse, response);
}

int32_t TelRilCallback::GetSimLockStatusResponse(
    const HDI::Ril::V1_0::RilRadioResponseInfo &responseInfo, int32_t simLockStatus)
{
    return Response(responseInfo, &TelRilManager::GetTelRilSim, &TelRilSim::GetSimLockStatusResponse, simLockStatus);
}

int32_t TelRilCallback::SetSimLockResponse(
    const HDI::Ril::V1_0::RilRadioResponseInfo &responseInfo, const HDI::Ril::V1_0::LockStatusResp &lockStatus)
{
    return Response(responseInfo, &TelRilManager::GetTelRilSim, &TelRilSim::SetSimLockResponse, lockStatus);
}

int32_t TelRilCallback::ChangeSimPasswordResponse(
    const HDI::Ril::V1_0::RilRadioResponseInfo &responseInfo, const HDI::Ril::V1_0::LockStatusResp &lockStatus)
{
    return Response(responseInfo, &TelRilManager::GetTelRilSim, &TelRilSim::ChangeSimPasswordResponse, lockStatus);
}

int32_t TelRilCallback::UnlockPinResponse(
    const HDI::Ril::V1_0::RilRadioResponseInfo &responseInfo, const HDI::Ril::V1_0::LockStatusResp &lockStatus)
{
    return Response(responseInfo, &TelRilManager::GetTelRilSim, &TelRilSim::UnlockPinResponse, lockStatus);
}

int32_t TelRilCallback::UnlockPukResponse(
    const HDI::Ril::V1_0::RilRadioResponseInfo &responseInfo, const HDI::Ril::V1_0::LockStatusResp &lockStatus)
{
    return Response(responseInfo, &TelRilManager::GetTelRilSim, &TelRilSim::UnlockPukResponse, lockStatus);
}

int32_t TelRilCallback::UnlockPin2Response(
    const HDI::Ril::V1_0::RilRadioResponseInfo &responseInfo, const HDI::Ril::V1_0::LockStatusResp &lockStatus)
{
    return Response(responseInfo, &TelRilManager::GetTelRilSim, &TelRilSim::UnlockPin2Response, lockStatus);
}

int32_t TelRilCallback::UnlockPuk2Response(
    const HDI::Ril::V1_0::RilRadioResponseInfo &responseInfo, const HDI::Ril::V1_0::LockStatusResp &lockStatus)
{
    return Response(responseInfo, &TelRilManager::GetTelRilSim, &TelRilSim::UnlockPuk2Response, lockStatus);
}

int32_t TelRilCallback::SetActiveSimResponse(const HDI::Ril::V1_0::RilRadioResponseInfo &responseInfo)
{
    return Response(responseInfo, &TelRilManager::GetTelRilSim, &TelRilSim::SetActiveSimResponse);
}

int32_t TelRilCallback::SimStkSendTerminalResponseResponse(const HDI::Ril::V1_0::RilRadioResponseInfo &responseInfo)
{
    return Response(responseInfo, &TelRilManager::GetTelRilSim, &TelRilSim::SimStkSendTerminalResponseResponse);
}

int32_t TelRilCallback::SimStkSendEnvelopeResponse(const HDI::Ril::V1_0::RilRadioResponseInfo &responseInfo)
{
    return Response(responseInfo, &TelRilManager::GetTelRilSim, &TelRilSim::SimStkSendEnvelopeResponse);
}

int32_t TelRilCallback::SimStkSendCallSetupRequestResultResponse(
    const HDI::Ril::V1_0::RilRadioResponseInfo &responseInfo)
{
    return Response(responseInfo, &TelRilManager::GetTelRilSim, &TelRilSim::SimStkSendCallSetupRequestResultResponse);
}

int32_t TelRilCallback::SimStkIsReadyResponse(const HDI::Ril::V1_0::RilRadioResponseInfo &responseInfo)
{
    return Response(responseInfo, &TelRilManager::GetTelRilSim, &TelRilSim::SimStkIsReadyResponse);
}

int32_t TelRilCallback::GetRadioProtocolResponse(
    const HDI::Ril::V1_0::RilRadioResponseInfo &responseInfo, const HDI::Ril::V1_0::RadioProtocol &radioProtocol)
{
    return TaskSchedule(responseInfo.slotId, &TelRilManager::GetTelRilSim, &TelRilSim::GetRadioProtocolResponse,
        responseInfo, radioProtocol);
}

int32_t TelRilCallback::SetRadioProtocolResponse(
    const HDI::Ril::V1_0::RilRadioResponseInfo &responseInfo, const HDI::Ril::V1_0::RadioProtocol &radioProtocol)
{
    return TaskSchedule(responseInfo.slotId, &TelRilManager::GetTelRilSim, &TelRilSim::SetRadioProtocolResponse,
        responseInfo, radioProtocol);
}

int32_t TelRilCallback::SimOpenLogicalChannelResponse(const HDI::Ril::V1_0::RilRadioResponseInfo &responseInfo,
    const HDI::Ril::V1_0::OpenLogicalChannelResponse &pOpenLogicalChannelResponse)
{
    return Response(responseInfo, &TelRilManager::GetTelRilSim, &TelRilSim::SimOpenLogicalChannelResponse,
        pOpenLogicalChannelResponse);
}

int32_t TelRilCallback::SimCloseLogicalChannelResponse(const HDI::Ril::V1_0::RilRadioResponseInfo &responseInfo)
{
    return Response(responseInfo, &TelRilManager::GetTelRilSim, &TelRilSim::SimCloseLogicalChannelResponse);
}

int32_t TelRilCallback::SimTransmitApduLogicalChannelResponse(
    const HDI::Ril::V1_0::RilRadioResponseInfo &responseInfo, const HDI::Ril::V1_0::IccIoResultInfo &result)
{
    return Response(
        responseInfo, &TelRilManager::GetTelRilSim, &TelRilSim::SimTransmitApduLogicalChannelResponse, result);
}

int32_t TelRilCallback::SimTransmitApduBasicChannelResponse(
    const HDI::Ril::V1_0::RilRadioResponseInfo &responseInfo, const HDI::Ril::V1_0::IccIoResultInfo &result)
{
    return Response(
        responseInfo, &TelRilManager::GetTelRilSim, &TelRilSim::SimTransmitApduBasicChannelResponse, result);
}

int32_t TelRilCallback::SimAuthenticationResponse(
    const HDI::Ril::V1_0::RilRadioResponseInfo &responseInfo, const HDI::Ril::V1_0::IccIoResultInfo &result)
{
    return Response(responseInfo, &TelRilManager::GetTelRilSim, &TelRilSim::SimAuthenticationResponse, result);
}

int32_t TelRilCallback::UnlockSimLockResponse(
    const HDI::Ril::V1_0::RilRadioResponseInfo &responseInfo, const HDI::Ril::V1_0::LockStatusResp &lockStatus)
{
    return Response(responseInfo, &TelRilManager::GetTelRilSim, &TelRilSim::UnlockSimLockResponse, lockStatus);
}

// Network
int32_t TelRilCallback::NetworkCsRegStatusUpdated(
    const HDI::Ril::V1_0::RilRadioResponseInfo &responseInfo, const HDI::Ril::V1_0::CsRegStatusInfo &csRegStatusInfo)
{
    return Notify(responseInfo, &TelRilManager::GetTelRilNetwork, &TelRilNetwork::NetworkCsRegStatusUpdated,
        csRegStatusInfo);
}

int32_t TelRilCallback::NetworkPsRegStatusUpdated(
    const HDI::Ril::V1_0::RilRadioResponseInfo &responseInfo, const HDI::Ril::V1_0::PsRegStatusInfo &psRegStatusInfo)
{
    return Notify(responseInfo, &TelRilManager::GetTelRilNetwork, &TelRilNetwork::NetworkPsRegStatusUpdated,
        psRegStatusInfo);
}

int32_t TelRilCallback::SignalStrengthUpdated(
    const HDI::Ril::V1_0::RilRadioResponseInfo &responseInfo, const HDI::Ril::V1_0::Rssi &rssi)
{
    return Notify(responseInfo, &TelRilManager::GetTelRilNetwork, &TelRilNetwork::SignalStrengthUpdated, rssi);
}

int32_t TelRilCallback::NetworkTimeZoneUpdated(
    const HDI::Ril::V1_0::RilRadioResponseInfo &responseInfo, const std::string &timeZoneStr)
{
    return Notify(responseInfo, &TelRilManager::GetTelRilNetwork, &TelRilNetwork::NetworkTimeZoneUpdated, timeZoneStr);
}

int32_t TelRilCallback::NetworkTimeUpdated(
    const HDI::Ril::V1_0::RilRadioResponseInfo &responseInfo, const std::string &timeStr)
{
    return Notify(responseInfo, &TelRilManager::GetTelRilNetwork, &TelRilNetwork::NetworkTimeUpdated, timeStr);
}

int32_t TelRilCallback::NetworkPhyChnlCfgUpdated(const HDI::Ril::V1_0::RilRadioResponseInfo &responseInfo,
    const HDI::Ril::V1_0::ChannelConfigInfoList &channelConfigInfoList)
{
    return Notify(responseInfo, &TelRilManager::GetTelRilNetwork, &TelRilNetwork::NetworkPhyChnlCfgUpdated,
        channelConfigInfoList);
}

int32_t TelRilCallback::NetworkCurrentCellUpdated(const HDI::Ril::V1_0::RilRadioResponseInfo &responseInfo,
    const HDI::Ril::V1_0::CellListCurrentInfo &cellListCurrentInfo)
{
    return Notify(responseInfo, &TelRilManager::GetTelRilNetwork, &TelRilNetwork::NetworkCurrentCellUpdated,
        cellListCurrentInfo);
}

int32_t TelRilCallback::GetSignalStrengthResponse(
    const HDI::Ril::V1_0::RilRadioResponseInfo &responseInfo, const HDI::Ril::V1_0::Rssi &rssi)
{
    return Response(responseInfo, &TelRilManager::GetTelRilNetwork, &TelRilNetwork::GetSignalStrengthResponse, rssi);
}

int32_t TelRilCallback::GetCsRegStatusResponse(
    const HDI::Ril::V1_0::RilRadioResponseInfo &responseInfo, const HDI::Ril::V1_0::CsRegStatusInfo &csRegStatusInfo)
{
    return Response(
        responseInfo, &TelRilManager::GetTelRilNetwork, &TelRilNetwork::GetCsRegStatusResponse, csRegStatusInfo);
}

int32_t TelRilCallback::GetPsRegStatusResponse(
    const HDI::Ril::V1_0::RilRadioResponseInfo &responseInfo, const HDI::Ril::V1_0::PsRegStatusInfo &psRegStatusInfo)
{
    return Response(
        responseInfo, &TelRilManager::GetTelRilNetwork, &TelRilNetwork::GetPsRegStatusResponse, psRegStatusInfo);
}

int32_t TelRilCallback::GetOperatorInfoResponse(
    const HDI::Ril::V1_0::RilRadioResponseInfo &responseInfo, const HDI::Ril::V1_0::OperatorInfo &operatorInfo)
{
    return Response(
        responseInfo, &TelRilManager::GetTelRilNetwork, &TelRilNetwork::GetOperatorInfoResponse, operatorInfo);
}

int32_t TelRilCallback::GetNetworkSearchInformationResponse(const HDI::Ril::V1_0::RilRadioResponseInfo &responseInfo,
    const HDI::Ril::V1_0::AvailableNetworkList &availableNetworkList)
{
    return Response(responseInfo, &TelRilManager::GetTelRilNetwork, &TelRilNetwork::GetNetworkSearchInformationResponse,
        availableNetworkList);
}

int32_t TelRilCallback::GetNetworkSelectionModeResponse(const HDI::Ril::V1_0::RilRadioResponseInfo &responseInfo,
    const HDI::Ril::V1_0::SetNetworkModeInfo &setNetworkModeInfo)
{
    return Response(responseInfo, &TelRilManager::GetTelRilNetwork, &TelRilNetwork::GetNetworkSelectionModeResponse,
        setNetworkModeInfo);
}

int32_t TelRilCallback::SetNetworkSelectionModeResponse(const HDI::Ril::V1_0::RilRadioResponseInfo &responseInfo)
{
    return Response(responseInfo, &TelRilManager::GetTelRilNetwork, &TelRilNetwork::SetNetworkSelectionModeResponse);
}

int32_t TelRilCallback::GetNeighboringCellInfoListResponse(
    const HDI::Ril::V1_0::RilRadioResponseInfo &responseInfo, const HDI::Ril::V1_0::CellListNearbyInfo &cellInfoList)
{
    return Response(responseInfo, &TelRilManager::GetTelRilNetwork, &TelRilNetwork::GetNeighboringCellInfoListResponse,
        cellInfoList);
}

int32_t TelRilCallback::GetCurrentCellInfoResponse(
    const HDI::Ril::V1_0::RilRadioResponseInfo &responseInfo, const HDI::Ril::V1_0::CellListCurrentInfo &cellInfoList)
{
    return Response(
        responseInfo, &TelRilManager::GetTelRilNetwork, &TelRilNetwork::GetCurrentCellInfoResponse, cellInfoList);
}

int32_t TelRilCallback::SetPreferredNetworkResponse(const HDI::Ril::V1_0::RilRadioResponseInfo &responseInfo)
{
    return Response(responseInfo, &TelRilManager::GetTelRilNetwork, &TelRilNetwork::SetPreferredNetworkResponse);
}

int32_t TelRilCallback::GetPreferredNetworkResponse(const HDI::Ril::V1_0::RilRadioResponseInfo &responseInfo,
    const HDI::Ril::V1_0::PreferredNetworkTypeInfo &preferredNetworkTypeInfo)
{
    return Response(responseInfo, &TelRilManager::GetTelRilNetwork, &TelRilNetwork::GetPreferredNetworkResponse,
        preferredNetworkTypeInfo);
}

int32_t TelRilCallback::GetPhysicalChannelConfigResponse(const HDI::Ril::V1_0::RilRadioResponseInfo &responseInfo,
    const HDI::Ril::V1_0::ChannelConfigInfoList &channelConfigInfoList)
{
    return Response(responseInfo, &TelRilManager::GetTelRilNetwork, &TelRilNetwork::GetPhysicalChannelConfigResponse,
        channelConfigInfoList);
}

int32_t TelRilCallback::SetLocateUpdatesResponse(const HDI::Ril::V1_0::RilRadioResponseInfo &responseInfo)
{
    return Response(responseInfo, &TelRilManager::GetTelRilNetwork, &TelRilNetwork::SetLocateUpdatesResponse);
}

int32_t TelRilCallback::SetNotificationFilterResponse(const HDI::Ril::V1_0::RilRadioResponseInfo &responseInfo)
{
    return Response(responseInfo, &TelRilManager::GetTelRilNetwork, &TelRilNetwork::SetNotificationFilterResponse);
}

int32_t TelRilCallback::SetDeviceStateResponse(const HDI::Ril::V1_0::RilRadioResponseInfo &responseInfo)
{
    return Response(responseInfo, &TelRilManager::GetTelRilNetwork, &TelRilNetwork::SetDeviceStateResponse);
}

int32_t TelRilCallback::NewSmsNotify(
    const HDI::Ril::V1_0::RilRadioResponseInfo &responseInfo, const HDI::Ril::V1_0::SmsMessageInfo &smsMessageInfo)
{
    return Notify(responseInfo, &TelRilManager::GetTelRilSms, &TelRilSms::NewSmsNotify, smsMessageInfo);
}

int32_t TelRilCallback::NewCdmaSmsNotify(
    const HDI::Ril::V1_0::RilRadioResponseInfo &responseInfo, const HDI::Ril::V1_0::SmsMessageInfo &smsMessageInfo)
{
    return Notify(responseInfo, &TelRilManager::GetTelRilSms, &TelRilSms::NewCdmaSmsNotify, smsMessageInfo);
}

int32_t TelRilCallback::SmsStatusReportNotify(
    const HDI::Ril::V1_0::RilRadioResponseInfo &responseInfo, const HDI::Ril::V1_0::SmsMessageInfo &smsMessageInfo)
{
    return Notify(responseInfo, &TelRilManager::GetTelRilSms, &TelRilSms::SmsStatusReportNotify, smsMessageInfo);
}

int32_t TelRilCallback::NewSmsStoredOnSimNotify(
    const HDI::Ril::V1_0::RilRadioResponseInfo &responseInfo, int32_t recordNumber, int32_t indicationType)
{
    return Notify(
        responseInfo, &TelRilManager::GetTelRilSms, &TelRilSms::NewSmsStoredOnSimNotify, recordNumber, indicationType);
}

int32_t TelRilCallback::CBConfigNotify(const HDI::Ril::V1_0::RilRadioResponseInfo &responseInfo,
    const HDI::Ril::V1_0::CBConfigReportInfo &cellBroadConfigReportInfo)
{
    return Notify(responseInfo, &TelRilManager::GetTelRilSms, &TelRilSms::CBConfigNotify, cellBroadConfigReportInfo);
}

int32_t TelRilCallback::SendGsmSmsResponse(const HDI::Ril::V1_0::RilRadioResponseInfo &responseInfo,
    const HDI::Ril::V1_0::SendSmsResultInfo &sendSmsResultInfo)
{
    return Response(responseInfo, &TelRilManager::GetTelRilSms, &TelRilSms::SendGsmSmsResponse, sendSmsResultInfo);
}

int32_t TelRilCallback::SendCdmaSmsResponse(const HDI::Ril::V1_0::RilRadioResponseInfo &responseInfo,
    const HDI::Ril::V1_0::SendSmsResultInfo &sendSmsResultInfo)
{
    return Response(responseInfo, &TelRilManager::GetTelRilSms, &TelRilSms::SendCdmaSmsResponse, sendSmsResultInfo);
}

int32_t TelRilCallback::AddSimMessageResponse(const HDI::Ril::V1_0::RilRadioResponseInfo &responseInfo)
{
    return Response(responseInfo, &TelRilManager::GetTelRilSms, &TelRilSms::AddSimMessageResponse);
}

int32_t TelRilCallback::DelSimMessageResponse(const HDI::Ril::V1_0::RilRadioResponseInfo &responseInfo)
{
    return Response(responseInfo, &TelRilManager::GetTelRilSms, &TelRilSms::DelSimMessageResponse);
}

int32_t TelRilCallback::UpdateSimMessageResponse(const HDI::Ril::V1_0::RilRadioResponseInfo &responseInfo)
{
    return Response(responseInfo, &TelRilManager::GetTelRilSms, &TelRilSms::UpdateSimMessageResponse);
}

int32_t TelRilCallback::AddCdmaSimMessageResponse(const HDI::Ril::V1_0::RilRadioResponseInfo &responseInfo)
{
    return Response(responseInfo, &TelRilManager::GetTelRilSms, &TelRilSms::AddCdmaSimMessageResponse);
}

int32_t TelRilCallback::DelCdmaSimMessageResponse(const HDI::Ril::V1_0::RilRadioResponseInfo &responseInfo)
{
    return Response(responseInfo, &TelRilManager::GetTelRilSms, &TelRilSms::DelCdmaSimMessageResponse);
}

int32_t TelRilCallback::UpdateCdmaSimMessageResponse(const HDI::Ril::V1_0::RilRadioResponseInfo &responseInfo)
{
    return Response(responseInfo, &TelRilManager::GetTelRilSms, &TelRilSms::UpdateCdmaSimMessageResponse);
}

int32_t TelRilCallback::SetSmscAddrResponse(const HDI::Ril::V1_0::RilRadioResponseInfo &responseInfo)
{
    return Response(responseInfo, &TelRilManager::GetTelRilSms, &TelRilSms::SetSmscAddrResponse);
}

int32_t TelRilCallback::GetSmscAddrResponse(const HDI::Ril::V1_0::RilRadioResponseInfo &responseInfo,
    const HDI::Ril::V1_0::ServiceCenterAddress &serviceCenterAddress)
{
    return Response(responseInfo, &TelRilManager::GetTelRilSms, &TelRilSms::GetSmscAddrResponse, serviceCenterAddress);
}

int32_t TelRilCallback::SetCBConfigResponse(const HDI::Ril::V1_0::RilRadioResponseInfo &responseInfo)
{
    return Response(responseInfo, &TelRilManager::GetTelRilSms, &TelRilSms::SetCBConfigResponse);
}

int32_t TelRilCallback::GetCBConfigResponse(
    const HDI::Ril::V1_0::RilRadioResponseInfo &responseInfo, const HDI::Ril::V1_0::CBConfigInfo &cellBroadcastInfo)
{
    return Response(responseInfo, &TelRilManager::GetTelRilSms, &TelRilSms::GetCBConfigResponse, cellBroadcastInfo);
}

int32_t TelRilCallback::SetCdmaCBConfigResponse(const HDI::Ril::V1_0::RilRadioResponseInfo &responseInfo)
{
    return Response(responseInfo, &TelRilManager::GetTelRilSms, &TelRilSms::SetCdmaCBConfigResponse);
}

int32_t TelRilCallback::GetCdmaCBConfigResponse(
    const HDI::Ril::V1_0::RilRadioResponseInfo &responseInfo, const HDI::Ril::V1_0::CdmaCBConfigInfo &cdmaCBConfigInfo)
{
    return Response(responseInfo, &TelRilManager::GetTelRilSms, &TelRilSms::GetCdmaCBConfigResponse, cdmaCBConfigInfo);
}

int32_t TelRilCallback::SendSmsMoreModeResponse(const HDI::Ril::V1_0::RilRadioResponseInfo &responseInfo,
    const HDI::Ril::V1_0::SendSmsResultInfo &sendSmsResultInfo)
{
    return Response(responseInfo, &TelRilManager::GetTelRilSms, &TelRilSms::SendSmsMoreModeResponse, sendSmsResultInfo);
}

int32_t TelRilCallback::SendSmsAckResponse(const HDI::Ril::V1_0::RilRadioResponseInfo &responseInfo)
{
    return Response(responseInfo, &TelRilManager::GetTelRilSms, &TelRilSms::SendSmsAckResponse);
}
} // namespace Telephony
} // namespace OHOS
