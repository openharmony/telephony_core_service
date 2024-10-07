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

#include "tel_ril_sim.h"

#include "radio_event.h"
#include "sim_data_type.h"
#include "sim_utils.h"

namespace OHOS {
namespace Telephony {
TelRilSim::TelRilSim(int32_t slotId, sptr<HDI::Ril::V1_3::IRil> rilInterface,
    std::shared_ptr<ObserverHandler> observerHandler, std::shared_ptr<TelRilHandler> handler)
    : TelRilBase(slotId, rilInterface, observerHandler, handler)
{}

// notification
int32_t TelRilSim::SimStateUpdated()
{
    return Notify(TELEPHONY_LOG_FUNC_NAME, RadioEvent::RADIO_SIM_STATE_CHANGE);
}

int32_t TelRilSim::SimStkSessionEndNotify()
{
    return Notify(TELEPHONY_LOG_FUNC_NAME, RadioEvent::RADIO_STK_SESSION_END);
}

int32_t TelRilSim::SimStkProactiveNotify(const std::string &response)
{
    return Notify<std::string>(
        TELEPHONY_LOG_FUNC_NAME, std::make_shared<std::string>(response), RadioEvent::RADIO_STK_PROACTIVE_COMMAND);
}

int32_t TelRilSim::SimStkAlphaNotify(const std::string &response)
{
    return Notify<std::string>(
        TELEPHONY_LOG_FUNC_NAME, std::make_shared<std::string>(response), RadioEvent::RADIO_STK_ALPHA_NOTIFY);
}

int32_t TelRilSim::SimStkEventNotify(const std::string &response)
{
    return Notify<std::string>(
        TELEPHONY_LOG_FUNC_NAME, std::make_shared<std::string>(response), RadioEvent::RADIO_STK_EVENT_NOTIFY);
}

int32_t TelRilSim::SimStkCallSetupNotify()
{
    return Notify(TELEPHONY_LOG_FUNC_NAME, RadioEvent::RADIO_STK_CALL_SETUP);
}

int32_t TelRilSim::SimRefreshNotify()
{
    return Notify(TELEPHONY_LOG_FUNC_NAME, RadioEvent::RADIO_ICC_REFRESH);
}

int32_t TelRilSim::SimRadioProtocolUpdated(const HDI::Ril::V1_1::RadioProtocol &radioProtocol)
{
    std::shared_ptr<RadioProtocol> protocol = std::make_shared<RadioProtocol>();
    BuildRadioProtocol(protocol, radioProtocol);
    return Notify<RadioProtocol>(TELEPHONY_LOG_FUNC_NAME, protocol, RADIO_SIM_RADIO_PROTOCOL_NOTIFY);
}

// response
int32_t TelRilSim::GetSimIOResponse(
    const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo, const HDI::Ril::V1_1::IccIoResultInfo &result)
{
    return ResponseIccIo(responseInfo, result);
}

int32_t TelRilSim::ErrorIccIoResponse(
    std::shared_ptr<TelRilRequest> telRilRequest, const RadioResponseInfo &responseInfo)
{
    std::shared_ptr<RadioResponseInfo> respInfo = std::make_shared<RadioResponseInfo>();
    if (telRilRequest != nullptr && telRilRequest->pointer_ != nullptr) {
        const std::shared_ptr<OHOS::AppExecFwk::EventHandler> &handler = telRilRequest->pointer_->GetOwner();
        if (handler == nullptr) {
            TELEPHONY_LOGE("ERROR: handler == nullptr !!!");
            return TELEPHONY_ERR_LOCAL_PTR_NULL;
        }
        respInfo->serial = responseInfo.serial;
        respInfo->error = responseInfo.error;
        respInfo->flag = telRilRequest->pointer_->GetParam();

        uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
        std::unique_ptr<Telephony::IccToRilMsg> toMsg =
            telRilRequest->pointer_->GetUniqueObject<Telephony::IccToRilMsg>();
        if (toMsg == nullptr) {
            TELEPHONY_LOGE("ERROR: toMsg == nullptr !!!");
            return TELEPHONY_ERR_LOCAL_PTR_NULL;
        }
        std::shared_ptr<Telephony::IccFromRilMsg> object =
            std::make_shared<Telephony::IccFromRilMsg>(toMsg->controlHolder);
        object->controlHolder = toMsg->controlHolder;
        object->fileData.exception = static_cast<std::shared_ptr<void>>(respInfo);
        SendEventData(TELEPHONY_LOG_FUNC_NAME, eventId, handler, object);
    } else {
        TELEPHONY_LOGE("ERROR: telRilRequest or telRilRequest->pointer_ == nullptr !!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    return TELEPHONY_ERR_SUCCESS;
}

int32_t TelRilSim::ProcessIccIoInfo(
    std::shared_ptr<TelRilRequest> telRilRequest, std::shared_ptr<IccIoResultInfo> iccIoResult)
{
    if (telRilRequest == nullptr) {
        TELEPHONY_LOGE("ERROR: telRilRequest== nullptr !!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    if (telRilRequest->pointer_ == nullptr) {
        TELEPHONY_LOGE("ERROR: telRilRequest->pointer_== nullptr !!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    if (telRilRequest->pointer_->GetOwner() == nullptr || iccIoResult == nullptr) {
        TELEPHONY_LOGE("ERROR: telRilRequest->pointer_->GetOwner() or iccIoResult == nullptr !!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    const std::shared_ptr<OHOS::AppExecFwk::EventHandler> &handler = telRilRequest->pointer_->GetOwner();
    uint32_t eventId = telRilRequest->pointer_->GetInnerEventId();
    std::unique_ptr<Telephony::IccToRilMsg> toMsg = telRilRequest->pointer_->GetUniqueObject<Telephony::IccToRilMsg>();
    if (toMsg == nullptr) {
        TELEPHONY_LOGE("ERROR: GetUniqueObject<IccToRilMsg>() failed !!!");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    std::unique_ptr<Telephony::IccFromRilMsg> object = std::make_unique<Telephony::IccFromRilMsg>(toMsg->controlHolder);
    object->fileData.resultData = iccIoResult->response;
    object->fileData.sw1 = iccIoResult->sw1;
    object->fileData.sw2 = iccIoResult->sw2;
    object->controlHolder = toMsg->controlHolder;
    object->arg1 = toMsg->arg1;
    object->arg2 = toMsg->arg2;
    SendEventData(TELEPHONY_LOG_FUNC_NAME, eventId, handler, std::move(object));
    return TELEPHONY_ERR_SUCCESS;
}

int32_t TelRilSim::GetSimStatusResponse(
    const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo, const HDI::Ril::V1_1::CardStatusInfo &result)
{
    std::shared_ptr<CardStatusInfo> cardStatusInfo = std::make_shared<CardStatusInfo>();
    BuildCardStatusInfo(cardStatusInfo, result);
    return Response<CardStatusInfo>(TELEPHONY_LOG_FUNC_NAME, responseInfo, cardStatusInfo);
}

int32_t TelRilSim::GetSimCardStatusResponse(const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo,
    const HDI::Ril::V1_3::SimCardStatusInfo &result)
{
    std::shared_ptr<SimCardStatusInfo> simCardStatusInfo = std::make_shared<SimCardStatusInfo>();
    BuildSimCardStatusInfo(simCardStatusInfo, result);
    return Response<SimCardStatusInfo>(TELEPHONY_LOG_FUNC_NAME, responseInfo, simCardStatusInfo);
}

int32_t TelRilSim::GetImsiResponse(const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo, const std::string &result)
{
    return Response<std::string>(TELEPHONY_LOG_FUNC_NAME, responseInfo, std::make_shared<std::string>(result));
}

int32_t TelRilSim::GetSimLockStatusResponse(
    const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo, int32_t simLockStatus)
{
    return Response<int32_t>(TELEPHONY_LOG_FUNC_NAME, responseInfo, std::make_shared<int32_t>(simLockStatus));
}

int32_t TelRilSim::SetSimLockResponse(
    const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo, const HDI::Ril::V1_1::LockStatusResp &lockStatus)
{
    std::shared_ptr<LockStatusResp> lockStatusResp = std::make_shared<LockStatusResp>();
    BuildLockStatusResp(lockStatusResp, lockStatus);
    return Response<LockStatusResp>(TELEPHONY_LOG_FUNC_NAME, responseInfo, lockStatusResp);
}

int32_t TelRilSim::ChangeSimPasswordResponse(
    const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo, const HDI::Ril::V1_1::LockStatusResp &lockStatus)
{
    std::shared_ptr<LockStatusResp> lockStatusResp = std::make_shared<LockStatusResp>();
    BuildLockStatusResp(lockStatusResp, lockStatus);
    return Response<LockStatusResp>(TELEPHONY_LOG_FUNC_NAME, responseInfo, lockStatusResp);
}

int32_t TelRilSim::UnlockPinResponse(
    const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo, const HDI::Ril::V1_1::LockStatusResp &lockStatus)
{
    std::shared_ptr<LockStatusResp> lockStatusResp = std::make_shared<LockStatusResp>();
    BuildLockStatusResp(lockStatusResp, lockStatus);
    return Response<LockStatusResp>(TELEPHONY_LOG_FUNC_NAME, responseInfo, lockStatusResp);
}

int32_t TelRilSim::UnlockPukResponse(
    const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo, const HDI::Ril::V1_1::LockStatusResp &lockStatus)
{
    std::shared_ptr<LockStatusResp> lockStatusResp = std::make_shared<LockStatusResp>();
    BuildLockStatusResp(lockStatusResp, lockStatus);
    return Response<LockStatusResp>(TELEPHONY_LOG_FUNC_NAME, responseInfo, lockStatusResp);
}

int32_t TelRilSim::UnlockPin2Response(
    const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo, const HDI::Ril::V1_1::LockStatusResp &lockStatus)
{
    std::shared_ptr<LockStatusResp> lockStatusResp = std::make_shared<LockStatusResp>();
    BuildLockStatusResp(lockStatusResp, lockStatus);
    return Response<LockStatusResp>(TELEPHONY_LOG_FUNC_NAME, responseInfo, lockStatusResp);
}

int32_t TelRilSim::UnlockPuk2Response(
    const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo, const HDI::Ril::V1_1::LockStatusResp &lockStatus)
{
    std::shared_ptr<LockStatusResp> lockStatusResp = std::make_shared<LockStatusResp>();
    BuildLockStatusResp(lockStatusResp, lockStatus);
    return Response<LockStatusResp>(TELEPHONY_LOG_FUNC_NAME, responseInfo, lockStatusResp);
}

int32_t TelRilSim::SetActiveSimResponse(const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo)
{
    return Response(TELEPHONY_LOG_FUNC_NAME, responseInfo);
}

int32_t TelRilSim::SimStkSendTerminalResponseResponse(const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo)
{
    return Response(TELEPHONY_LOG_FUNC_NAME, responseInfo);
}

int32_t TelRilSim::SimStkSendEnvelopeResponse(const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo)
{
    return Response(TELEPHONY_LOG_FUNC_NAME, responseInfo);
}

int32_t TelRilSim::SimStkSendCallSetupRequestResultResponse(const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo)
{
    return Response(TELEPHONY_LOG_FUNC_NAME, responseInfo);
}

int32_t TelRilSim::SimStkIsReadyResponse(const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo)
{
    return Response(TELEPHONY_LOG_FUNC_NAME, responseInfo);
}

int32_t TelRilSim::GetRadioProtocolResponse(
    const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo, const HDI::Ril::V1_1::RadioProtocol &radioProtocol)
{
    std::shared_ptr<RadioProtocol> protocol = std::make_shared<RadioProtocol>();
    BuildRadioProtocol(protocol, radioProtocol);
    return Response<RadioProtocol>(TELEPHONY_LOG_FUNC_NAME, responseInfo, protocol);
}

int32_t TelRilSim::SetRadioProtocolResponse(
    const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo, const HDI::Ril::V1_1::RadioProtocol &radioProtocol)
{
    std::shared_ptr<RadioProtocol> protocol = std::make_shared<RadioProtocol>();
    BuildRadioProtocol(protocol, radioProtocol);
    return Response<RadioProtocol>(TELEPHONY_LOG_FUNC_NAME, responseInfo, protocol);
}

int32_t TelRilSim::SimOpenLogicalChannelResponse(const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo,
    const HDI::Ril::V1_1::OpenLogicalChannelResponse &pOpenLogicalChannelResponse)
{
    std::shared_ptr<OpenLogicalChannelResponse> openLogicalChannelResp = std::make_shared<OpenLogicalChannelResponse>();
    BuildOpenLogicalChannelResp(openLogicalChannelResp, pOpenLogicalChannelResponse);
    return Response<OpenLogicalChannelResponse>(TELEPHONY_LOG_FUNC_NAME, responseInfo, openLogicalChannelResp);
}

int32_t TelRilSim::SimCloseLogicalChannelResponse(const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo)
{
    return Response(TELEPHONY_LOG_FUNC_NAME, responseInfo);
}

int32_t TelRilSim::SimTransmitApduLogicalChannelResponse(
    const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo, const HDI::Ril::V1_1::IccIoResultInfo &result)
{
    return ResponseIccIo(responseInfo, result);
}

int32_t TelRilSim::SimTransmitApduBasicChannelResponse(
    const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo, const HDI::Ril::V1_1::IccIoResultInfo &result)
{
    return ResponseIccIo(responseInfo, result);
}

int32_t TelRilSim::SimAuthenticationResponse(
    const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo, const HDI::Ril::V1_1::IccIoResultInfo &result)
{
    std::shared_ptr<IccIoResultInfo> simAuthResp = std::make_shared<IccIoResultInfo>();
    simAuthResp->sw1 = result.sw1;
    simAuthResp->sw2 = result.sw2;
    simAuthResp->response = result.response;
    return Response<IccIoResultInfo>(TELEPHONY_LOG_FUNC_NAME, responseInfo, simAuthResp);
}

int32_t TelRilSim::UnlockSimLockResponse(
    const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo, const HDI::Ril::V1_1::LockStatusResp &lockStatus)
{
    std::shared_ptr<LockStatusResp> lockStatusResp = std::make_shared<LockStatusResp>();
    BuildLockStatusResp(lockStatusResp, lockStatus);
    return Response<LockStatusResp>(TELEPHONY_LOG_FUNC_NAME, responseInfo, lockStatusResp);
}

int32_t TelRilSim::SendSimMatchedOperatorInfoResponse(const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo)
{
    return Response(TELEPHONY_LOG_FUNC_NAME, responseInfo);
}

int32_t TelRilSim::GetSimStatus(const AppExecFwk::InnerEvent::Pointer &result)
{
    return Request(TELEPHONY_LOG_FUNC_NAME, result, &HDI::Ril::V1_1::IRil::GetSimStatus);
}

int32_t TelRilSim::GetSimIO(SimIoRequestInfo simIoInfo, const AppExecFwk::InnerEvent::Pointer &response)
{
    OHOS::HDI::Ril::V1_1::SimIoRequestInfo iccIoRequestInfo;
    iccIoRequestInfo.command = simIoInfo.command;
    iccIoRequestInfo.fileId = simIoInfo.fileId;
    iccIoRequestInfo.p1 = simIoInfo.p1;
    iccIoRequestInfo.p2 = simIoInfo.p2;
    iccIoRequestInfo.p3 = simIoInfo.p3;
    iccIoRequestInfo.data = simIoInfo.data;
    iccIoRequestInfo.path = simIoInfo.path;
    iccIoRequestInfo.pin2 = simIoInfo.pin2;
    return Request(TELEPHONY_LOG_FUNC_NAME, response, &HDI::Ril::V1_1::IRil::GetSimIO, iccIoRequestInfo);
}

int32_t TelRilSim::GetImsi(const AppExecFwk::InnerEvent::Pointer &result)
{
    return Request(TELEPHONY_LOG_FUNC_NAME, result, &HDI::Ril::V1_1::IRil::GetImsi);
}

int32_t TelRilSim::GetSimLockStatus(std::string fac, const AppExecFwk::InnerEvent::Pointer &response)
{
    const int32_t MODE = 2;
    OHOS::HDI::Ril::V1_1::SimLockInfo simLockInfo;
    simLockInfo.fac = fac;
    simLockInfo.mode = MODE;
    simLockInfo.classx = 0;
    return Request(TELEPHONY_LOG_FUNC_NAME, response, &HDI::Ril::V1_1::IRil::GetSimLockStatus, simLockInfo);
}

int32_t TelRilSim::SetSimLock(
    std::string fac, int32_t mode, std::string passwd, const AppExecFwk::InnerEvent::Pointer &response)
{
    OHOS::HDI::Ril::V1_1::SimLockInfo simLockInfo;
    simLockInfo.fac = fac;
    simLockInfo.mode = mode;
    simLockInfo.passwd = passwd;
    simLockInfo.classx = 0;
    return Request(TELEPHONY_LOG_FUNC_NAME, response, &HDI::Ril::V1_1::IRil::SetSimLock, simLockInfo);
}

int32_t TelRilSim::ChangeSimPassword(std::string fac, std::string oldPassword, std::string newPassword,
    int32_t passwordLength, const AppExecFwk::InnerEvent::Pointer &response)
{
    OHOS::HDI::Ril::V1_1::SimPasswordInfo simPwdInfo;
    simPwdInfo.fac = fac;
    simPwdInfo.oldPassword = oldPassword;
    simPwdInfo.newPassword = newPassword;
    simPwdInfo.passwordLength = passwordLength;
    return Request(TELEPHONY_LOG_FUNC_NAME, response, &HDI::Ril::V1_1::IRil::ChangeSimPassword, simPwdInfo);
}

int32_t TelRilSim::UnlockPin(std::string pin, const AppExecFwk::InnerEvent::Pointer &response)
{
    return Request(TELEPHONY_LOG_FUNC_NAME, response, &HDI::Ril::V1_1::IRil::UnlockPin, pin);
}

int32_t TelRilSim::UnlockPuk(std::string puk, std::string pin, const AppExecFwk::InnerEvent::Pointer &response)
{
    return Request(TELEPHONY_LOG_FUNC_NAME, response, &HDI::Ril::V1_1::IRil::UnlockPuk, puk, pin);
}

int32_t TelRilSim::UnlockPin2(std::string pin2, const AppExecFwk::InnerEvent::Pointer &response)
{
    return Request(TELEPHONY_LOG_FUNC_NAME, response, &HDI::Ril::V1_1::IRil::UnlockPin2, pin2);
}

int32_t TelRilSim::UnlockPuk2(std::string puk2, std::string pin2, const AppExecFwk::InnerEvent::Pointer &response)
{
    return Request(TELEPHONY_LOG_FUNC_NAME, response, &HDI::Ril::V1_1::IRil::UnlockPuk2, puk2, pin2);
}

int32_t TelRilSim::SetActiveSim(int32_t index, int32_t enable, const AppExecFwk::InnerEvent::Pointer &response)
{
    return Request(TELEPHONY_LOG_FUNC_NAME, response, &HDI::Ril::V1_1::IRil::SetActiveSim, index, enable);
}

int32_t TelRilSim::SimStkSendTerminalResponse(
    const std::string &strCmd, const AppExecFwk::InnerEvent::Pointer &response)
{
    return Request(TELEPHONY_LOG_FUNC_NAME, response, &HDI::Ril::V1_1::IRil::SimStkSendTerminalResponse, strCmd);
}

int32_t TelRilSim::SimStkSendEnvelope(const std::string &strCmd, const AppExecFwk::InnerEvent::Pointer &response)
{
    return Request(TELEPHONY_LOG_FUNC_NAME, response, &HDI::Ril::V1_1::IRil::SimStkSendEnvelope, strCmd);
}

int32_t TelRilSim::SimStkSendCallSetupRequestResult(bool accept, const AppExecFwk::InnerEvent::Pointer &response)
{
    return Request(
        TELEPHONY_LOG_FUNC_NAME, response, &HDI::Ril::V1_1::IRil::SimStkSendCallSetupRequestResult, (int32_t)accept);
}

int32_t TelRilSim::SimStkIsReady(const AppExecFwk::InnerEvent::Pointer &response)
{
    return Request(TELEPHONY_LOG_FUNC_NAME, response, &HDI::Ril::V1_1::IRil::SimStkIsReady);
}

int32_t TelRilSim::GetRadioProtocol(const AppExecFwk::InnerEvent::Pointer &response)
{
    return Request(TELEPHONY_LOG_FUNC_NAME, response, &HDI::Ril::V1_1::IRil::GetRadioProtocol);
}

int32_t TelRilSim::SetRadioProtocol(RadioProtocol radioProtocol, const AppExecFwk::InnerEvent::Pointer &response)
{
    HDI::Ril::V1_1::RadioProtocol protocol;
    protocol.slotId = radioProtocol.slotId;
    protocol.sessionId = radioProtocol.sessionId;
    protocol.phase = static_cast<HDI::Ril::V1_1::RadioProtocolPhase>(radioProtocol.phase);
    protocol.technology = radioProtocol.technology;
    protocol.modemId = radioProtocol.modemId;
    protocol.status = static_cast<HDI::Ril::V1_1::RadioProtocolStatus>(radioProtocol.status);
    return Request(TELEPHONY_LOG_FUNC_NAME, response, &HDI::Ril::V1_1::IRil::SetRadioProtocol, protocol);
}

int32_t TelRilSim::SimOpenLogicalChannel(std::string appID, int32_t p2, const AppExecFwk::InnerEvent::Pointer &response)
{
    return Request(TELEPHONY_LOG_FUNC_NAME, response, &HDI::Ril::V1_1::IRil::SimOpenLogicalChannel, appID, p2);
}

int32_t TelRilSim::SimCloseLogicalChannel(int32_t channelId, const AppExecFwk::InnerEvent::Pointer &response)
{
    return Request(TELEPHONY_LOG_FUNC_NAME, response, &HDI::Ril::V1_1::IRil::SimCloseLogicalChannel, channelId);
}

int32_t TelRilSim::SimTransmitApduLogicalChannel(
    const ApduSimIORequestInfo &reqInfo, const AppExecFwk::InnerEvent::Pointer &response)
{
    OHOS::HDI::Ril::V1_1::ApduSimIORequestInfo ApduRequestInfo;
    BuildApduRequestInfo(ApduRequestInfo, reqInfo);
    return Request(
        TELEPHONY_LOG_FUNC_NAME, response, &HDI::Ril::V1_1::IRil::SimTransmitApduLogicalChannel, ApduRequestInfo);
}

int32_t TelRilSim::SimTransmitApduBasicChannel(
    const ApduSimIORequestInfo &reqInfo, const AppExecFwk::InnerEvent::Pointer &response)
{
    OHOS::HDI::Ril::V1_1::ApduSimIORequestInfo ApduRequestInfo;
    BuildApduRequestInfo(ApduRequestInfo, reqInfo);
    return Request(
        TELEPHONY_LOG_FUNC_NAME, response, &HDI::Ril::V1_1::IRil::SimTransmitApduBasicChannel, ApduRequestInfo);
}

int32_t TelRilSim::SimAuthentication(
    const SimAuthenticationRequestInfo &reqInfo, const AppExecFwk::InnerEvent::Pointer &response)
{
    OHOS::HDI::Ril::V1_1::SimAuthenticationRequestInfo simAuthInfo;
    simAuthInfo.serial = reqInfo.serial;
    simAuthInfo.aid = reqInfo.aid;
    simAuthInfo.authData = reqInfo.authData;
    return Request(TELEPHONY_LOG_FUNC_NAME, response, &HDI::Ril::V1_1::IRil::SimAuthentication, simAuthInfo);
}

int32_t TelRilSim::UnlockSimLock(
    int32_t lockType, std::string password, const AppExecFwk::InnerEvent::Pointer &response)
{
    return Request(TELEPHONY_LOG_FUNC_NAME, response, &HDI::Ril::V1_1::IRil::UnlockSimLock, lockType, password);
}

int32_t TelRilSim::SendSimMatchedOperatorInfo(
    const NcfgOperatorInfo &reqInfo, const AppExecFwk::InnerEvent::Pointer &response)
{
    OHOS::HDI::Ril::V1_2::NcfgOperatorInfo ncfgOperatorInfo;
    ncfgOperatorInfo.operName = reqInfo.operName;
    ncfgOperatorInfo.operKey = reqInfo.operKey;
    ncfgOperatorInfo.state = reqInfo.state;
    ncfgOperatorInfo.reserve = reqInfo.reserve;
    return Request(
        TELEPHONY_LOG_FUNC_NAME, response, &HDI::Ril::V1_2::IRil::SendSimMatchedOperatorInfo, ncfgOperatorInfo);
}

void TelRilSim::BuildIccIoResult(
    std::shared_ptr<IccIoResultInfo> iccIoResult, const HDI::Ril::V1_1::IccIoResultInfo &result)
{
    if (iccIoResult == nullptr) {
        TELEPHONY_LOGE("BuildIccIoResult iccIoResult is nullptr");
        return;
    }
    iccIoResult->response = result.response;
    iccIoResult->sw1 = result.sw1;
    iccIoResult->sw2 = result.sw2;
}

void TelRilSim::BuildCardStatusInfo(
    std::shared_ptr<CardStatusInfo> cardStatusInfo, const HDI::Ril::V1_1::CardStatusInfo &result)
{
    if (cardStatusInfo == nullptr) {
        TELEPHONY_LOGE("BuildCardStatusInfo cardStatusInfo is nullptr");
        return;
    }
    cardStatusInfo->index = result.index;
    cardStatusInfo->simType = result.simType;
    cardStatusInfo->simState = result.simState;
    TELEPHONY_LOGD("cardStatusInfo: index:%{public}d, simType:%{public}d, simState:%{public}d",
        result.index, result.simType, result.simState);
}

void TelRilSim::BuildSimCardStatusInfo(std::shared_ptr<SimCardStatusInfo> simCardStatusInfo,
    const HDI::Ril::V1_3::SimCardStatusInfo &result)
{
    if (simCardStatusInfo == nullptr) {
        TELEPHONY_LOGE("BuildSimCardStatusInfo simCardStatusInfo is nullptr");
        return;
    }
    simCardStatusInfo->index = result.index;
    simCardStatusInfo->simType = result.simType;
    simCardStatusInfo->simState = result.simState;
    simCardStatusInfo->iccid = result.iccid;
    TELEPHONY_LOGD("simCardStatusInfo: index:%{public}d, simType:%{public}d, simState:%{public}d",
        result.index, result.simType, result.simState);
}

void TelRilSim::BuildLockStatusResp(
    std::shared_ptr<LockStatusResp> lockStatusResp, const HDI::Ril::V1_1::LockStatusResp &lockStatus)
{
    if (lockStatusResp == nullptr) {
        TELEPHONY_LOGE("BuildLockStatusResp lockStatusResp is nullptr");
        return;
    }
    lockStatusResp->result = lockStatus.result;
    lockStatusResp->remain = lockStatus.remain;
}

void TelRilSim::BuildRadioProtocol(
    std::shared_ptr<RadioProtocol> protocol, const HDI::Ril::V1_1::RadioProtocol &radioProtocol)
{
    if (protocol == nullptr) {
        TELEPHONY_LOGE("BuildRadioProtocol protocol is nullptr");
        return;
    }
    protocol->slotId = radioProtocol.slotId;
    protocol->sessionId = radioProtocol.sessionId;
    protocol->phase = static_cast<RadioProtocolPhase>(radioProtocol.phase);
    protocol->technology = radioProtocol.technology;
    protocol->modemId = radioProtocol.modemId;
    protocol->status = static_cast<RadioProtocolStatus>(radioProtocol.status);
}

void TelRilSim::BuildOpenLogicalChannelResp(std::shared_ptr<OpenLogicalChannelResponse> openLogicalChannelResp,
    const HDI::Ril::V1_1::OpenLogicalChannelResponse &pOpenLogicalChannelResponse)
{
    if (openLogicalChannelResp == nullptr) {
        TELEPHONY_LOGE("BuildOpenLogicalChannelResp openLogicalChannelResp is nullptr");
        return;
    }
    openLogicalChannelResp->sw1 = pOpenLogicalChannelResponse.sw1;
    openLogicalChannelResp->sw2 = pOpenLogicalChannelResponse.sw2;
    openLogicalChannelResp->channelId = pOpenLogicalChannelResponse.channelId;
    openLogicalChannelResp->response = pOpenLogicalChannelResponse.response;
}

void TelRilSim::BuildApduRequestInfo(
    OHOS::HDI::Ril::V1_1::ApduSimIORequestInfo &ApduRequestInfo, const ApduSimIORequestInfo &reqInfo)
{
    ApduRequestInfo.channelId = reqInfo.channelId;
    ApduRequestInfo.type = reqInfo.type;
    ApduRequestInfo.instruction = reqInfo.instruction;
    ApduRequestInfo.p1 = reqInfo.p1;
    ApduRequestInfo.p2 = reqInfo.p2;
    ApduRequestInfo.p3 = reqInfo.p3;
    ApduRequestInfo.data = reqInfo.data;
}

int32_t TelRilSim::ResponseIccIo(
    const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo, const HDI::Ril::V1_1::IccIoResultInfo &result)
{
    std::shared_ptr<IccIoResultInfo> iccIoResult = std::make_shared<IccIoResultInfo>();
    BuildIccIoResult(iccIoResult, result);
    const struct RadioResponseInfo radioResponseInfo = BuildHRilRadioResponseInfo(responseInfo);
    TELEPHONY_LOGI("radioResponseInfo.serial:%{public}d,radioResponseInfo.error:%{public}d", radioResponseInfo.serial,
        radioResponseInfo.error);
    std::shared_ptr<TelRilRequest> telRilRequest = FindTelRilRequest(radioResponseInfo);
    if (telRilRequest == nullptr || telRilRequest->pointer_ == nullptr) {
        TELEPHONY_LOGE("ERROR: ResponseIccIo telRilRequest == nullptr || telRilRequest->pointer_ == nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    if (radioResponseInfo.error != ErrType::NONE) {
        return ErrorIccIoResponse(telRilRequest, radioResponseInfo);
    }
    return ProcessIccIoInfo(telRilRequest, iccIoResult);
}
} // namespace Telephony
} // namespace OHOS
