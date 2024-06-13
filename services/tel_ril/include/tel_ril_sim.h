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

#ifndef TEL_RIL_SIM_H
#define TEL_RIL_SIM_H

#include "tel_ril_sim_parcel.h"
#include "tel_ril_base.h"
#include "telephony_types.h"

namespace OHOS {
namespace Telephony {
class TelRilSim : public TelRilBase {
public:
    TelRilSim(int32_t slotId, sptr<HDI::Ril::V1_3::IRil> rilInterface, std::shared_ptr<ObserverHandler> observerHandler,
        std::shared_ptr<TelRilHandler> handler);
    ~TelRilSim() = default;

    int32_t SimStateUpdated();
    int32_t SimStkSessionEndNotify();
    int32_t SimStkProactiveNotify(const std::string &response);
    int32_t SimStkAlphaNotify(const std::string &response);
    int32_t SimStkEventNotify(const std::string &response);
    int32_t SimStkCallSetupNotify();
    int32_t SimRefreshNotify();
    int32_t SimRadioProtocolUpdated(const HDI::Ril::V1_1::RadioProtocol &radioProtocol);

    int32_t GetSimStatus(const AppExecFwk::InnerEvent::Pointer &result);
    int32_t GetImsi(const AppExecFwk::InnerEvent::Pointer &result);
    int32_t GetSimIO(SimIoRequestInfo simIoInfo, const AppExecFwk::InnerEvent::Pointer &response);
    int32_t GetSimLockStatus(std::string fac, const AppExecFwk::InnerEvent::Pointer &response);
    int32_t SetSimLock(
        std::string fac, int32_t mode, std::string passwd, const AppExecFwk::InnerEvent::Pointer &response);
    int32_t ChangeSimPassword(std::string fac, std::string oldPassword, std::string newPassword,
        int32_t passwordLength, const AppExecFwk::InnerEvent::Pointer &response);
    int32_t UnlockPin(std::string pin, const AppExecFwk::InnerEvent::Pointer &response);
    int32_t UnlockPuk(std::string puk, std::string pin, const AppExecFwk::InnerEvent::Pointer &response);
    int32_t UnlockPin2(std::string pin2, const AppExecFwk::InnerEvent::Pointer &response);
    int32_t UnlockPuk2(std::string puk2, std::string pin2, const AppExecFwk::InnerEvent::Pointer &response);
    int32_t SetActiveSim(int32_t index, int32_t enable, const AppExecFwk::InnerEvent::Pointer &response);
    int32_t SimStkSendTerminalResponse(const std::string &strCmd, const AppExecFwk::InnerEvent::Pointer &response);
    int32_t SimStkSendEnvelope(const std::string &strCmd, const AppExecFwk::InnerEvent::Pointer &response);
    int32_t SimStkSendCallSetupRequestResult(bool accept, const AppExecFwk::InnerEvent::Pointer &response);
    int32_t SimStkIsReady(const AppExecFwk::InnerEvent::Pointer &response);
    int32_t GetRadioProtocol(const AppExecFwk::InnerEvent::Pointer &response);
    int32_t SetRadioProtocol(RadioProtocol radioProtocol, const AppExecFwk::InnerEvent::Pointer &response);
    int32_t SimOpenLogicalChannel(std::string appID, int32_t p2, const AppExecFwk::InnerEvent::Pointer &response);
    int32_t SimCloseLogicalChannel(int32_t channelId, const AppExecFwk::InnerEvent::Pointer &response);
    int32_t SimTransmitApduLogicalChannel(
        const ApduSimIORequestInfo &reqInfo, const AppExecFwk::InnerEvent::Pointer &response);
    int32_t SimTransmitApduBasicChannel(
        const ApduSimIORequestInfo &reqInfo, const AppExecFwk::InnerEvent::Pointer &response);
    int32_t SimAuthentication(
        const SimAuthenticationRequestInfo &reqInfo, const AppExecFwk::InnerEvent::Pointer &response);
    int32_t UnlockSimLock(int32_t lockType, std::string password, const AppExecFwk::InnerEvent::Pointer &response);
    int32_t SendSimMatchedOperatorInfo(
        const NcfgOperatorInfo &reqInfo, const AppExecFwk::InnerEvent::Pointer &response);

    int32_t GetSimStatusResponse(
        const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo, const HDI::Ril::V1_1::CardStatusInfo &result);
    int32_t GetSimCardStatusResponse(
        const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo, const HDI::Ril::V1_3::SimCardStatusInfo &result);
    int32_t GetImsiResponse(const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo, const std::string &result);
    int32_t GetSimIOResponse(
        const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo, const HDI::Ril::V1_1::IccIoResultInfo &result);
    int32_t GetSimLockStatusResponse(const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo, int32_t simLockStatus);
    int32_t SetSimLockResponse(
        const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo, const HDI::Ril::V1_1::LockStatusResp &lockStatus);
    int32_t ChangeSimPasswordResponse(
        const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo, const HDI::Ril::V1_1::LockStatusResp &lockStatus);
    int32_t UnlockPinResponse(
        const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo, const HDI::Ril::V1_1::LockStatusResp &lockStatus);
    int32_t UnlockPukResponse(
        const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo, const HDI::Ril::V1_1::LockStatusResp &lockStatus);
    int32_t UnlockPin2Response(
        const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo, const HDI::Ril::V1_1::LockStatusResp &lockStatus);
    int32_t UnlockPuk2Response(
        const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo, const HDI::Ril::V1_1::LockStatusResp &lockStatus);
    int32_t SetActiveSimResponse(const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo);
    int32_t SimStkSendTerminalResponseResponse(const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo);
    int32_t SimStkSendEnvelopeResponse(const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo);
    int32_t SimStkSendCallSetupRequestResultResponse(const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo);
    int32_t SimStkIsReadyResponse(const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo);
    int32_t GetRadioProtocolResponse(
        const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo, const HDI::Ril::V1_1::RadioProtocol &radioProtocol);
    int32_t SetRadioProtocolResponse(
        const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo, const HDI::Ril::V1_1::RadioProtocol &radioProtocol);
    int32_t SimOpenLogicalChannelResponse(const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo,
        const HDI::Ril::V1_1::OpenLogicalChannelResponse &pOpenLogicalChannelResponse);
    int32_t SimCloseLogicalChannelResponse(const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo);
    int32_t SimTransmitApduLogicalChannelResponse(
        const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo, const HDI::Ril::V1_1::IccIoResultInfo &result);
    int32_t SimTransmitApduBasicChannelResponse(
        const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo, const HDI::Ril::V1_1::IccIoResultInfo &result);
    int32_t SimAuthenticationResponse(
        const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo, const HDI::Ril::V1_1::IccIoResultInfo &result);
    int32_t UnlockSimLockResponse(
        const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo, const HDI::Ril::V1_1::LockStatusResp &lockStatus);
    int32_t SendSimMatchedOperatorInfoResponse(const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo);

private:
    int32_t ProcessIccIoInfo(
        std::shared_ptr<TelRilRequest> telRilRequest, std::shared_ptr<IccIoResultInfo> iccIoResult);
    int32_t ErrorIccIoResponse(
        std::shared_ptr<TelRilRequest> telRilRequest, const RadioResponseInfo &responseInfo);
    void BuildIccIoResult(std::shared_ptr<IccIoResultInfo> iccIoResult, const HDI::Ril::V1_1::IccIoResultInfo &result);
    void BuildCardStatusInfo(
        std::shared_ptr<CardStatusInfo> cardStatusInfo, const HDI::Ril::V1_1::CardStatusInfo &result);
    void BuildSimCardStatusInfo(
        std::shared_ptr<SimCardStatusInfo> simCardStatusInfo, const HDI::Ril::V1_3::SimCardStatusInfo &result);
    void BuildLockStatusResp(
        std::shared_ptr<LockStatusResp> lockStatusResp, const HDI::Ril::V1_1::LockStatusResp &lockStatus);
    void BuildRadioProtocol(
        std::shared_ptr<RadioProtocol> protocol, const HDI::Ril::V1_1::RadioProtocol &radioProtocol);
    void BuildOpenLogicalChannelResp(std::shared_ptr<OpenLogicalChannelResponse> openLogicalChannelResp,
        const HDI::Ril::V1_1::OpenLogicalChannelResponse &pOpenLogicalChannelResponse);
    void BuildApduRequestInfo(
        OHOS::HDI::Ril::V1_1::ApduSimIORequestInfo &ApduRequestInfo, const ApduSimIORequestInfo &reqInfo);
    int32_t ResponseIccIo(
        const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo, const HDI::Ril::V1_1::IccIoResultInfo &result);
};
} // namespace Telephony
} // namespace OHOS
#endif // TEL_RIL_SIM_H
