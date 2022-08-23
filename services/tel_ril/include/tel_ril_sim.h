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

#include "hril_sim_parcel.h"
#include "tel_ril_base.h"

namespace OHOS {
namespace Telephony {
class TelRilSim : public TelRilBase {
public:
    TelRilSim(int32_t slotId, sptr<IRemoteObject> cellularRadio, std::shared_ptr<ObserverHandler> observerHandler,
        std::shared_ptr<TelRilHandler> handler);
    ~TelRilSim() = default;

    int32_t SimStateUpdated(MessageParcel &data);
    int32_t SimStkSessionEndNotify(MessageParcel &data);
    int32_t SimStkProactiveNotify(MessageParcel &data);
    int32_t SimStkAlphaNotify(MessageParcel &data);
    int32_t SimStkEventNotify(MessageParcel &data);
    int32_t SimStkCallSetupNotify(MessageParcel &data);
    int32_t SimRefreshNotify(MessageParcel &data);

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
    int32_t SetRadioProtocol(SimProtocolRequest simProtocolData, const AppExecFwk::InnerEvent::Pointer &response);
    int32_t SimOpenLogicalChannel(std::string appID, int32_t p2, const AppExecFwk::InnerEvent::Pointer &response);
    int32_t SimCloseLogicalChannel(int32_t channelId, const AppExecFwk::InnerEvent::Pointer &response);
    int32_t SimTransmitApduLogicalChannel(ApduSimIORequestInfo reqInfo,
        const AppExecFwk::InnerEvent::Pointer &response);
    int32_t SimTransmitApduBasicChannel(ApduSimIORequestInfo reqInfo,
        const AppExecFwk::InnerEvent::Pointer &response);
    int32_t SimAuthentication(SimAuthenticationRequestInfo reqInfo,
        const AppExecFwk::InnerEvent::Pointer &response);
    int32_t UnlockSimLock(int32_t lockType, std::string password, const AppExecFwk::InnerEvent::Pointer &response);

    int32_t GetSimStatusResponse(MessageParcel &data);
    int32_t GetImsiResponse(MessageParcel &data);
    int32_t GetSimIOResponse(MessageParcel &data);
    int32_t GetSimLockStatusResponse(MessageParcel &data);
    int32_t SetSimLockResponse(MessageParcel &data);
    int32_t ChangeSimPasswordResponse(MessageParcel &data);
    int32_t UnlockPinResponse(MessageParcel &data);
    int32_t UnlockPukResponse(MessageParcel &data);
    int32_t UnlockPin2Response(MessageParcel &data);
    int32_t UnlockPuk2Response(MessageParcel &data);
    int32_t SetActiveSimResponse(MessageParcel &data);
    int32_t SimStkSendTerminalResponseResponse(MessageParcel &data);
    int32_t SimStkSendEnvelopeResponse(MessageParcel &data);
    int32_t SimStkSendCallSetupRequestResultResponse(MessageParcel &data);
    int32_t SimStkIsReadyResponse(MessageParcel &data);
    int32_t SetRadioProtocolResponse(MessageParcel &data);
    int32_t SimOpenLogicalChannelResponse(MessageParcel &data);
    int32_t SimCloseLogicalChannelResponse(MessageParcel &data);
    int32_t SimTransmitApduLogicalChannelResponse(MessageParcel &data);
    int32_t SimTransmitApduBasicChannelResponse(MessageParcel &data);
    int32_t SimAuthenticationResponse(MessageParcel &data);
    int32_t UnlockSimLockResponse(MessageParcel &data);

    bool IsSimRespOrNotify(uint32_t code);

private:
    bool IsSimResponse(uint32_t code);
    bool IsSimNotification(uint32_t code);
    void AddHandlerToMap();
    int32_t ProcessIccIoInfo(
        std::shared_ptr<TelRilRequest> telRilRequest, std::shared_ptr<IccIoResultInfo> iccIoResult);
    int32_t ErrorIccIoResponse(
        std::shared_ptr<TelRilRequest> telRilRequest, const HRilRadioResponseInfo &responseInfo);
};
} // namespace Telephony
} // namespace OHOS
#endif // TEL_RIL_SIM_H
