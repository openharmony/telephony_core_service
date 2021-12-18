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
#include "observer_handler.h"
#include "tel_ril_base.h"

namespace OHOS {
namespace Telephony {
class TelRilSim : public TelRilBase {
public:
    TelRilSim(sptr<IRemoteObject> cellularRadio, std::shared_ptr<ObserverHandler> observerHandler);

    ~TelRilSim() = default;

    void SimStateUpdated(MessageParcel &data);

    void GetSimStatus(const AppExecFwk::InnerEvent::Pointer &result);
    void GetImsi(const AppExecFwk::InnerEvent::Pointer &result);
    void GetSimIO(SimIoRequestInfo data, const AppExecFwk::InnerEvent::Pointer &response);
    void GetSimLockStatus(std::string fac, const AppExecFwk::InnerEvent::Pointer &response);
    void SetSimLock(
        std::string fac, int32_t mode, std::string passwd, const AppExecFwk::InnerEvent::Pointer &response);
    void ChangeSimPassword(std::string fac, std::string oldPassword, std::string newPassword,
        int32_t passwordLength, const AppExecFwk::InnerEvent::Pointer &response);
    void UnlockPin(std::string pin, const AppExecFwk::InnerEvent::Pointer &response);
    void UnlockPuk(std::string puk, std::string pin, const AppExecFwk::InnerEvent::Pointer &response);
    void GetSimPinInputTimes(const AppExecFwk::InnerEvent::Pointer &response);
    void UnlockPin2(std::string pin2, const AppExecFwk::InnerEvent::Pointer &response);
    void UnlockPuk2(std::string puk2, std::string pin2, const AppExecFwk::InnerEvent::Pointer &response);
    void GetSimPin2InputTimes(const AppExecFwk::InnerEvent::Pointer &response);
    void SetActiveSim(int32_t index, int32_t enable, const AppExecFwk::InnerEvent::Pointer &response);

    void GetSimStatusResponse(MessageParcel &data);
    void GetImsiResponse(MessageParcel &data);
    void GetSimIOResponse(MessageParcel &data);
    void GetSimLockStatusResponse(MessageParcel &data);
    void SetSimLockResponse(MessageParcel &data);
    void ChangeSimPasswordResponse(MessageParcel &data);
    void UnlockPinResponse(MessageParcel &data);
    void UnlockPukResponse(MessageParcel &data);
    void GetSimPinInputTimesResponse(MessageParcel &data);
    void UnlockPin2Response(MessageParcel &data);
    void UnlockPuk2Response(MessageParcel &data);
    void GetSimPin2InputTimesResponse(MessageParcel &data);
    void SetActiveSimResponse(MessageParcel &data);

    bool IsSimRespOrNotify(uint32_t code);

    void ProcessSimRespOrNotify(uint32_t code, MessageParcel &data);

private:
    bool IsSimResponse(uint32_t code);
    bool IsSimNotification(uint32_t code);
    void AddHandlerToMap();
    void ProcessIccIoInfo(
        std::shared_ptr<TelRilRequest> telRilRequest, std::shared_ptr<IccIoResultInfo> iccIoResult);
    void ErrorIccIoResponse(
        std::shared_ptr<TelRilRequest> telRilRequest, const HRilRadioResponseInfo &responseInfo);

private:
    using Func = void (TelRilSim::*)(MessageParcel &data);
    std::map<uint32_t, Func> memberFuncMap_;
};
} // namespace Telephony
} // namespace OHOS
#endif // TEL_RIL_SIM_H
