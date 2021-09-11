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
    /**
     * @brief Get IMSI
     *
     * @param :string aid
     */
    void GetSimStatus(const AppExecFwk::InnerEvent::Pointer &result);
    void GetImsi(const AppExecFwk::InnerEvent::Pointer &result);
    void RequestSimIO(int32_t command, int32_t fileId, int32_t p1, int32_t p2, int32_t p3, std::string data,
        std::string path, const AppExecFwk::InnerEvent::Pointer &response);
    void GetIccID(const AppExecFwk::InnerEvent::Pointer &result);
    void GetSimLockStatus(std::string fac, const AppExecFwk::InnerEvent::Pointer &response);
    void SetSimLock(
        std::string fac, int32_t mode, std::string passwd, const AppExecFwk::InnerEvent::Pointer &response);
    void ChangeSimPassword(std::string fac, std::string oldPassword, std::string newPassword,
        int32_t passwordLength, const AppExecFwk::InnerEvent::Pointer &response);
    void EnterSimPin(std::string pin, const AppExecFwk::InnerEvent::Pointer &response);
    void UnlockSimPin(std::string puk, std::string pin, const AppExecFwk::InnerEvent::Pointer &response);
    void GetSimPinInputTimes(const AppExecFwk::InnerEvent::Pointer &response);

    /**
     * @brief Get ICC card status response
     *
     * @param data is HDF service callback message
     */
    void GetSimStatusResponse(MessageParcel &data);

    /**
     * @brief Get IMSI response of SIM card
     *
     * @param data is HDF service callback message
     */
    void GetImsiResponse(MessageParcel &data);
    /**
     * @brief Get IccID response of SIM card
     *
     * @param data is HDF service callback message
     */
    void GetIccIDResponse(MessageParcel &data);

    /**
     * @brief ICC I / O operation response
     *
     * @param data is HDF service callback message
     */
    void RequestSimIOResponse(MessageParcel &data);

    /**
     * @brief Change  Null to  empty string
     * @param:  std::string str
     * @return: Returns empty string.
     */
    void GetSimLockStatusResponse(MessageParcel &data);

    /**
     * @brief Change  Null to  empty string
     * @param:  std::string str
     * @return: Returns empty string.
     */
    void SetSimLockResponse(MessageParcel &data);
    /**
     * @brief Change  Null to  empty string
     * @param:  std::string str
     * @return: Returns empty string.
     */
    void ChangeSimPasswordResponse(MessageParcel &data);
    void EnterSimPinResponse(MessageParcel &data);
    void UnlockSimPinResponse(MessageParcel &data);
    void GetSimPinInputTimesResponse(MessageParcel &data);

    /**
     * @brief Change  Null to  empty string
     * @param:  std::string str
     * @return: Returns empty string.
     */
    std::string ChangeNullToEmptyString(std::string str);

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
