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

#include <memory>
#include <map>
#include <unordered_map>
#include "observer_handler.h"
#include "telephony_log.h"
#include "tel_ril_base.h"
#include "i_tel_ril_manager.h"
#include "hril_sim_parcel.h"

namespace OHOS {
class TelRilSim : public TelRilBase {
public:
    TelRilSim(sptr<IRemoteObject> cellularRadio, std::shared_ptr<ObserverHandler> observerHandler);

    ~TelRilSim() = default;

    /**
     * @brief Get IMSI
     *
     * @param :string aid
     */
    void GetImsi(std::string aid, const AppExecFwk::InnerEvent::Pointer &result);

    void ReadIccFile(int32_t command, int32_t fileId, std::string path, int32_t p1, int32_t p2, int32_t p3,
        std::string data, std::string pin2, std::string aid, const AppExecFwk::InnerEvent::Pointer &response);

    void GetSimStatus(const AppExecFwk::InnerEvent::Pointer &result);

    /**
     * @brief Get ICC card status response
     *
     * @param data is HDF service callback message
     */
    void GetSimStatusResponse(OHOS::MessageParcel &data);

    /**
     * @brief Get IMSI response of SIM card
     *
     * @param data is HDF service callback message
     */
    void GetImsiResponse(OHOS::MessageParcel &data);

    /**
     * @brief ICC I / O operation response
     *
     * @param data is HDF service callback message
     */
    void ReadIccFileResponse(OHOS::MessageParcel &data);

    /**
     * @brief Change  Null to  empty string
     * @param:  std::string str
     * @return: Returns empty string.
     */
    std::string ChangeNullToEmptyString(std::string str);

    bool IsSimRespOrNotify(uint32_t code);

    void ProcessSimRespOrNotify(uint32_t code, OHOS::MessageParcel &data);

private:
    bool IsSimResponse(uint32_t code);
    bool IsSimNotification(uint32_t code);
    void AddHandlerToMap();
    void ProcessIccioInfo(
        std::shared_ptr<TelRilRequest> telRilRequest, std::shared_ptr<IccIoResultInfo> iccIoResult);

private:
    using Func = void (TelRilSim::*)(MessageParcel &data);
    std::map<uint32_t, Func> memberFuncMap_;
};
} // namespace OHOS
#endif // TEL_RIL_SIM_H
