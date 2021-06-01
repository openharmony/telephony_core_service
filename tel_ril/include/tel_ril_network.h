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
#ifndef TEL_RIL_NETWORK_H
#define TEL_RIL_NETWORK_H

#include <memory>
#include <map>
#include <unordered_map>
#include "observer_handler.h"
#include "telephony_log.h"
#include "tel_ril_base.h"
#include "i_tel_ril_manager.h"

namespace OHOS {
class TelRilNetwork : public TelRilBase {
public:
    TelRilNetwork(sptr<IRemoteObject> cellularRadio, std::shared_ptr<ObserverHandler> observerHandler);
    ~TelRilNetwork() = default;

    // send  commond
    void GetSignalStrength(const AppExecFwk::InnerEvent::Pointer &response);
    void GetCsRegStatus(const AppExecFwk::InnerEvent::Pointer &response);
    void GetPsRegStatus(const AppExecFwk::InnerEvent::Pointer &response);
    void GetOperatorInfo(const AppExecFwk::InnerEvent::Pointer &response);

    // ril unsol
    void SignalStrengthUpdated(OHOS::MessageParcel &data);
    void CsRegStatusUpdated(OHOS::MessageParcel &data);
    void UpdateImsNetworkStatus(OHOS::MessageParcel &data);

    /**
     * @brief Get signal intensity response
     *
     * @param data is HDF service callback message
     */
    void GetSignalStrengthResponse(OHOS::MessageParcel &data);

    /**
     * @brief Current voice registration status response
     *
     * @param data is HDF service callback message
     */
    void GetCsRegStatusResponse(OHOS::MessageParcel &data);

    /**
     * @brief Get network registration status response
     *
     * @param data is HDF service callback message
     */
    void GetPsRegStatusResponse(OHOS::MessageParcel &data);

    /**
     * @brief Current operator ons or eons response
     *
     * @param data is HDF service callback message
     */
    void GetOperatorInfoResponse(OHOS::MessageParcel &data);

    void ProcessNetworkRespOrNotify(uint32_t code, OHOS::MessageParcel &data);

    bool IsNetworkRespOrNotify(uint32_t code);

private:
    void AddHandlerToMap();
    bool IsNetworkResponse(uint32_t code);
    bool IsNetworkNotification(uint32_t code);

private:
    using Func = void (TelRilNetwork::*)(MessageParcel &data);
    std::map<uint32_t, Func> memberFuncMap_;
};
} // namespace OHOS
#endif // TEL_RIL_NETWORK_H
