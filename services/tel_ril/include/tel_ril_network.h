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

#include "tel_ril_base.h"
#include "hril_network_parcel.h"

namespace OHOS {
namespace Telephony {
class TelRilNetwork : public TelRilBase {
public:
    TelRilNetwork(int32_t slotId, sptr<IRemoteObject> cellularRadio, std::shared_ptr<ObserverHandler> observerHandler,
        std::shared_ptr<TelRilHandler> handler);
    ~TelRilNetwork() = default;

    // send  command
    int32_t GetRadioCapability(const AppExecFwk::InnerEvent::Pointer &response);
    int32_t GetImsRegStatus(const AppExecFwk::InnerEvent::Pointer &response);
    int32_t GetSignalStrength(const AppExecFwk::InnerEvent::Pointer &response);
    int32_t GetCsRegStatus(const AppExecFwk::InnerEvent::Pointer &response);
    int32_t GetPsRegStatus(const AppExecFwk::InnerEvent::Pointer &response);
    int32_t GetOperatorInfo(const AppExecFwk::InnerEvent::Pointer &response);
    int32_t GetNetworkSearchInformation(const AppExecFwk::InnerEvent::Pointer &response);
    int32_t GetNetworkSelectionMode(const AppExecFwk::InnerEvent::Pointer &response);
    int32_t SetNetworkSelectionMode(
        int32_t automaticFlag, std::string oper, const AppExecFwk::InnerEvent::Pointer &response);
    int32_t SetPreferredNetwork(int32_t preferredNetworkType, const AppExecFwk::InnerEvent::Pointer &response);
    int32_t GetPreferredNetwork(const AppExecFwk::InnerEvent::Pointer &response);
    int32_t GetCellInfoList(const AppExecFwk::InnerEvent::Pointer &response);
    int32_t GetCurrentCellInfo(const AppExecFwk::InnerEvent::Pointer &response);
    int32_t GetPhysicalChannelConfig(const AppExecFwk::InnerEvent::Pointer &response);
    int32_t SetLocateUpdates(HRilRegNotifyMode mode, const AppExecFwk::InnerEvent::Pointer &response);

    // ril unsol
    int32_t SignalStrengthUpdated(MessageParcel &data);
    int32_t NetworkCsRegStatusUpdated(MessageParcel &data);
    int32_t NetworkPsRegStatusUpdated(MessageParcel &data);
    int32_t NetworkTimeZoneUpdated(MessageParcel &data);
    int32_t NetworkTimeUpdated(MessageParcel &data);
    int32_t NetworkImsRegStatusUpdated(MessageParcel &data);
    int32_t NetworkPhyChnlCfgUpdated(MessageParcel &data);
    int32_t NetworkCurrentCellUpdated(MessageParcel &data);
    int32_t GetImsRegStatusResponse(MessageParcel &data);
    int32_t GetRadioCapabilityResponse(MessageParcel &data);
    /**
     * @brief Get signal intensity response
     * @param data is HDF service callback message
     */
    int32_t GetSignalStrengthResponse(MessageParcel &data);

    /**
     * @brief Current voice registration status response
     * @param data is HDF service callback message
     */
    int32_t GetCsRegStatusResponse(MessageParcel &data);

    /**
     * @brief Get network registration status response
     * @param data is HDF service callback message
     */
    int32_t GetPsRegStatusResponse(MessageParcel &data);

    int32_t GetNetworkSearchInformationResponse(MessageParcel &data);
    int32_t GetNetworkSelectionModeResponse(MessageParcel &data);
    int32_t SetNetworkSelectionModeResponse(MessageParcel &data);
    int32_t SetPreferredNetworkResponse(MessageParcel &data);
    int32_t GetPreferredNetworkResponse(MessageParcel &data);
    int32_t GetPhysicalChannelConfigResponse(MessageParcel &data);
    int32_t SetLocateUpdatesResponse(MessageParcel &data);

    /**
     * @brief Current operator ons or eons response
     * @param data is HDF service callback message
     */
    int32_t GetOperatorInfoResponse(MessageParcel &data);
    int32_t GetNeighboringCellInfoListResponse(MessageParcel &data);
    int32_t GetCurrentCellInfoResponse(MessageParcel &data);
    bool IsNetworkRespOrNotify(uint32_t code);

private:
    void AddHandlerToMap();
    bool IsNetworkResponse(uint32_t code);
    bool IsNetworkNotification(uint32_t code);
};
} // namespace Telephony
} // namespace OHOS
#endif // TEL_RIL_NETWORK_H
