/*
 * Copyright (C) 2021-2022 Huawei Device Co., Ltd.
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

#include "hril_network_parcel.h"
#include "tel_ril_base.h"

namespace OHOS {
namespace Telephony {
class TelRilNetwork : public TelRilBase {
public:
    TelRilNetwork(int32_t slotId, sptr<IRemoteObject> cellularRadio, sptr<HDI::Ril::V1_0::IRilInterface> rilInterface,
        std::shared_ptr<ObserverHandler> observerHandler, std::shared_ptr<TelRilHandler> handler);
    ~TelRilNetwork() = default;

    // send  command
    int32_t GetRadioCapability(const AppExecFwk::InnerEvent::Pointer &response);
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
    int32_t SetNotificationFilter(int32_t newFilter, const AppExecFwk::InnerEvent::Pointer &response);
    int32_t SetDeviceState(
        int32_t deviceStateType, bool deviceStateOn, const AppExecFwk::InnerEvent::Pointer &response);

    // ril unsol
    int32_t SignalStrengthUpdated(const HDI::Ril::V1_0::IRssi &rssi);
    int32_t NetworkCsRegStatusUpdated(const HDI::Ril::V1_0::ICsRegStatusInfo &csRegStatusInfo);
    int32_t NetworkPsRegStatusUpdated(const HDI::Ril::V1_0::IPsRegStatusInfo &psRegStatusInfo);
    int32_t NetworkTimeZoneUpdated(const std::string &timeZoneStr);
    int32_t NetworkTimeUpdated(const std::string &timeStr);
    int32_t NetworkPhyChnlCfgUpdated(const HDI::Ril::V1_0::IChannelConfigInfoList &channelConfigInfoList);
    int32_t NetworkCurrentCellUpdated(const HDI::Ril::V1_0::ICellListCurrentInfo &cellListCurrentInfo);

    int32_t GetSignalStrengthResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo,
        const HDI::Ril::V1_0::IRssi &rssi);
    int32_t GetCsRegStatusResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo,
        const HDI::Ril::V1_0::ICsRegStatusInfo &csRegStatusInfo);
    int32_t GetPsRegStatusResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo,
        const HDI::Ril::V1_0::IPsRegStatusInfo &psRegStatusInfo);
    int32_t GetOperatorInfoResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo,
        const HDI::Ril::V1_0::IOperatorInfo &operatorInfo);
    int32_t GetNetworkSearchInformationResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo,
        const HDI::Ril::V1_0::IAvailableNetworkList &availableNetworkList);
    int32_t GetNetworkSelectionModeResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo,
        const HDI::Ril::V1_0::ISetNetworkModeInfo &setNetworkModeInfo);
    int32_t SetNetworkSelectionModeResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo);
    int32_t GetNeighboringCellInfoListResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo,
        const HDI::Ril::V1_0::ICellListNearbyInfo &cellInfoList);
    int32_t GetCurrentCellInfoResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo,
        const HDI::Ril::V1_0::ICellListCurrentInfo &cellInfoList);
    int32_t SetPreferredNetworkResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo);
    int32_t GetPreferredNetworkResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo,
        const HDI::Ril::V1_0::IPreferredNetworkTypeInfo &preferredNetworkTypeInfo);
    int32_t GetRadioCapabilityResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo,
        const HDI::Ril::V1_0::IRadioCapabilityInfo &radioCapabilityInfo);
    int32_t GetPhysicalChannelConfigResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo,
        const HDI::Ril::V1_0::IChannelConfigInfoList &channelConfigInfoList);
    int32_t SetLocateUpdatesResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo);
    int32_t SetNotificationFilterResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo);
    int32_t SetDeviceStateResponse(const HDI::Ril::V1_0::IHRilRadioResponseInfo &responseInfo);

private:
    void BuildSignalStrength(std::shared_ptr<Rssi> signalStrength, const HDI::Ril::V1_0::IRssi &rssi);
    void BuildCsRegStatusInfo(
        std::shared_ptr<CsRegStatusInfo> regStatusInfo, const HDI::Ril::V1_0::ICsRegStatusInfo &csRegStatusInfo);
    void BuildPsRegStatusInfo(
        std::shared_ptr<PsRegStatusResultInfo> regStatusInfo, const HDI::Ril::V1_0::IPsRegStatusInfo &psRegStatusInfo);
    void BuildOperatorInfo(
        std::shared_ptr<OperatorInfoResult> operatorInfoResult, const HDI::Ril::V1_0::IOperatorInfo &operatorInfo);
    void BuildAvailableNetworkList(std::shared_ptr<AvailableNetworkList> availableNetworkInfos,
        const HDI::Ril::V1_0::IAvailableNetworkList &availableNetworkList);
    void BuildNetworkModeInfo(std::shared_ptr<SetNetworkModeInfo> networkModeInfo,
        const HDI::Ril::V1_0::ISetNetworkModeInfo &setNetworkModeInfo);
    void BuildNeighboringCellInfoList(std::shared_ptr<CellListNearbyInfo> cellListNearbyInfo,
        const HDI::Ril::V1_0::ICellListNearbyInfo &cellInfoList);
    void FillGsmCellNearbyInfo(CellNearbyInfo &cellInfo, const HDI::Ril::V1_0::ICellNearbyInfo &info);
    void FillLteCellNearbyInfo(CellNearbyInfo &cellInfo, const HDI::Ril::V1_0::ICellNearbyInfo &info);
    void FillWcdmaCellNearbyInfo(CellNearbyInfo &cellInfo, const HDI::Ril::V1_0::ICellNearbyInfo &info);
    void FillCdmaCellNearbyInfo(CellNearbyInfo &cellInfo, const HDI::Ril::V1_0::ICellNearbyInfo &info);
    void FillTdscdmaCellNearbyInfo(CellNearbyInfo &cellInfo, const HDI::Ril::V1_0::ICellNearbyInfo &info);
    void FillNrCellNearbyInfo(CellNearbyInfo &cellInfo, const HDI::Ril::V1_0::ICellNearbyInfo &info);
    void FillCellNearbyInfo(CellNearbyInfo &cellInfo, const HDI::Ril::V1_0::ICellNearbyInfo &info);
    void BuildCurrentCellInfoList(std::shared_ptr<CellListCurrentInfo> currentCellList,
        const HDI::Ril::V1_0::ICellListCurrentInfo &cellInfoList);
    void FillCurrentCellInfo(CurrentCellInfo &cellInfo, const HDI::Ril::V1_0::ICurrentCellInfo &info);
    void FillGsmCurrentCellInfo(CurrentCellInfo &cellInfo, const HDI::Ril::V1_0::ICurrentCellInfo &info);
    void FillLteCurrentCellInfo(CurrentCellInfo &cellInfo, const HDI::Ril::V1_0::ICurrentCellInfo &info);
    void FillWcdmaCurrentCellInfo(CurrentCellInfo &cellInfo, const HDI::Ril::V1_0::ICurrentCellInfo &info);
    void FillCdmaCurrentCellInfo(CurrentCellInfo &cellInfo, const HDI::Ril::V1_0::ICurrentCellInfo &info);
    void FillTdscdmaCurrentCellInfo(CurrentCellInfo &cellInfo, const HDI::Ril::V1_0::ICurrentCellInfo &info);
    void FillNrCurrentCellInfo(CurrentCellInfo &cellInfo, const HDI::Ril::V1_0::ICurrentCellInfo &info);
    void BuildChannelConfigInfoList(std::shared_ptr<ChannelConfigInfoList> channelConfigList,
        const HDI::Ril::V1_0::IChannelConfigInfoList &channelConfigInfoList);
};
} // namespace Telephony
} // namespace OHOS
#endif // TEL_RIL_NETWORK_H
