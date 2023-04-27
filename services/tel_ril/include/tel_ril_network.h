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
    TelRilNetwork(int32_t slotId, sptr<HDI::Ril::V1_1::IRil> rilInterface,
        std::shared_ptr<ObserverHandler> observerHandler, std::shared_ptr<TelRilHandler> handler);
    ~TelRilNetwork() = default;

    // send  command
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
    int32_t SetNrOptionMode(int32_t mode, const AppExecFwk::InnerEvent::Pointer &response);
    int32_t GetNrOptionMode(const AppExecFwk::InnerEvent::Pointer &response);
    int32_t GetRrcConnectionState(const AppExecFwk::InnerEvent::Pointer &response);

    // ril unsol
    int32_t SignalStrengthUpdated(const HDI::Ril::V1_1::Rssi &rssi);
    int32_t NetworkCsRegStatusUpdated(const HDI::Ril::V1_1::CsRegStatusInfo &csRegStatusInfo);
    int32_t NetworkPsRegStatusUpdated(const HDI::Ril::V1_1::PsRegStatusInfo &psRegStatusInfo);
    int32_t NetworkTimeZoneUpdated(const std::string &timeZoneStr);
    int32_t NetworkTimeUpdated(const std::string &timeStr);
    int32_t NetworkPhyChnlCfgUpdated(const HDI::Ril::V1_1::ChannelConfigInfoList &channelConfigInfoList);
    int32_t NetworkCurrentCellUpdated(const HDI::Ril::V1_1::CellListCurrentInfo &cellListCurrentInfo);
    int32_t NetworkCurrentCellUpdated_1_1(const HDI::Ril::V1_1::CellListCurrentInfo_1_1 &cellListCurrentInformation);

    int32_t GetSignalStrengthResponse(
        const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo, const HDI::Ril::V1_1::Rssi &rssi);
    int32_t GetCsRegStatusResponse(const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo,
        const HDI::Ril::V1_1::CsRegStatusInfo &csRegStatusInfo);
    int32_t GetPsRegStatusResponse(const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo,
        const HDI::Ril::V1_1::PsRegStatusInfo &psRegStatusInfo);
    int32_t GetOperatorInfoResponse(
        const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo, const HDI::Ril::V1_1::OperatorInfo &operatorInfo);
    int32_t GetNetworkSearchInformationResponse(const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo,
        const HDI::Ril::V1_1::AvailableNetworkList &availableNetworkList);
    int32_t GetNetworkSelectionModeResponse(const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo,
        const HDI::Ril::V1_1::SetNetworkModeInfo &setNetworkModeInfo);
    int32_t SetNetworkSelectionModeResponse(const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo);
    int32_t GetNeighboringCellInfoListResponse(const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo,
        const HDI::Ril::V1_1::CellListNearbyInfo &cellInfoList);
    int32_t GetCurrentCellInfoResponse(const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo,
        const HDI::Ril::V1_1::CellListCurrentInfo &cellInfoList);
    int32_t GetCurrentCellInfoResponse_1_1(const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo,
        const HDI::Ril::V1_1::CellListCurrentInfo_1_1 &cellListCurrentInformation);
    int32_t SetPreferredNetworkResponse(const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo);
    int32_t GetPreferredNetworkResponse(const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo,
        const HDI::Ril::V1_1::PreferredNetworkTypeInfo &preferredNetworkTypeInfo);
    int32_t GetPhysicalChannelConfigResponse(const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo,
        const HDI::Ril::V1_1::ChannelConfigInfoList &channelConfigInfoList);
    int32_t SetLocateUpdatesResponse(const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo);
    int32_t SetNotificationFilterResponse(const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo);
    int32_t SetDeviceStateResponse(const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo);
    int32_t SetNrOptionModeResponse(const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo);
    int32_t GetNrOptionModeResponse(const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo, int32_t mode);
    int32_t GetRrcConnectionStateResponse(
        const HDI::Ril::V1_1::RilRadioResponseInfo &responseInfo, int32_t rrcConnectionState);
    int32_t GetRrcConnectionStateUpdated(int32_t state);

private:
    void BuildSignalStrength(std::shared_ptr<Rssi> signalStrength, const HDI::Ril::V1_1::Rssi &rssi);
    void BuildCsRegStatusInfo(
        std::shared_ptr<CsRegStatusInfo> regStatusInfo, const HDI::Ril::V1_1::CsRegStatusInfo &csRegStatusInfo);
    void BuildPsRegStatusInfo(
        std::shared_ptr<PsRegStatusResultInfo> regStatusInfo, const HDI::Ril::V1_1::PsRegStatusInfo &psRegStatusInfo);
    void BuildOperatorInfo(
        std::shared_ptr<OperatorInfoResult> operatorInfoResult, const HDI::Ril::V1_1::OperatorInfo &operatorInfo);
    void BuildAvailableNetworkList(std::shared_ptr<AvailableNetworkList> availableNetworkInfos,
        const HDI::Ril::V1_1::AvailableNetworkList &availableNetworkList);
    void BuildNetworkModeInfo(std::shared_ptr<SetNetworkModeInfo> networkModeInfo,
        const HDI::Ril::V1_1::SetNetworkModeInfo &setNetworkModeInfo);
    void BuildNeighboringCellInfoList(std::shared_ptr<CellListNearbyInfo> cellListNearbyInfo,
        const HDI::Ril::V1_1::CellListNearbyInfo &cellInfoList);
    void FillGsmCellNearbyInfo(CellNearbyInfo &cellInfo, const HDI::Ril::V1_1::CellNearbyInfo &info);
    void FillLteCellNearbyInfo(CellNearbyInfo &cellInfo, const HDI::Ril::V1_1::CellNearbyInfo &info);
    void FillWcdmaCellNearbyInfo(CellNearbyInfo &cellInfo, const HDI::Ril::V1_1::CellNearbyInfo &info);
    void FillCdmaCellNearbyInfo(CellNearbyInfo &cellInfo, const HDI::Ril::V1_1::CellNearbyInfo &info);
    void FillTdscdmaCellNearbyInfo(CellNearbyInfo &cellInfo, const HDI::Ril::V1_1::CellNearbyInfo &info);
    void FillNrCellNearbyInfo(CellNearbyInfo &cellInfo, const HDI::Ril::V1_1::CellNearbyInfo &info);
    void FillCellNearbyInfo(CellNearbyInfo &cellInfo, const HDI::Ril::V1_1::CellNearbyInfo &info);
    void BuildCurrentCellInfoList(std::shared_ptr<CellListCurrentInfo> currentCellList,
        const HDI::Ril::V1_1::CellListCurrentInfo &cellInfoList);
    void FillCurrentCellInfo(CurrentCellInfo &cellInfo, const HDI::Ril::V1_1::CurrentCellInfo &info);
    void FillGsmCurrentCellInfo(CurrentCellInfo &cellInfo, const HDI::Ril::V1_1::CurrentCellInfo &info);
    void FillLteCurrentCellInfo(CurrentCellInfo &cellInfo, const HDI::Ril::V1_1::CurrentCellInfo &info);
    void FillWcdmaCurrentCellInfo(CurrentCellInfo &cellInfo, const HDI::Ril::V1_1::CurrentCellInfo &info);
    void FillCdmaCurrentCellInfo(CurrentCellInfo &cellInfo, const HDI::Ril::V1_1::CurrentCellInfo &info);
    void FillTdscdmaCurrentCellInfo(CurrentCellInfo &cellInfo, const HDI::Ril::V1_1::CurrentCellInfo &info);
    void FillNrCurrentCellInfo(CurrentCellInfo &cellInfo, const HDI::Ril::V1_1::CurrentCellInfo &info);
    void BuildCurrentCellInformationList(std::shared_ptr<CellListCurrentInformation> currentCellList,
        const HDI::Ril::V1_1::CellListCurrentInfo_1_1 &cellInfoList);
    void FillCurrentCellInformation(CurrentCellInformation &cellInfo, const HDI::Ril::V1_1::CurrentCellInfo_1_1 &info);
    void FillGsmCurrentCellInformation(
        CurrentCellInformation &cellInfo, const HDI::Ril::V1_1::CurrentCellInfo_1_1 &info);
    void FillLteCurrentCellInformation(
        CurrentCellInformation &cellInfo, const HDI::Ril::V1_1::CurrentCellInfo_1_1 &info);
    void FillWcdmaCurrentCellInformation(
        CurrentCellInformation &cellInfo, const HDI::Ril::V1_1::CurrentCellInfo_1_1 &info);
    void FillCdmaCurrentCellInformation(
        CurrentCellInformation &cellInfo, const HDI::Ril::V1_1::CurrentCellInfo_1_1 &info);
    void FillTdscdmaCurrentCellInformation(
        CurrentCellInformation &cellInfo, const HDI::Ril::V1_1::CurrentCellInfo_1_1 &info);
    void FillNrCurrentCellInformation(
        CurrentCellInformation &cellInfo, const HDI::Ril::V1_1::CurrentCellInfo_1_1 &info);
    void BuildChannelConfigInfoList(std::shared_ptr<ChannelConfigInfoList> channelConfigList,
        const HDI::Ril::V1_1::ChannelConfigInfoList &channelConfigInfoList);
};
} // namespace Telephony
} // namespace OHOS
#endif // TEL_RIL_NETWORK_H
