/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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
#ifndef MOCK_I_NETWORK_SEARCH_MANAGER_H
#define MOCK_I_NETWORK_SEARCH_MANAGER_H

#include "i_network_search.h"
#include <gmock/gmock.h>

namespace OHOS {
namespace Telephony {
class MockINetworkSearch : public INetworkSearch {
public:
    virtual ~MockINetworkSearch() = default;
    MOCK_METHOD(bool, OnInit, (), (override));
    MOCK_METHOD(int32_t, InitTelExtraModule, (int32_t slotId), (override));
    MOCK_METHOD(int32_t, GetPsRadioTech, (int32_t slotId, int32_t &psRadioTech), (override));
    MOCK_METHOD(int32_t, GetCsRadioTech, (int32_t slotId, int32_t &csRadioTech), (override));
    MOCK_METHOD(std::u16string, GetOperatorNumeric, (int32_t slotId), (override));
    MOCK_METHOD(std::string, GetResidentNetworkNumeric, (int32_t slotId), (override));
    MOCK_METHOD(int32_t, GetOperatorName, (int32_t slotId, std::u16string &operatorName), (override));
    MOCK_METHOD(int32_t, GetNetworkStatus, (int32_t slotId, sptr<NetworkState> &networkState), (override));
    MOCK_METHOD(int32_t, GetRadioState, (int32_t slotId), (override));
    MOCK_METHOD(int32_t, GetRadioState, (int32_t slotId, const sptr<INetworkSearchCallback> &callback), (override));
    MOCK_METHOD(void, SetRadioState, (int32_t slotId, bool isOn, int32_t rst), (override));
    MOCK_METHOD(int32_t, SetRadioState, (int32_t slotId, bool isOn, int32_t rst,
        const sptr<INetworkSearchCallback> &callback), (override));
    MOCK_METHOD(int32_t, GetSignalInfoList, (int32_t slotId,
        std::vector<sptr<SignalInformation>> &signals), (override));
    MOCK_METHOD(void, RegisterCoreNotify, (int32_t slotId,
        const std::shared_ptr<AppExecFwk::EventHandler> &handler, int32_t what), (override));
    MOCK_METHOD(void, UnRegisterCoreNotify, (int32_t slotId,
        const std::shared_ptr<AppExecFwk::EventHandler> &handler, int32_t what), (override));
    MOCK_METHOD(void, RegisterCellularDataObject, (const sptr<NetworkSearchCallBackBase> &callback), (override));
    MOCK_METHOD(void, UnRegisterCellularDataObject, (const sptr<NetworkSearchCallBackBase> &callback), (override));
    MOCK_METHOD(void, RegisterCellularCallObject, (const sptr<NetworkSearchCallBackBase> &callback), (override));
    MOCK_METHOD(void, UnRegisterCellularCallObject, (const sptr<NetworkSearchCallBackBase> &callback), (override));
    MOCK_METHOD(int32_t, GetNetworkSearchInformation, (int32_t slotId,
        const sptr<INetworkSearchCallback> &callback), (override));
    MOCK_METHOD(int32_t, GetNetworkSelectionMode, (int32_t slotId,
        const sptr<INetworkSearchCallback> &callback), (override));
    MOCK_METHOD(int32_t, SetNetworkSelectionMode, (int32_t slotId, int32_t selectMode,
        const sptr<NetworkInformation> &networkInformation, bool resumeSelection,
        const sptr<INetworkSearchCallback> &callback), (override));
    MOCK_METHOD(int32_t, GetIsoCountryCodeForNetwork, (int32_t slotId, std::u16string &countryCode), (override));
    MOCK_METHOD(int32_t, GetPreferredNetwork, (int32_t slotId,
        const sptr<INetworkSearchCallback> &callback), (override));
    MOCK_METHOD(int32_t, SetPreferredNetwork, (int32_t slotId, int32_t networkMode,
        const sptr<INetworkSearchCallback> &callback), (override));
    MOCK_METHOD(bool, SetPreferredNetwork, (int32_t slotId, int32_t networkMode), (override));
    MOCK_METHOD(bool, SetForcePreferredNetwork, (int32_t slotId, int32_t networkMode), (override));
    MOCK_METHOD(int32_t, GetPsRegState, (int32_t slotId), (override));
    MOCK_METHOD(int32_t, GetCsRegState, (int32_t slotId), (override));
    MOCK_METHOD(int32_t, GetPsRoamingState, (int32_t slotId), (override));
    MOCK_METHOD(int32_t, GetImei, (int32_t slotId, std::u16string &imei), (override));
    MOCK_METHOD(int32_t, GetImeiSv, (int32_t slotId, std::u16string &imeiSv), (override));
    MOCK_METHOD(int32_t, GetImsRegStatus, (int32_t slotId, ImsServiceType imsSrvType, ImsRegInfo &info), (override));
    MOCK_METHOD(int32_t, GetCellInfoList, (int32_t slotId, std::vector<sptr<CellInformation>> &cellInfo), (override));
    MOCK_METHOD(int32_t, GetNeighboringCellInfoList, (int32_t slotId,
        std::vector<sptr<CellInformation>> &cellInfo), (override));
    MOCK_METHOD(int32_t, SendUpdateCellLocationRequest, (int32_t slotId), (override));
    MOCK_METHOD(sptr<CellLocation>, GetCellLocation, (int32_t slotId), (override));
    MOCK_METHOD(int32_t, GetMeid, (int32_t slotId, std::u16string &meid), (override));
    MOCK_METHOD(int32_t, GetUniqueDeviceId, (int32_t slotId, std::u16string &deviceId), (override));
    MOCK_METHOD(PhoneType, GetPhoneType, (int32_t slotId), (override));
    MOCK_METHOD(int32_t, SetNrOptionMode, (int32_t slotId, int32_t mode), (override));
    MOCK_METHOD(int32_t, SetNrOptionMode, (int32_t slotId, int32_t mode,
        const sptr<INetworkSearchCallback> &callback), (override));
    MOCK_METHOD(int32_t, GetNrOptionMode, (int32_t slotId, NrMode &mode), (override));
    MOCK_METHOD(int32_t, GetNrOptionMode, (int32_t slotId, const sptr<INetworkSearchCallback> &callback), (override));
    MOCK_METHOD(FrequencyType, GetFrequencyType, (int32_t slotId), (override));
    MOCK_METHOD(NrState, GetNrState, (int32_t slotId), (override));
    MOCK_METHOD(int32_t, RegisterImsRegInfoCallback, (int32_t slotId, ImsServiceType imsSrvType,
        const int32_t tokenId, const sptr<ImsRegInfoCallback> &callback), (override));
    MOCK_METHOD(int32_t, UnregisterImsRegInfoCallback, (int32_t slotId, ImsServiceType imsSrvType,
        const int32_t tokenId), (override));
    MOCK_METHOD(int32_t, GetBasebandVersion, (int32_t slotId, std::string &version), (override));
    MOCK_METHOD(void, InitAirplaneMode, (int32_t slotId), (override));
    MOCK_METHOD(int32_t, GetAirplaneMode, (bool &airplaneMode), (override));
    MOCK_METHOD(int32_t, GetNetworkCapability, (int32_t slotId, int32_t networkCapabilityType,
        int32_t &networkCapabilityState), (override));
    MOCK_METHOD(int32_t, SetNetworkCapability, (int32_t slotId, int32_t networkCapabilityType,
        int32_t networkCapabilityState), (override));
    MOCK_METHOD(int32_t, UpdateRadioOn, (int32_t slotId), (override));
    MOCK_METHOD(int32_t, GetRrcConnectionState, (int32_t slotId, int32_t &status), (override));
    MOCK_METHOD(int32_t, FactoryReset, (int32_t slotId), (override));
    MOCK_METHOD(int32_t, GetNrSsbId, (int32_t slotId,
        const std::shared_ptr<NrSsbInformation> &nrSsbInformation), (override));
    MOCK_METHOD(bool, IsNrSupported, (int32_t slotId), (override));
    MOCK_METHOD(bool, IsSatelliteEnabled, (), (override));
    MOCK_METHOD(void, DcPhysicalLinkActiveUpdate, (int32_t slotId, bool isActive), (override));
    MOCK_METHOD(int32_t, NotifyCallStatusToNetworkSearch, (int32_t slotId, int32_t callStatus), (override));
    MOCK_METHOD(int32_t, HandleNotifyStateChangeWithDelay, (int32_t slotId, bool isNeedDelay), (override));
    MOCK_METHOD(int32_t, StartRadioOnState, (int32_t slotId), (override));
    MOCK_METHOD(int32_t, StartGetRilSignalIntensity, (int32_t slotId), (override));
    MOCK_METHOD(int32_t, ProcessSignalIntensity, (int32_t slotId, const struct Rssi &signalIntensity), (override));
    MOCK_METHOD(int32_t, IsGsm, (int32_t slotId, bool &isGsm), (override));
    MOCK_METHOD(int32_t, IsCdma, (int32_t slotId, bool &isCdma), (override));
    MOCK_METHOD(int32_t, UpdateOperatorName, (int32_t slotId), (override));
    MOCK_METHOD(void, UpdateDeviceState, (int32_t slotId, bool isEnterStrMode, bool isNeedUpdateNetworkState), (override));
};

}
}

#endif