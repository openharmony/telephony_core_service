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

#ifndef I_NETWORK_SEARCH_H
#define I_NETWORK_SEARCH_H

#include <vector>
#include "event_handler.h"
#include "network_search_result.h"
#include "network_state.h"
#include "signal_information.h"
#include "i_network_search_callback.h"
#include "network_search_callback_base.h"
#include "cell_information.h"
#include "cell_location.h"

namespace OHOS {
namespace Telephony {
class INetworkSearch {
public:
    using HANDLE = const std::shared_ptr<AppExecFwk::EventHandler>;
    using NSCALLBACK = const sptr<INetworkSearchCallback>;
    virtual bool OnInit() = 0;
    virtual int32_t GetPsRadioTech(int32_t slotId) = 0;
    virtual int32_t GetCsRadioTech(int32_t slotId) = 0;
    virtual std::u16string GetOperatorNumeric(int32_t slotId) = 0;
    virtual std::u16string GetOperatorName(int32_t slotId) = 0;
    virtual sptr<NetworkState> GetNetworkStatus(int32_t slotId) = 0;
    virtual int32_t GetRadioState(int32_t slotId) = 0;
    virtual bool GetRadioState(int32_t slotId, NSCALLBACK &callback) = 0;
    /**
     * Set radio state
     * 27007-410_2001 8.2 Set phone functionality +CFUN
     * 3GPP TS 27.007 V4.1.0 (2001-03)
     */
    virtual void SetRadioState(int32_t slotId, bool isOn, int32_t rst) = 0;
    virtual bool SetRadioState(int32_t slotId, bool isOn, int32_t rst, NSCALLBACK &callback) = 0;
    virtual std::vector<sptr<SignalInformation>> GetSignalInfoList(int32_t slotId) = 0;
    virtual void RegisterCoreNotify(int32_t slotId, HANDLE &handler, int32_t what) = 0;
    virtual void UnRegisterCoreNotify(int32_t slotId, HANDLE &handler, int32_t what) = 0;
    virtual void RegisterCellularDataObject(const sptr<NetworkSearchCallBackBase> &callback) = 0;
    virtual void UnRegisterCellularDataObject(const sptr<NetworkSearchCallBackBase> &callback) = 0;
    virtual void RegisterCellularCallObject(const sptr<NetworkSearchCallBackBase> &callback) = 0;
    virtual void UnRegisterCellularCallObject(const sptr<NetworkSearchCallBackBase> &callback) = 0;
    virtual bool GetNetworkSearchInformation(int32_t slotId, NSCALLBACK &callback) = 0;
    virtual bool GetNetworkSelectionMode(int32_t slotId, NSCALLBACK &callback) = 0;
    virtual bool SetNetworkSelectionMode(int32_t slotId, int32_t selectMode,
        const sptr<NetworkInformation> &networkInformation, bool resumeSelection, NSCALLBACK &callback) = 0;
    virtual std::u16string GetIsoCountryCodeForNetwork(int32_t slotId) = 0;
    virtual bool GetPreferredNetwork(int32_t slotId, NSCALLBACK &callback) = 0;
    virtual bool SetPreferredNetwork(int32_t slotId, int32_t networkMode, NSCALLBACK &callback) = 0;
    virtual int32_t GetPsRegState(int32_t slotId) = 0;
    virtual int32_t GetCsRegState(int32_t slotId) = 0;
    virtual int32_t GetPsRoamingState(int32_t slotId) = 0;
    virtual std::u16string GetImei(int32_t slotId) = 0;
    virtual bool SetPsAttachStatus(int32_t slotId, int32_t psAttachStatus, NSCALLBACK &callback) = 0;
    virtual bool GetImsRegStatus(int32_t slotId) = 0;
    virtual std::vector<sptr<CellInformation>> GetCellInfoList(int32_t slotId) = 0;
    virtual bool SendUpdateCellLocationRequest(int32_t slotId) = 0;
    virtual sptr<CellLocation> GetCellLocation(int32_t slotId) = 0;
    virtual std::u16string GetMeid(int32_t slotId) = 0;
    virtual std::u16string GetUniqueDeviceId(int32_t slotId) = 0;
    virtual PhoneType GetPhoneType(int32_t slotId) = 0;
    virtual NrMode GetNrOptionMode(int32_t slotId) = 0;
    virtual FrequencyType GetFrequencyType(int32_t slotId) = 0;
    virtual NrState GetNrState(int32_t slotId) = 0;
    /**
     * @brief support Nr network or not
     *
     * @return true support
     * @return false not support
     */
    virtual bool IsNrSupported(int32_t slotId) = 0;
    virtual void DcPhysicalLinkActiveUpdate(int32_t slotId, bool isActive) = 0;
};
} // namespace Telephony
} // namespace OHOS
#endif // I_NETWORK_SEARCH_H
