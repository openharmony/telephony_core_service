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

#ifndef I_BASE_PHONE_SERVICE_H
#define I_BASE_PHONE_SERVICE_H

#include "i_network_search_callback.h"
#include "i_sim_manager.h"
#include "i_sim_state_manager.h"
#include "network_search_result.h"
#include "network_state.h"
#include "signal_information.h"

namespace OHOS {
namespace Telephony {
class ICoreService : public IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.telephony.ICoreService");

public:
    virtual ~ICoreService() = default;
    virtual int32_t GetPsRadioTech(int32_t slotId) = 0;
    virtual int32_t GetCsRadioTech(int32_t slotId) = 0;
    virtual std::u16string GetOperatorNumeric(int32_t slotId) = 0;
    virtual std::u16string GetOperatorName(int32_t slotId) = 0;
    virtual std::vector<sptr<SignalInformation>> GetSignalInfoList(int32_t slotId) = 0;
    virtual const sptr<NetworkState> GetNetworkState(int32_t slotId) = 0;
    virtual bool SetRadioState(bool isOn, const sptr<INetworkSearchCallback> &callback) = 0;
    virtual bool GetRadioState(const sptr<INetworkSearchCallback> &callback) = 0;
    virtual bool HasSimCard(int32_t slotId) = 0;
    virtual int32_t GetSimState(int32_t slotId) = 0;
    virtual bool UnlockPin(std::u16string pin, LockStatusResponse &response, int32_t phoneId) = 0;
    virtual bool UnlockPuk(
        std::u16string newPin, std::u16string puk, LockStatusResponse &response, int32_t phoneId) = 0;
    virtual bool AlterPin(
        std::u16string newPin, std::u16string oldPin, LockStatusResponse &response, int32_t phoneId) = 0;
    virtual bool SetLockState(
        std::u16string pin, int32_t enable, LockStatusResponse &response, int32_t phoneId) = 0;
    virtual int32_t GetLockState(int32_t phoneId) = 0;
    virtual std::u16string GetSimOperatorNumeric(int32_t slotId) = 0;
    virtual std::u16string GetIsoCountryCodeForSim(int32_t slotId) = 0;
    virtual std::u16string GetSimSpn(int32_t slotId) = 0;
    virtual std::u16string GetSimIccId(int32_t slotId) = 0;
    virtual std::u16string GetIMSI(int32_t slotId) = 0;
    virtual bool IsSimActive(int32_t slotId) = 0;
    virtual bool GetNetworkSearchResult(int32_t slotId, const sptr<INetworkSearchCallback> &callback) = 0;
    virtual bool GetNetworkSelectionMode(int32_t slotId, const sptr<INetworkSearchCallback> &callback) = 0;
    virtual std::u16string GetLocaleFromDefaultSim() = 0;
    virtual std::u16string GetSimGid1(int32_t slotId) = 0;
    virtual bool SetNetworkSelectionMode(int32_t slotId, int32_t selectMode,
        const sptr<NetworkInformation> &networkInformation, bool resumeSelection,
        const sptr<INetworkSearchCallback> &callback) = 0;
    virtual std::u16string GetIsoCountryCodeForNetwork(int32_t slotId) = 0;
    virtual bool GetSimAccountInfo(int32_t subId, IccAccountInfo &info) = 0;
    virtual bool SetDefaultVoiceSlotId(int32_t subId) = 0;
    virtual int32_t GetDefaultVoiceSlotId() = 0;
    virtual int32_t RefreshSimState(int32_t slotId) = 0;
    enum {
        GET_PS_RADIO_TECH = 0,
        GET_CS_RADIO_TECH,
        GET_OPERATOR_NUMERIC,
        GET_OPERATOR_NAME,
        GET_SIGNAL_INFO_LIST,
        GET_NETWORK_STATE,
        GET_CELL_INFO_LIST,
        SET_RADIO_STATE,
        GET_RADIO_STATE,
        HAS_SIM_CARD,
        GET_SIM_STATE,
        GET_ISO_COUNTRY_CODE,
        GET_ISO_COUNTRY_CODE_FOR_NETWORK,
        GET_SPN,
        GET_ICCID,
        GET_IMSI,
        IS_SIM_ACTIVE,
        UNLOCK_PIN,
        UNLOCK_PUK,
        ALTER_PIN,
        CHECK_PIN,
        SWITCH_PIN,
        GET_SIM_OPERATOR_NUMERIC,
        GET_NETWORK_SEARCH_RESULT,
        GET_NETWORK_SELECTION_MODE,
        GET_SIM_LANGUAGE,
        GET_SIM_GID1,
        SET_NETWORK_SELECTION_MODE,
        GET_CELL_LOCATION,
        GET_SIM_ACCOUNT_INFO,
        SET_DEFAULT_VOICE_SLOTID,
        GET_DEFAULT_VOICE_SLOTID,
        REFRESH_SIM_STATE
    };

protected:
    const int32_t ERROR = -1;
    const int32_t MAX_SLOT = 2;
};
} // namespace Telephony
} // namespace OHOS

#endif // I_BASE_PHONE_SERVICE_H
