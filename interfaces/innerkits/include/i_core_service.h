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

#ifndef I_BASE_PHONE_SERVICE_H
#define I_BASE_PHONE_SERVICE_H

#include "cell_information.h"
#include "dialling_numbers_info.h"
#include "i_network_search_callback.h"
#include "ims_reg_info_callback.h"
#include "network_search_result.h"
#include "network_state.h"
#include "signal_information.h"
#include "sim_state_type.h"

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
    virtual bool SetRadioState(int32_t slotId, bool isOn, const sptr<INetworkSearchCallback> &callback) = 0;
    virtual bool GetRadioState(int32_t slotId, const sptr<INetworkSearchCallback> &callback) = 0;
    virtual std::u16string GetImei(int32_t slotId) = 0;
    virtual std::u16string GetMeid(int32_t slotId) = 0;
    virtual std::u16string GetUniqueDeviceId(int32_t slotId) = 0;
    virtual bool IsNrSupported(int32_t slotId) = 0;
    virtual NrMode GetNrOptionMode(int32_t slotId) = 0;
    virtual bool HasSimCard(int32_t slotId) = 0;
    virtual int32_t GetSimState(int32_t slotId) = 0;
    virtual int32_t GetCardType(int32_t slotId) = 0;
    virtual bool UnlockPin(int32_t slotId, std::u16string pin, LockStatusResponse &response) = 0;
    virtual bool UnlockPuk(int32_t slotId, std::u16string newPin, std::u16string puk, LockStatusResponse &response) = 0;
    virtual bool AlterPin(
        int32_t slotId, std::u16string newPin, std::u16string oldPin, LockStatusResponse &response) = 0;
    virtual bool UnlockPin2(int32_t slotId, std::u16string pin2, LockStatusResponse &response) = 0;
    virtual bool UnlockPuk2(
        int32_t slotId, std::u16string newPin2, std::u16string puk2, LockStatusResponse &response) = 0;
    virtual bool AlterPin2(
        int32_t slotId, std::u16string newPin2, std::u16string oldPin2, LockStatusResponse &response) = 0;
    virtual bool SetLockState(int32_t slotId, const LockInfo &options, LockStatusResponse &response) = 0;
    virtual int32_t GetLockState(int32_t slotId, LockType lockType) = 0;
    virtual std::u16string GetSimOperatorNumeric(int32_t slotId) = 0;
    virtual std::u16string GetISOCountryCodeForSim(int32_t slotId) = 0;
    virtual std::u16string GetSimSpn(int32_t slotId) = 0;
    virtual std::u16string GetSimIccId(int32_t slotId) = 0;
    virtual std::u16string GetIMSI(int32_t slotId) = 0;
    virtual bool IsSimActive(int32_t slotId) = 0;
    virtual bool GetNetworkSearchInformation(int32_t slotId, const sptr<INetworkSearchCallback> &callback) = 0;
    virtual bool GetNetworkSelectionMode(int32_t slotId, const sptr<INetworkSearchCallback> &callback) = 0;
    virtual std::u16string GetLocaleFromDefaultSim() = 0;
    virtual std::u16string GetSimGid1(int32_t slotId) = 0;
    virtual std::u16string GetSimEons(int32_t slotId, const std::string &plmn, int32_t lac, bool longNameRequired) = 0;
    virtual bool SetNetworkSelectionMode(int32_t slotId, int32_t selectMode,
        const sptr<NetworkInformation> &networkInformation, bool resumeSelection,
        const sptr<INetworkSearchCallback> &callback) = 0;
    virtual std::u16string GetIsoCountryCodeForNetwork(int32_t slotId) = 0;
    virtual bool GetSimAccountInfo(int32_t slotId, IccAccountInfo &info) = 0;
    virtual bool SetDefaultVoiceSlotId(int32_t slotId) = 0;
    virtual int32_t GetDefaultVoiceSlotId() = 0;
    virtual bool SetPrimarySlotId(int32_t slotId) = 0;
    virtual int32_t GetPrimarySlotId() = 0;
    virtual bool SetShowNumber(int32_t slotId, const std::u16string number) = 0;
    virtual std::u16string GetShowNumber(int32_t slotId) = 0;
    virtual bool SetShowName(int32_t slotId, const std::u16string name) = 0;
    virtual std::u16string GetShowName(int32_t slotId) = 0;
    virtual bool GetActiveSimAccountInfoList(std::vector<IccAccountInfo> &iccAccountInfoList) = 0;
    virtual bool GetOperatorConfigs(int32_t slotId, OperatorConfig &poc) = 0;
    virtual int32_t RefreshSimState(int32_t slotId) = 0;
    virtual bool SetActiveSim(int32_t slotId, int32_t enable) = 0;
    virtual bool GetPreferredNetwork(int32_t slotId, const sptr<INetworkSearchCallback> &callback) = 0;
    virtual bool SetPreferredNetwork(
        int32_t slotId, int32_t networkMode, const sptr<INetworkSearchCallback> &callback) = 0;
    virtual std::u16string GetSimTelephoneNumber(int32_t slotId) = 0;
    virtual std::u16string GetSimTeleNumberIdentifier(const int32_t slotId) = 0;
    virtual std::u16string GetVoiceMailIdentifier(int32_t slotId) = 0;
    virtual std::u16string GetVoiceMailNumber(int32_t slotId) = 0;
    virtual std::vector<std::shared_ptr<DiallingNumbersInfo>> QueryIccDiallingNumbers(int slotId, int type) = 0;
    virtual bool AddIccDiallingNumbers(
        int slotId, int type, const std::shared_ptr<DiallingNumbersInfo> &diallingNumber) = 0;
    virtual bool DelIccDiallingNumbers(
        int slotId, int type, const std::shared_ptr<DiallingNumbersInfo> &diallingNumber) = 0;
    virtual bool UpdateIccDiallingNumbers(
        int slotId, int type, const std::shared_ptr<DiallingNumbersInfo> &diallingNumber) = 0;
    virtual bool SetVoiceMailInfo(
        const int32_t slotId, const std::u16string &mailName, const std::u16string &mailNumber) = 0;
    virtual int32_t GetImsRegStatus(int32_t slotId, ImsServiceType imsSrvType, ImsRegInfo &info) = 0;
    virtual int32_t GetMaxSimCount() = 0;
    virtual bool SendEnvelopeCmd(int32_t slotId, const std::string &cmd) = 0;
    virtual bool SendTerminalResponseCmd(int32_t slotId, const std::string &cmd) = 0;
    virtual bool UnlockSimLock(int32_t slotId, const PersoLockInfo &lockInfo, LockStatusResponse &response) = 0;
    virtual std::vector<sptr<CellInformation>> GetCellInfoList(int32_t slotId) = 0;
    virtual bool SendUpdateCellLocationRequest(int32_t slotId) = 0;
    virtual bool HasOperatorPrivileges(const int32_t slotId) = 0;
    virtual int32_t SimAuthentication(
        int32_t slotId, const std::string &aid, const std::string &authData, SimAuthenticationResponse &response) = 0;
    virtual int32_t RegisterImsRegInfoCallback(
        int32_t slotId, ImsServiceType imsSrvType, const sptr<ImsRegInfoCallback> &callback) = 0;
    virtual int32_t UnregisterImsRegInfoCallback(int32_t slotId, ImsServiceType imsSrvType) = 0;
    enum class InterfaceID {
        GET_PS_RADIO_TECH = 0,
        GET_CS_RADIO_TECH,
        GET_OPERATOR_NUMERIC,
        GET_OPERATOR_NAME,
        GET_SIGNAL_INFO_LIST,
        GET_NETWORK_STATE,
        GET_CELL_INFO_LIST,
        SET_RADIO_STATE,
        GET_RADIO_STATE,
        GET_IMEI,
        GET_MEID,
        GET_UNIQUE_DEVICE_ID,
        HAS_SIM_CARD,
        GET_SIM_STATE,
        GET_ISO_COUNTRY_CODE,
        GET_ISO_COUNTRY_CODE_FOR_NETWORK,
        SET_PS_ATTACH_STATUS,
        GET_SPN,
        GET_ICCID,
        GET_IMSI,
        IS_SIM_ACTIVE,
        UNLOCK_PIN,
        UNLOCK_PUK,
        ALTER_PIN,
        CHECK_LOCK,
        SWITCH_LOCK,
        UNLOCK_PIN2,
        UNLOCK_PUK2,
        ALTER_PIN2,
        GET_SIM_OPERATOR_NUMERIC,
        GET_NETWORK_SEARCH_RESULT,
        GET_NETWORK_SELECTION_MODE,
        GET_SIM_LANGUAGE,
        GET_SIM_GID1,
        SET_NETWORK_SELECTION_MODE,
        GET_CELL_LOCATION,
        GET_SIM_SUB_INFO,
        SET_DEFAULT_VOICE_SLOTID,
        GET_DEFAULT_VOICE_SLOTID,
        SET_PRIMARY_SLOTID,
        GET_PRIMARY_SLOTID,
        SET_DEFAULT_DATA_SLOTID,
        GET_DEFAULT_DATA_SLOTID,
        SET_SHOW_NUMBER,
        GET_SHOW_NUMBER,
        SET_SHOW_NAME,
        GET_SHOW_NAME,
        GET_ACTIVE_ACCOUNT_INFO_LIST,
        GET_OPERATOR_CONFIG,
        REFRESH_SIM_STATE,
        SET_SIM_ACTIVE,
        GET_PREFERRED_NETWORK_MODE,
        SET_PREFERRED_NETWORK_MODE,
        GET_SIM_PHONE_NUMBER,
        GET_SIM_TELENUMBER_IDENTIFIER,
        GET_VOICE_MAIL_TAG,
        GET_VOICE_MAIL_NUMBER,
        ICC_DIALLING_NUMBERS_GET,
        ICC_DIALLING_NUMBERS_DELETE,
        ICC_DIALLING_NUMBERS_INSERT,
        ICC_DIALLING_NUMBERS_UPDATE,
        SET_VOICE_MAIL,
        GET_MAX_SIM_COUNT,
        GET_IMS_REG_STATUS,
        STK_CMD_FROM_APP_ENVELOPE,
        STK_CMD_FROM_APP_TERMINAL_RESPONSE,
        GET_CARD_TYPE,
        UNLOCK_SIMLOCK,
        HAS_OPERATOR_PRIVILEGES,
        SIM_AUTHENTICATION,
        IS_NR_SUPPORTED,
        GET_NR_OPTION_MODE,
        REG_IMS_CALLBACK,
        UN_REG_IMS_CALLBACK,
        GET_SIM_EONS,
    };

protected:
    const int32_t ERROR = -1;
    const int32_t MIN_STRING_LE = 1;
    const int32_t MAX_STRING_LE = 32;
    const int32_t MAX_VECTOR = 100;
};
} // namespace Telephony
} // namespace OHOS
#endif // I_BASE_PHONE_SERVICE_H
