/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef TELEPHONY_EXT_WRAPPER_H
#define TELEPHONY_EXT_WRAPPER_H

#include "nocopyable.h"
#include "singleton.h"
#include "network_state.h"
#include "network_search_types.h"
#include "network_search_result.h"
#include "signal_information.h"
#include "network_state.h"
#include "cell_information.h"
#include "want.h"
#include "i_icc_file.h"
#include "tel_ril_types.h"

namespace OHOS {
namespace Telephony {

enum class SimSlotType {
    INVALID_SLOT_ID = -1,
    VSIM_SLOT_ID = 2,
};

class TelephonyExtWrapper final {
DECLARE_DELAYED_REF_SINGLETON(TelephonyExtWrapper);

public:
    DISALLOW_COPY_AND_MOVE(TelephonyExtWrapper);
    void InitTelephonyExtWrapper();

    typedef bool (*CHECK_OPC_VERSION_IS_UPDATE)(void);
    typedef void (*UPDATE_OPC_VERSION)(void);
    typedef void (*GET_VOICE_MAIL_ICCID_PARAMETER)(int32_t slotId, const char* iccid, std::string &number);
    typedef void (*SET_VOICE_MAIL_ICCID_PARAMETER)(int32_t, const char*, const char*);
    typedef void (*INIT_VOICE_MAIL_MANAGER_EXT)(int32_t);
    typedef void (*DEINIT_VOICE_MAIL_MANAGER_EXT)(int32_t);
    typedef void (*RESET_VOICE_MAIL_LOADED_FLAG_EXT)(int32_t);
    typedef void (*SET_VOICE_MAIL_ON_SIM_EXT)(int32_t, const char*, const char*);
    typedef bool (*GET_VOICE_MAIL_FIXED_EXT)(int32_t, const char*);
    typedef void (*GET_VOICE_MAIL_NUMBER_EXT)(int32_t slotId, const char* carrier, std::string &number);
    typedef void (*GET_VOICE_MAIL_TAG_EXT)(int32_t slotId, const char* carrier, std::string &tag);
    typedef void (*RESET_VOICE_MAIL_MANAGER_EXT)(int32_t);
    typedef void (*GET_NETWORK_STATUS_EXT)(int32_t slotId, sptr<OHOS::Telephony::NetworkState> &networkState);

    typedef int32_t (*GET_CELL_INFO_LIST)(int32_t slotId, std::vector<sptr<OHOS::Telephony::CellInformation>> &cells);
    typedef void (*GET_RADIO_TECH_EXT)(int32_t slotId, int32_t &domainRadioTech);
    typedef void (*GET_NR_OPTION_MODE_EXT)(int32_t slotId, int32_t &mode);
    typedef void (*GET_NR_OPTION_MODE_EXTEND)(int32_t slotId, OHOS::Telephony::NrMode &mode);
    typedef void (*GET_PREFERRED_NETWORK_EXT)(int32_t &preferredNetworkType);
    typedef bool (*IS_NR_SUPPORTED_NATIVE)(int32_t modemRaf);
    typedef void (*GET_SIGNAL_INFO_LIST_EXT)(int32_t slotId,
	    std::vector<sptr<OHOS::Telephony::SignalInformation>> &signals);
    typedef void (*GET_NETWORK_CAPABILITY_EXT)(int32_t slotId, int32_t networkCapabilityType,
	    int32_t &networkCapabilityState);
    typedef void (*ON_GET_NETWORK_SEARCH_INFORMATION_EXT)(int32_t &availableSize,
        std::vector<OHOS::Telephony::NetworkInformation> &networkInformations);
    typedef void (*CREATE_ICC_FILE_EXT)(int32_t slotId, std::shared_ptr<OHOS::Telephony::IIccFileExt> iccFileExt);

    typedef void (*UPDATE_COUNTRY_CODE_EXT)(int32_t, const char *);
    typedef void (*UPDATE_TIME_ZONE_OFFSET_EXT)(int32_t, int32_t);
    typedef void (*UPDATE_NETWORK_STATE_EXT)(int32_t slotId, std::unique_ptr<NetworkState> &networkState);
    typedef int32_t (*UPDATE_NSA_STATE_EXT)(
        int32_t slotId, int32_t cellId, bool endcAvailable, bool dcNrRestricted, int32_t nsaState);
    typedef void (*PUBLISH_SPN_INFO_CHANGED_EXT)(OHOS::AAFwk::Want &want);
    typedef void (*GET_ROAMINGBROKER_NUMERIC)(int32_t slotId, std::string &numeric);
    typedef void (*GET_ROAMINGBROKER_IMSI)(int32_t slotId, std::string &imsi);
    /* add for vsim begin */
    typedef void (*IS_VSIM_IN_STATUS)(int32_t slotId, int32_t type, bool &status);
    typedef void (*GET_VSIM_SLOT_ID)(int32_t &slotId);
    typedef void (*ON_ALL_FILES_FETCHED_EXT)(int32_t slotId);
    typedef void (*PUT_VSIM_EXTRA_INFO)(OHOS::AAFwk::Want &want, int32_t slotId, int32_t value);
    typedef void (*CHANGE_SPN_AND_RULE_EXT)(std::string &spn, int32_t &rule, bool &showSpn);
    typedef void (*GET_VSIM_CARD_STATE)(int32_t &cardType);
    typedef bool (*GET_SIM_ID_EXT)(int32_t slotId, int32_t &simId);
    typedef bool (*GET_SLOT_ID_EXT)(int32_t simId, int32_t &slotId);
    typedef bool (*IS_HANDLE_VSIM)(void);
    typedef bool (*SEND_EVENT)(std::shared_ptr<std::string> cmdData, int32_t slotId);
    typedef bool (*INIT_BIP)(int32_t slotId);
    /* add for vsim end */
    typedef bool (*IS_ALLOWED_INSERT_APN)(std::string &value);
    typedef void (*GET_TARGET_OPKEY)(int32_t slotId, std::u16string &opkey);
    typedef void (*SORT_SIGNAL_INFO_LIST_EXT)(
        int32_t slotId, std::vector<sptr<OHOS::Telephony::SignalInformation>> &signals);
    typedef void (*GET_OPKEY_VERSION)(std::string &versionInfo);

    typedef bool (*PROCESS_SIGNAL_INFOS)(int32_t slotId, Rssi &signalIntensity);
    typedef bool (*PROCESS_STATE_CHANGE_EXT)(int32_t slotId, sptr<NetworkState> &ns);

    CHECK_OPC_VERSION_IS_UPDATE checkOpcVersionIsUpdate_ = nullptr;
    UPDATE_OPC_VERSION updateOpcVersion_ = nullptr;
    GET_VOICE_MAIL_ICCID_PARAMETER getVoiceMailIccidParameter_ = nullptr;
    SET_VOICE_MAIL_ICCID_PARAMETER setVoiceMailIccidParameter_ = nullptr;
    INIT_VOICE_MAIL_MANAGER_EXT initVoiceMailManagerExt_ = nullptr;
    DEINIT_VOICE_MAIL_MANAGER_EXT deinitVoiceMailManagerExt_ = nullptr;
    RESET_VOICE_MAIL_LOADED_FLAG_EXT resetVoiceMailLoadedFlagExt_ = nullptr;
    SET_VOICE_MAIL_ON_SIM_EXT setVoiceMailOnSimExt_ = nullptr;
    GET_VOICE_MAIL_FIXED_EXT getVoiceMailFixedExt_ = nullptr;
    GET_VOICE_MAIL_NUMBER_EXT getVoiceMailNumberExt_ = nullptr;
    GET_VOICE_MAIL_TAG_EXT getVoiceMailTagExt_ = nullptr;
    RESET_VOICE_MAIL_MANAGER_EXT resetVoiceMailManagerExt_ = nullptr;
    GET_NETWORK_STATUS_EXT getNetworkStatusExt_ = nullptr;

    GET_CELL_INFO_LIST getCellInfoList_ = nullptr;
    GET_RADIO_TECH_EXT getRadioTechExt_ = nullptr;
    GET_NR_OPTION_MODE_EXT getNrOptionModeExt_ = nullptr;
    GET_NR_OPTION_MODE_EXTEND getNrOptionModeExtend_ = nullptr;
    GET_PREFERRED_NETWORK_EXT getPreferredNetworkExt_ = nullptr;
    IS_NR_SUPPORTED_NATIVE isNrSupportedNative_ = nullptr;
    GET_SIGNAL_INFO_LIST_EXT getSignalInfoListExt_ = nullptr;
    GET_NETWORK_CAPABILITY_EXT getNetworkCapabilityExt_ = nullptr;
    ON_GET_NETWORK_SEARCH_INFORMATION_EXT onGetNetworkSearchInformationExt_ = nullptr;
    CREATE_ICC_FILE_EXT createIccFileExt_ = nullptr;
    UPDATE_NETWORK_STATE_EXT updateNetworkStateExt_ = nullptr;
    UPDATE_NSA_STATE_EXT updateNsaStateExt_ = nullptr;
    PUBLISH_SPN_INFO_CHANGED_EXT publishSpnInfoChangedExt_ = nullptr;

    UPDATE_COUNTRY_CODE_EXT updateCountryCodeExt_ = nullptr;
    UPDATE_TIME_ZONE_OFFSET_EXT updateTimeZoneOffsetExt_ = nullptr;

    /* add for vsim begin */
    IS_VSIM_IN_STATUS isVSimInStatus_ = nullptr;
    GET_VSIM_SLOT_ID getVSimSlotId_ = nullptr;
    ON_ALL_FILES_FETCHED_EXT onAllFilesFetchedExt_ = nullptr;
    PUT_VSIM_EXTRA_INFO putVSimExtraInfo_ = nullptr;
    CHANGE_SPN_AND_RULE_EXT changeSpnAndRuleExt_ = nullptr;
    GET_VSIM_CARD_STATE getVSimCardState_ = nullptr;
    GET_SIM_ID_EXT getSimIdExt_ = nullptr;
    GET_SLOT_ID_EXT getSlotIdExt_ = nullptr;
    IS_HANDLE_VSIM isHandleVSim_ = nullptr;
    SEND_EVENT sendEvent_ = nullptr;
    INIT_BIP initBip_ = nullptr;
    /* add for vsim end */
    IS_ALLOWED_INSERT_APN isAllowedInsertApn_ = nullptr;
    GET_TARGET_OPKEY getTargetOpkey_ = nullptr;
    SORT_SIGNAL_INFO_LIST_EXT sortSignalInfoListExt_ = nullptr;
    GET_OPKEY_VERSION getOpkeyVersion_ = nullptr;
    GET_ROAMINGBROKER_NUMERIC getRoamingBrokerNumeric_ = nullptr;
    GET_ROAMINGBROKER_IMSI getRoamingBrokerImsi_ = nullptr;
    PROCESS_SIGNAL_INFOS processSignalInfos_ = nullptr;
    PROCESS_STATE_CHANGE_EXT processStateChangeExt_ = nullptr;

private:
    void* telephonyExtWrapperHandle_ = nullptr;
    void* telephonyVSimWrapperHandle_ = nullptr;
    void InitTelephonyExtWrapperForNetWork();
    void InitTelephonyExtWrapperForVoiceMail();
    void InitTelephonyExtWrapperForCust();
    void InitTelephonyExtWrapperForVSim();
    void InitTelephonyExtWrapperForApnCust();
    void InitTelephonyExtWrapperForSim();
    void InitTelephonyExtWrapperForOpkeyVersion();
};

#define TELEPHONY_EXT_WRAPPER ::OHOS::DelayedRefSingleton<TelephonyExtWrapper>::GetInstance()
} // namespace Telephony
} // namespace OHOS
#endif // TELEPHONY_EXT_WRAPPER_H
