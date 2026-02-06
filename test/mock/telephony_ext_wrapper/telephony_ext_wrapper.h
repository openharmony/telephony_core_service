/*
 * Copyright (c) 2025-2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 */

#ifndef TELEPHONY_EXT_WRAPPER_H
#define TELEPHONY_EXT_WRAPPER_H

#include "nocopyable.h"
#include "singleton.h"
#include "network_state.h"
#include "network_search_types.h"
#include "network_search_result.h"
#include "signal_information.h"
#include "cell_information.h"
#include "want.h"
#include "i_icc_file.h"
#include "sim_state_type.h"
#include "tel_ril_types.h"
#include "operator_name_params.h"
#include "telephony_types.h"
#include "telephony_log_wrapper.h"
#include <memory>
#include <vector>
#include <string>

namespace OHOS {
namespace Telephony {
#define NONULL_HANDLE (reinterpret_cast<void*>(0x4))
enum class SimSlotType {
    INVALID_SLOT_ID = -1,
    VSIM_SLOT_ID = 2,
};

class TelephonyExtWrapper final {
    DECLARE_DELAYED_REF_SINGLETON(TelephonyExtWrapper);

public:
    DISALLOW_COPY_AND_MOVE(TelephonyExtWrapper);
    void InitTelephonyExtWrapper();
    void DeInitTelephonyExtWrapper();

    // === typedefs ===
    typedef bool (*CHECK_OPC_VERSION_IS_UPDATE)(void);
    typedef void (*UPDATE_OPC_VERSION)(void);
    typedef void (*GET_VOICE_MAIL_ICCID_PARAMETER)(int32_t slotId, const char *iccid, std::string &number);
    typedef void (*SET_VOICE_MAIL_ICCID_PARAMETER)(int32_t, const char *, const char *);
    typedef void (*INIT_VOICE_MAIL_MANAGER_EXT)(int32_t);
    typedef void (*DEINIT_VOICE_MAIL_MANAGER_EXT)(int32_t);
    typedef void (*RESET_VOICE_MAIL_LOADED_FLAG_EXT)(int32_t);
    typedef void (*SET_VOICE_MAIL_ON_SIM_EXT)(int32_t, const char *, const char *);
    typedef bool (*GET_VOICE_MAIL_FIXED_EXT)(int32_t, const char *);
    typedef void (*GET_VOICE_MAIL_NUMBER_EXT)(int32_t slotId, const char *carrier, std::string &number);
    typedef void (*GET_VOICE_MAIL_TAG_EXT)(int32_t slotId, const char *carrier, std::string &tag);
    typedef void (*RESET_VOICE_MAIL_MANAGER_EXT)(int32_t);
    typedef void (*GET_NETWORK_STATUS_EXT)(int32_t slotId, sptr<NetworkState> &networkState);

    typedef int32_t (*GET_CELL_INFO_LIST)(int32_t slotId, std::vector<sptr<CellInformation>> &cells);
    typedef void (*GET_RADIO_TECH_EXT)(int32_t slotId, int32_t &domainRadioTech);
    typedef void (*GET_NR_OPTION_MODE_EXT)(int32_t slotId, int32_t &mode);
    typedef void (*GET_NR_OPTION_MODE_EXTEND)(int32_t slotId, NrMode &mode);
    typedef void (*GET_PREFERRED_NETWORK_EXT)(int32_t &preferredNetworkType);
    typedef bool (*IS_CHIPSET_NETWORK_EXT_SUPPORTED)();
    typedef bool (*IS_NR_SUPPORTED_NATIVE)(int32_t modemRaf);
    typedef void (*GET_SIGNAL_INFO_LIST_EXT)(int32_t slotId, std::vector<sptr<SignalInformation>> &signals);
    typedef void (*GET_NETWORK_CAPABILITY_EXT)(
        int32_t slotId, int32_t networkCapabilityType, int32_t &networkCapabilityState);
    typedef void (*ON_GET_NETWORK_SEARCH_INFORMATION_EXT)(
        int32_t &availableSize, std::vector<NetworkInformation> &networkInformations);
    typedef void (*CREATE_ICC_FILE_EXT)(int32_t slotId, std::shared_ptr<IIccFileExt> iccFileExt);

    typedef void (*UPDATE_COUNTRY_CODE_EXT)(int32_t, const char *);
    typedef void (*UPDATE_TIME_ZONE_OFFSET_EXT)(int32_t, NitzData);
    typedef void (*UPDATE_NETWORK_STATE_EXT)(int32_t slotId, std::unique_ptr<NetworkState> &networkState);
    typedef void (*UPDATE_OPERATOR_NAME_PARAMS)(
        int32_t slotId, sptr<NetworkState> &networkState, OperatorNameParams &params);
    typedef int32_t (*UPDATE_NSA_STATE_EXT)(
        int32_t slotId, int32_t cellId, bool endcAvailable, bool dcNrRestricted, int32_t nsaState);
    typedef void (*PUBLISH_SPN_INFO_CHANGED_EXT)(OHOS::AAFwk::Want &want);
    typedef void (*PUBLISH_AP_CONTAINER_IND)(int32_t slotId);
    typedef void (*GET_ROAMINGBROKER_NUMERIC)(int32_t slotId, std::string &numeric);
    typedef void (*GET_ROAMINGBROKER_IMSI)(int32_t slotId, std::string &imsi);
    typedef bool (*SET_NR_OPTION_MODE_EXT)(int32_t slotId, int32_t masterSlotId, int32_t mode, int32_t &errCode);
    typedef void (*UpdatePlmnExt)(int32_t slotId, const std::string &plmn);
    typedef bool (*IsInModem2Optimization)(int32_t slotId);

    typedef void (*IS_VSIM_IN_STATUS)(int32_t slotId, int32_t type, bool &status);
    typedef void (*GET_VSIM_SLOT_ID)(int32_t &slotId);
    typedef void (*ON_ALL_FILES_FETCHED_EXT)(int32_t slotId);
    typedef void (*PUT_VSIM_EXTRA_INFO)(OHOS::AAFwk::Want &want, int32_t slotId, int32_t value);
    typedef void (*CHANGE_SPN_AND_RULE_EXT)(std::string &spn, int32_t &rule, bool &showSpn);
    typedef void (*GET_VSIM_CARD_STATE)(int32_t &cardType);
    typedef bool (*GET_SIM_ID_EXT)(int32_t slotId, int32_t &simId);
    typedef bool (*GET_SLOT_ID_EXT)(int32_t simId, int32_t &slotId);
    typedef bool (*IS_HANDLE_VSIM)(void);
    typedef bool (*IS_VSIM_ENABLED)(void);
    typedef bool (*IS_VSIM_IN_DISABLE_PROCESS)(void);
    typedef void (*UPDATE_SUB_STATE)(int32_t slotId, int32_t subState);
    typedef bool (*IS_IN_ENABLE_DISABLE_VSIM)(void);

    typedef bool (*SEND_EVENT)(std::shared_ptr<std::string> cmdData, int32_t slotId);
    typedef bool (*INIT_BIP)(int32_t slotId);
    typedef void (*GetStkBundleNameFunc)(std::string &bundleName);
    typedef bool (*IS_ALLOWED_INSERT_APN)(std::string &value);
    typedef void (*GET_TARGET_OPKEY)(int32_t slotId, std::u16string &opkey);
    typedef void (*SORT_SIGNAL_INFO_LIST_EXT)(int32_t slotId, std::vector<sptr<SignalInformation>> &signals);
    typedef void (*GET_OPKEY_VERSION)(std::string &versionInfo);
    typedef void (*GetOpnameVersion)(std::string &versionInfo);

    typedef bool (*PROCESS_SIGNAL_INFOS)(int32_t slotId, Rssi &signalIntensity);
    typedef bool (*PROCESS_STATE_CHANGE_EXT)(int32_t slotId, sptr<NetworkState> &ns);
    typedef bool (*PROCESS_OPERATOR_NAME)(int32_t slotId, std::string &plmnName, const std::string &numeric);
    typedef bool (*PROCESS_DELAY_OPERATOR_NAME)(int32_t slotId);
    typedef void (*DynamicLoadInit)(void);
    typedef void (*DynamicLoadDeInit)(void);
    typedef void (*UpdateHotplugCardState)(int32_t slotId, SimState state);
    typedef void (*CacheAssetPinForUpgrade)(
        int32_t slotId, const std::string &iccId, PinOperationType operationType, const std::string &pin);
    typedef bool (*IsDistributedCommunicationConnected)();
    typedef int32_t (*SendSimChgTypeInfoFunc)(int32_t slotId, int32_t type);
    typedef void (*SendSimAccountLoadedInfoFunc)(int32_t slotId, int32_t event);

    // === members ===
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
    IS_CHIPSET_NETWORK_EXT_SUPPORTED isChipsetNetworkExtSupported_ = nullptr;
    IS_NR_SUPPORTED_NATIVE isNrSupportedNative_ = nullptr;
    GET_SIGNAL_INFO_LIST_EXT getSignalInfoListExt_ = nullptr;
    GET_NETWORK_CAPABILITY_EXT getNetworkCapabilityExt_ = nullptr;
    ON_GET_NETWORK_SEARCH_INFORMATION_EXT onGetNetworkSearchInformationExt_ = nullptr;
    CREATE_ICC_FILE_EXT createIccFileExt_ = nullptr;
    UPDATE_NETWORK_STATE_EXT updateNetworkStateExt_ = nullptr;
    UPDATE_OPERATOR_NAME_PARAMS updateOperatorNameParamsExt_ = nullptr;
    UPDATE_NSA_STATE_EXT updateNsaStateExt_ = nullptr;
    PUBLISH_SPN_INFO_CHANGED_EXT publishSpnInfoChangedExt_ = nullptr;
    PUBLISH_AP_CONTAINER_IND publishContainerDisableHotZoneInd_ = nullptr;

    UPDATE_COUNTRY_CODE_EXT updateCountryCodeExt_ = nullptr;
    UPDATE_TIME_ZONE_OFFSET_EXT updateTimeZoneOffsetExt_ = nullptr;
    SET_NR_OPTION_MODE_EXT setNrOptionModeExt_ = nullptr;
    UpdatePlmnExt updatePlmnExt_ = nullptr;
    IsInModem2Optimization isInModem2Optimization_ = nullptr;

    IS_VSIM_IN_STATUS isVSimInStatus_ = nullptr;
    GET_VSIM_SLOT_ID getVSimSlotId_ = nullptr;
    ON_ALL_FILES_FETCHED_EXT onAllFilesFetchedExt_ = nullptr;
    PUT_VSIM_EXTRA_INFO putVSimExtraInfo_ = nullptr;
    CHANGE_SPN_AND_RULE_EXT changeSpnAndRuleExt_ = nullptr;
    GET_VSIM_CARD_STATE getVSimCardState_ = nullptr;
    GET_SIM_ID_EXT getSimIdExt_ = nullptr;
    GET_SLOT_ID_EXT getSlotIdExt_ = nullptr;
    IS_HANDLE_VSIM isHandleVSim_ = nullptr;
    IS_VSIM_ENABLED isVSimEnabled_ = nullptr;
    IS_VSIM_IN_DISABLE_PROCESS isVSimInDisableProcess_ = nullptr;
    UPDATE_SUB_STATE updateSubState_ = nullptr;
    IS_IN_ENABLE_DISABLE_VSIM isInEnaDisableVSim_ = nullptr;

    SEND_EVENT sendEvent_ = nullptr;
    INIT_BIP initBip_ = nullptr;
    IS_ALLOWED_INSERT_APN isAllowedInsertApn_ = nullptr;
    GET_TARGET_OPKEY getTargetOpkey_ = nullptr;
    SORT_SIGNAL_INFO_LIST_EXT sortSignalInfoListExt_ = nullptr;
    GET_OPKEY_VERSION getOpkeyVersion_ = nullptr;
    GetOpnameVersion getOpnameVersion_ = nullptr;
    GET_ROAMINGBROKER_NUMERIC getRoamingBrokerNumeric_ = nullptr;
    GET_ROAMINGBROKER_IMSI getRoamingBrokerImsi_ = nullptr;
    PROCESS_SIGNAL_INFOS processSignalInfos_ = nullptr;
    PROCESS_STATE_CHANGE_EXT processStateChangeExt_ = nullptr;
    PROCESS_OPERATOR_NAME processOperatorName_ = nullptr;
    PROCESS_DELAY_OPERATOR_NAME isInDelayProcessForOperatorName_ = nullptr;
    DynamicLoadInit dynamicLoadInit_ = nullptr;
    DynamicLoadDeInit dynamicLoadDeInit_ = nullptr;
    UpdateHotplugCardState updateHotPlugCardState_ = nullptr;
    CacheAssetPinForUpgrade cacheAssetPinForUpgrade_ = nullptr;
    IsDistributedCommunicationConnected isDistributedCommunicationConnected_ = nullptr;
    bool GetStkBundleName(std::string &bundleName);
    void SendSimChgTypeInfo(int32_t slotId, int32_t type);
    void SendSimAccountLoadedInfo(int32_t slotId, int32_t event);

private:
    void* telephonyExtWrapperHandle_ = nullptr;
    void* telephonyVSimWrapperHandle_ = nullptr;
    void* telephonyDynamicLoadWrapperHandle_ = nullptr;
    GetStkBundleNameFunc getStkBundleNameFunc_ = nullptr;
    SendSimChgTypeInfoFunc sendSimChgTypeInfo_ = nullptr;
    SendSimAccountLoadedInfoFunc sendSimAccountLoadedInfo_ = nullptr;
    void InitTelephonyExtWrapperForNetWork();
    void InitTelephonyExtWrapperForNetWork1();
    void InitTelephonyExtWrapperForVoiceMail();
    void InitTelephonyExtWrapperForCust();
    void InitTelephonyExtWrapperForVSim();
    void InitTelephonyExtWrapperForApnCust();
    void InitTelephonyExtWrapperForSim();
    void InitTelephonyExtWrapperForOpkeyVersion();
    void InitTelephonyExtWrapperForOpnameVersion();
    void InitTelephonyExtWrapperForDynamicLoad();
};

// =================== 空实现函数（全局函数） ===================
inline bool CheckOpcVersionIsUpdateImpl()
{
    return false;
}
inline void UpdateOpcVersionImpl() {}
inline void GetVoiceMailIccidParameterImpl(int32_t, const char *, std::string &) {}
inline void SetVoiceMailIccidParameterImpl(int32_t, const char *, const char *) {}
inline void InitVoiceMailManagerExtImpl(int32_t) {}
inline void DeinitVoiceMailManagerExtImpl(int32_t) {}
inline void ResetVoiceMailLoadedFlagExtImpl(int32_t) {}
inline void SetVoiceMailOnSimExtImpl(int32_t, const char *, const char *) {}
inline bool GetVoiceMailFixedExtImpl(int32_t, const char *)
{
    return false;
}
inline void GetVoiceMailNumberExtImpl(int32_t, const char *, std::string &) {}
inline void GetVoiceMailTagExtImpl(int32_t, const char *, std::string &) {}
inline void ResetVoiceMailManagerExtImpl(int32_t) {}
inline void GetNetworkStatusExtImpl(int32_t, sptr<NetworkState> &) {}
inline int32_t GetCellInfoListImpl(int32_t, std::vector<sptr<CellInformation>> &)
{
    return 0;
}
inline void GetRadioTechExtImpl(int32_t, int32_t &) {}
inline void GetNrOptionModeExtImpl(int32_t, int32_t &) {}
inline void GetNrOptionModeExtendImpl(int32_t, NrMode &) {}
inline void GetPreferredNetworkExtImpl(int32_t &) {}
inline bool IsChipsetNetworkExtSupportedImpl() {
    return false;
}
inline bool IsNrSupportedNativeImpl(int32_t)
{
    return false;
}
inline void GetSignalInfoListExtImpl(int32_t, std::vector<sptr<SignalInformation>> &) {}
inline void GetNetworkCapabilityExtImpl(int32_t, int32_t, int32_t &) {}
inline void OnGetNetworkSearchInformationExtImpl(int32_t &, std::vector<NetworkInformation> &) {}
inline void CreateIccFileExtImpl(int32_t, std::shared_ptr<IIccFileExt>) {}

inline void UpdateCountryCodeExtImpl(int32_t, const char *) {}
inline void UpdateTimeZoneOffsetExtImpl(int32_t, NitzData) {}
inline void UpdateNetworkStateExtImpl(int32_t, std::unique_ptr<NetworkState> &) {}
inline void UpdateOperatorNameParamsExtImpl(int32_t, sptr<NetworkState> &, OperatorNameParams &) {}
inline int32_t UpdateNsaStateExtImpl(int32_t, int32_t, bool, bool, int32_t)
{
    return 0;
}
inline void PublishSpnInfoChangedExtImpl(OHOS::AAFwk::Want &) {}
inline void PublishContainerDisableHotZoneIndImpl(int32_t) {}
inline void GetRoamingBrokerNumericImpl(int32_t, std::string &) {}
inline void GetRoamingBrokerImsiImpl(int32_t, std::string &) {}
inline bool SetNrOptionModeExtImpl(int32_t, int32_t, int32_t, int32_t &)
{
    return false;
}
inline void UpdatePlmnExtImpl(int32_t, const std::string &)
{}
inline bool IsInModem2OptimizationImpl(int32_t)
{
    return false;
}

inline void IsVSimInStatusImpl(int32_t, int32_t, bool &) {}
inline void GetVSimSlotIdImpl(int32_t &) {}
inline void OnAllFilesFetchedExtImpl(int32_t) {}
inline void PutVSimExtraInfoImpl(OHOS::AAFwk::Want &, int32_t, int32_t) {}
inline void ChangeSpnAndRuleExtImpl(std::string &, int32_t &, bool &) {}
inline void GetVSimCardStateImpl(int32_t &) {}
inline bool GetSimIdExtImpl(int32_t, int32_t &)
{
    return false;
}
inline bool GetSlotIdExtImpl(int32_t, int32_t &)
{
    return false;
}
inline bool IsHandleVSimImpl()
{
    return false;
}
inline bool IsVSimEnabledImpl()
{
    return false;
}
inline bool IsVSimInDisableProcessImpl()
{
    return false;
}
inline void UpdateSubStateImpl(int32_t, int32_t)
{}
inline bool IsInEnableDisableVSimImpl()
{
    return false;
}

inline bool SendEventImpl(std::shared_ptr<std::string>, int32_t)
{
    return false;
}
inline bool InitBipImpl(int32_t)
{
    return false;
}
inline bool IsAllowedInsertApnImpl(std::string &)
{
    return false;
}
inline void GetTargetOpkeyImpl(int32_t, std::u16string &) {}
inline void SortSignalInfoListExtImpl(int32_t, std::vector<sptr<SignalInformation>> &) {}
inline void GetOpkeyVersionImpl(std::string &) {}
inline void GetOpnameVersionImpl(std::string &) {}
inline bool ProcessSignalInfosImpl(int32_t, Rssi &)
{
    return false;
}
inline bool ProcessStateChangeExtImpl(int32_t, sptr<NetworkState> &)
{
    return false;
}
inline bool ProcessOperatorNameImpl(int32_t, std::string &, const std::string &)
{
    return false;
}
inline bool IsProcessDelayOperatorNameImpl(int32_t)
{
    return false;
}
inline void InitDynamicLoadHandlerImpl() {}
inline void DeInitDynamicLoadHandlerImpl() {}
inline void UpdateHotPlugCardStateImpl(int32_t, SimState) {}
inline void CacheAssetPinForUpgradeImpl(int32_t, const std::string &, PinOperationType, const std::string &) {}
inline bool IsDistributedCommunicationConnectedImpl()
{
    return false;
}
inline int32_t SendSimChgTypeInfoImpl(int32_t slotId, int32_t type)
{
    return 0;
}
inline void SendSimAccountLoadedInfoImpl(int32_t slotId, int32_t event) {}
// =================== TelephonyExtWrapper 成员 inline 实现（绑定空实现） ===================
inline TelephonyExtWrapper::TelephonyExtWrapper() = default;

inline TelephonyExtWrapper::~TelephonyExtWrapper() = default;

inline void TelephonyExtWrapper::InitTelephonyExtWrapper()
{
    telephonyExtWrapperHandle_ = NONULL_HANDLE;
    InitTelephonyExtWrapperForDynamicLoad();
    InitTelephonyExtWrapperForSim();
    InitTelephonyExtWrapperForNetWork();
    InitTelephonyExtWrapperForVoiceMail();
    InitTelephonyExtWrapperForCust();
    InitTelephonyExtWrapperForVSim();
    InitTelephonyExtWrapperForApnCust();
    InitTelephonyExtWrapperForOpkeyVersion();
    InitTelephonyExtWrapperForOpnameVersion();
}

inline void TelephonyExtWrapper::DeInitTelephonyExtWrapper()
{
    if (dynamicLoadDeInit_ != nullptr) {
        dynamicLoadDeInit_();
    }
}

inline void TelephonyExtWrapper::InitTelephonyExtWrapperForNetWork()
{
    checkOpcVersionIsUpdate_ = &CheckOpcVersionIsUpdateImpl;
    updateOpcVersion_ = &UpdateOpcVersionImpl;
    getCellInfoList_ = &GetCellInfoListImpl;
    getRadioTechExt_ = &GetRadioTechExtImpl;
    getNrOptionModeExt_ = &GetNrOptionModeExtImpl;
    getNrOptionModeExtend_ = &GetNrOptionModeExtendImpl;
    getPreferredNetworkExt_ = &GetPreferredNetworkExtImpl;
    isChipsetNetworkExtSupported_ = &IsChipsetNetworkExtSupportedImpl;
    isNrSupportedNative_ = &IsNrSupportedNativeImpl;
    getSignalInfoListExt_ = &GetSignalInfoListExtImpl;
    getNetworkCapabilityExt_ = &GetNetworkCapabilityExtImpl;
    onGetNetworkSearchInformationExt_ = &OnGetNetworkSearchInformationExtImpl;
    getNetworkStatusExt_ = &GetNetworkStatusExtImpl;
    updateCountryCodeExt_ = &UpdateCountryCodeExtImpl;
    updateTimeZoneOffsetExt_ = &UpdateTimeZoneOffsetExtImpl;
    sortSignalInfoListExt_ = &SortSignalInfoListExtImpl;
    updateNsaStateExt_ = &UpdateNsaStateExtImpl;
    processSignalInfos_ = &ProcessSignalInfosImpl;
    processStateChangeExt_ = &ProcessStateChangeExtImpl;
    InitTelephonyExtWrapperForNetWork1();
}

inline void TelephonyExtWrapper::InitTelephonyExtWrapperForNetWork1()
{
    processOperatorName_ = &ProcessOperatorNameImpl;
    isInDelayProcessForOperatorName_ = &IsProcessDelayOperatorNameImpl;
    setNrOptionModeExt_ = &SetNrOptionModeExtImpl;
    updatePlmnExt_ = &UpdatePlmnExtImpl;
    isInModem2Optimization_ = &IsInModem2OptimizationImpl;
}

inline void TelephonyExtWrapper::InitTelephonyExtWrapperForVoiceMail()
{
    getVoiceMailIccidParameter_ = &GetVoiceMailIccidParameterImpl;
    setVoiceMailIccidParameter_ = &SetVoiceMailIccidParameterImpl;
    initVoiceMailManagerExt_ = &InitVoiceMailManagerExtImpl;
    deinitVoiceMailManagerExt_ = &DeinitVoiceMailManagerExtImpl;
    resetVoiceMailLoadedFlagExt_ = &ResetVoiceMailLoadedFlagExtImpl;
    setVoiceMailOnSimExt_ = &SetVoiceMailOnSimExtImpl;
    getVoiceMailFixedExt_ = &GetVoiceMailFixedExtImpl;
    getVoiceMailNumberExt_ = &GetVoiceMailNumberExtImpl;
    getVoiceMailTagExt_ = &GetVoiceMailTagExtImpl;
    resetVoiceMailManagerExt_ = &ResetVoiceMailManagerExtImpl;
    getNetworkStatusExt_ = &GetNetworkStatusExtImpl;
}

inline void TelephonyExtWrapper::InitTelephonyExtWrapperForCust()
{
    updateNetworkStateExt_ = &UpdateNetworkStateExtImpl;
    publishSpnInfoChangedExt_ = &PublishSpnInfoChangedExtImpl;
    updateOperatorNameParamsExt_ = &UpdateOperatorNameParamsExtImpl;
    publishContainerDisableHotZoneInd_ = &PublishContainerDisableHotZoneIndImpl;
    InitTelephonyExtWrapperForApnCust();
}

inline void TelephonyExtWrapper::InitTelephonyExtWrapperForVSim()
{
    telephonyVSimWrapperHandle_ = NONULL_HANDLE;
    isVSimInStatus_ = &IsVSimInStatusImpl;
    getVSimSlotId_ = &GetVSimSlotIdImpl;
    onAllFilesFetchedExt_ = &OnAllFilesFetchedExtImpl;
    putVSimExtraInfo_ = &PutVSimExtraInfoImpl;
    changeSpnAndRuleExt_ = &ChangeSpnAndRuleExtImpl;
    getVSimCardState_ = &GetVSimCardStateImpl;
    getSimIdExt_ = &GetSimIdExtImpl;
    getSlotIdExt_ = &GetSlotIdExtImpl;
    isHandleVSim_ = &IsHandleVSimImpl;
    isVSimEnabled_ = &IsVSimEnabledImpl;
    updateSubState_ = &UpdateSubStateImpl;
    isInEnaDisableVSim_ = &IsInEnableDisableVSimImpl;
    isVSimInDisableProcess_ = &IsVSimInDisableProcessImpl;
}

inline void TelephonyExtWrapper::InitTelephonyExtWrapperForApnCust()
{
    isAllowedInsertApn_ = &IsAllowedInsertApnImpl;
    getTargetOpkey_ = &GetTargetOpkeyImpl;
}

inline void TelephonyExtWrapper::InitTelephonyExtWrapperForSim()
{
    createIccFileExt_ = &CreateIccFileExtImpl;
    getRoamingBrokerNumeric_ = &GetRoamingBrokerNumericImpl;
    getRoamingBrokerImsi_ = &GetRoamingBrokerImsiImpl;
    sendEvent_ = &SendEventImpl;
    initBip_ = &InitBipImpl;
    updateHotPlugCardState_ = &UpdateHotPlugCardStateImpl;
    cacheAssetPinForUpgrade_ = &CacheAssetPinForUpgradeImpl;
    isDistributedCommunicationConnected_ = &IsDistributedCommunicationConnectedImpl;
    sendSimChgTypeInfo_  = &SendSimChgTypeInfoImpl;
    sendSimAccountLoadedInfo_  = &SendSimAccountLoadedInfoImpl;
}

inline void TelephonyExtWrapper::InitTelephonyExtWrapperForOpkeyVersion()
{
    getOpkeyVersion_ = &GetOpkeyVersionImpl;
}

inline void TelephonyExtWrapper::InitTelephonyExtWrapperForOpnameVersion()
{
    getOpnameVersion_ = &GetOpnameVersionImpl;
}

inline void TelephonyExtWrapper::InitTelephonyExtWrapperForDynamicLoad()
{
    telephonyDynamicLoadWrapperHandle_ = NONULL_HANDLE;
    dynamicLoadInit_ = &InitDynamicLoadHandlerImpl;
    dynamicLoadDeInit_ = &DeInitDynamicLoadHandlerImpl;
    if (dynamicLoadInit_ != nullptr) {
        dynamicLoadInit_();
    }
}

inline bool TelephonyExtWrapper::GetStkBundleName(std::string &bundleName)
{
    if (getStkBundleNameFunc_ != nullptr) {
        getStkBundleNameFunc_(bundleName);
    }
    return !bundleName.empty();
}

inline void TelephonyExtWrapper::SendSimChgTypeInfo(int32_t slotId, int32_t type)
{
    if (sendSimChgTypeInfo_ != nullptr) {
        sendSimChgTypeInfo_(slotId, type);
    }
}
 
inline void TelephonyExtWrapper::SendSimAccountLoadedInfo(int32_t slotId, int32_t event)
{
    if (sendSimAccountLoadedInfo_ != nullptr) {
        sendSimAccountLoadedInfo_(slotId, event);
    }
}
#define TELEPHONY_EXT_WRAPPER ::OHOS::DelayedRefSingleton<TelephonyExtWrapper>::GetInstance()
}  // namespace Telephony
}  // namespace OHOS
#endif  // TELEPHONY_EXT_WRAPPER_H
