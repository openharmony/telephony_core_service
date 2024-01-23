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

#include <dlfcn.h>
#include "telephony_ext_wrapper.h"
#include "telephony_log_wrapper.h"

namespace OHOS {
namespace Telephony {
namespace {
const std::string TELEPHONY_EXT_WRAPPER_PATH = "libtelephony_ext_service.z.so";
const std::string TELEPHONY_VSIM_WRAPPER_PATH = "libtel_vsim_symbol.z.so";
} // namespace

TelephonyExtWrapper::TelephonyExtWrapper() {}
TelephonyExtWrapper::~TelephonyExtWrapper()
{
    TELEPHONY_LOGD("TelephonyExtWrapper::~TelephonyExtWrapper() start");
    if (telephonyExtWrapperHandle_ != nullptr) {
        dlclose(telephonyExtWrapperHandle_);
        telephonyExtWrapperHandle_ = nullptr;
    }
    if (telephonyVSimWrapperHandle_ != nullptr) {
        dlclose(telephonyVSimWrapperHandle_);
        telephonyVSimWrapperHandle_ = nullptr;
    }
}

void TelephonyExtWrapper::InitTelephonyExtWrapper()
{
    TELEPHONY_LOGD("TelephonyExtWrapper::InitTelephonyExtWrapper() start");
    telephonyExtWrapperHandle_ = dlopen(TELEPHONY_EXT_WRAPPER_PATH.c_str(), RTLD_NOW);
    if (telephonyExtWrapperHandle_ == nullptr) {
        TELEPHONY_LOGE("libtelephony_ext_service.z.so was not loaded, error: %{public}s", dlerror());
        return;
    }
    InitTelephonyExtWrapperForNetWork();
    InitTelephonyExtWrapperForVoiceMail();
    InitTelephonyExtWrapperForVSim();
    TELEPHONY_LOGI("telephony ext wrapper init success");
}

void TelephonyExtWrapper::InitTelephonyExtWrapperForNetWork()
{
    checkOpcVersionIsUpdate_ = (CHECK_OPC_VERSION_IS_UPDATE)dlsym(telephonyExtWrapperHandle_,
        "CheckOpcVersionIsUpdate");
    updateOpcVersion_ = (UPDATE_OPC_VERSION)dlsym(telephonyExtWrapperHandle_, "UpdateOpcVersion");
    getCellInfoList_ = (GET_CELL_INFO_LIST)dlsym(telephonyExtWrapperHandle_, "GetCellInfoListExt");
    getRadioTechExt_ = (GET_RADIO_TECH_EXT)dlsym(telephonyExtWrapperHandle_, "GetRadioTechExt");
    getNrOptionModeExt_ = (GET_NR_OPTION_MODE_EXT)dlsym(telephonyExtWrapperHandle_, "GetNrOptionModeExt");
    getNrOptionModeExtend_ = (GET_NR_OPTION_MODE_EXTEND)dlsym(telephonyExtWrapperHandle_, "GetNrOptionModeExtend");
    getPreferredNetworkExt_ = (GET_PREFERRED_NETWORK_EXT)dlsym(telephonyExtWrapperHandle_, "GetPreferredNetworkExt");
    isNrSupportedNative_ = (IS_NR_SUPPORTED_NATIVE)dlsym(telephonyExtWrapperHandle_, "IsNrSupportedNativeExt");
    getSignalInfoListExt_ = (GET_SIGNAL_INFO_LIST_EXT)dlsym(telephonyExtWrapperHandle_, "GetSignalInfoListExt");
    getNetworkCapabilityExt_ = (GET_NETWORK_CAPABILITY_EXT)dlsym(telephonyExtWrapperHandle_, "GetNetworkCapabilityExt");
    onGetNetworkSearchInformationExt_ = (ON_GET_NETWORK_SEARCH_INFORMATION_EXT)dlsym(telephonyExtWrapperHandle_,
        "OnGetNetworkSearchInformationExt");
    getNetworkStatusExt_ = (GET_NETWORK_STATUS_EXT)dlsym(telephonyExtWrapperHandle_, "GetNetworkStatusExt");
    if (checkOpcVersionIsUpdate_ == nullptr || updateOpcVersion_ == nullptr || getCellInfoList_ == nullptr ||
        getRadioTechExt_ == nullptr || getNrOptionModeExt_ == nullptr || getSignalInfoListExt_ == nullptr ||
        getNetworkCapabilityExt_ == nullptr || onGetNetworkSearchInformationExt_ == nullptr ||
        getNetworkStatusExt_ == nullptr || isNrSupportedNative_ == nullptr ||
        getNrOptionModeExtend_ == nullptr || getPreferredNetworkExt_ == nullptr) {
        TELEPHONY_LOGE("telephony ext wrapper symbol failed, error: %{public}s", dlerror());
    }
    updateCountryCodeExt_ = (UPDATE_COUNTRY_CODE_EXT)dlsym(telephonyExtWrapperHandle_, "UpdateCountryCodeExt");
    updateTimeZoneOffsetExt_ =
        (UPDATE_TIME_ZONE_OFFSET_EXT)dlsym(telephonyExtWrapperHandle_, "UpdateTimeZoneOffsetExt");
    if (updateCountryCodeExt_ == nullptr || updateTimeZoneOffsetExt_ == nullptr) {
        TELEPHONY_LOGE("telephony ext wrapper symbol failed, error: %{public}s", dlerror());
    }
}

void TelephonyExtWrapper::InitTelephonyExtWrapperForVoiceMail()
{
    getVoiceMailIccidParameter_ = (GET_VOICE_MAIL_ICCID_PARAMETER)dlsym(telephonyExtWrapperHandle_,
        "GetVoiceMailIccidParameter");
    setVoiceMailIccidParameter_ = (SET_VOICE_MAIL_ICCID_PARAMETER)dlsym(telephonyExtWrapperHandle_,
        "SetVoiceMailIccidParameter");
    initVoiceMailManagerExt_ = (INIT_VOICE_MAIL_MANAGER_EXT)dlsym(telephonyExtWrapperHandle_,
        "InitVoiceMailManagerExt");
    deinitVoiceMailManagerExt_ = (DEINIT_VOICE_MAIL_MANAGER_EXT)dlsym(telephonyExtWrapperHandle_,
        "DeinitVoiceMailManagerExt");
    resetVoiceMailLoadedFlagExt_ = (RESET_VOICE_MAIL_LOADED_FLAG_EXT)dlsym(telephonyExtWrapperHandle_,
        "ResetVoiceMailLoadedFlagExt");
    setVoiceMailOnSimExt_ = (SET_VOICE_MAIL_ON_SIM_EXT)dlsym(telephonyExtWrapperHandle_,
        "SetVoiceMailOnSimExt");
    getVoiceMailFixedExt_ = (GET_VOICE_MAIL_FIXED_EXT)dlsym(telephonyExtWrapperHandle_,
        "GetVoiceMailFixedExt");
    getVoiceMailNumberExt_ = (GET_VOICE_MAIL_NUMBER_EXT)dlsym(telephonyExtWrapperHandle_,
        "GetVoiceMailNumberExt");
    getVoiceMailTagExt_ = (GET_VOICE_MAIL_TAG_EXT)dlsym(telephonyExtWrapperHandle_,
        "GetVoiceMailTagExt");
    resetVoiceMailManagerExt_ = (RESET_VOICE_MAIL_MANAGER_EXT)dlsym(telephonyExtWrapperHandle_,
        "ResetVoiceMailManagerExt");
    getNetworkStatusExt_ = (GET_NETWORK_STATUS_EXT)dlsym(telephonyExtWrapperHandle_, "GetNetworkStatusExt");
    if (getVoiceMailIccidParameter_ == nullptr || setVoiceMailIccidParameter_ == nullptr ||
        initVoiceMailManagerExt_ == nullptr || deinitVoiceMailManagerExt_ == nullptr ||
        resetVoiceMailLoadedFlagExt_ == nullptr || setVoiceMailOnSimExt_ == nullptr ||
        getVoiceMailFixedExt_ == nullptr || getVoiceMailNumberExt_ == nullptr ||
        getVoiceMailTagExt_ == nullptr || resetVoiceMailManagerExt_ == nullptr ||
        getNetworkStatusExt_ == nullptr) {
        TELEPHONY_LOGE("telephony ext wrapper symbol failed, error: %{public}s", dlerror());
        return;
    }
}

void TelephonyExtWrapper::InitTelephonyExtWrapperForVSim()
{
    TELEPHONY_LOGI("[VSIM] telephony ext wrapper init begin");
    telephonyVSimWrapperHandle_ = dlopen(TELEPHONY_EXT_WRAPPER_PATH.c_str(), RTLD_NOW);
    if (telephonyVSimWrapperHandle_ == nullptr) {
        TELEPHONY_LOGE("libtel_vsim_symbol.z.so was not loaded, error: %{public}s", dlerror());
        return;
    }
    isVSimInStatus_ = (IS_VSIM_IN_STATUS) dlsym(telephonyVSimWrapperHandle_, "IsVSimInStatus");
    getVSimSlotId_ = (GET_VSIM_SLOT_ID) dlsym(telephonyVSimWrapperHandle_, "GetVSimSlotId");
    onAllFilesFetchedExt_ = (ON_ALL_FILES_FETCHED_EXT) dlsym(telephonyVSimWrapperHandle_,
        "OnAllFilesFetchedExt");
    putVSimExtraInfo_ = (PUT_VSIM_EXTRA_INFO) dlsym(telephonyVSimWrapperHandle_,
        "PutVSimExtraInfo");
    changeSpnAndRuleExt_ = (CHANGE_SPN_AND_RULE_EXT) dlsym(telephonyVSimWrapperHandle_,
        "ChangeSpnAndRuleExt");
    getVSimCardState_ = (GET_VSIM_CARD_STATE) dlsym(telephonyVSimWrapperHandle_, "GetVSimCardState");
    getSimIdExt_ = (GET_SIM_ID_EXT) dlsym(telephonyVSimWrapperHandle_, "GetSimIdExt");
    getSlotIdExt_ = (GET_SLOT_ID_EXT) dlsym(telephonyVSimWrapperHandle_, "GetSlotIdExt");
    if (isVSimInStatus_ == nullptr || getVSimSlotId_ == nullptr || onAllFilesFetchedExt_ == nullptr ||
        putVSimExtraInfo_ == nullptr || changeSpnAndRuleExt_ == nullptr || getVSimCardState_ == nullptr ||
        getSimIdExt_ == nullptr || getSlotIdExt_ == nullptr) {
        TELEPHONY_LOGE("[VSIM] telephony ext wrapper symbol failed, error: %{public}s", dlerror());
        return;
    }
    TELEPHONY_LOGI("[VSIM] telephony ext wrapper init success");
}

} // namespace Telephony
} // namespace OHOS
