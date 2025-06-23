// Copyright (C) 2025 Huawei Device Co., Ltd.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "ohos.telephony.radio.proj.hpp"
#include "ohos.telephony.radio.impl.hpp"
#include "taihe/runtime.hpp"
#include "stdexcept"
#include "telephony_config.h"
#include "core_service_client.h"
#include "telephony_types.h"
#include "telephony_errors.h"
#include "network_search_types.h"
#include "ani_util.h"
#include "signal_information.h"
#include "telephony_log_wrapper.h"
#include "network_search.h"

using namespace taihe;
using namespace OHOS;
using namespace OHOS::Telephony;
namespace {
// To be implemented.

constexpr const char *GET_TELEPHONY_STATE = "ohos.permission.GET_TELEPHONY_STATE";
constexpr const char *GET_NETWORK_INFO = "ohos.permission.GET_NETWORK_INFO";

bool IsValidSlotId(int32_t slotId)
{
    if ((slotId >= DEFAULT_SIM_SLOT_ID) && (slotId < SIM_SLOT_COUNT)) {
        return true;
    }
    TELEPHONY_LOGE("NativeGetImsRegInfo slotId is invalid");
    set_business_error(JS_ERROR_TELEPHONY_ARGUMENT_ERROR, AniUtil::GetErrorMessage(JS_ERROR_TELEPHONY_ARGUMENT_ERROR));
    return false;
}

static int32_t WrapRegState(int32_t nativeState)
{
    RegServiceState state = static_cast<RegServiceState>(nativeState);
    switch (state) {
        case RegServiceState::REG_STATE_IN_SERVICE: {
            return RegStatus::REGISTRATION_STATE_IN_SERVICE;
        }
        case RegServiceState::REG_STATE_EMERGENCY_ONLY: {
            return RegStatus::REGISTRATION_STATE_EMERGENCY_CALL_ONLY;
        }
        case RegServiceState::REG_STATE_POWER_OFF: {
            return RegStatus::REGISTRATION_STATE_POWER_OFF;
        }
        default:
            return RegStatus::REGISTRATION_STATE_NO_SERVICE;
    }
}

static int32_t WrapRadioTech(int32_t radioTechType)
{
    RadioTech techType = static_cast<RadioTech>(radioTechType);
    switch (techType) {
        case RadioTech::RADIO_TECHNOLOGY_GSM:
            return static_cast<int32_t>(RatType::RADIO_TECHNOLOGY_GSM);
        case RadioTech::RADIO_TECHNOLOGY_LTE:
            return static_cast<int32_t>(RatType::RADIO_TECHNOLOGY_LTE);
        case RadioTech::RADIO_TECHNOLOGY_WCDMA:
            return static_cast<int32_t>(RatType::RADIO_TECHNOLOGY_WCDMA);
        case RadioTech::RADIO_TECHNOLOGY_1XRTT:
            return static_cast<int32_t>(RatType::RADIO_TECHNOLOGY_1XRTT);
        case RadioTech::RADIO_TECHNOLOGY_HSPA:
            return static_cast<int32_t>(RatType::RADIO_TECHNOLOGY_HSPA);
        case RadioTech::RADIO_TECHNOLOGY_HSPAP:
            return static_cast<int32_t>(RatType::RADIO_TECHNOLOGY_HSPAP);
        case RadioTech::RADIO_TECHNOLOGY_TD_SCDMA:
            return static_cast<int32_t>(RatType::RADIO_TECHNOLOGY_TD_SCDMA);
        case RadioTech::RADIO_TECHNOLOGY_EVDO:
            return static_cast<int32_t>(RatType::RADIO_TECHNOLOGY_EVDO);
        case RadioTech::RADIO_TECHNOLOGY_EHRPD:
            return static_cast<int32_t>(RatType::RADIO_TECHNOLOGY_EHRPD);
        case RadioTech::RADIO_TECHNOLOGY_LTE_CA:
            return static_cast<int32_t>(RatType::RADIO_TECHNOLOGY_LTE_CA);
        case RadioTech::RADIO_TECHNOLOGY_IWLAN:
            return static_cast<int32_t>(RatType::RADIO_TECHNOLOGY_IWLAN);
        case RadioTech::RADIO_TECHNOLOGY_NR:
            return static_cast<int32_t>(RatType::RADIO_TECHNOLOGY_NR);
        default:
            return static_cast<int32_t>(RatType::RADIO_TECHNOLOGY_UNKNOWN);
    }
}

static int32_t WrapSignalInformationType(SignalInformation::NetworkType type)
{
    switch (type) {
        case SignalInformation::NetworkType::GSM:
            return static_cast<int32_t>(NetworkType::NETWORK_TYPE_GSM);
        case SignalInformation::NetworkType::CDMA:
            return static_cast<int32_t>(NetworkType::NETWORK_TYPE_CDMA);
        case SignalInformation::NetworkType::LTE:
            return static_cast<int32_t>(NetworkType::NETWORK_TYPE_LTE);
        case SignalInformation::NetworkType::WCDMA:
            return static_cast<int32_t>(NetworkType::NETWORK_TYPE_WCDMA);
        case SignalInformation::NetworkType::TDSCDMA:
            return static_cast<int32_t>(NetworkType::NETWORK_TYPE_TDSCDMA);
        case SignalInformation::NetworkType::NR:
            return static_cast<int32_t>(NetworkType::NETWORK_TYPE_NR);
        default:
            return static_cast<int32_t>(NetworkType::NETWORK_TYPE_UNKNOWN);
    }
}

::ohos::telephony::radio::ImsRegInfo MakeImsRegInfo(ImsRegState imsRegState, ImsRegTech imsRegTech)
{
    return {static_cast<::ohos::telephony::radio::ImsRegState::key_t>(imsRegState),
        static_cast<::ohos::telephony::radio::ImsRegTech::key_t>(imsRegTech)};
}

::ohos::telephony::radio::NetworkState MakeNetworkState(GetNetworkStateContext context)
{
    return {context.longOperatorName, context.shortOperatorName, context.plmnNumeric, context.isRoaming,
        static_cast<::ohos::telephony::radio::RegState::key_t>(WrapRegState(context.regStatus)),
        static_cast<::ohos::telephony::radio::RadioTechnology::key_t>(WrapRadioTech(context.cfgTech)),
        static_cast<::ohos::telephony::radio::NsaState::key_t>(context.nsaState),
        context.isEmergency};
}

::ohos::telephony::radio::SignalInformation MakeSignalInformation(int32_t signalType, int32_t signalLevel,
    int32_t signalIntensity)
{
    return {static_cast<::ohos::telephony::radio::NetworkType::key_t>(signalType), signalLevel, signalIntensity};
}

void SetBusinessErrorWithoutPermission(int32_t errorCode)
{
    std::string errorMessage = AniUtil::GetErrorMessage(errorCode);
    set_business_error(errorCode, errorMessage);
    return;
}

void SetBusinessErrorWithPermission(int32_t errorCode, const std::string &funcName, const std::string &permission)
{
    if (errorCode == TELEPHONY_ERR_PERMISSION_ERR) {
        std::string errorMessage = AniUtil::ConverErrorMessageWithPermissionForJs(errorCode, funcName, permission);
        set_business_error(errorCode, errorMessage);
        return;
    }
    SetBusinessErrorWithoutPermission(errorCode);
}

::ohos::telephony::radio::ImsRegInfo GetImsRegInfoSync(int32_t slotId,
    ::ohos::telephony::radio::ImsServiceType imsType)
{
    struct ImsRegInfo imsRegInfo;
    if (!IsValidSlotId(slotId)) {
        return MakeImsRegInfo(IMS_UNREGISTERED, IMS_REG_TECH_NONE);
    }
    int32_t ret = DelayedRefSingleton<CoreServiceClient>::GetInstance().GetImsRegStatus(slotId,
        static_cast<ImsServiceType>(imsType.get_value()), imsRegInfo);
    int32_t errorCode =  AniUtil::GetErrorCode(ret);
    if (errorCode == JS_ERROR_TELEPHONY_SUCCESS) {
        return MakeImsRegInfo(imsRegInfo.imsRegState, imsRegInfo.imsRegTech);
    }
    SetBusinessErrorWithPermission(errorCode, "getImsRegInfo", GET_TELEPHONY_STATE);
    return MakeImsRegInfo(IMS_UNREGISTERED, IMS_REG_TECH_NONE);
}

::taihe::array<::ohos::telephony::radio::SignalInformation> GetSignalInformationSync(int32_t slotId)
{
    std::vector<sptr<SignalInformation>> signalInfoList;
    std::vector<::ohos::telephony::radio::SignalInformation> signalInfoArrayList;
    if (!IsValidSlotId(slotId)) {
        return ::taihe::array<::ohos::telephony::radio::SignalInformation>(taihe::copy_data_t{},
            signalInfoArrayList.data(), signalInfoArrayList.size());
    }
    auto ret = DelayedRefSingleton<CoreServiceClient>::GetInstance().GetSignalInfoList(slotId, signalInfoList);
    int32_t errorCode =  AniUtil::GetErrorCode(ret);
    if (errorCode == TELEPHONY_SUCCESS) {
        for (sptr<SignalInformation> infoItem : signalInfoList) {
            int32_t signalType = static_cast<int32_t>(NetworkType::NETWORK_TYPE_UNKNOWN);
            int32_t signalLevel = 0;
            int32_t signalIntensity = 0;
            if (infoItem != nullptr) {
                signalType = WrapSignalInformationType(infoItem->GetNetworkType());
                signalLevel = infoItem->GetSignalLevel();
                signalIntensity = infoItem->GetSignalIntensity();
            }
            auto signalInfo = MakeSignalInformation(signalType, signalLevel, signalIntensity);
            signalInfoArrayList.push_back(signalInfo);
        }
        auto signalInfoArray = ::taihe::array<::ohos::telephony::radio::SignalInformation>(taihe::copy_data_t{},
            signalInfoArrayList.data(), signalInfoArrayList.size());
        return signalInfoArray;
    }
    SetBusinessErrorWithoutPermission(errorCode);
    return ::taihe::array<::ohos::telephony::radio::SignalInformation>(taihe::copy_data_t{},
        signalInfoArrayList.data(), signalInfoArrayList.size());
}

int32_t GetPrimarySlotIdSync()
{
    int32_t slotId = 0;
    auto errorCode = DelayedRefSingleton<CoreServiceClient>::GetInstance().GetPrimarySlotId(slotId);
    if (errorCode == TELEPHONY_SUCCESS) {
        return slotId;
    }
    SetBusinessErrorWithoutPermission(errorCode);
    return slotId;
}

::ohos::telephony::radio::NetworkState GetNetworkStateSyncWithSlotId(int32_t slotId)
{
    GetNetworkStateContext context;
    sptr<NetworkState> networkState = nullptr;
    int32_t ret = DelayedRefSingleton<CoreServiceClient>::GetInstance().GetNetworkState(slotId, networkState);
    int32_t errorCode =  AniUtil::GetErrorCode(ret);
    if (errorCode == TELEPHONY_SUCCESS) {
        context.regStatus = static_cast<int32_t>(networkState->GetRegStatus());
        context.longOperatorName = networkState->GetLongOperatorName();
        context.shortOperatorName = networkState->GetShortOperatorName();
        context.plmnNumeric = networkState->GetPlmnNumeric();
        context.isRoaming = networkState->IsRoaming();
        context.isEmergency = networkState->IsEmergency();
        context.cfgTech = static_cast<int32_t>(networkState->GetCfgTech());
        return MakeNetworkState(context);
    }
    SetBusinessErrorWithPermission(errorCode, "getNetworkState", GET_NETWORK_INFO);
    return MakeNetworkState(context);
}

::ohos::telephony::radio::NetworkState GetNetworkStateSyncDefault()
{
    int32_t slotId = DEFAULT_SIM_SLOT_ID;
    return GetNetworkStateSyncWithSlotId(slotId);
}

::ohos::telephony::radio::NetworkState GetNetworkStateSyncOptional(optional_view<int32_t> slotId)
{
    int32_t slotIdValue = slotId.value_or(static_cast<int32_t>(DEFAULT_SIM_SLOT_ID));
    return GetNetworkStateSyncWithSlotId(slotIdValue);
}

bool IsNRSupportedDefault()
{
    TelephonyConfig telephonyConfig;
    bool isNrSupported =
        telephonyConfig.IsCapabilitySupport(static_cast<int32_t>(TelephonyConfig::ConfigType::MODEM_CAP_SUPPORT_NR));
#ifdef OHOS_BUILD_ENABLE_TELEPHONY_EXT
    TELEPHONY_EXT_UTILS_WRAPPER.InitTelephonyExtUtilsWrapper();
    if (TELEPHONY_EXT_UTILS_WRAPPER.isChipsetNrSupported_ != nullptr) {
        isNrSupported = isNrSupported && TELEPHONY_EXT_UTILS_WRAPPER.isChipsetNrSupported_();
    }
#endif
    return isNrSupported;
}

bool IsNRSupportedWithSlotID(int32_t slotId)
{
    return IsNRSupportedDefault();
}

}  // namespace

// Since these macros are auto-generate, lint will cause false positive.
// NOLINTBEGIN
TH_EXPORT_CPP_API_GetImsRegInfoSync(GetImsRegInfoSync);
TH_EXPORT_CPP_API_GetSignalInformationSync(GetSignalInformationSync);
TH_EXPORT_CPP_API_GetPrimarySlotIdSync(GetPrimarySlotIdSync);
TH_EXPORT_CPP_API_GetNetworkStateSyncDefault(GetNetworkStateSyncDefault);
TH_EXPORT_CPP_API_GetNetworkStateSyncOptional(GetNetworkStateSyncOptional);
TH_EXPORT_CPP_API_GetNetworkStateSyncWithSlotId(GetNetworkStateSyncWithSlotId);
TH_EXPORT_CPP_API_IsNRSupportedWithSlotID(IsNRSupportedWithSlotID);
TH_EXPORT_CPP_API_IsNRSupportedDefault(IsNRSupportedDefault);
// NOLINTEND
