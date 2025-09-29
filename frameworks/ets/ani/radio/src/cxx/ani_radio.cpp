/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "ani_radio.h"
#include "wrapper.rs.h"
#include "napi_util.h"
#include "napi_util.h"
#include "cxx.h"
#include "telephony_types.h"
#include "telephony_errors.h"
#include "telephony_permission.h"
#include "telephony_config.h"
#include "telephony_log_wrapper.h"
#include "core_service_client.h"
#include "signal_information.h"
#include "telephony_ext_utils_wrapper.h"

namespace OHOS {
using namespace Telephony;
namespace RadioAni {

static inline bool IsValidSlotId(int32_t slotId)
{
    return ((slotId >= DEFAULT_SIM_SLOT_ID) && (slotId < SIM_SLOT_COUNT));
}

static inline bool IsValidSlotIdEx(int32_t slotId)
{
    // One more slot for VSim.
    return ((slotId >= DEFAULT_SIM_SLOT_ID) && (slotId < SIM_SLOT_COUNT + 1));
}

static inline ArktsError ConvertArktsErrorWithPermission(int32_t errorCode, const std::string &funcName,
                                                         const std::string &permission)
{
    JsError error = NapiUtil::ConverErrorMessageWithPermissionForJs(
        errorCode, funcName, permission);

    ArktsError ArktsErr = {
        .errorCode = error.errorCode,
        .errorMessage = rust::string(error.errorMessage),
    };
    return ArktsErr;
}

static inline ArktsError ConvertArktsError(int32_t errorCode)
{
    JsError error = NapiUtil::ConverErrorMessageForJs(errorCode);

    ArktsError ArktsErr = {
        .errorCode = error.errorCode,
        .errorMessage = rust::string(error.errorMessage),
    };
    return ArktsErr;
}

ArktsError GetImsRegInfo(int32_t slotId, int32_t imsSrvType, ImsRegInfoAni &imsRegInfo)
{
    int32_t errorCode;
    ImsRegInfo info;
    if (!IsValidSlotId(slotId)) {
        errorCode = TELEPHONY_ERR_SLOTID_INVALID;
        return ConvertArktsErrorWithPermission(errorCode, "getImsRegInfo",
                                               Permission::GET_TELEPHONY_STATE);
    }
    errorCode = DelayedRefSingleton<CoreServiceClient>::GetInstance().GetImsRegStatus(
        slotId, static_cast<ImsServiceType>(imsSrvType), info);
    if (errorCode == TELEPHONY_SUCCESS) {
        ims_reg_info_conversion(imsRegInfo, static_cast<int32_t>(info.imsRegState),
                                static_cast<int32_t>(info.imsRegTech));
    }
    
    return ConvertArktsErrorWithPermission(errorCode, "getImsRegInfo",
                                           Permission::GET_TELEPHONY_STATE);
}

enum class NetworkType : int32_t {
    NETWORK_TYPE_UNKNOWN,
    NETWORK_TYPE_GSM,
    NETWORK_TYPE_CDMA,
    NETWORK_TYPE_WCDMA,
    NETWORK_TYPE_TDSCDMA,
    NETWORK_TYPE_LTE,
    NETWORK_TYPE_NR
};

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

ArktsError GetSignalInformation(int32_t slotId, rust::Vec<SignalInformationAni> &signalInfoList)
{
    int32_t errorCode;
    std::vector<sptr<SignalInformation>> infoList;
    if (!IsValidSlotIdEx(slotId)) {
        TELEPHONY_LOGE("slotId%{public}d is invalid", slotId);
        errorCode = ERROR_SLOT_ID_INVALID;
        return ConvertArktsError(errorCode);
    }

    errorCode = DelayedRefSingleton<CoreServiceClient>::GetInstance().GetSignalInfoList(
        slotId, infoList);
    if (errorCode == TELEPHONY_SUCCESS) {
        for (sptr<SignalInformation> infoItem : infoList) {
            int32_t signalType = static_cast<int32_t>(NetworkType::NETWORK_TYPE_UNKNOWN);
            int32_t signalLevel = 0;
            int32_t signalIntensity = 0;
            if (infoItem != nullptr) {
                signalType = WrapSignalInformationType(infoItem->GetNetworkType());
                signalLevel = infoItem->GetSignalLevel();
                signalIntensity = infoItem->GetSignalIntensity();
            }
            signal_information_push_data(signalInfoList, signalType, signalLevel, signalIntensity);
        }
    }
    return ConvertArktsError(errorCode);
}

ArktsError GetNetworkState(int32_t slotId, NetworkStateAni &networkState)
{
    int32_t errorCode = TELEPHONY_SUCCESS;
    if (!IsValidSlotIdEx(slotId)) {
        TELEPHONY_LOGE("slotId%{public}d is invalid", slotId);
        errorCode = ERROR_SLOT_ID_INVALID;
        return ConvertArktsErrorWithPermission(errorCode, "getNetworkState",
                                               Permission::GET_NETWORK_INFO);
    }

    sptr<NetworkState> state = nullptr;
    errorCode = DelayedRefSingleton<CoreServiceClient>::GetInstance().GetNetworkState(slotId, state);
    if (errorCode != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("Ani GetNetworkState errorCode = %{public}d", errorCode);
        return ConvertArktsErrorWithPermission(errorCode, "getNetworkState",
                                               Permission::GET_NETWORK_INFO);
    }

    if (state == nullptr) {
        TELEPHONY_LOGE("Ani GetNetworkState networkState is nullptr");
        errorCode = ERROR_NATIVE_API_EXECUTE_FAIL;
        return ConvertArktsErrorWithPermission(errorCode, "getNetworkState",
                                               Permission::GET_NETWORK_INFO);
    }

    networkState.long_operator_name = rust::String(state->GetLongOperatorName());
    networkState.short_operator_name = rust::String(state->GetShortOperatorName());
    networkState.plmn_numeric = rust::String(state->GetPlmnNumeric());
    networkState.is_roaming = state->IsRoaming(),
    networkState.reg_state = static_cast<int32_t>(state->GetRegStatus());
    networkState.cfg_tech = static_cast<int32_t>(state->GetCfgTech());
    networkState.is_emergency = state->IsEmergency();
    return ConvertArktsErrorWithPermission(errorCode, "getNetworkState",
                                           Permission::GET_NETWORK_INFO);
}

bool IsNrSupported()
{
    TelephonyConfig telephonyConfig;
    bool isNrSupported = telephonyConfig.IsCapabilitySupport(
        static_cast<int32_t>(TelephonyConfig::ConfigType::MODEM_CAP_SUPPORT_NR));
#ifdef OHOS_BUILD_ENABLE_TELEPHONY_EXT
    TELEPHONY_EXT_UTILS_WRAPPER.InitTelephonyExtUtilsWrapper();
    if (TELEPHONY_EXT_UTILS_WRAPPER.isChipsetNrSupported_ != nullptr) {
        isNrSupported = isNrSupported && TELEPHONY_EXT_UTILS_WRAPPER.isChipsetNrSupported_();
    }
#endif
    return isNrSupported;
}

ArktsError GetPrimarySlotId(int32_t &slotId)
{
    int32_t errorCode;
    int32_t id = 0;
    errorCode = DelayedRefSingleton<CoreServiceClient>::GetInstance().GetPrimarySlotId(id);
    if (errorCode == TELEPHONY_SUCCESS) {
        slotId = id;
    }
    return ConvertArktsError(errorCode);
}

int32_t AniImsRegInfoCallback::OnImsRegInfoChanged(int32_t slotId, ImsServiceType imsSrvType,
                                                   const ImsRegInfo &info)
{
    on_ims_reg_info_change(slotId, static_cast<int32_t>(imsSrvType),
        static_cast<int32_t>(info.imsRegState), static_cast<int32_t>(info.imsRegTech));
    return TELEPHONY_SUCCESS;
}

static bool IsValidImsSrvType(int32_t imsSrvType)
{
    bool flag = true;
    switch (imsSrvType) {
        case ImsServiceType::TYPE_VOICE:
        case ImsServiceType::TYPE_VIDEO:
        case ImsServiceType::TYPE_UT:
        case ImsServiceType::TYPE_SMS:
            break;
        default:
            TELEPHONY_LOGE("imsSrvType %{public}d is invalid", imsSrvType);
            flag = false;
            break;
    }

    return flag;
}

ArktsError EventListenerRegister(int32_t slotId, int32_t imsSrvType)
{
    int32_t errorCode;
    if (!IsValidSlotIdEx(slotId) || !IsValidImsSrvType(imsSrvType)) {
        TELEPHONY_LOGE("slotId%{public}d is invalid", slotId);
        errorCode = TELEPHONY_ERR_ARGUMENT_INVALID;
        return ConvertArktsErrorWithPermission(errorCode, "on_imsRegStateChange",
                                               Permission::GET_NETWORK_INFO);
    }

    sptr<ImsRegInfoCallback> imsCallback = new AniImsRegInfoCallback();
    errorCode = DelayedRefSingleton<CoreServiceClient>::GetInstance().RegisterImsRegInfoCallback(
        slotId, static_cast<ImsServiceType>(imsSrvType), imsCallback);

    return ConvertArktsErrorWithPermission(errorCode, "on_imsRegStateChange",
                                           Permission::GET_TELEPHONY_STATE);
}

ArktsError EventListenerUnRegister(int32_t slotId, int32_t imsSrvType)
{
    int32_t errorCode;
    if (!IsValidSlotIdEx(slotId) || !IsValidImsSrvType(imsSrvType)) {
        TELEPHONY_LOGE("slotId%{public}d is invalid", slotId);
        errorCode = TELEPHONY_ERR_ARGUMENT_INVALID;
        return ConvertArktsErrorWithPermission(errorCode, "off_imsRegStateChange",
                                               Permission::GET_NETWORK_INFO);
    }
    errorCode = DelayedRefSingleton<CoreServiceClient>::GetInstance()
        .UnregisterImsRegInfoCallback(slotId, static_cast<ImsServiceType>(imsSrvType));
    return ConvertArktsErrorWithPermission(errorCode, "off_imsRegStateChange",
                                           Permission::GET_TELEPHONY_STATE);
}

} // namespace RadioAni
} // namespace OHOS