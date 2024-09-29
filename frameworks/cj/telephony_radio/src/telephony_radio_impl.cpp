/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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


#include "telephony_radio_impl.h"

#include "core_service_client.h"
#include "telephony_config.h"
#include "telephony_ext_utils_wrapper.h"
#include "telephony_log_wrapper.h"

namespace OHOS {
namespace Telephony {

    static int32_t ConvertCJErrCode(int32_t errCode)
    {
        TELEPHONY_LOGD("The original error code is displayed: %{public}d", errCode);
        switch (errCode) {
            case TELEPHONY_ERR_ARGUMENT_MISMATCH:
            case TELEPHONY_ERR_ARGUMENT_INVALID:
            case TELEPHONY_ERR_ARGUMENT_NULL:
            case TELEPHONY_ERR_SLOTID_INVALID:
            case ERROR_SLOT_ID_INVALID:
                // 83000001
                return CJ_ERROR_TELEPHONY_ARGUMENT_ERROR;
            case TELEPHONY_ERR_DESCRIPTOR_MISMATCH:
            case TELEPHONY_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL:
            case TELEPHONY_ERR_WRITE_DATA_FAIL:
            case TELEPHONY_ERR_WRITE_REPLY_FAIL:
            case TELEPHONY_ERR_READ_DATA_FAIL:
            case TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL:
            case TELEPHONY_ERR_REGISTER_CALLBACK_FAIL:
            case TELEPHONY_ERR_CALLBACK_ALREADY_REGISTERED:
            case TELEPHONY_ERR_UNINIT:
            case TELEPHONY_ERR_UNREGISTER_CALLBACK_FAIL:
                // 83000002
                return CJ_ERROR_TELEPHONY_SERVICE_ERROR;
            case TELEPHONY_ERR_VCARD_FILE_INVALID:
            case TELEPHONY_ERR_FAIL:
            case TELEPHONY_ERR_MEMCPY_FAIL:
            case TELEPHONY_ERR_MEMSET_FAIL:
            case TELEPHONY_ERR_STRCPY_FAIL:
            case TELEPHONY_ERR_LOCAL_PTR_NULL:
            case TELEPHONY_ERR_SUBSCRIBE_BROADCAST_FAIL:
            case TELEPHONY_ERR_PUBLISH_BROADCAST_FAIL:
            case TELEPHONY_ERR_ADD_DEATH_RECIPIENT_FAIL:
            case TELEPHONY_ERR_STRTOINT_FAIL:
            case TELEPHONY_ERR_RIL_CMD_FAIL:
            case TELEPHONY_ERR_DATABASE_WRITE_FAIL:
            case TELEPHONY_ERR_DATABASE_READ_FAIL:
            case TELEPHONY_ERR_UNKNOWN_NETWORK_TYPE:
            case ERROR_SERVICE_UNAVAILABLE:
            case ERROR_NATIVE_API_EXECUTE_FAIL:
                // 83000003
                return CJ_ERROR_TELEPHONY_SYSTEM_ERROR;
            case TELEPHONY_ERR_NO_SIM_CARD:
                // 83000004
                return CJ_ERROR_TELEPHONY_NO_SIM_CARD;
            case TELEPHONY_ERR_AIRPLANE_MODE_ON:
                // 83000005
                return CJ_ERROR_TELEPHONY_AIRPLANE_MODE_ON;
            case TELEPHONY_ERR_NETWORK_NOT_IN_SERVICE:
                // 83000006
                return CJ_ERROR_TELEPHONY_NETWORK_NOT_IN_SERVICE;
            case TELEPHONY_ERR_PERMISSION_ERR:
                // 201
                return CJ_ERROR_TELEPHONY_PERMISSION_DENIED;
            case TELEPHONY_ERR_ILLEGAL_USE_OF_SYSTEM_API:
                // 202
                return CJ_ERROR_TELEPHONY_PERMISSION_DENIED;
            default:
                return errCode;
        }
    }

    static inline bool IsValidSlotId(int32_t slotId)
    {
        return ((slotId >= DEFAULT_SIM_SLOT_ID) && (slotId < SIM_SLOT_COUNT));
    }

    static inline bool IsValidSlotIdEx(int32_t slotId)
    {
        // One more slot for VSim.
        return ((slotId >= DEFAULT_SIM_SLOT_ID) && (slotId < SIM_SLOT_COUNT + 1));
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

    static std::string ToUtf8(std::u16string str16)
    {
        std::wstring_convert<std::codecvt_utf8_utf16<char16_t>, char16_t> convert;
        // 将std::u16string转换为std::string
        std::string result = convert.to_bytes(str16);
        return result;
    }

    CNetworkRadioTech TelephonyRadioImpl::GetRadioTech(int32_t slotId, int32_t &errCode)
    {
        int32_t psRadioTech = static_cast<int32_t>(RadioTech::RADIO_TECHNOLOGY_INVALID);
        int32_t csRadioTech = static_cast<int32_t>(RadioTech::RADIO_TECHNOLOGY_INVALID);
        CNetworkRadioTech networkRadioTech = {
            .csRadioTech = csRadioTech,
            .psRadioTech = psRadioTech
        };
        if (!IsValidSlotId(slotId)) {
            TELEPHONY_LOGE("TelephonyRadioImpl::GetRadioTech slotId is invalid");
            errCode = ConvertCJErrCode(ERROR_SLOT_ID_INVALID);
            return networkRadioTech;
        }
        int32_t psResult =
            DelayedRefSingleton<CoreServiceClient>::GetInstance().GetPsRadioTech(slotId, psRadioTech);
        int32_t csResult =
            DelayedRefSingleton<CoreServiceClient>::GetInstance().GetCsRadioTech(slotId, csRadioTech);
        if (psResult == TELEPHONY_SUCCESS && csResult == TELEPHONY_SUCCESS) {
            networkRadioTech.csRadioTech = WrapRadioTech(csRadioTech);
            networkRadioTech.psRadioTech = WrapRadioTech(psRadioTech);
        }
        errCode = ConvertCJErrCode(csResult);
        return networkRadioTech;
    }

    CNetworkState TelephonyRadioImpl::GetNetworkState(int32_t slotId, int32_t &errCode)
    {
        CNetworkState cnetworkState = {
            .longOperatorName = nullptr,
            .shortOperatorName = nullptr,
            .plmnNumeric = nullptr,
            .isRoaming = false,
            .isCaActive = false,
            .nsaState = static_cast<int32_t>(NsaState::NSA_STATE_NOT_SUPPORT)
        };
        if (!IsValidSlotIdEx(slotId)) {
            TELEPHONY_LOGE("NativeGetNetworkState slotId is invalid");
            errCode = ConvertCJErrCode(ERROR_SLOT_ID_INVALID);
            return cnetworkState;
        }
        sptr<NetworkState> networkState = nullptr;
        int32_t result = DelayedRefSingleton<CoreServiceClient>::GetInstance().GetNetworkState(slotId, networkState);
        errCode = ConvertCJErrCode(result);
        if (errCode != TELEPHONY_SUCCESS) {
            TELEPHONY_LOGE("NativeGetNetworkState errorCode = %{public}d", result);
            return cnetworkState;
        }
        if (networkState == nullptr) {
            TELEPHONY_LOGE("NativeGetNetworkState networkState is nullptr");
            errCode = ConvertCJErrCode(ERROR_NATIVE_API_EXECUTE_FAIL);
            return cnetworkState;
        }
        cnetworkState.longOperatorName = MallocCString(networkState->GetLongOperatorName());
        cnetworkState.shortOperatorName = MallocCString(networkState->GetShortOperatorName());
        cnetworkState.plmnNumeric = MallocCString(networkState->GetPlmnNumeric());
        cnetworkState.isRoaming = networkState->IsRoaming();
        cnetworkState.isEmergency = networkState->IsEmergency();
        cnetworkState.regState = WrapRegState(static_cast<int32_t>(networkState->GetRegStatus()));
        cnetworkState.cfgTech = WrapRadioTech(static_cast<int32_t>(networkState->GetCfgTech()));
        return cnetworkState;
    }

    int32_t TelephonyRadioImpl::GetNetworkSelectionMode(int32_t slotId, int32_t &errCode)
    {
        int32_t selectMode = DEFAULT_ERROR;
        if (!IsValidSlotId(slotId)) {
            TELEPHONY_LOGE("NativeGetNetworkSelectionMode slotId is invalid");
            errCode = ConvertCJErrCode(ERROR_SLOT_ID_INVALID);
            return selectMode;
        }
        auto selectModeContext = std::make_unique<GetSelectModeContext>();
        auto asyncContext = static_cast<GetSelectModeContext *>(selectModeContext.get());
        asyncContext->slotId = slotId;
        std::unique_ptr<GetNetworkSearchModeCallback> callback =
            std::make_unique<GetNetworkSearchModeCallback>(asyncContext);
        std::unique_lock<std::mutex> callbackLock(asyncContext->callbackMutex);
        asyncContext->errorCode = DelayedRefSingleton<CoreServiceClient>::GetInstance().GetNetworkSelectionMode(
            asyncContext->slotId, callback.release());
        if (asyncContext->errorCode == TELEPHONY_SUCCESS) {
            asyncContext->cv.wait_for(
                callbackLock,
                std::chrono::seconds(WAIT_TIME_SECOND),
                [asyncContext] { return asyncContext->callbackEnd; });
            TELEPHONY_LOGI("NativeGetNetworkSelectionMode after callback end");
        }
        errCode = ConvertCJErrCode(asyncContext->errorCode);
        selectMode = asyncContext->selectMode;
        return selectMode;
    }

    char* TelephonyRadioImpl::GetISOCountryCodeForNetwork(int32_t slotId, int32_t &errCode)
    {
         if (!IsValidSlotId(slotId)) {
            TELEPHONY_LOGE("NativeGetCountryCode slotId is invalid");
            errCode = ConvertCJErrCode(ERROR_SLOT_ID_INVALID);
            return nullptr;
        }
        std::u16string countryCode;
        errCode =
            DelayedRefSingleton<CoreServiceClient>::GetInstance().GetIsoCountryCodeForNetwork(slotId, countryCode);
        std::string code = ToUtf8(countryCode);
        char* result = MallocCString(code);
        errCode = ConvertCJErrCode(errCode);
        return result;
    }

    int32_t TelephonyRadioImpl::GetPrimarySlotId(int32_t &errCode)
    {
        int32_t slotId = DEFAULT_SIM_SLOT_ID;
        errCode =
            DelayedRefSingleton<CoreServiceClient>::GetInstance().GetPrimarySlotId(slotId);
        errCode = ConvertCJErrCode(errCode);
        return slotId;
    }

    CArraySignalInformation TelephonyRadioImpl::GetSignalInfoList(int32_t slotId, int32_t &errCode)
    {
        std::vector<sptr<SignalInformation>> signalInfoList;
        CArraySignalInformation csignalInfoList = {
            .head  = nullptr,
            .size = 0
        };
        if (!IsValidSlotIdEx(slotId)) {
            TELEPHONY_LOGE("NativeGetSignalInfoList slotId is invalid");
            errCode = ConvertCJErrCode(ERROR_SLOT_ID_INVALID);
            return csignalInfoList;
        }
        errCode =
            DelayedRefSingleton<CoreServiceClient>::GetInstance().GetSignalInfoList(slotId, signalInfoList);
        errCode = ConvertCJErrCode(errCode);
        size_t infoSize = signalInfoList.size();
        TELEPHONY_LOGD("NativeGetSignalInfoList size = %{public}zu", signalInfoList.size());
        CSignalInformation* head =
            reinterpret_cast<CSignalInformation *>(malloc(sizeof(CSignalInformation) * infoSize));
        if (head == nullptr && infoSize > 0) {
            TELEPHONY_LOGE("NativeGetSignalInfoList malloc failed!");
            return csignalInfoList;
        }
        int i = 0;
        for (sptr<SignalInformation> infoItem : signalInfoList) {
            int32_t signalType = static_cast<int32_t>(NetworkType::NETWORK_TYPE_UNKNOWN);
            int32_t signalLevel = 0;
            int32_t signalIntensity = 0;
            if (infoItem != nullptr) {
                signalType = WrapSignalInformationType(infoItem->GetNetworkType());
                signalLevel = infoItem->GetSignalLevel();
                signalIntensity = infoItem->GetSignalIntensity();
            }
            head[i].signalType = signalType;
            head[i].signalLevel = signalLevel;
            head[i].dBm = signalIntensity;
            i++;
        }
        csignalInfoList.size = static_cast<int64_t>(infoSize);
        csignalInfoList.head = head;
        return csignalInfoList;
    }

    bool TelephonyRadioImpl::IsNRSupported()
    {
        bool isNrSupported = false;
        TelephonyConfig telephonyConfig;
        isNrSupported =
            telephonyConfig.IsCapabilitySupport(
                static_cast<int32_t>(TelephonyConfig::ConfigType::MODEM_CAP_SUPPORT_NR));
#ifdef OHOS_BUILD_ENABLE_TELEPHONY_EXT
    TELEPHONY_EXT_UTILS_WRAPPER.InitTelephonyExtUtilsWrapper();
    if (TELEPHONY_EXT_UTILS_WRAPPER.isNrSupported_ != nullptr) {
        TELEPHONY_EXT_UTILS_WRAPPER.isNrSupported_(isNrSupported);
    }
#endif
        return isNrSupported;
    }

    bool TelephonyRadioImpl::IsRadioOn(int32_t slotId, int32_t &errCode)
    {
        bool result = false;
        if (!IsValidSlotId(slotId)) {
            TELEPHONY_LOGE("NativeIsRadioOn slotId is invalid");
            errCode = ConvertCJErrCode(ERROR_SLOT_ID_INVALID);
            return result;
        }
        auto radioOnContext = std::make_unique<IsRadioOnContext>();
        auto asyncContext = static_cast<IsRadioOnContext *>(radioOnContext.get());
        asyncContext->slotId = slotId;
        std::unique_ptr<GetRadioStateCallback> callback = std::make_unique<GetRadioStateCallback>(asyncContext);
        std::unique_lock<std::mutex> callbackLock(asyncContext->callbackMutex);
        asyncContext->errorCode =
            DelayedRefSingleton<CoreServiceClient>::GetInstance().GetRadioState(slotId, callback.release());
        if (asyncContext->errorCode == TELEPHONY_SUCCESS) {
            asyncContext->cv.wait_for(
                callbackLock,
                std::chrono::seconds(WAIT_TIME_SECOND),
                [asyncContext] { return asyncContext->callbackEnd; });
            TELEPHONY_LOGI("NativeIsRadioOn after callback end");
        }
        errCode = ConvertCJErrCode(asyncContext->errorCode);
        result = asyncContext->isRadioOn;
        return result;
    }

    char* TelephonyRadioImpl::GetOperatorName(int32_t slotId, int32_t &errCode)
    {
        if (!IsValidSlotId(slotId)) {
            TELEPHONY_LOGE("NativeGetOperatorName slotId is invalid");
            errCode = ConvertCJErrCode(ERROR_SLOT_ID_INVALID);
            return nullptr;
        }
        std::u16string u16OperatorName = u"";
        errCode =
            DelayedRefSingleton<CoreServiceClient>::GetInstance().GetOperatorName(slotId, u16OperatorName);
        errCode = ConvertCJErrCode(errCode);
        std::string operatorName = ToUtf8(u16OperatorName);
        if (operatorName.size() > BUF_SIZE) {
            operatorName = operatorName.substr(0, BUF_SIZE);
        }
        char* result = MallocCString(operatorName);
        return result;
    }
}
}