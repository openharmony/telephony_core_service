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


#include "telephony_sim_impl.h"

#include "core_service_client.h"
#include "telephony_log_wrapper.h"

namespace OHOS {
namespace Telephony {

    inline char* MallocCString(const std::string& origin)
    {
        if (origin.empty()) {
            return nullptr;
        }
        auto lenth = origin.length() + 1;
        char* res = static_cast<char*>(malloc(sizeof(char) * lenth));
        if (res == nullptr) {
            return nullptr;
        }
        return std::char_traits<char>::copy(res, origin.c_str(), lenth);
    }

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

    static std::string ToUtf8(std::u16string str16)
    {
        std::wstring_convert<std::codecvt_utf8_utf16<char16_t>, char16_t> convert;
        // 将std::u16string转换为std::string
        std::string result = convert.to_bytes(str16);
        return result;
    }

    bool TelephonySimImpl::IsSimActive(int32_t slotId, int32_t &errCode)
    {
        bool result = false;
        if (!IsValidSlotId(slotId)) {
            TELEPHONY_LOGE("NativeIsSimActive slotId is invalid");
            errCode = ConvertCJErrCode(ERROR_SLOT_ID_INVALID);
            return result;
        }
        result = DelayedRefSingleton<CoreServiceClient>::GetInstance().IsSimActive(slotId);
        return result;
    }

    int32_t TelephonySimImpl::getDefaultVoiceSlotId()
    {
        int32_t slotId = -1;
        slotId = DelayedRefSingleton<CoreServiceClient>::GetInstance().GetDefaultVoiceSlotId();
        return slotId;
    }

    bool TelephonySimImpl::hasOperatorPrivileges(int32_t slotId, int32_t &errCode)
    {
        bool hasOperatorPrivileges = false;
        if (!IsValidSlotId(slotId)) {
            TELEPHONY_LOGE("NativeHasOperatorPrivileges slotId is invalid");
            errCode = ConvertCJErrCode(ERROR_SLOT_ID_INVALID);
            return hasOperatorPrivileges;
        }
        errCode = DelayedRefSingleton<CoreServiceClient>::GetInstance().HasOperatorPrivileges(
            slotId, hasOperatorPrivileges);
        errCode = ConvertCJErrCode(errCode);
        return hasOperatorPrivileges;
    }

    char* TelephonySimImpl::getISOCountryCodeForSim(int32_t slotId, int32_t &errCode)
    {
        if (!IsValidSlotId(slotId)) {
            TELEPHONY_LOGE("NativeGetIsoForSim slotId is invalid");
            errCode = ConvertCJErrCode(ERROR_SLOT_ID_INVALID);
            return nullptr;
        }
        std::u16string countryCode = u"";
        std::string operatorName;
        errCode = DelayedRefSingleton<CoreServiceClient>::GetInstance().GetISOCountryCodeForSim(
            slotId, countryCode);
        operatorName = errCode == ERROR_NONE ? ToUtf8(countryCode) : "";
        errCode = ConvertCJErrCode(errCode);
        char* result = MallocCString(operatorName);
        return result;
    }
    
    char* TelephonySimImpl::getSimOperatorNumeric(int32_t slotId, int32_t &errCode)
    {
        if (!IsValidSlotId(slotId)) {
            TELEPHONY_LOGE("NativeGetSimOperatorNumeric slotId is invalid");
            errCode = ConvertCJErrCode(ERROR_SLOT_ID_INVALID);
            return nullptr;
        }
        std::u16string operatorNumeric = u"";
        std::string operatorName;
        errCode = DelayedRefSingleton<CoreServiceClient>::GetInstance().GetSimOperatorNumeric(
            slotId, operatorNumeric);
        operatorName = errCode == ERROR_NONE ? ToUtf8(operatorNumeric) : "";
        errCode = ConvertCJErrCode(errCode);
        char* result = MallocCString(operatorName);
        return result;
    }

    char* TelephonySimImpl::getSimSpn(int32_t slotId, int32_t &errCode)
    {
        if (!IsValidSlotId(slotId)) {
            TELEPHONY_LOGE("NativeGetSimSpn slotId is invalid");
            errCode = ConvertCJErrCode(ERROR_SLOT_ID_INVALID);
            return nullptr;
        }
        std::u16string spn = u"";
        std::string operatorName;
        errCode = DelayedRefSingleton<CoreServiceClient>::GetInstance().GetSimSpn(slotId, spn);
        operatorName = errCode == ERROR_NONE ? ToUtf8(spn) : "";
        errCode = ConvertCJErrCode(errCode);
        char* result = MallocCString(operatorName);
        return result;
    }

    int32_t TelephonySimImpl::getSimState(int32_t slotId, int32_t &errCode)
    {
        SimState simState = SimState::SIM_STATE_UNKNOWN;
        if (!IsValidSlotId(slotId)) {
            TELEPHONY_LOGE("slotId is invalid");
            errCode = ConvertCJErrCode(ERROR_SLOT_ID_INVALID);
            return static_cast<int32_t>(simState);
        }
        errCode =
            DelayedRefSingleton<CoreServiceClient>::GetInstance().GetSimState(slotId, simState);
        errCode = ConvertCJErrCode(errCode);
        return static_cast<int32_t>(simState);
    }

    int32_t TelephonySimImpl::getCardType(int32_t slotId, int32_t &errCode)
    {
        CardType cardType = CardType::UNKNOWN_CARD;
        if (!IsValidSlotId(slotId)) {
            TELEPHONY_LOGE("NativeGetCardType slotId is invalid");
            errCode = ConvertCJErrCode(ERROR_SLOT_ID_INVALID);
            return static_cast<int32_t>(cardType);
        }
        errCode =
            DelayedRefSingleton<CoreServiceClient>::GetInstance().GetCardType(slotId, cardType);
        errCode = ConvertCJErrCode(errCode);
        return static_cast<int32_t>(cardType);
    }

    bool TelephonySimImpl::hasSimCard(int32_t slotId, int32_t &errCode)
    {
        bool hasSimCard = false;
        if (!IsValidSlotIdEx(slotId)) {
            TELEPHONY_LOGE("slotId is invalid");
            errCode = ConvertCJErrCode(ERROR_SLOT_ID_INVALID);
            return hasSimCard;
        }
        errCode = DelayedRefSingleton<CoreServiceClient>::GetInstance().HasSimCard(slotId, hasSimCard);
        errCode = ConvertCJErrCode(errCode);
        return hasSimCard;
    }

    static void IccAccountInfoConversion(CIccAccountInfo &accountInfo, const IccAccountInfo &iccAccountInfo)
    {
        accountInfo.simId = iccAccountInfo.simId;
        accountInfo.slotIndex = iccAccountInfo.slotIndex;
        accountInfo.isEsim = iccAccountInfo.isEsim;
        accountInfo.isActive = iccAccountInfo.isActive;
        accountInfo.iccId = MallocCString(ToUtf8(iccAccountInfo.iccId));
        accountInfo.showName = MallocCString(ToUtf8(iccAccountInfo.showName));
        accountInfo.showNumber = MallocCString(ToUtf8(iccAccountInfo.showNumber));
    }

    CIccAccountInfo TelephonySimImpl::getSimAccountInfo(int32_t slotId, int32_t &errCode)
    {
        CIccAccountInfo accountInfo = {
            .simId = 0,
            .slotIndex = 0,
            .isEsim = false,
            .isActive = false,
            .iccId = nullptr,
            .showName = nullptr,
            .showNumber = nullptr
        };
        if (!IsValidSlotIdEx(slotId)) {
            TELEPHONY_LOGE("NativeGetSimAccountInfo slotId is invalid");
            errCode = ConvertCJErrCode(ERROR_SLOT_ID_INVALID);
            return accountInfo;
        }
        IccAccountInfo operInfo;
        errCode =
            DelayedRefSingleton<CoreServiceClient>::GetInstance().GetSimAccountInfo(slotId, operInfo);
        if (errCode == ERROR_NONE) {
            IccAccountInfoConversion(accountInfo, operInfo);
        }
        errCode = ConvertCJErrCode(errCode);
        return accountInfo;
    }

    CArryIccAccountInfo TelephonySimImpl::getActiveSimAccountInfoList(int32_t &errCode)
    {
        std::vector<IccAccountInfo> activeInfo;
        CArryIccAccountInfo accountInfoList = {
            .head = nullptr,
            .size = 0
        };
        errCode = DelayedRefSingleton<CoreServiceClient>::GetInstance().GetActiveSimAccountInfoList(activeInfo);
        if (errCode == ERROR_NONE) {
            size_t infoSize = activeInfo.size();
            CIccAccountInfo* head = reinterpret_cast<CIccAccountInfo *>(malloc(sizeof(CIccAccountInfo) * infoSize));
            if (head == nullptr && infoSize > 0) {
                TELEPHONY_LOGE("NativeGetSimAccountInfo malloc failed!");
                return accountInfoList;
            }
            for (size_t i = 0; i < infoSize; i++) {
                IccAccountInfoConversion(head[i], activeInfo.at(i));
            }
            accountInfoList.head = head;
            accountInfoList.size = static_cast<int64_t>(infoSize);
        }
        errCode = ConvertCJErrCode(errCode);
        return accountInfoList;
    }

    int32_t TelephonySimImpl::getMaxSimCount()
    {
        return DelayedRefSingleton<CoreServiceClient>::GetInstance().GetMaxSimCount();
    }

    char* TelephonySimImpl::getOpKey(int32_t slotId, int32_t &errCode)
    {
        if (!IsValidSlotId(slotId)) {
            TELEPHONY_LOGE("NativeGetOpKey slotId is invalid");
            errCode = ConvertCJErrCode(ERROR_SLOT_ID_INVALID);
            return nullptr;
        }
        std::u16string opkey = u"";
        errCode = DelayedRefSingleton<CoreServiceClient>::GetInstance().GetOpKey(slotId, opkey);
        std::string value = errCode == ERROR_NONE ? ToUtf8(opkey) : "";
        errCode = ConvertCJErrCode(errCode);
        char* result = MallocCString(value);
        return result;
    }

    char* TelephonySimImpl::getOpName(int32_t slotId, int32_t &errCode)
    {
        if (!IsValidSlotId(slotId)) {
            TELEPHONY_LOGE("NativeGetOpName slotId is invalid");
            errCode = ConvertCJErrCode(ERROR_SLOT_ID_INVALID);
            return nullptr;
        }
        std::u16string opname = u"";
        errCode = DelayedRefSingleton<CoreServiceClient>::GetInstance().GetOpName(slotId, opname);
        std::string value = errCode == ERROR_NONE ? ToUtf8(opname) : "";
        errCode = ConvertCJErrCode(errCode);
        char* result = MallocCString(value);
        return result;
    }

    int32_t TelephonySimImpl::getDefaultVoiceSimId(int32_t &errCode)
    {
        int32_t simId = 0;
        errCode = DelayedRefSingleton<CoreServiceClient>::GetInstance().GetDefaultVoiceSimId(simId);
        errCode = ConvertCJErrCode(errCode);
        return simId;
    }

}
}