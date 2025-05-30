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
#include <cstdint>
#include <iostream>
#include "ani_sim.h"
#include "cxx.h"
#include "telephony_errors.h"
#include "wrapper.rs.h"
#include "napi_util.h"
#include "core_service_client.h"
#include "sim_state_type.h"
#include "telephony_types.h"
#include "telephony_permission.h"

using namespace std;

namespace OHOS {
using namespace Telephony;
namespace SimAni {

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

ArktsError getLockState(int32_t slotId, int32_t lockType, int32_t &lockState)
{
    int32_t errorCode;
    LockState state = LockState::LOCK_ERROR;

    if (!IsValidSlotId(slotId)) {
        errorCode = ERROR_SLOT_ID_INVALID;
        return ConvertArktsErrorWithPermission(errorCode, "GetLockState",
                                               Permission::GET_TELEPHONY_STATE);
    }

    errorCode = DelayedRefSingleton<CoreServiceClient>::GetInstance().GetLockState(
        slotId, static_cast<LockType>(lockType), state);
    if (errorCode == ERROR_NONE) {
        lockState = static_cast<int32_t>(state);
    }

    return ConvertArktsErrorWithPermission(errorCode, "GetLockState",
                                           Permission::GET_TELEPHONY_STATE);
}

ArktsError unlockPuk(int32_t slotId, rust::String newPin,
                     rust::String puk, AniLockStatusResponse &lockStatusResponse)
{
    int32_t errorCode;
    std::string strNewPin = std::string(newPin);
    std::string strPuk = std::string(puk);
    LockStatusResponse response { UNLOCK_FAIL, ERROR_DEFAULT };

    if (!IsValidSlotId(slotId)) {
        errorCode = ERROR_SLOT_ID_INVALID;
        return ConvertArktsErrorWithPermission(errorCode, "UnlockPuk",
                                               Permission::SET_TELEPHONY_STATE);
    }

    errorCode = DelayedRefSingleton<CoreServiceClient>::GetInstance().UnlockPuk(slotId,
        NapiUtil::ToUtf16(strNewPin.data()), NapiUtil::ToUtf16(strPuk.data()), response);
    if (errorCode == ERROR_NONE) {
        lock_status_response_conversion(lockStatusResponse,
                                        response.result, response.remain);
    }

    return ConvertArktsErrorWithPermission(errorCode, "UnlockPuk",
                                           Permission::SET_TELEPHONY_STATE);
}

ArktsError unlockPin(int32_t slotId, rust::String pin,
                     AniLockStatusResponse &lockStatusResponse)
{
    int32_t errorCode;
    std::string strPin = std::string(pin);
    LockStatusResponse response { UNLOCK_FAIL, ERROR_DEFAULT };

    if (!IsValidSlotId(slotId)) {
        errorCode = ERROR_SLOT_ID_INVALID;
        return ConvertArktsErrorWithPermission(errorCode, "UnlockPin",
                                               Permission::SET_TELEPHONY_STATE);
    }

    errorCode = DelayedRefSingleton<CoreServiceClient>::GetInstance().UnlockPin(slotId,
        NapiUtil::ToUtf16(strPin.data()), response);
    if (errorCode == ERROR_NONE) {
        lock_status_response_conversion(lockStatusResponse,
                                        response.result, response.remain);
    }
    
    return ConvertArktsErrorWithPermission(errorCode, "UnlockPin",
                                           Permission::SET_TELEPHONY_STATE);
}

ArktsError hasSimCard(int32_t slotId, bool &hasCard)
{
    int32_t errorCode;

    if (!IsValidSlotIdEx(slotId)) {
        errorCode = ERROR_SLOT_ID_INVALID;
    } else {
        errorCode = DelayedRefSingleton<CoreServiceClient>::GetInstance().HasSimCard(slotId, hasCard);
    }
    
    return ConvertArktsError(errorCode);
}

ArktsError isSimActive(int32_t slotId, bool &isActive)
{
    int32_t errorCode = TELEPHONY_SUCCESS;

    if (!IsValidSlotId(slotId)) {
        errorCode = ERROR_SLOT_ID_INVALID;
    }

    isActive = DelayedRefSingleton<CoreServiceClient>::GetInstance().IsSimActive(slotId);
    return ConvertArktsError(errorCode);
}

ArktsError getDefaultVoiceSlotId(int32_t &slotId)
{
    slotId = DelayedRefSingleton<CoreServiceClient>::GetInstance().GetDefaultVoiceSlotId();
    return ConvertArktsError(TELEPHONY_SUCCESS);
}

ArktsError getOperatorConfigs(int32_t slotId, rust::Vec<AniOperatorConfig> &configValues)
{
    int32_t errorCode;

    if (!IsValidSlotId(slotId)) {
        errorCode = ERROR_SLOT_ID_INVALID;
        return ConvertArktsErrorWithPermission(errorCode, "GetOperatorConfigs",
                                               Permission::GET_TELEPHONY_STATE);
    }

    OperatorConfig config;
    errorCode = DelayedRefSingleton<CoreServiceClient>::GetInstance().GetOperatorConfigs(slotId, config);
    if (errorCode == ERROR_NONE) {
        for (const auto &val : config.configValue) {
            std::string key = NapiUtil::ToUtf8(val.first);
            std::string value = NapiUtil::ToUtf8(val.second);
            operator_config_push_kv(configValues, rust::String(key), rust::String(value));
        }
    }

    return ConvertArktsErrorWithPermission(errorCode, "GetOperatorConfigs",
                                           Permission::GET_TELEPHONY_STATE);
}

ArktsError getActiveSimAccountInfoList(rust::Vec<AniIccAccountInfo> &accountInfoValues)
{
    std::vector<IccAccountInfo> activeInfo;
    int32_t errorCode = DelayedRefSingleton<CoreServiceClient>::GetInstance()
                       .GetActiveSimAccountInfoList(activeInfo);
    if (errorCode == ERROR_NONE) {
        for (size_t i = 0; i < activeInfo.size(); i++) {
            icc_account_info_push_data(
                accountInfoValues,
                activeInfo[i].simId,
                activeInfo[i].slotIndex,
                activeInfo[i].isEsim,
                activeInfo[i].isActive,
                rust::String(NapiUtil::ToUtf8(activeInfo[i].iccId)),
                rust::String(NapiUtil::ToUtf8(activeInfo[i].showName)),
                rust::String(NapiUtil::ToUtf8(activeInfo[i].showNumber))
            );
        }
    }
    return ConvertArktsErrorWithPermission(errorCode, "GetActiveSimAccountInfoList",
                                           Permission::GET_TELEPHONY_STATE);
}

ArktsError getSimAccountInfo(int32_t slotId, AniIccAccountInfo &accountInfoValue)
{
    int32_t errorCode;
    IccAccountInfo operInfo;

    if (!IsValidSlotIdEx(slotId)) {
        errorCode = ERROR_SLOT_ID_INVALID;
        return ConvertArktsErrorWithPermission(errorCode, "GetSimAccountInfo",
                                               Permission::GET_TELEPHONY_STATE);
    }

    errorCode = DelayedRefSingleton<CoreServiceClient>::GetInstance().GetSimAccountInfo(slotId, operInfo);
    if (errorCode == ERROR_NONE) {
        icc_account_info_conversion(
            accountInfoValue,
            operInfo.simId,
            operInfo.slotIndex,
            operInfo.isEsim,
            operInfo.isActive,
            rust::String(NapiUtil::ToUtf8(operInfo.iccId)),
            rust::String(NapiUtil::ToUtf8(operInfo.showName)),
            rust::String(NapiUtil::ToUtf8(operInfo.showNumber))
        );
    }

    return ConvertArktsErrorWithPermission(errorCode, "GetSimAccountInfo",
                                           Permission::GET_TELEPHONY_STATE);
}

ArktsError getSimState(int32_t slotId, int32_t &simState)
{
    int32_t errorCode;
    if (!IsValidSlotId(slotId)) {
        errorCode = ERROR_SLOT_ID_INVALID;
        return ConvertArktsError(errorCode);
    }

    SimState state = SimState::SIM_STATE_UNKNOWN;

    errorCode = DelayedRefSingleton<CoreServiceClient>::GetInstance().GetSimState(slotId, state);
    if (errorCode == ERROR_NONE) {
        simState = static_cast<int32_t>(state);
    }
    return ConvertArktsError(errorCode);
}

ArktsError getISOCountryCodeForSim(int32_t slotId, rust::String &countryCode)
{
    int32_t errorCode;
    if (!IsValidSlotId(slotId)) {
        errorCode = ERROR_SLOT_ID_INVALID;
        return ConvertArktsError(errorCode);
    }

    std::u16string code;
    errorCode = DelayedRefSingleton<CoreServiceClient>::GetInstance().GetISOCountryCodeForSim(slotId, code);
    if (errorCode == ERROR_NONE) {
        countryCode = rust::String(NapiUtil::ToUtf8(code));
    }
    return ConvertArktsError(errorCode);
}

int32_t getMaxSimCount()
{
    return DelayedRefSingleton<CoreServiceClient>::GetInstance().GetMaxSimCount();
}

} // namespace SimAni
} // namespace OHOS