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

#include "ani_sim.h"
#include <cstdint>
#include <iostream>
#include <string>
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
namespace Telephony {
namespace SimAni {
constexpr const char *CHINA_TELE_COM_CARD = "china_telecom_card";

static inline bool IsValidSlotId(int32_t slotId)
{
    return ((slotId >= DEFAULT_SIM_SLOT_ID) && (slotId < SIM_SLOT_COUNT));
}

static inline bool IsValidSlotIdEx(int32_t slotId)
{
    // One more slot for VSim.
    return ((slotId >= DEFAULT_SIM_SLOT_ID) && (slotId < SIM_SLOT_COUNT + 1));
}

static inline bool IsValidSlotIdForDefault(int32_t slotId)
{
    return ((slotId >= DEFAULT_SIM_SLOT_ID_REMOVE) && (slotId < SIM_SLOT_COUNT));
}

static inline ArktsError ConvertArktsErrorWithPermission(int32_t errorCode, const std::string &funcName,
                                                         const std::string &permission)
{
    JsError error = NapiUtil::ConverErrorMessageWithPermissionForJs(
        errorCode, funcName, permission);

    ArktsError arktsErr = {
        .errorCode = error.errorCode,
        .errorMessage = rust::string(error.errorMessage),
    };
    return arktsErr;
}

static inline ArktsError ConvertArktsError(int32_t errorCode)
{
    JsError error = NapiUtil::ConverErrorMessageForJs(errorCode);

    ArktsError arktsErr = {
        .errorCode = error.errorCode,
        .errorMessage = rust::string(error.errorMessage),
    };
    return arktsErr;
}

ArktsError GetLockState(int32_t slotId, int32_t lockType, int32_t &lockState)
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

ArktsError UnlockPuk(int32_t slotId, rust::String newPin,
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

ArktsError UnlockPin(int32_t slotId, rust::String pin,
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

ArktsError HasSimCard(int32_t slotId, bool &hasCard)
{
    int32_t errorCode;

    if (!IsValidSlotIdEx(slotId)) {
        errorCode = ERROR_SLOT_ID_INVALID;
    } else {
        errorCode = DelayedRefSingleton<CoreServiceClient>::GetInstance().HasSimCard(slotId, hasCard);
    }

    return ConvertArktsError(errorCode);
}

ArktsError IsSimActive(int32_t slotId, bool &isActive)
{
    int32_t errorCode = TELEPHONY_SUCCESS;

    if (!IsValidSlotId(slotId)) {
        errorCode = ERROR_SLOT_ID_INVALID;
    }

    isActive = DelayedRefSingleton<CoreServiceClient>::GetInstance().IsSimActive(slotId);
    return ConvertArktsError(errorCode);
}

ArktsError GetDefaultVoiceSlotId(int32_t &slotId)
{
    slotId = DelayedRefSingleton<CoreServiceClient>::GetInstance().GetDefaultVoiceSlotId();
    return ConvertArktsError(TELEPHONY_SUCCESS);
}

ArktsError GetOperatorConfigs(int32_t slotId, rust::Vec<AniOperatorConfig> &configValues)
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

ArktsError GetActiveSimAccountInfoList(rust::Vec<AniIccAccountInfo> &accountInfoValues)
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

ArktsError GetSimAccountInfo(int32_t slotId, AniIccAccountInfo &accountInfoValue)
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

ArktsError GetSimState(int32_t slotId, int32_t &simState)
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

ArktsError GetISOCountryCodeForSim(int32_t slotId, rust::String &countryCode)
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

int32_t GetMaxSimCount()
{
    return DelayedRefSingleton<CoreServiceClient>::GetInstance().GetMaxSimCount();
}

ArktsError GetSimAuthentication(int32_t slotId, int32_t authType, rust::String authData,
    AniSimAuthenticationResponse &simAuthenticationResponse)
{
    int32_t errorCode;
    if (!IsValidSlotId(slotId)) {
        errorCode = ERROR_SLOT_ID_INVALID;
        return ConvertArktsErrorWithPermission(errorCode, "GetSimAuthentication", Permission::GET_TELEPHONY_STATE);
    }

    SimAuthenticationResponse response;
    errorCode = DelayedRefSingleton<CoreServiceClient>::GetInstance().SimAuthentication(slotId,
        static_cast<AuthType>(authType), std::string(authData), response);
    if (errorCode == ERROR_NONE) {
        sim_authentication_response_conversion(simAuthenticationResponse, response.sw1, response.sw2,
            response.response);
    }
    return ConvertArktsErrorWithPermission(errorCode, "GetSimAuthentication", Permission::GET_TELEPHONY_STATE);
}

ArktsError GetDsdsMode(int32_t &dsdsMode)
{
    dsdsMode = DSDS_MODE_V2;
    int32_t errorCode = DelayedRefSingleton<CoreServiceClient>::GetInstance().GetDsdsMode(dsdsMode);
    return ConvertArktsErrorWithPermission(errorCode, "GetDsdsMode", Permission::GET_TELEPHONY_STATE);
}


ArktsError GetDefaultVoiceSimId(int32_t &simId)
{
    int32_t errorCode = DelayedRefSingleton<CoreServiceClient>::GetInstance().GetDefaultVoiceSimId(simId);
    return ConvertArktsError(errorCode);
}

ArktsError GetOpName(int32_t slotId, rust::String &opName)
{
    int32_t errorCode = TELEPHONY_ERR_SUCCESS;
    if (!IsValidSlotId(slotId)) {
        errorCode = ERROR_SLOT_ID_INVALID;
        return ConvertArktsError(errorCode);
    }

    std::u16string name;
    errorCode = DelayedRefSingleton<CoreServiceClient>::GetInstance().GetOpName(slotId, name);
    if (errorCode == ERROR_NONE) {
        opName = rust::String(NapiUtil::ToUtf8(name));
    }
    return ConvertArktsError(errorCode);
}

ArktsError GetOpKey(int32_t slotId, rust::String &opKey)
{
    int32_t errorCode = TELEPHONY_ERR_SUCCESS;
    if (!IsValidSlotId(slotId)) {
        errorCode = ERROR_SLOT_ID_INVALID;
        return ConvertArktsError(errorCode);
    }

    std::u16string key;
    errorCode = DelayedRefSingleton<CoreServiceClient>::GetInstance().GetOpKey(slotId, key);
    if (errorCode == ERROR_NONE) {
        opKey = rust::String(NapiUtil::ToUtf8(key));
    }
    return ConvertArktsError(errorCode);
}

ArktsError UnlockSimLock(int32_t slotId, int32_t persoLocktype, rust::String password,
    AniLockStatusResponse &lockStatusResponse)
{
    int32_t errorCode = TELEPHONY_ERR_SUCCESS;
    if (!IsValidSlotId(slotId)) {
        errorCode = ERROR_SLOT_ID_INVALID;
        return ConvertArktsErrorWithPermission(errorCode, "UnlockSimLock", Permission::SET_TELEPHONY_STATE);
    }

    PersoLockInfo info{ static_cast<PersoLockType>(persoLocktype),
        NapiUtil::ToUtf16(std::string(password)) };
    LockStatusResponse response{ UNLOCK_FAIL, ERROR_DEFAULT };
    errorCode = DelayedRefSingleton<CoreServiceClient>::GetInstance().UnlockSimLock(slotId, info, response);
    if (errorCode == ERROR_NONE) {
        lock_status_response_conversion(lockStatusResponse, response.result, response.remain);
    }

    return ConvertArktsErrorWithPermission(errorCode, "UnlockSimLock", Permission::SET_TELEPHONY_STATE);
}

ArktsError SendTerminalResponseCmd(int32_t slotId, rust::String cmd)
{
    int32_t errorCode = TELEPHONY_ERR_SUCCESS;
    if (!IsValidSlotId(slotId)) {
        errorCode = ERROR_SLOT_ID_INVALID;
        return ConvertArktsErrorWithPermission(errorCode, "SendTerminalResponseCmd", Permission::SET_TELEPHONY_STATE);
    }

    errorCode = DelayedRefSingleton<CoreServiceClient>::GetInstance().SendTerminalResponseCmd(slotId, std::string(cmd));
    return ConvertArktsErrorWithPermission(errorCode, "SendTerminalResponseCmd", Permission::SET_TELEPHONY_STATE);
}

ArktsError SendEnvelopeCmd(int32_t slotId, rust::String cmd)
{
    int32_t errorCode = TELEPHONY_ERR_SUCCESS;
    if (!IsValidSlotId(slotId)) {
        errorCode = ERROR_SLOT_ID_INVALID;
        return ConvertArktsErrorWithPermission(errorCode, "SendEnvelopeCmd", Permission::SET_TELEPHONY_STATE);
    }

    errorCode = DelayedRefSingleton<CoreServiceClient>::GetInstance().SendEnvelopeCmd(slotId, std::string(cmd));
    return ConvertArktsErrorWithPermission(errorCode, "SendEnvelopeCmd", Permission::SET_TELEPHONY_STATE);
}

static void GetDiallingNumberInfo(const std::shared_ptr<DiallingNumbersInfo> &telNumber,
    const ArktsDiallingNumbersInfo &info)
{
    if (!telNumber) {
        return;
    }

    telNumber->index_ = info.recordNumber;
    telNumber->name_ = NapiUtil::ToUtf16(std::string(info.alphaTag));
    telNumber->number_ = NapiUtil::ToUtf16(std::string(info.teleNumber));
    telNumber->pin2_ = NapiUtil::ToUtf16(std::string(info.pin2));
}

ArktsError UpdateIccDiallingNumbers(int32_t slotId, int32_t contactType,
    const ArktsDiallingNumbersInfo &diallingNumbers)
{
    int32_t errorCode = TELEPHONY_ERR_SUCCESS;
    if (!IsValidSlotId(slotId)) {
        errorCode = ERROR_SLOT_ID_INVALID;
        return ConvertArktsErrorWithPermission(errorCode, "UpdateIccDiallingNumbers", Permission::WRITE_CONTACTS);
    }

    std::shared_ptr<DiallingNumbersInfo> telNumber = std::make_shared<DiallingNumbersInfo>();
    GetDiallingNumberInfo(telNumber, diallingNumbers);
    errorCode = DelayedRefSingleton<CoreServiceClient>::GetInstance().UpdateIccDiallingNumbers(
        slotId, contactType, telNumber);

    return ConvertArktsErrorWithPermission(errorCode, "UpdateIccDiallingNumbers", Permission::WRITE_CONTACTS);
}

ArktsError DelIccDiallingNumbers(int32_t slotId, int32_t contactType, const ArktsDiallingNumbersInfo &diallingNumbers)
{
    int32_t errorCode = TELEPHONY_ERR_SUCCESS;
    if (!IsValidSlotId(slotId)) {
        errorCode = ERROR_SLOT_ID_INVALID;
        return ConvertArktsErrorWithPermission(errorCode, "DelIccDiallingNumbers", Permission::WRITE_CONTACTS);
    }

    std::shared_ptr<DiallingNumbersInfo> telNumber = std::make_shared<DiallingNumbersInfo>();
    GetDiallingNumberInfo(telNumber, diallingNumbers);
    errorCode = DelayedRefSingleton<CoreServiceClient>::GetInstance().DelIccDiallingNumbers(
        slotId, contactType, telNumber);

    return ConvertArktsErrorWithPermission(errorCode, "DelIccDiallingNumbers", Permission::WRITE_CONTACTS);
}

ArktsError AddIccDiallingNumbers(int32_t slotId, int32_t contactType, const ArktsDiallingNumbersInfo &diallingNumbers)
{
    int32_t errorCode = TELEPHONY_ERR_SUCCESS;
    if (!IsValidSlotId(slotId)) {
        errorCode = ERROR_SLOT_ID_INVALID;
        return ConvertArktsErrorWithPermission(errorCode, "AddIccDiallingNumbers", Permission::WRITE_CONTACTS);
    }

    std::shared_ptr<DiallingNumbersInfo> telNumber = std::make_shared<DiallingNumbersInfo>();
    GetDiallingNumberInfo(telNumber, diallingNumbers);
    errorCode = DelayedRefSingleton<CoreServiceClient>::GetInstance().AddIccDiallingNumbers(
        slotId, contactType, telNumber);

    return ConvertArktsErrorWithPermission(errorCode, "AddIccDiallingNumbers", Permission::WRITE_CONTACTS);
}

ArktsError QueryIccDiallingNumbers(int32_t slotId, int32_t contactType,
    rust::Vec<ArktsDiallingNumbersInfo> &diallingNumbers)
{
    int32_t errorCode = TELEPHONY_ERR_SUCCESS;
    if (!IsValidSlotId(slotId)) {
        errorCode = ERROR_SLOT_ID_INVALID;
        return ConvertArktsErrorWithPermission(errorCode, "QueryIccDiallingNumbers", Permission::READ_CONTACTS);
    }

    std::vector<std::shared_ptr<DiallingNumbersInfo>> diallingNumbersResult;
    errorCode = DelayedRefSingleton<CoreServiceClient>::GetInstance().QueryIccDiallingNumbers(
        slotId, contactType, diallingNumbersResult);
    if (!diallingNumbersResult.empty()) {
        for (const auto &dialNumber : diallingNumbersResult) {
            ArktsDiallingNumbersInfo info = {};
            info.recordNumber = dialNumber->index_;
            info.alphaTag = NapiUtil::ToUtf8(dialNumber->name_);
            info.teleNumber = NapiUtil::ToUtf8(dialNumber->number_);
            info.pin2 = NapiUtil::ToUtf8(dialNumber->pin2_);
            diallingNumbers.push_back(std::move(info));
        }
    }

    return ConvertArktsErrorWithPermission(errorCode, "QueryIccDiallingNumbers", Permission::READ_CONTACTS);
}

ArktsError AlterPin2(int32_t slotId, const rust::String newPin2, const rust::String oldPin2,
    AniLockStatusResponse &lockStatusResponse)
{
    int32_t errorCode = TELEPHONY_ERR_SUCCESS;
    if (!IsValidSlotId(slotId)) {
        errorCode = ERROR_SLOT_ID_INVALID;
        return ConvertArktsErrorWithPermission(errorCode, "AlterPin2", Permission::SET_TELEPHONY_STATE);
    }

    LockStatusResponse response{ UNLOCK_FAIL, ERROR_DEFAULT };
    errorCode = DelayedRefSingleton<CoreServiceClient>::GetInstance().AlterPin2(slotId,
        NapiUtil::ToUtf16(std::string(newPin2)), NapiUtil::ToUtf16(std::string(oldPin2)), response);
    if (errorCode == ERROR_NONE) {
        lock_status_response_conversion(lockStatusResponse, response.result, response.remain);
    }

    return ConvertArktsErrorWithPermission(errorCode, "AlterPin2", Permission::SET_TELEPHONY_STATE);
}

ArktsError UnlockPuk2(int32_t slotId, const rust::String newPin2, const rust::String puk2,
    AniLockStatusResponse &lockStatusResponse)
{
    int32_t errorCode = TELEPHONY_ERR_SUCCESS;
    if (!IsValidSlotId(slotId)) {
        errorCode = ERROR_SLOT_ID_INVALID;
        return ConvertArktsErrorWithPermission(errorCode, "UnlockPuk2", Permission::SET_TELEPHONY_STATE);
    }

    LockStatusResponse response{ UNLOCK_FAIL, ERROR_DEFAULT };
    errorCode = DelayedRefSingleton<CoreServiceClient>::GetInstance().UnlockPuk2(slotId,
        NapiUtil::ToUtf16(std::string(newPin2)), NapiUtil::ToUtf16(std::string(puk2)), response);
    if (errorCode == ERROR_NONE) {
        lock_status_response_conversion(lockStatusResponse, response.result, response.remain);
    }

    return ConvertArktsErrorWithPermission(errorCode, "UnlockPuk2", Permission::SET_TELEPHONY_STATE);
}

ArktsError UnlockPin2(int32_t slotId, const rust::String pin2, AniLockStatusResponse &lockStatusResponse)
{
    int32_t errorCode = TELEPHONY_ERR_SUCCESS;
    if (!IsValidSlotId(slotId)) {
        errorCode = ERROR_SLOT_ID_INVALID;
        return ConvertArktsErrorWithPermission(errorCode, "UnlockPin2", Permission::SET_TELEPHONY_STATE);
    }

    LockStatusResponse response{ UNLOCK_FAIL, ERROR_DEFAULT };
    errorCode = DelayedRefSingleton<CoreServiceClient>::GetInstance().UnlockPin2(slotId,
        NapiUtil::ToUtf16(std::string(pin2)), response);
    if (errorCode == ERROR_NONE) {
        lock_status_response_conversion(lockStatusResponse, response.result, response.remain);
    }

    return ConvertArktsErrorWithPermission(errorCode, "UnlockPin2", Permission::SET_TELEPHONY_STATE);
}

ArktsError SetLockState(int32_t slotId, int32_t lockType, const rust::String password, int32_t state,
    AniLockStatusResponse &lockStatusResponse)
{
    int32_t errorCode = TELEPHONY_ERR_SUCCESS;
    if (!IsValidSlotId(slotId)) {
        errorCode = ERROR_SLOT_ID_INVALID;
        return ConvertArktsErrorWithPermission(errorCode, "SetLockState", Permission::SET_TELEPHONY_STATE);
    }

    LockStatusResponse response{ UNLOCK_FAIL, ERROR_DEFAULT };
    const LockInfo info{ static_cast<LockType>(lockType), NapiUtil::ToUtf16(std::string(password)),
        static_cast<LockState>(state) };
    errorCode = DelayedRefSingleton<CoreServiceClient>::GetInstance().SetLockState(slotId, info, response);
    if (errorCode == ERROR_NONE) {
        lock_status_response_conversion(lockStatusResponse, response.result, response.remain);
    }

    return ConvertArktsErrorWithPermission(errorCode, "SetLockState", Permission::SET_TELEPHONY_STATE);
}

ArktsError AlterPin(int32_t slotId, const rust::String newPin, const rust::String oldPin,
    AniLockStatusResponse &lockStatusResponse)
{
    int32_t errorCode = TELEPHONY_ERR_SUCCESS;
    if (!IsValidSlotId(slotId)) {
        errorCode = ERROR_SLOT_ID_INVALID;
        return ConvertArktsErrorWithPermission(errorCode, "AlterPin", Permission::SET_TELEPHONY_STATE);
    }

    LockStatusResponse response{ UNLOCK_FAIL, ERROR_DEFAULT };
    errorCode = DelayedRefSingleton<CoreServiceClient>::GetInstance().AlterPin(slotId,
        NapiUtil::ToUtf16(std::string(newPin)), NapiUtil::ToUtf16(std::string(oldPin)), response);
    if (errorCode == ERROR_NONE) {
        lock_status_response_conversion(lockStatusResponse, response.result, response.remain);
    }

    return ConvertArktsErrorWithPermission(errorCode, "AlterPin", Permission::SET_TELEPHONY_STATE);
}

ArktsError GetShowNumber(int32_t slotId, rust::String &showNumber)
{
    int32_t errorCode = TELEPHONY_ERR_SUCCESS;
    if (!IsValidSlotId(slotId)) {
        errorCode = ERROR_SLOT_ID_INVALID;
        return ConvertArktsErrorWithPermission(errorCode, "GetShowNumber", Permission::GET_TELEPHONY_STATE);
    }

    std::u16string showNumber16;
    errorCode = DelayedRefSingleton<CoreServiceClient>::GetInstance().GetShowNumber(slotId, showNumber16);
    if (errorCode == ERROR_NONE) {
        showNumber = rust::String(NapiUtil::ToUtf8(showNumber16));
    }
    return ConvertArktsErrorWithPermission(errorCode, "GetShowNumber", Permission::GET_TELEPHONY_STATE);
}

ArktsError SetShowNumber(int32_t slotId, rust::String showNumber)
{
    int32_t errorCode = TELEPHONY_ERR_SUCCESS;
    if (!IsValidSlotId(slotId)) {
        errorCode = ERROR_SLOT_ID_INVALID;
        return ConvertArktsErrorWithPermission(errorCode, "SetShowNumber", Permission::SET_TELEPHONY_STATE);
    }

    errorCode = DelayedRefSingleton<CoreServiceClient>::GetInstance().SetShowNumber(slotId,
        NapiUtil::ToUtf16(std::string(showNumber)));
    return ConvertArktsErrorWithPermission(errorCode, "SetShowNumber", Permission::SET_TELEPHONY_STATE);
}

ArktsError GetShowName(int32_t slotId, rust::String &showName)
{
    int32_t errorCode = TELEPHONY_ERR_SUCCESS;
    if (!IsValidSlotId(slotId)) {
        errorCode = ERROR_SLOT_ID_INVALID;
        return ConvertArktsErrorWithPermission(errorCode, "GetShowName", Permission::GET_TELEPHONY_STATE);
    }

    std::u16string showName16;
    errorCode = DelayedRefSingleton<CoreServiceClient>::GetInstance().GetShowName(slotId, showName16);
    if (errorCode == ERROR_NONE) {
        showName = rust::String(NapiUtil::ToUtf8(showName16));
    }
    return ConvertArktsErrorWithPermission(errorCode, "GetShowName", Permission::GET_TELEPHONY_STATE);
}

ArktsError SetShowName(int32_t slotId, rust::String showName)
{
    int32_t errorCode = TELEPHONY_ERR_SUCCESS;
    if (!IsValidSlotId(slotId)) {
        errorCode = ERROR_SLOT_ID_INVALID;
        return ConvertArktsErrorWithPermission(errorCode, "SetShowName", Permission::SET_TELEPHONY_STATE);
    }

    errorCode = DelayedRefSingleton<CoreServiceClient>::GetInstance().SetShowName(slotId,
        NapiUtil::ToUtf16(std::string(showName)));
    return ConvertArktsErrorWithPermission(errorCode, "SetShowName", Permission::SET_TELEPHONY_STATE);
}

ArktsError DeactivateSim(int32_t slotId)
{
    int32_t errorCode = TELEPHONY_ERR_SUCCESS;
    if (!IsValidSlotId(slotId)) {
        errorCode = ERROR_SLOT_ID_INVALID;
        return ConvertArktsErrorWithPermission(errorCode, "DeactivateSim", Permission::SET_TELEPHONY_STATE);
    }

    int32_t enable = 0;
    errorCode = DelayedRefSingleton<CoreServiceClient>::GetInstance().SetActiveSim(slotId, enable);
    return ConvertArktsErrorWithPermission(errorCode, "DeactivateSim", Permission::SET_TELEPHONY_STATE);
}

ArktsError ActivateSim(int32_t slotId)
{
    int32_t errorCode = TELEPHONY_ERR_SUCCESS;
    if (!IsValidSlotId(slotId)) {
        errorCode = ERROR_SLOT_ID_INVALID;
        return ConvertArktsErrorWithPermission(errorCode, "ActivateSim", Permission::SET_TELEPHONY_STATE);
    }

    int32_t enable = 1;
    errorCode = DelayedRefSingleton<CoreServiceClient>::GetInstance().SetActiveSim(slotId, enable);
    return ConvertArktsErrorWithPermission(errorCode, "ActivateSim", Permission::SET_TELEPHONY_STATE);
}


ArktsError SetDefaultVoiceSlotId(int32_t slotId)
{
    int32_t errorCode = TELEPHONY_ERR_SUCCESS;
    if (!IsValidSlotIdForDefault(slotId)) {
        errorCode = ERROR_SLOT_ID_INVALID;
        return ConvertArktsErrorWithPermission(errorCode, "SetDefaultVoiceSlotId", Permission::SET_TELEPHONY_STATE);
    }

    errorCode = DelayedRefSingleton<CoreServiceClient>::GetInstance().SetDefaultVoiceSlotId(slotId);
    return ConvertArktsErrorWithPermission(errorCode, "SetDefaultVoiceSlotId", Permission::SET_TELEPHONY_STATE);
}

ArktsError GetImsi(int32_t slotId, rust::String &imsi)
{
    int32_t errorCode = TELEPHONY_ERR_SUCCESS;
    if (!IsValidSlotId(slotId)) {
        errorCode = ERROR_SLOT_ID_INVALID;
        return ConvertArktsErrorWithPermission(errorCode, "GetIMSI", Permission::GET_TELEPHONY_STATE);
    }

    std::u16string imsi16;
    errorCode = DelayedRefSingleton<CoreServiceClient>::GetInstance().GetIMSI(slotId, imsi16);
    if (errorCode == ERROR_NONE) {
        imsi = rust::String(NapiUtil::ToUtf8(imsi16));
    }
    return ConvertArktsErrorWithPermission(errorCode, "GetIMSI", Permission::GET_TELEPHONY_STATE);
}

ArktsError IsOperatorSimCard(int32_t slotId, rust::String operatorName, bool &isOperatorCard)
{
    int32_t errorCode = TELEPHONY_ERR_SUCCESS;
    if (!IsValidSlotId(slotId)) {
        errorCode = ERROR_SLOT_ID_INVALID;
    }

    if (!std::string(operatorName).compare(CHINA_TELE_COM_CARD)) {
        errorCode = DelayedRefSingleton<CoreServiceClient>::GetInstance().IsCTSimCard(slotId, isOperatorCard);
    } else {
        errorCode = TELEPHONY_ERR_ARGUMENT_MISMATCH;
    }

    return ConvertArktsError(errorCode);
}

ArktsError GetSimGid1(int32_t slotId, rust::String &sigGid1)
{
    int32_t errorCode = TELEPHONY_ERR_SUCCESS;
    if (!IsValidSlotId(slotId)) {
        errorCode = ERROR_SLOT_ID_INVALID;
        return ConvertArktsErrorWithPermission(errorCode, "GetSimGid1", Permission::GET_TELEPHONY_STATE);
    }

    std::u16string simGid116;
    errorCode = DelayedRefSingleton<CoreServiceClient>::GetInstance().GetSimGid1(slotId, simGid116);
    if (errorCode == ERROR_NONE) {
        sigGid1 = rust::String(NapiUtil::ToUtf8(simGid116));
    }
    return ConvertArktsErrorWithPermission(errorCode, "GetSimGid1", Permission::GET_TELEPHONY_STATE);
}

ArktsError GetSimTelephoneNumber(int32_t slotId, rust::String &simTelephoneNumber)
{
    int32_t errorCode = TELEPHONY_ERR_SUCCESS;
    if (!IsValidSlotId(slotId)) {
        errorCode = ERROR_SLOT_ID_INVALID;
        return ConvertArktsErrorWithPermission(errorCode, "GetSimTelephoneNumber", Permission::GET_TELEPHONY_STATE);
    }

    std::u16string simTelephoneNumber16;
    errorCode =
        DelayedRefSingleton<CoreServiceClient>::GetInstance().GetSimTelephoneNumber(slotId, simTelephoneNumber16);
    if (errorCode == ERROR_NONE) {
        simTelephoneNumber = rust::String(NapiUtil::ToUtf8(simTelephoneNumber16));
    }
    return ConvertArktsErrorWithPermission(errorCode, "GetSimTelephoneNumber", Permission::GET_TELEPHONY_STATE);
}

ArktsError SetVoiceMailInfo(int32_t slotId, rust::String mailName, rust::String mailNumber)
{
    int32_t errorCode = TELEPHONY_ERR_SUCCESS;
    if (!IsValidSlotId(slotId)) {
        errorCode = ERROR_SLOT_ID_INVALID;
        return ConvertArktsErrorWithPermission(errorCode, "SetVoiceMailInfo", Permission::SET_TELEPHONY_STATE);
    }

    errorCode = DelayedRefSingleton<CoreServiceClient>::GetInstance().SetVoiceMailInfo(slotId,
        NapiUtil::ToUtf16(std::string(mailName)), NapiUtil::ToUtf16(std::string(mailNumber)));
    return ConvertArktsErrorWithPermission(errorCode, "SetVoiceMailInfo", Permission::SET_TELEPHONY_STATE);
}

ArktsError GetVoiceMailNumber(int32_t slotId, rust::String &voiceMailNumber)
{
    int32_t errorCode = TELEPHONY_ERR_SUCCESS;
    if (!IsValidSlotId(slotId)) {
        errorCode = ERROR_SLOT_ID_INVALID;
        return ConvertArktsErrorWithPermission(errorCode, "GetVoiceMailNumber", Permission::GET_TELEPHONY_STATE);
    }

    std::u16string voiceMailNumber16;
    errorCode = DelayedRefSingleton<CoreServiceClient>::GetInstance().GetVoiceMailNumber(slotId, voiceMailNumber16);
    if (errorCode == ERROR_NONE) {
        voiceMailNumber = rust::String(NapiUtil::ToUtf8(voiceMailNumber16));
    }
    return ConvertArktsErrorWithPermission(errorCode, "GetVoiceMailNumber", Permission::GET_TELEPHONY_STATE);
}

ArktsError GetVoiceMailIdentifier(int32_t slotId, rust::String &voiceMailIdentifier)
{
    int32_t errorCode = TELEPHONY_ERR_SUCCESS;
    if (!IsValidSlotId(slotId)) {
        errorCode = ERROR_SLOT_ID_INVALID;
        return ConvertArktsErrorWithPermission(errorCode, "GetVoiceMailIdentifier", Permission::GET_TELEPHONY_STATE);
    }

    std::u16string voiceMailIdentifier16;
    errorCode =
        DelayedRefSingleton<CoreServiceClient>::GetInstance().GetVoiceMailIdentifier(slotId, voiceMailIdentifier16);
    if (errorCode == ERROR_NONE) {
        voiceMailIdentifier = rust::String(NapiUtil::ToUtf8(voiceMailIdentifier16));
    }
    return ConvertArktsErrorWithPermission(errorCode, "GetVoiceMailIdentifier", Permission::GET_TELEPHONY_STATE);
}

ArktsError GetSimIccId(int32_t slotId, rust::String &simIccId)
{
    int32_t errorCode = TELEPHONY_ERR_SUCCESS;
    if (!IsValidSlotId(slotId)) {
        errorCode = ERROR_SLOT_ID_INVALID;
        return ConvertArktsErrorWithPermission(errorCode, "GetSimIccId", Permission::GET_TELEPHONY_STATE);
    }

    std::u16string simIccId16;
    errorCode = DelayedRefSingleton<CoreServiceClient>::GetInstance().GetSimIccId(slotId, simIccId16);
    if (errorCode == ERROR_NONE) {
        simIccId = rust::String(NapiUtil::ToUtf8(simIccId16));
    }
    return ConvertArktsErrorWithPermission(errorCode, "GetSimIccId", Permission::GET_TELEPHONY_STATE);
}

ArktsError GetCardType(int32_t slotId, int32_t &cardType)
{
    int32_t errorCode = TELEPHONY_ERR_SUCCESS;
    CardType type = CardType::UNKNOWN_CARD;

    if (!IsValidSlotId(slotId)) {
        errorCode = ERROR_SLOT_ID_INVALID;
        return ConvertArktsError(errorCode);
    }

    errorCode = DelayedRefSingleton<CoreServiceClient>::GetInstance().GetCardType(slotId, type);
    if (errorCode == ERROR_NONE) {
        cardType = static_cast<int32_t>(type);
    }

    return ConvertArktsError(errorCode);
}

ArktsError GetSimSpn(int32_t slotId, rust::String &simSpn)
{
    int32_t errorCode = TELEPHONY_ERR_SUCCESS;
    if (!IsValidSlotId(slotId)) {
        errorCode = ERROR_SLOT_ID_INVALID;
        return ConvertArktsError(errorCode);
    }

    std::u16string simSpn16;
    errorCode = DelayedRefSingleton<CoreServiceClient>::GetInstance().GetSimSpn(slotId, simSpn16);
    if (errorCode == ERROR_NONE) {
        simSpn = rust::String(NapiUtil::ToUtf8(simSpn16));
    }
    return ConvertArktsError(errorCode);
}

ArktsError GetSimOperatorNumeric(int32_t slotId, rust::String &simOperatorNumeric)
{
    int32_t errorCode = TELEPHONY_ERR_SUCCESS;
    if (!IsValidSlotId(slotId)) {
        errorCode = ERROR_SLOT_ID_INVALID;
        return ConvertArktsError(errorCode);
    }

    std::u16string simOperatorNumeric16;
    errorCode =
        DelayedRefSingleton<CoreServiceClient>::GetInstance().GetSimOperatorNumeric(slotId, simOperatorNumeric16);
    if (errorCode == ERROR_NONE) {
        simOperatorNumeric = rust::String(NapiUtil::ToUtf8(simOperatorNumeric16));
    }
    return ConvertArktsError(errorCode);
}

ArktsError HasOperatorPrivileges(int32_t slotId, bool &hasPrivileges)
{
    int32_t errorCode = TELEPHONY_ERR_SUCCESS;
    if (!IsValidSlotId(slotId)) {
        errorCode = ERROR_SLOT_ID_INVALID;
    } else {
        errorCode = DelayedRefSingleton<CoreServiceClient>::GetInstance().HasOperatorPrivileges(slotId, hasPrivileges);
    }

    return ConvertArktsError(errorCode);
}
} // namespace SimAni
} // namespace Telephony
} // namespace OHOS