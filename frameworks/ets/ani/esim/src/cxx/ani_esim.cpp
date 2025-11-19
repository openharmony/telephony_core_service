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

#include "ani_esim.h"
#include <cstdint>
#include <iostream>
#include <memory>
#include "ani_reset_memory_callback.h"
#include "ani_esim_service_callback.h"
#include "wrapper.rs.h"
#include "cxx.h"
#include "esim_service_client.h"
#include "napi_util.h"
#include "telephony_types.h"
#include "telephony_permission.h"

using namespace std;

namespace OHOS {
namespace Telephony {
namespace EsimAni {

static inline bool IsValidSlotId(int32_t slotId)
{
    return ((slotId >= DEFAULT_SIM_SLOT_ID) && (slotId < SIM_SLOT_COUNT));
}

static inline ArktsError ConvertArktsErrorWithPermission(int32_t errorCode, const std::string &funcName,
                                                         const std::string &permission)
{
    JsError error = NapiUtil::ConverEsimErrorMessageWithPermissionForJs(
        errorCode, funcName, permission);

    ArktsError ArktsErr = {
        .errorCode = error.errorCode,
        .errorMessage = rust::string(error.errorMessage),
    };
    return ArktsErr;
}

static void ConvertGetEuiccProfileInfoListResult(const GetEuiccProfileInfoListResult &profileList,
    GetEuiccProfileInfoListResultAni &profileListAni)
{
    profileListAni.responseResult = static_cast<int32_t>(profileList.result_);
    profileListAni.isRemovable = profileList.isRemovable_;
    for (auto &profile : profileList.profiles_) {
        EuiccProfileAni profileAni{};
        profileAni.iccid = NapiUtil::ToUtf8(profile.iccId_);
        profileAni.nickName = NapiUtil::ToUtf8(profile.nickName_);
        profileAni.serviceProviderName = NapiUtil::ToUtf8(profile.serviceProviderName_);
        profileAni.profileName = NapiUtil::ToUtf8(profile.profileName_);
        profileAni.state = static_cast<int32_t>(profile.state_);
        profileAni.profileClass = static_cast<int32_t>(profile.profileClass_);
        profileAni.operatorId.mcc = NapiUtil::ToUtf8(profile.carrierId_.mcc_);
        profileAni.operatorId.mnc = NapiUtil::ToUtf8(profile.carrierId_.mnc_);
        profileAni.operatorId.gid1 = NapiUtil::ToUtf8(profile.carrierId_.gid1_);
        profileAni.operatorId.gid2 = NapiUtil::ToUtf8(profile.carrierId_.gid2_);
        profileAni.policyRules = static_cast<int32_t>(profile.policyRules_);
        for (auto &rule : profile.accessRules_) {
            AccessRuleAni ruleAni{};
            ruleAni.certificateHashHexStr = NapiUtil::ToUtf8(rule.certificateHashHexStr_);
            ruleAni.packageName = NapiUtil::ToUtf8(rule.packageName_);
            ruleAni.accessType = rule.accessType_;
            profileAni.accessRules.push_back(ruleAni);
        }
        profileListAni.profiles.push_back(profileAni);
    }
}

static DownloadableProfile ConvertDownloadableProfileAni(const DownloadableProfileAni &profileInfo)
{
    DownloadableProfile profile;
    profile.encodedActivationCode_ = NapiUtil::ToUtf16(std::string(profileInfo.activationCode));
    profile.confirmationCode_ = NapiUtil::ToUtf16(std::string(profileInfo.confirmationCode));
    profile.carrierName_ = NapiUtil::ToUtf16(std::string(profileInfo.carrierName));

    for (auto &rule : profileInfo.accessRules) {
        AccessRule access;
        access.accessType_ = rule.accessType;
        access.certificateHashHexStr_ = NapiUtil::ToUtf16(std::string(rule.certificateHashHexStr));
        access.packageName_ = NapiUtil::ToUtf16(std::string(rule.packageName));
        profile.accessRules_.push_back(std::move(access));
    }

    return profile;
}

static DownloadableProfileAni ConvertDownloadableProfile(const DownloadableProfile &profile)
{
    DownloadableProfileAni profileAni;
    profileAni.activationCode = NapiUtil::ToUtf8(profile.encodedActivationCode_);
    profileAni.confirmationCode = NapiUtil::ToUtf8(profile.confirmationCode_);
    profileAni.carrierName = NapiUtil::ToUtf8(profile.carrierName_);
    for (auto &accessRule : profile.accessRules_) {
        AccessRuleAni accessRuleAni;
        accessRuleAni.certificateHashHexStr = NapiUtil::ToUtf8(accessRule.certificateHashHexStr_);
        accessRuleAni.packageName = NapiUtil::ToUtf8(accessRule.packageName_);
        accessRuleAni.accessType = accessRule.accessType_;
        profileAni.accessRules.push_back(accessRuleAni);
    }

    return profileAni;
}

static void ConvertGetDownloadableProfileMetadataResult(const GetDownloadableProfileMetadataResult &metadataResult,
    GetDownloadableProfileMetadataResultAni &metadataResultAni)
{
    metadataResultAni.downloadableProfile = ConvertDownloadableProfile(metadataResult.downloadableProfiles_);
    metadataResultAni.pprType = metadataResult.pprType_;
    metadataResultAni.pprFlag = metadataResult.pprFlag_;
    metadataResultAni.iccid = NapiUtil::ToUtf8(metadataResult.iccId_);
    metadataResultAni.serviceProviderName = NapiUtil::ToUtf8(metadataResult.serviceProviderName_);
    metadataResultAni.profileName = NapiUtil::ToUtf8(metadataResult.profileName_);
    metadataResultAni.profileClass = static_cast<int32_t>(metadataResult.profileClass_);
    metadataResultAni.solvableErrors = static_cast<int32_t>(metadataResult.resolvableErrors_);
    metadataResultAni.responseResult = static_cast<int32_t>(metadataResult.result_);
}

ArktsError ResetMemory(int32_t slotId, int32_t options, int32_t &resultCode)
{
    int32_t errorCode = ERROR_DEFAULT;
    if (!IsValidSlotId(slotId)) {
        errorCode = ERROR_SLOT_ID_INVALID;
        return ConvertArktsErrorWithPermission(errorCode, "ResetMemory",
                                               Permission::SET_TELEPHONY_ESIM_STATE);
    }

    std::unique_ptr<AniAsyncResetMemory> profileContextUnique = std::make_unique<AniAsyncResetMemory>();
    AniAsyncResetMemory *profileContext = profileContextUnique.get();

    std::unique_ptr<AniResetMemoryCallback> callback = std::make_unique<AniResetMemoryCallback>(profileContext);
    std::unique_lock<std::mutex> callbackLock(profileContext->callbackMutex);
    errorCode = DelayedRefSingleton<EsimServiceClient>::GetInstance().ResetMemory(
        slotId, options, callback.release());
    profileContext->errorCode = errorCode;
    if (errorCode == TELEPHONY_SUCCESS) {
        profileContext->cv.wait_until(callbackLock, std::chrono::seconds(WAIT_TIME_SECOND),
            [profileContext] { return profileContext->isCallbackEnd; });
    }

    if ((!profileContext->isCallbackEnd) && (profileContext->errorCode == TELEPHONY_SUCCESS)) {
        profileContext->errorCode = TELEPHONY_ERR_ESIM_GET_RESULT_TIMEOUT;
    }
    resultCode = profileContext->callbackVal;

    return ConvertArktsErrorWithPermission(profileContext->errorCode, "ResetMemory",
                                           Permission::SET_TELEPHONY_ESIM_STATE);
}

ArktsError IsSupported(int32_t slotId, bool &isSupportedResult)
{
    int32_t errorCode = TELEPHONY_ERR_FAIL;
    if (!IsValidSlotId(slotId)) {
        errorCode = ERROR_SLOT_ID_INVALID;
        return ConvertArktsErrorWithPermission(errorCode, "isSupported", Permission::GET_TELEPHONY_ESIM_STATE);
    }

    errorCode = DelayedRefSingleton<EsimServiceClient>::GetInstance().IsSupported(slotId);
    if (errorCode != TELEPHONY_SUCCESS) {
        isSupportedResult = false;
    } else {
        isSupportedResult = true;
    }
    return ConvertArktsErrorWithPermission(errorCode, "isSupported", Permission::GET_TELEPHONY_ESIM_STATE);
}

ArktsError AddProfile(const DownloadableProfileAni &profileAni, bool &addProfileResult)
{
    int32_t slotId = GetDefaultEsimSlotId<int32_t>();
    auto profile = ConvertDownloadableProfileAni(profileAni);
    int32_t errorCode = DelayedRefSingleton<EsimServiceClient>::GetInstance().AddProfile(slotId, profile);
    if (errorCode != TELEPHONY_SUCCESS) {
        addProfileResult = false;
    } else {
        addProfileResult = true;
    }
    return ConvertArktsErrorWithPermission(errorCode, "addProfile", Permission::SET_TELEPHONY_ESIM_STATE_OPEN);
}

ArktsError GetEid(int32_t slotId, rust::String &eid)
{
    int32_t errorCode = TELEPHONY_ERR_FAIL;
    if (!IsValidSlotId(slotId)) {
        errorCode = ERROR_SLOT_ID_INVALID;
        return ConvertArktsErrorWithPermission(errorCode, "getEid", Permission::GET_TELEPHONY_ESIM_STATE);
    }

    auto context = std::make_shared<AniCallbackContext<std::string>>();
    auto callback = OHOS::sptr<AniGetEidCallback>::MakeSptr(context);
    std::unique_lock<ffrt::mutex> callbackLock(context->callbackMutex);
    errorCode = DelayedRefSingleton<EsimServiceClient>::GetInstance().GetEid(slotId, callback);
    if (errorCode == TELEPHONY_SUCCESS) {
        context->cv.wait_for(callbackLock, std::chrono::seconds(WAIT_TIME_SECOND),
            [context] { return context->isCallbackEnd; });
        if (!context->isCallbackEnd) {
            errorCode = TELEPHONY_ERR_ESIM_GET_RESULT_TIMEOUT;
        } else {
            eid = context->resultValue;
        }
    }
    return ConvertArktsErrorWithPermission(errorCode, "getEid", Permission::GET_TELEPHONY_ESIM_STATE);
}

ArktsError GetOsuStatus(int32_t slotId, int32_t &osuStatus)
{
    int32_t errorCode = TELEPHONY_ERR_FAIL;
    if (!IsValidSlotId(slotId)) {
        errorCode = ERROR_SLOT_ID_INVALID;
        return ConvertArktsErrorWithPermission(errorCode, "getOsuStatus", Permission::GET_TELEPHONY_ESIM_STATE);
    }

    errorCode = DelayedRefSingleton<EsimServiceClient>::GetInstance().GetOsuStatus(slotId, osuStatus);
    return ConvertArktsErrorWithPermission(errorCode, "getOsuStatus", Permission::GET_TELEPHONY_ESIM_STATE);
}

ArktsError StartOsu(int32_t slotId, int32_t &osuStatus)
{
    int32_t errorCode = TELEPHONY_ERR_FAIL;
    if (!IsValidSlotId(slotId)) {
        errorCode = ERROR_SLOT_ID_INVALID;
        return ConvertArktsErrorWithPermission(errorCode, "startOsu", Permission::SET_TELEPHONY_ESIM_STATE);
    }

    auto context = std::make_shared<AniCallbackContext<int32_t>>();
    auto callback = OHOS::sptr<AniStartOsuCallback>::MakeSptr(context);
    std::unique_lock<ffrt::mutex> callbackLock(context->callbackMutex);
    errorCode = DelayedRefSingleton<EsimServiceClient>::GetInstance().StartOsu(slotId, callback);
    if (errorCode == TELEPHONY_SUCCESS) {
        context->cv.wait_for(callbackLock, std::chrono::seconds(WAIT_TIME_SECOND),
            [context] { return context->isCallbackEnd; });
        if (!context->isCallbackEnd) {
            errorCode = TELEPHONY_ERR_ESIM_GET_RESULT_TIMEOUT;
        } else {
            osuStatus = context->resultValue;
        }
    }
    return ConvertArktsErrorWithPermission(errorCode, "startOsu", Permission::SET_TELEPHONY_ESIM_STATE);
}

ArktsError GetDownloadableProfileMetadata(int32_t slotId, int32_t portIndex, const DownloadableProfileAni &profileAni,
    bool forceDisableProfile, GetDownloadableProfileMetadataResultAni &metadataResult)
{
    int32_t errorCode = TELEPHONY_ERR_FAIL;
    if (!IsValidSlotId(slotId)) {
        errorCode = ERROR_SLOT_ID_INVALID;
        return ConvertArktsErrorWithPermission(errorCode, "getDownloadableProfileMetadata",
            Permission::GET_TELEPHONY_ESIM_STATE);
    }

    auto context = std::make_shared<AniCallbackContext<GetDownloadableProfileMetadataResult>>();
    auto callback = OHOS::sptr<AniGetDownloadableProfileMetadataCallback>::MakeSptr(context);
    auto profile = ConvertDownloadableProfileAni(profileAni);
    std::unique_lock<ffrt::mutex> callbackLock(context->callbackMutex);
    errorCode = DelayedRefSingleton<EsimServiceClient>::GetInstance().GetDownloadableProfileMetadata(slotId, portIndex,
        profile, forceDisableProfile, callback);
    if (errorCode == TELEPHONY_SUCCESS) {
        context->cv.wait_for(callbackLock, std::chrono::seconds(WAIT_LONG_TERM_TASK_SECOND),
            [context] { return context->isCallbackEnd; });
        if (!context->isCallbackEnd) {
            errorCode = TELEPHONY_ERR_ESIM_GET_RESULT_TIMEOUT;
        } else {
            ConvertGetDownloadableProfileMetadataResult(context->resultValue, metadataResult);
        }
    }
    return ConvertArktsErrorWithPermission(errorCode, "getDownloadableProfileMetadata",
        Permission::GET_TELEPHONY_ESIM_STATE);
}

ArktsError GetDownloadableProfiles(int32_t slotId, int32_t portIndex, bool forceDisableProfile, int32_t &resultCode,
    rust::Vec<DownloadableProfileAni> &downloadableProfiles)
{
    int32_t errorCode = TELEPHONY_ERR_FAIL;
    if (!IsValidSlotId(slotId)) {
        errorCode = ERROR_SLOT_ID_INVALID;
        return ConvertArktsErrorWithPermission(errorCode, "getDownloadableProfiles",
            Permission::GET_TELEPHONY_ESIM_STATE);
    }

    auto context = std::make_shared<AniCallbackContext<GetDownloadableProfilesResult>>();
    auto callback = OHOS::sptr<AniGetDownloadableProfilesCallback>::MakeSptr(context);
    std::unique_lock<ffrt::mutex> callbackLock(context->callbackMutex);
    errorCode = DelayedRefSingleton<EsimServiceClient>::GetInstance().GetDownloadableProfiles(slotId, portIndex,
        forceDisableProfile, callback);
    if (errorCode == TELEPHONY_SUCCESS) {
        context->cv.wait_for(callbackLock, std::chrono::seconds(WAIT_TIME_SECOND),
            [context] { return context->isCallbackEnd; });
        if (!context->isCallbackEnd) {
            errorCode = TELEPHONY_ERR_ESIM_GET_RESULT_TIMEOUT;
        } else {
            resultCode = static_cast<int32_t>(context->resultValue.result_);
            for (auto &profile : context->resultValue.downloadableProfiles_) {
                downloadableProfiles.push_back(ConvertDownloadableProfile(profile));
            }
        }
    }
    return ConvertArktsErrorWithPermission(errorCode, "getDownloadableProfiles", Permission::GET_TELEPHONY_ESIM_STATE);
}

ArktsError DownloadProfile(int32_t slotId, int32_t portIndex, const DownloadableProfileAni &profileAni,
    const DownloadConfigurationAni &configAni, DownloadProfileResultAni &resultAni)
{
    int32_t errorCode = TELEPHONY_ERR_FAIL;
    if (!IsValidSlotId(slotId)) {
        errorCode = ERROR_SLOT_ID_INVALID;
        return ConvertArktsErrorWithPermission(errorCode, "downloadProfile",
            Permission::GET_TELEPHONY_ESIM_STATE);
    }

    DownloadProfileResult result;
    DownloadProfileConfigInfo configInfo;
    configInfo.portIndex_ = portIndex;
    configInfo.isSwitchAfterDownload_ = configAni.switchAfterDownload;
    configInfo.isForceDeactivateSim_ = configAni.forceDisableProfile;
    configInfo.isPprAllowed_ = configAni.isPprAllowed;
    DownloadableProfile profile = ConvertDownloadableProfileAni(profileAni);

    auto context = std::make_shared<AniCallbackContext<DownloadProfileResult>>();
    auto callback = OHOS::sptr<AniDownloadProfileResultCallback>::MakeSptr(context);
    std::unique_lock<ffrt::mutex> callbackLock(context->callbackMutex);
    errorCode =
        DelayedRefSingleton<EsimServiceClient>::GetInstance().DownloadProfile(slotId, configInfo, profile, callback);
    if (errorCode == TELEPHONY_SUCCESS) {
        context->cv.wait_for(callbackLock, std::chrono::seconds(WAIT_LONG_TERM_TASK_SECOND),
            [context] { return context->isCallbackEnd; });
        if (!context->isCallbackEnd) {
            errorCode = TELEPHONY_ERR_ESIM_GET_RESULT_TIMEOUT;
        } else {
            resultAni.responseResult = static_cast<int32_t>(context->resultValue.result_);
            resultAni.solvableErrors = static_cast<int32_t>(context->resultValue.resolvableErrors_);
            resultAni.cardId = context->resultValue.cardId_;
        }
    }

    return ConvertArktsErrorWithPermission(errorCode, "downloadProfile", Permission::SET_TELEPHONY_ESIM_STATE);
}

ArktsError GetEuiccProfileInfoList(int32_t slotId, GetEuiccProfileInfoListResultAni &profileList)
{
    int32_t errorCode = TELEPHONY_ERR_FAIL;
    if (!IsValidSlotId(slotId)) {
        errorCode = ERROR_SLOT_ID_INVALID;
        return ConvertArktsErrorWithPermission(errorCode, "getEuiccProfileInfoList",
            Permission::GET_TELEPHONY_ESIM_STATE);
    }

    auto context = std::make_shared<AniCallbackContext<GetEuiccProfileInfoListResult>>();
    auto callback = OHOS::sptr<AniGetEuiccProfileInfoListCallback>::MakeSptr(context);
    std::unique_lock<ffrt::mutex> callbackLock(context->callbackMutex);
    errorCode = DelayedRefSingleton<EsimServiceClient>::GetInstance().GetEuiccProfileInfoList(slotId, callback);
    if (errorCode == TELEPHONY_SUCCESS) {
        context->cv.wait_for(callbackLock, std::chrono::seconds(WAIT_TIME_SECOND),
            [context] { return context->isCallbackEnd; });
        if (!context->isCallbackEnd) {
            errorCode = TELEPHONY_ERR_ESIM_GET_RESULT_TIMEOUT;
        } else {
            ConvertGetEuiccProfileInfoListResult(context->resultValue, profileList);
        }
    }

    return ConvertArktsErrorWithPermission(errorCode, "getEuiccProfileInfoList", Permission::GET_TELEPHONY_ESIM_STATE);
}

ArktsError GetEuiccInfo(int32_t slotId, rust::String &euiccInfo)
{
    int32_t errorCode = TELEPHONY_ERR_FAIL;
    if (!IsValidSlotId(slotId)) {
        errorCode = ERROR_SLOT_ID_INVALID;
        return ConvertArktsErrorWithPermission(errorCode, "getEuiccInfo", Permission::GET_TELEPHONY_ESIM_STATE);
    }

    auto context = std::make_shared<AniCallbackContext<std::string>>();
    auto callback = OHOS::sptr<AniGetEuiccInfoCallback>::MakeSptr(context);
    std::unique_lock<ffrt::mutex> callbackLock(context->callbackMutex);
    errorCode = DelayedRefSingleton<EsimServiceClient>::GetInstance().GetEuiccInfo(slotId, callback);
    if (errorCode == TELEPHONY_SUCCESS) {
        context->cv.wait_for(callbackLock, std::chrono::seconds(WAIT_TIME_SECOND),
            [context] { return context->isCallbackEnd; });
        if (!context->isCallbackEnd) {
            errorCode = TELEPHONY_ERR_ESIM_GET_RESULT_TIMEOUT;
        } else {
            euiccInfo = context->resultValue;
        }
    }

    return ConvertArktsErrorWithPermission(errorCode, "getEuiccInfo", Permission::GET_TELEPHONY_ESIM_STATE);
}

ArktsError DeleteProfile(int32_t slotId, rust::String iccid, int32_t &resultCode)
{
    int32_t errorCode = TELEPHONY_ERR_FAIL;
    if (!IsValidSlotId(slotId)) {
        errorCode = ERROR_SLOT_ID_INVALID;
        return ConvertArktsErrorWithPermission(errorCode, "deleteProfile", Permission::SET_TELEPHONY_ESIM_STATE);
    }

    auto context = std::make_shared<AniCallbackContext<int32_t>>();
    auto callback = OHOS::sptr<AniDeleteProfileCallback>::MakeSptr(context);
    std::unique_lock<ffrt::mutex> callbackLock(context->callbackMutex);
    errorCode =
        DelayedRefSingleton<EsimServiceClient>::GetInstance().DeleteProfile(slotId, std::string(iccid), callback);
    if (errorCode == TELEPHONY_SUCCESS) {
        context->cv.wait_for(callbackLock, std::chrono::seconds(WAIT_TIME_SECOND),
            [context] { return context->isCallbackEnd; });
        if (!context->isCallbackEnd) {
            errorCode = TELEPHONY_ERR_ESIM_GET_RESULT_TIMEOUT;
        } else {
            resultCode = context->resultValue;
        }
    }

    return ConvertArktsErrorWithPermission(errorCode, "deleteProfile", Permission::SET_TELEPHONY_ESIM_STATE);
}

ArktsError SwitchToProfile(int32_t slotId, int32_t portIndex, rust::String iccid, bool forceDisableProfile,
    int32_t &resultCode)
{
    int32_t errorCode = TELEPHONY_ERR_FAIL;
    if (!IsValidSlotId(slotId)) {
        errorCode = ERROR_SLOT_ID_INVALID;
        return ConvertArktsErrorWithPermission(errorCode, "switchToProfile", Permission::SET_TELEPHONY_ESIM_STATE);
    }

    auto context = std::make_shared<AniCallbackContext<int32_t>>();
    auto callback = OHOS::sptr<AniSwitchToProfileCallback>::MakeSptr(context);
    std::unique_lock<ffrt::mutex> callbackLock(context->callbackMutex);
    errorCode = DelayedRefSingleton<EsimServiceClient>::GetInstance().SwitchToProfile(slotId, portIndex,
        std::string(iccid), forceDisableProfile, callback);
    if (errorCode == TELEPHONY_SUCCESS) {
        context->cv.wait_for(callbackLock, std::chrono::seconds(WAIT_TIME_SECOND),
            [context] { return context->isCallbackEnd; });
        if (!context->isCallbackEnd) {
            errorCode = TELEPHONY_ERR_ESIM_GET_RESULT_TIMEOUT;
        } else {
            resultCode = context->resultValue;
        }
    }

    return ConvertArktsErrorWithPermission(errorCode, "switchToProfile", Permission::SET_TELEPHONY_ESIM_STATE);
}

ArktsError SetProfileNickname(int32_t slotId, rust::String iccid, rust::String nickname, int32_t &resultCode)
{
    int32_t errorCode = TELEPHONY_ERR_FAIL;
    if (!IsValidSlotId(slotId)) {
        errorCode = ERROR_SLOT_ID_INVALID;
        return ConvertArktsErrorWithPermission(errorCode, "setProfileNickname", Permission::SET_TELEPHONY_ESIM_STATE);
    }

    auto context = std::make_shared<AniCallbackContext<int32_t>>();
    auto callback = OHOS::sptr<AniSetProfileNickNameCallback>::MakeSptr(context);
    std::unique_lock<ffrt::mutex> callbackLock(context->callbackMutex);
    errorCode = DelayedRefSingleton<EsimServiceClient>::GetInstance().SetProfileNickname(slotId, std::string(iccid),
        std::string(nickname), callback);
    if (errorCode == TELEPHONY_SUCCESS) {
        context->cv.wait_for(callbackLock, std::chrono::seconds(WAIT_TIME_SECOND),
            [context] { return context->isCallbackEnd; });
        if (!context->isCallbackEnd) {
            errorCode = TELEPHONY_ERR_ESIM_GET_RESULT_TIMEOUT;
        } else {
            resultCode = context->resultValue;
        }
    }

    return ConvertArktsErrorWithPermission(errorCode, "setProfileNickname", Permission::SET_TELEPHONY_ESIM_STATE);
}

ArktsError ReserveProfilesForFactoryRestore(int32_t slotId, int32_t &resultCode)
{
    int32_t errorCode = TELEPHONY_ERR_FAIL;
    if (!IsValidSlotId(slotId)) {
        errorCode = ERROR_SLOT_ID_INVALID;
        return ConvertArktsErrorWithPermission(errorCode, "reserveProfilesForFactoryRestore",
            Permission::SET_TELEPHONY_ESIM_STATE);
    }

    int32_t result = -1;
    errorCode = DelayedRefSingleton<EsimServiceClient>::GetInstance().ReserveProfilesForFactoryRestore(slotId, result);
    if (errorCode == TELEPHONY_SUCCESS) {
        resultCode = result;
    }

    return ConvertArktsErrorWithPermission(errorCode, "reserveProfilesForFactoryRestore",
        Permission::SET_TELEPHONY_ESIM_STATE);
}

ArktsError SetDefaultSmdpAddress(int32_t slotId, rust::String address, int32_t &resultCode)
{
    int32_t errorCode = TELEPHONY_ERR_FAIL;
    if (!IsValidSlotId(slotId)) {
        errorCode = ERROR_SLOT_ID_INVALID;
        return ConvertArktsErrorWithPermission(errorCode, "setDefaultSmdpAddress",
            Permission::SET_TELEPHONY_ESIM_STATE);
    }

    auto context = std::make_shared<AniCallbackContext<int32_t>>();
    auto callback = OHOS::sptr<AniSetDefaultSmdpAddressCallback>::MakeSptr(context);
    std::unique_lock<ffrt::mutex> callbackLock(context->callbackMutex);
    errorCode = DelayedRefSingleton<EsimServiceClient>::GetInstance().SetDefaultSmdpAddress(slotId,
        std::string(address), callback);
    if (errorCode == TELEPHONY_SUCCESS) {
        context->cv.wait_for(callbackLock, std::chrono::seconds(WAIT_TIME_SECOND),
            [context] { return context->isCallbackEnd; });
        if (!context->isCallbackEnd) {
            errorCode = TELEPHONY_ERR_ESIM_GET_RESULT_TIMEOUT;
        } else {
            resultCode = context->resultValue;
        }
    }

    return ConvertArktsErrorWithPermission(errorCode, "setDefaultSmdpAddress", Permission::SET_TELEPHONY_ESIM_STATE);
}

ArktsError GetDefaultSmdpAddress(int32_t slotId, rust::String &address)
{
    int32_t errorCode = TELEPHONY_ERR_FAIL;
    if (!IsValidSlotId(slotId)) {
        errorCode = ERROR_SLOT_ID_INVALID;
        return ConvertArktsErrorWithPermission(errorCode, "getDefaultSmdpAddress",
            Permission::GET_TELEPHONY_ESIM_STATE);
    }

    auto context = std::make_shared<AniCallbackContext<std::string>>();
    auto callback = OHOS::sptr<AniGetDefaultSmdpAddressCallback>::MakeSptr(context);
    std::unique_lock<ffrt::mutex> callbackLock(context->callbackMutex);
    errorCode = DelayedRefSingleton<EsimServiceClient>::GetInstance().GetDefaultSmdpAddress(slotId, callback);
    if (errorCode == TELEPHONY_SUCCESS) {
        context->cv.wait_for(callbackLock, std::chrono::seconds(WAIT_TIME_SECOND),
            [context] { return context->isCallbackEnd; });
        if (!context->isCallbackEnd) {
            errorCode = TELEPHONY_ERR_ESIM_GET_RESULT_TIMEOUT;
        } else {
            address = context->resultValue;
        }
    }

    return ConvertArktsErrorWithPermission(errorCode, "getDefaultSmdpAddress", Permission::GET_TELEPHONY_ESIM_STATE);
}

ArktsError CancelSession(int32_t slotId, rust::String transactionId, int32_t cancelReason, int32_t &resultCode)
{
    int32_t errorCode = TELEPHONY_ERR_FAIL;
    if (!IsValidSlotId(slotId)) {
        errorCode = ERROR_SLOT_ID_INVALID;
        return ConvertArktsErrorWithPermission(errorCode, "cancelSession", Permission::SET_TELEPHONY_ESIM_STATE);
    }

    auto context = std::make_shared<AniCallbackContext<int32_t>>();
    auto callback = OHOS::sptr<AniCancelSessionCallback>::MakeSptr(context);
    std::unique_lock<ffrt::mutex> callbackLock(context->callbackMutex);
    errorCode = DelayedRefSingleton<EsimServiceClient>::GetInstance().CancelSession(slotId, std::string(transactionId),
        cancelReason, callback);
    if (errorCode == TELEPHONY_SUCCESS) {
        context->cv.wait_for(callbackLock, std::chrono::seconds(WAIT_TIME_SECOND),
            [context] { return context->isCallbackEnd; });
        if (!context->isCallbackEnd) {
            errorCode = TELEPHONY_ERR_ESIM_GET_RESULT_TIMEOUT;
        } else {
            resultCode = context->resultValue;
        }
    }

    return ConvertArktsErrorWithPermission(errorCode, "cancelSession", Permission::SET_TELEPHONY_ESIM_STATE);
}
} // namespace EsimAni
} // namespace Telephony
} // namespace OHOS
