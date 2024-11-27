/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#include "napi_esim.h"

#include <memory>
#include <string>
#include <string_view>
#include "cancel_session_callback.h"
#include "delete_profile_callback.h"
#include "download_profile_callback.h"
#include "esim_state_type.h"
#include "esim_service_client.h"
#include "get_default_smdp_address_callback.h"
#include "get_downloadable_profile_metadata_callback.h"
#include "get_downloadable_profiles_callback.h"
#include "get_euicc_info_callback.h"
#include "get_euicc_profile_info_list_callback.h"
#include "napi_parameter_util.h"
#include "napi_util.h"
#include "network_state.h"
#include "reset_memory_callback.h"
#include "set_default_smdp_address_callback.h"
#include "set_profile_nick_name_callback.h"
#include "start_osu_callback.h"
#include "switch_to_profile.h"
#include "telephony_log_wrapper.h"
#include "telephony_permission.h"

namespace OHOS {
namespace Telephony {
namespace {
const int32_t UNDEFINED_VALUE = -1;
const int32_t PARAMETER_COUNT_ONE = 1;
const int32_t PARAMETER_COUNT_TWO = 2;
struct AsyncPara {
    std::string funcName = "";
    napi_env env = nullptr;
    napi_callback_info info = nullptr;
    napi_async_execute_callback execute = nullptr;
    napi_async_complete_callback complete = nullptr;
};
struct PermissionPara {
    std::string func = "";
    std::string permission = "";
};
size_t resetParameterCount = 0;

static inline bool IsValidSlotId(int32_t slotId)
{
    return ((slotId >= DEFAULT_SIM_SLOT_ID) && (slotId < SIM_SLOT_COUNT));
}

template<typename T, napi_async_execute_callback exec, napi_async_complete_callback complete>
napi_value NapiCreateAsyncWork(napi_env env, napi_callback_info info, std::string_view funcName)
{
    size_t argc = PARAMETER_COUNT_TWO;
    napi_value argv[]{nullptr, nullptr};
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr));

    std::unique_ptr<AsyncContext<T>> asyncContext = std::make_unique<AsyncContext<T>>();
    BaseContext &context = asyncContext->context;
    auto inParaTp = std::make_tuple(&asyncContext->slotId, &context.callbackRef);
    std::optional<NapiError> errCode = MatchParameters(env, argv, argc, inParaTp);
    if (errCode.has_value()) {
        JsError error = NapiUtil::ConverEsimErrorMessageForJs(errCode.value());
        NapiUtil::ThrowError(env, error.errorCode, error.errorMessage);
        return nullptr;
    }

    napi_value result = nullptr;
    if (context.callbackRef == nullptr) {
        NAPI_CALL(env, napi_create_promise(env, &context.deferred, &result));
    } else {
        NAPI_CALL(env, napi_get_undefined(env, &result));
    }

    napi_value resourceName = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, funcName.data(), funcName.length(), &resourceName));
    AsyncContext<T> *pContext = asyncContext.release();
    NAPI_CALL(env, napi_create_async_work(
        env, nullptr, resourceName, exec, complete, static_cast<void *>(pContext), &context.work));
    if (napi_queue_async_work_with_qos(env, context.work, napi_qos_default) != napi_ok) {
        delete pContext;
        result = nullptr;
    }
    return result;
}

template<typename AsyncContextType, typename... Ts>
napi_value NapiCreateAsyncWork2(const AsyncPara &para, AsyncContextType *asyncContext, std::tuple<Ts...> &theTuple)
{
    if (asyncContext == nullptr) {
        return nullptr;
    }

    napi_env env = para.env;
    BaseContext &context = asyncContext->asyncContext.context;

    size_t argc = sizeof...(Ts);
    napi_value argv[sizeof...(Ts)]{nullptr};
    NAPI_CALL(env, napi_get_cb_info(env, para.info, &argc, argv, nullptr, nullptr));

    std::optional<NapiError> errCode = MatchParameters(env, argv, argc, theTuple);
    if (errCode.has_value()) {
        JsError error = NapiUtil::ConverEsimErrorMessageForJs(errCode.value());
        NapiUtil::ThrowError(env, error.errorCode, error.errorMessage);
        return nullptr;
    }

    napi_value result = nullptr;
    if (context.callbackRef == nullptr) {
        NAPI_CALL(env, napi_create_promise(env, &context.deferred, &result));
    } else {
        NAPI_CALL(env, napi_get_undefined(env, &result));
    }

    napi_value resourceName = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, para.funcName.c_str(), para.funcName.length(), &resourceName));
    NAPI_CALL(env, napi_create_async_work(env, nullptr, resourceName, para.execute, para.complete,
        static_cast<void *>(asyncContext), &context.work));
    return result;
}

template<typename T>
void NapiAsyncBaseCompleteCallback(
    napi_env env, const AsyncContext<T> &asyncContext, JsError error, bool funcIgnoreReturnVal = false)
{
    const BaseContext &context = asyncContext.context;
    if (context.deferred != nullptr && !context.resolved) {
        napi_value errorMessage = NapiUtil::CreateErrorMessage(env, error.errorMessage, error.errorCode);
        NAPI_CALL_RETURN_VOID(env, napi_reject_deferred(env, context.deferred, errorMessage));
        NAPI_CALL_RETURN_VOID(env, napi_delete_async_work(env, context.work));
        return;
    }

    if (context.deferred != nullptr && context.resolved) {
        napi_value resValue =
            (funcIgnoreReturnVal ? NapiUtil::CreateUndefined(env) : GetNapiValue(env, asyncContext.callbackVal));
        NAPI_CALL_RETURN_VOID(env, napi_resolve_deferred(env, context.deferred, resValue));
        NAPI_CALL_RETURN_VOID(env, napi_delete_async_work(env, context.work));
        return;
    }

    napi_value res =
        (funcIgnoreReturnVal ? NapiUtil::CreateUndefined(env) : GetNapiValue(env, asyncContext.callbackVal));
    napi_value callbackValue[] { NapiUtil::CreateUndefined(env), res };
    if (!context.resolved) {
        callbackValue[0] = NapiUtil::CreateErrorMessage(env, error.errorMessage, error.errorCode);
        callbackValue[1] = NapiUtil::CreateUndefined(env);
    }
    napi_value undefined = nullptr;
    napi_value callback = nullptr;
    napi_value result = nullptr;
    NAPI_CALL_RETURN_VOID(env, napi_get_undefined(env, &undefined));
    NAPI_CALL_RETURN_VOID(env, napi_get_reference_value(env, context.callbackRef, &callback));
    NAPI_CALL_RETURN_VOID(
        env, napi_call_function(env, undefined, callback, std::size(callbackValue), callbackValue, &result));
    NAPI_CALL_RETURN_VOID(env, napi_delete_reference(env, context.callbackRef));
    NAPI_CALL_RETURN_VOID(env, napi_delete_async_work(env, context.work));
}

template<typename T>
void NapiAsyncPermissionCompleteCallback(napi_env env, napi_status status, const AsyncContext<T> &asyncContext,
    bool funcIgnoreReturnVal, PermissionPara permissionPara)
{
    if (status != napi_ok) {
        napi_throw_type_error(env, nullptr, "excute failed");
        return;
    }

    JsError error = NapiUtil::ConverEsimErrorMessageWithPermissionForJs(
        asyncContext.context.errorCode, permissionPara.func, permissionPara.permission);
    NapiAsyncBaseCompleteCallback(env, asyncContext, error, funcIgnoreReturnVal);
}

template <typename T>
void NapiAsyncCommomCompleteCallback(
    napi_env env, napi_status status, const AsyncContext<T> &asyncContext, bool funcIgnoreReturnVal)
{
    if (status != napi_ok) {
        napi_throw_type_error(env, nullptr, "excute failed");
        return;
    }

    JsError error = NapiUtil::ConverErrorMessageForJs(asyncContext.context.errorCode);
    NapiAsyncBaseCompleteCallback(env, asyncContext, error, funcIgnoreReturnVal);
}

napi_value EuiccInfoConversion(napi_env env, const EuiccInfo &resultInfo)
{
    napi_value val = nullptr;
    napi_create_object(env, &val);
    SetPropertyToNapiObject(env, val, "osVersion", NapiUtil::ToUtf8(resultInfo.osVersion_));

    return val;
}

napi_value DownloadProfileResultConversion(napi_env env, const DownloadProfileResult &resultInfo)
{
    napi_value val = nullptr;
    napi_create_object(env, &val);
    SetPropertyToNapiObject(env, val, "responseResult", static_cast<int32_t>(resultInfo.result_));
    SetPropertyToNapiObject(env, val, "solvableErrors", static_cast<int32_t>(resultInfo.resolvableErrors_));
    SetPropertyToNapiObject(env, val, "cardId", resultInfo.cardId_);

    return val;
}

napi_value AccessRuleInfoConversion(napi_env env, const AccessRule &accessInfo)
{
    napi_value val = nullptr;
    napi_create_object(env, &val);
    SetPropertyToNapiObject(env, val, "certificateHashHexStr", NapiUtil::ToUtf8(accessInfo.certificateHashHexStr_));
    SetPropertyToNapiObject(env, val, "packageName", NapiUtil::ToUtf8(accessInfo.packageName_));
    SetPropertyToNapiObject(env, val, "accessType", accessInfo.accessType_);

    return val;
}

napi_value ProfileInfoConversion(napi_env env, const DownloadableProfile &profileInfo)
{
    napi_value val = nullptr;
    napi_create_object(env, &val);
    SetPropertyToNapiObject(env, val, "activationCode", NapiUtil::ToUtf8(profileInfo.encodedActivationCode_));
    SetPropertyToNapiObject(env, val, "confirmationCode", NapiUtil::ToUtf8(profileInfo.confirmationCode_));
    SetPropertyToNapiObject(env, val, "carrierName", NapiUtil::ToUtf8(profileInfo.carrierName_));
    napi_value resultArray = nullptr;
    napi_create_array(env, &resultArray);
    for (size_t i = 0; i < profileInfo.accessRules_.size(); i++) {
        napi_value res = AccessRuleInfoConversion(env, profileInfo.accessRules_.at(i));
        napi_set_element(env, resultArray, i, res);
    }
    napi_set_named_property(env, val, "accessRules", resultArray);

    return val;
}

napi_value ProfileResultListConversion(napi_env env, const GetDownloadableProfilesResult &resultListInfo)
{
    napi_value val = nullptr;
    napi_create_object(env, &val);
    SetPropertyToNapiObject(env, val, "responseResult", static_cast<int32_t>(resultListInfo.result_));
    napi_value resultArray = nullptr;
    napi_create_array(env, &resultArray);
    for (size_t i = 0; i < resultListInfo.downloadableProfiles_.size(); i++) {
        napi_value res = ProfileInfoConversion(env, resultListInfo.downloadableProfiles_.at(i));
        napi_set_element(env, resultArray, i, res);
    }
    napi_set_named_property(env, val, "downloadableProfiles", resultArray);

    return val;
}

napi_value MetadataResultConversion(napi_env env, const GetDownloadableProfileMetadataResult &metadataInfo)
{
    napi_value val = nullptr;
    napi_create_object(env, &val);
    napi_value res = ProfileInfoConversion(env, metadataInfo.downloadableProfiles_);
    napi_set_named_property(env, val, "downloadableProfile", res);
    SetPropertyToNapiObject(env, val, "pprType", metadataInfo.pprType_);
    SetPropertyToNapiObject(env, val, "pprFlag", metadataInfo.pprFlag_);
    SetPropertyToNapiObject(env, val, "iccid", NapiUtil::ToUtf8(metadataInfo.iccId_));
    SetPropertyToNapiObject(env, val, "serviceProviderName", NapiUtil::ToUtf8(metadataInfo.serviceProviderName_));
    SetPropertyToNapiObject(env, val, "profileName", NapiUtil::ToUtf8(metadataInfo.profileName_));
    SetPropertyToNapiObject(env, val, "profileClass", static_cast<int32_t>(metadataInfo.profileClass_));
    SetPropertyToNapiObject(env, val, "solvableErrors", static_cast<int32_t>(metadataInfo.resolvableErrors_));
    SetPropertyToNapiObject(env, val, "responseResult", static_cast<int32_t>(metadataInfo.result_));

    return val;
}

napi_value OperatorIdConversion(napi_env env, const OperatorId &operatorId)
{
    napi_value val = nullptr;
    napi_create_object(env, &val);
    SetPropertyToNapiObject(env, val, "mcc", NapiUtil::ToUtf8(operatorId.mcc_));
    SetPropertyToNapiObject(env, val, "mnc", NapiUtil::ToUtf8(operatorId.mnc_));
    SetPropertyToNapiObject(env, val, "gid1", NapiUtil::ToUtf8(operatorId.gid1_));
    SetPropertyToNapiObject(env, val, "gid2", NapiUtil::ToUtf8(operatorId.gid2_));

    return val;
}

napi_value EuiccProfileInfoConversion(napi_env env, const EuiccProfile &euiccProfileInfo)
{
    napi_value val = nullptr;
    napi_create_object(env, &val);
    SetPropertyToNapiObject(env, val, "iccid", NapiUtil::ToUtf8(euiccProfileInfo.iccId_));
    SetPropertyToNapiObject(env, val, "nickName", NapiUtil::ToUtf8(euiccProfileInfo.nickName_));
    SetPropertyToNapiObject(env, val, "serviceProviderName", NapiUtil::ToUtf8(euiccProfileInfo.serviceProviderName_));
    SetPropertyToNapiObject(env, val, "profileName", NapiUtil::ToUtf8(euiccProfileInfo.profileName_));
    SetPropertyToNapiObject(env, val, "state", static_cast<int32_t>(euiccProfileInfo.state_));
    SetPropertyToNapiObject(env, val, "profileClass", static_cast<int32_t>(euiccProfileInfo.profileClass_));
    napi_value res = OperatorIdConversion(env, euiccProfileInfo.carrierId_);
    napi_set_named_property(env, val, "operatorId", res);
    SetPropertyToNapiObject(env, val, "policyRules", static_cast<int32_t>(euiccProfileInfo.policyRules_));
    napi_value resultArray = nullptr;
    napi_create_array(env, &resultArray);
    for (size_t i = 0; i < euiccProfileInfo.accessRules_.size(); i++) {
        napi_value res = AccessRuleInfoConversion(env, euiccProfileInfo.accessRules_.at(i));
        napi_set_element(env, resultArray, i, res);
    }
    napi_set_named_property(env, val, "accessRules", resultArray);

    return val;
}

napi_value EuiccProfileListConversion(napi_env env, const GetEuiccProfileInfoListResult &euiccListInfo)
{
    napi_value val = nullptr;
    napi_create_object(env, &val);
    SetPropertyToNapiObject(env, val, "responseResult", static_cast<int32_t>(euiccListInfo.result_));
    SetPropertyToNapiObject(env, val, "isRemovable", euiccListInfo.isRemovable_);
    napi_value resultArray = nullptr;
    napi_create_array(env, &resultArray);
    for (size_t i = 0; i < euiccListInfo.profiles_.size(); i++) {
        napi_value res = EuiccProfileInfoConversion(env, euiccListInfo.profiles_.at(i));
        napi_set_element(env, resultArray, i, res);
    }
    napi_set_named_property(env, val, "profiles", resultArray);

    return val;
}

AccessRule GetAccessRuleInfo(AsyncAccessRule &accessType)
{
    AccessRule access;
    access.certificateHashHexStr_ = NapiUtil::ToUtf16(accessType.certificateHashHexStr.data());
    access.packageName_ = NapiUtil::ToUtf16(accessType.packageName.data());
    access.accessType_ = accessType.accessType;

    return access;
}

DownloadableProfile GetProfileInfo(AsyncDownloadableProfile &profileInfo)
{
    DownloadableProfile profile;
    profile.encodedActivationCode_ = NapiUtil::ToUtf16(profileInfo.activationCode.data());
    profile.confirmationCode_ = NapiUtil::ToUtf16(profileInfo.confirmationCode.data());
    profile.carrierName_ = NapiUtil::ToUtf16(profileInfo.carrierName.data());

    for (size_t i = 0; i < profileInfo.accessRules.size(); i++) {
        AccessRule access = GetAccessRuleInfo(profileInfo.accessRules.at(i));
        profile.accessRules_.push_back(std::move(access));
    }

    return profile;
}

void AccessRuleInfoAnalyze(napi_env env, napi_value arg, AsyncAccessRule &accessType)
{
    napi_value hashState = NapiUtil::GetNamedProperty(env, arg, "certificateHashHexStr");
    if (hashState) {
        char hashHexStr[ARRAY_SIZE] = {0};
        NapiValueToCppValue(env, hashState, napi_string, hashHexStr);
        accessType.certificateHashHexStr = std::string(hashHexStr);
    }

    napi_value nameState = NapiUtil::GetNamedProperty(env, arg, "packageName");
    if (nameState) {
        char nameStr[ARRAY_SIZE] = {0};
        NapiValueToCppValue(env, nameState, napi_string, nameStr);
        accessType.packageName = std::string(nameStr);
    }

    napi_value type = NapiUtil::GetNamedProperty(env, arg, "accessType");
    if (type) {
        NapiValueToCppValue(env, type, napi_number, &accessType.accessType);
    }
}

void ProfileInfoAnalyze(napi_env env, napi_value arg, AsyncDownloadableProfile &profileInfo)
{
    napi_value activateState = NapiUtil::GetNamedProperty(env, arg, "activationCode");
    if (activateState) {
        char activationStr[ARRAY_SIZE] = {0};
        NapiValueToCppValue(env, activateState, napi_string, activationStr);
        profileInfo.activationCode = std::string(activationStr);
    }

    napi_value confirmState = NapiUtil::GetNamedProperty(env, arg, "confirmationCode");
    if (confirmState) {
        char confirmationStr[ARRAY_SIZE] = {0};
        NapiValueToCppValue(env, confirmState, napi_string, confirmationStr);
        profileInfo.confirmationCode = std::string(confirmationStr);
    }

    napi_value nameState = NapiUtil::GetNamedProperty(env, arg, "carrierName");
    if (nameState) {
        char carrierStr[ARRAY_SIZE] = {0};
        NapiValueToCppValue(env, nameState, napi_string, carrierStr);
        profileInfo.carrierName = std::string(carrierStr);
    }

    napi_value ruleState = NapiUtil::GetNamedProperty(env, arg, "accessRules");
    if (ruleState) {
        uint32_t array_length;
        napi_get_array_length(env, ruleState, &array_length);
        for (uint32_t i = 0; i < array_length; i++) {
            napi_value name;
            if (napi_get_element(env, ruleState, i, &name) != napi_ok) {
                TELEPHONY_LOGE("accessRules get element fail");
            }
            AsyncAccessRule accessRuleInfo;
            AccessRuleInfoAnalyze(env, name, accessRuleInfo);
            profileInfo.accessRules.push_back(std::move(accessRuleInfo));
        }
    }
}

void ConfigurationInfoAnalyze(napi_env env, napi_value arg, AsyncDownloadConfiguration &configuration)
{
    napi_value switchState = NapiUtil::GetNamedProperty(env, arg, "switchAfterDownload");
    if (switchState) {
        NapiValueToCppValue(env, switchState, napi_boolean, &configuration.switchAfterDownload);
    }

    napi_value forceState = NapiUtil::GetNamedProperty(env, arg, "forceDisableProfile");
    if (forceState) {
        NapiValueToCppValue(env, forceState, napi_boolean, &configuration.forceDisableProfile);
    }

    napi_value alowState = NapiUtil::GetNamedProperty(env, arg, "isPprAllowed");
    if (alowState) {
        NapiValueToCppValue(env, alowState, napi_boolean, &configuration.isPprAllowed);
    }
}

ResetOption GetDefaultResetOption(void)
{
    return ResetOption::DELETE_OPERATIONAL_PROFILES;
}

napi_value GetEid(napi_env env, napi_callback_info info)
{
    size_t parameterCount = PARAMETER_COUNT_ONE;
    napi_value parameters[] = { nullptr };
    napi_get_cb_info(env, info, &parameterCount, parameters, nullptr, nullptr);
    std::string id;
    napi_value value = nullptr;
    if (parameterCount != PARAMETER_COUNT_ONE) {
        TELEPHONY_LOGE("GetEid parameter count is incorrect");
        NAPI_CALL(env, napi_create_string_utf8(env, id.c_str(), id.length(), &value));
        return value;
    }
    int32_t slotId = UNDEFINED_VALUE;
    if (napi_get_value_int32(env, parameters[0], &slotId) != napi_ok) {
        TELEPHONY_LOGE("GetEid convert parameter fail");
        NAPI_CALL(env, napi_create_string_utf8(env, id.c_str(), id.length(), &value));
        return value;
    }
    if (IsValidSlotId(slotId)) {
        DelayedRefSingleton<EsimServiceClient>::GetInstance().GetEid(slotId, id);
    }
    NAPI_CALL(env, napi_create_string_utf8(env, id.c_str(), id.length(), &value));
    return value;
}

napi_value IsSupported(napi_env env, napi_callback_info info)
{
    size_t parameterCount = PARAMETER_COUNT_ONE;
    napi_value parameters[] = { nullptr };
    napi_get_cb_info(env, info, &parameterCount, parameters, nullptr, nullptr);
    bool isSupported = false;
    napi_value value = nullptr;
    if (parameterCount != PARAMETER_COUNT_ONE) {
        TELEPHONY_LOGE("isSupported parameter count is incorrect");
        NAPI_CALL(env, napi_create_int32(env, isSupported, &value));
        return value;
    }
    int32_t slotId = UNDEFINED_VALUE;
    if (napi_get_value_int32(env, parameters[0], &slotId) != napi_ok) {
        TELEPHONY_LOGE("isSupported convert parameter fail");
        NAPI_CALL(env, napi_create_int32(env, isSupported, &value));
        return value;
    }
    if (IsValidSlotId(slotId)) {
        isSupported = DelayedRefSingleton<EsimServiceClient>::GetInstance().IsSupported(slotId);
    }
    NAPI_CALL(env, napi_get_boolean(env, isSupported, &value));
    return value;
}

void NativeAddProfile(napi_env env, void *data)
{
    if (data == nullptr) {
        return;
    }
    AsyncAddProfileInfo *addProfileContext = static_cast<AsyncAddProfileInfo *>(data);
    int32_t slotId = GetDefaultEsimSlotId<int32_t>();
    DownloadableProfile profile = GetProfileInfo(addProfileContext->profile);
    int32_t errcode = DelayedRefSingleton<EsimServiceClient>::GetInstance().AddProfile(slotId, profile);
    if (errcode == ERROR_NONE) {
        addProfileContext->asyncContext.context.resolved = true;
        addProfileContext->asyncContext.callbackVal = true;
    } else {
        addProfileContext->asyncContext.context.resolved = false;
        addProfileContext->asyncContext.callbackVal = false;
    }
}

void AddProfileCallback(napi_env env, napi_status status, void *data)
{
    NAPI_CALL_RETURN_VOID(env, (data == nullptr ? napi_invalid_arg : napi_ok));
    std::unique_ptr<AsyncAddProfileInfo> context(static_cast<AsyncAddProfileInfo *>(data));
    if (context == nullptr) {
        TELEPHONY_LOGE("AddProfileCallback context is nullptr");
        return;
    }
    NapiAsyncCommomCompleteCallback(env, status, context->asyncContext, false);
}

napi_value AddProfile(napi_env env, napi_callback_info info)
{
    auto addProfile = new (std::nothrow) AsyncAddProfileInfo();
    if (addProfile == nullptr) {
        return nullptr;
    }
    BaseContext &context = addProfile->asyncContext.context;
    napi_value object = NapiUtil::CreateUndefined(env);
    auto initPara = std::make_tuple(&object, &context.callbackRef);
    AsyncPara para{
        .funcName = "AddProfile",
        .env = env,
        .info = info,
        .execute = NativeAddProfile,
        .complete = AddProfileCallback,
    };
    napi_value result = NapiCreateAsyncWork2<AsyncAddProfileInfo>(para, addProfile, initPara);
    if (result) {
        ProfileInfoAnalyze(env, object, addProfile->profile);
        NAPI_CALL(env, napi_queue_async_work_with_qos(env, context.work, napi_qos_default));
    }
    return result;
}

void NativeGetEuiccInfo(napi_env env, void *data)
{
    if (data == nullptr) {
        return;
    }
    auto euiccContext = static_cast<AsyncEuiccInfo *>(data);
    if (!IsValidSlotId(euiccContext->asyncContext.slotId)) {
        TELEPHONY_LOGE("NativeGetEuiccInfo slotId is invalid");
        euiccContext->asyncContext.context.errorCode = ERROR_SLOT_ID_INVALID;
        return;
    }
    std::unique_ptr<GetEuiccInformationCallback> callback = std::make_unique<GetEuiccInformationCallback>(euiccContext);
    int32_t errorCode = DelayedRefSingleton<EsimServiceClient>::GetInstance().GetEuiccInfo(
        euiccContext->asyncContext.slotId, callback.release());
    std::unique_lock<std::mutex> callbackLock(euiccContext->asyncContext.callbackMutex);
    TELEPHONY_LOGI("NAPI NativeGetEuiccInfo %{public}d", errorCode);
    euiccContext->asyncContext.context.errorCode = errorCode;
    if (errorCode == TELEPHONY_SUCCESS) {
        euiccContext->asyncContext.cv.wait_for(callbackLock, std::chrono::seconds(WAIT_TIME_SECOND),
            [euiccContext] { return euiccContext->asyncContext.callbackEnd; });
        TELEPHONY_LOGI("NativeGetEuiccInfo after callback end");
    }
}

void GetEuiccInfoCallback(napi_env env, napi_status status, void *data)
{
    NAPI_CALL_RETURN_VOID(env, (data == nullptr ? napi_invalid_arg : napi_ok));
    std::unique_ptr<AsyncEuiccInfo> context(static_cast<AsyncEuiccInfo *>(data));
    if (context == nullptr) {
        TELEPHONY_LOGE("GetEuiccInfoCallback context is nullptr");
        return;
    }
    AsyncContext<napi_value> &asyncContext = context->asyncContext;
    if (asyncContext.context.resolved) {
        asyncContext.callbackVal = EuiccInfoConversion(env, context->result);
    }
    NapiAsyncPermissionCompleteCallback(
        env, status, context->asyncContext, false, { "GetEuiccInfo", Permission::GET_TELEPHONY_ESIM_STATE });
}

napi_value GetEuiccInfo(napi_env env, napi_callback_info info)
{
    auto euiccInfo = new (std::nothrow) AsyncEuiccInfo();
    if (euiccInfo == nullptr) {
        return nullptr;
    }
    BaseContext &context = euiccInfo->asyncContext.context;

    auto initPara = std::make_tuple(&euiccInfo->asyncContext.slotId, &context.callbackRef);
    AsyncPara para {
        .funcName = "GetEuiccInfo",
        .env = env,
        .info = info,
        .execute = NativeGetEuiccInfo,
        .complete = GetEuiccInfoCallback,
    };
    napi_value result = NapiCreateAsyncWork2<AsyncEuiccInfo>(para, euiccInfo, initPara);
    if (result) {
        NAPI_CALL(env, napi_queue_async_work_with_qos(env, context.work, napi_qos_default));
    }
    return result;
}

void NativeGetDefaultSmdpAddress(napi_env env, void *data)
{
    if (data == nullptr) {
        return;
    }
    auto contextInfo = static_cast<AsyncContext<std::string> *>(data);
    if (!IsValidSlotId(contextInfo->slotId)) {
        TELEPHONY_LOGE("NativeGetDefaultSmdpAddress slotId is invalid");
        contextInfo->context.errorCode = ERROR_SLOT_ID_INVALID;
        return;
    }
    std::unique_ptr<GetDefaultSmdpAddressResultCallback> callback =
        std::make_unique<GetDefaultSmdpAddressResultCallback>(contextInfo);
    int32_t errorCode = DelayedRefSingleton<EsimServiceClient>::GetInstance().GetDefaultSmdpAddress(
        contextInfo->slotId, callback.release());
    contextInfo->context.errorCode = errorCode;
    std::unique_lock<std::mutex> callbackLock(contextInfo->callbackMutex);
    TELEPHONY_LOGI("NAPI NativeGetDefaultSmdpAddress %{public}d", errorCode);
    contextInfo->context.errorCode = errorCode;
    if (errorCode == TELEPHONY_SUCCESS) {
        contextInfo->cv.wait_for(callbackLock, std::chrono::seconds(WAIT_TIME_SECOND),
            [contextInfo] { return contextInfo->callbackEnd; });
        TELEPHONY_LOGI("NativeGetDefaultSmdpAddress after callback end");
    }
}

void GetDefaultSmdpAddressCallback(napi_env env, napi_status status, void *data)
{
    NAPI_CALL_RETURN_VOID(env, (data == nullptr ? napi_invalid_arg : napi_ok));
    std::unique_ptr<AsyncContext<std::string>> context(static_cast<AsyncContext<std::string> *>(data));
    if (context == nullptr) {
        TELEPHONY_LOGE("GetDefaultSmdpAddressCallback context is nullptr");
        return;
    }
    NapiAsyncPermissionCompleteCallback(
        env, status, *context, false, { "GetDefaultSmdpAddress", Permission::GET_TELEPHONY_ESIM_STATE });
}

napi_value GetDefaultSmdpAddress(napi_env env, napi_callback_info info)
{
    return NapiCreateAsyncWork<std::string, NativeGetDefaultSmdpAddress, GetDefaultSmdpAddressCallback>(env,
        info, "GetDefaultSmdpAddress");
}

void NativeSetDefaultSmdpAddress(napi_env env, void *data)
{
    if (data == nullptr) {
        return;
    }
    auto context = static_cast<AsyncContextInfo *>(data);
    if (!IsValidSlotId(context->asyncContext.slotId)) {
        TELEPHONY_LOGE("NativeSetDefaultSmdpAddress slotId is invalid");
        context->asyncContext.context.errorCode = ERROR_SLOT_ID_INVALID;
        return;
    }

    std::unique_ptr<SetDefaultSmdpAddressResultCallback> callback =
        std::make_unique<SetDefaultSmdpAddressResultCallback>(context);
    int32_t errorCode = DelayedRefSingleton<EsimServiceClient>::GetInstance().SetDefaultSmdpAddress(
        context->asyncContext.slotId, context->inputStr, callback.release());
    std::unique_lock<std::mutex> callbackLock(context->asyncContext.callbackMutex);
    TELEPHONY_LOGI("NAPI NativeSetDefaultSmdpAddress %{public}d", errorCode);

    if (errorCode == TELEPHONY_SUCCESS) {
        context->asyncContext.cv.wait_for(callbackLock, std::chrono::seconds(WAIT_TIME_SECOND),
            [context] { return context->asyncContext.callbackEnd; });
        TELEPHONY_LOGI("NativeSetDefaultSmdpAddress after callback end");
    }
    context->asyncContext.context.errorCode = errorCode;
}

void SetDefaultSmdpAddressCallback(napi_env env, napi_status status, void *data)
{
    NAPI_CALL_RETURN_VOID(env, (data == nullptr ? napi_invalid_arg : napi_ok));
    std::unique_ptr<AsyncContextInfo> context(static_cast<AsyncContextInfo *>(data));
    if (context == nullptr) {
        TELEPHONY_LOGE("SetDefaultSmdpAddressCallback context is nullptr");
        return;
    }
    NapiAsyncPermissionCompleteCallback(
        env, status, context->asyncContext, false, { "SetDefaultSmdpAddress", Permission::SET_TELEPHONY_ESIM_STATE });
}

napi_value SetDefaultSmdpAddress(napi_env env, napi_callback_info info)
{
    auto asyncContext = new (std::nothrow) AsyncContextInfo();
    if (asyncContext == nullptr) {
        return nullptr;
    }
    BaseContext &context = asyncContext->asyncContext.context;

    char inputTepStr[ARRAY_SIZE] = {0};
    auto initPara = std::make_tuple(&asyncContext->asyncContext.slotId, inputTepStr, &context.callbackRef);
    AsyncPara para {
        .funcName = "SetDefaultSmdpAddress",
        .env = env,
        .info = info,
        .execute = NativeSetDefaultSmdpAddress,
        .complete = SetDefaultSmdpAddressCallback,
    };
    napi_value result = NapiCreateAsyncWork2<AsyncContextInfo>(para, asyncContext, initPara);
    if (result) {
        asyncContext->inputStr = std::string(inputTepStr);
        NAPI_CALL(env, napi_queue_async_work_with_qos(env, context.work, napi_qos_default));
    }
    return result;
}

void NativeSwitchToProfile(napi_env env, void *data)
{
    if (data == nullptr) {
        return;
    }

    auto profileContext = static_cast<AsyncSwitchProfileInfo *>(data);
    if (!IsValidSlotId(profileContext->asyncContext.slotId)) {
        TELEPHONY_LOGE("NativeGetEuiccInfo slotId is invalid");
        profileContext->asyncContext.context.errorCode = ERROR_SLOT_ID_INVALID;
        return;
    }
    std::unique_ptr<SwitchToProfileResultCallback> callback =
        std::make_unique<SwitchToProfileResultCallback>(profileContext);
    int32_t errorCode = DelayedRefSingleton<EsimServiceClient>::GetInstance().SwitchToProfile(
        profileContext->asyncContext.slotId, profileContext->portIndex, profileContext->iccid,
        profileContext->forceDisableProfile, callback.release());
    std::unique_lock<std::mutex> callbackLock(profileContext->asyncContext.callbackMutex);
    TELEPHONY_LOGI("NAPI NativeSwitchToProfile %{public}d", errorCode);
    profileContext->asyncContext.context.errorCode = errorCode;
    if (errorCode == TELEPHONY_SUCCESS) {
        profileContext->asyncContext.cv.wait_for(callbackLock, std::chrono::seconds(WAIT_TIME_SECOND),
            [profileContext] { return profileContext->asyncContext.callbackEnd; });
        TELEPHONY_LOGI("NativeSwitchToProfile after callback end");
    }
}

void SwitchToProfileCallback(napi_env env, napi_status status, void *data)
{
    NAPI_CALL_RETURN_VOID(env, (data == nullptr ? napi_invalid_arg : napi_ok));
    std::unique_ptr<AsyncSwitchProfileInfo> context(static_cast<AsyncSwitchProfileInfo *>(data));
    if (context == nullptr) {
        TELEPHONY_LOGE("SwitchToProfileCallback context is nullptr");
        return;
    }
    NapiAsyncPermissionCompleteCallback(
        env, status, context->asyncContext, false, { "SwitchToProfile", Permission::SET_TELEPHONY_ESIM_STATE });
}

napi_value SwitchToProfile(napi_env env, napi_callback_info info)
{
    auto profileContext = new (std::nothrow) AsyncSwitchProfileInfo();
    if (profileContext == nullptr) {
        return nullptr;
    }
    BaseContext &context = profileContext->asyncContext.context;

    char iccIdStr[ARRAY_SIZE] = {0};
    auto initPara = std::make_tuple(&profileContext->asyncContext.slotId, &profileContext->portIndex,
        iccIdStr, &profileContext->forceDisableProfile, &context.callbackRef);

    AsyncPara para {
        .funcName = "SwitchToProfile",
        .env = env,
        .info = info,
        .execute = NativeSwitchToProfile,
        .complete = SwitchToProfileCallback,
    };
    napi_value result = NapiCreateAsyncWork2<AsyncSwitchProfileInfo>(para, profileContext, initPara);
    if (result) {
        profileContext->iccid = std::string(iccIdStr);
        NAPI_CALL(env, napi_queue_async_work_with_qos(env, context.work, napi_qos_default));
    }
    return result;
}

void NativeDeleteProfile(napi_env env, void *data)
{
    if (data == nullptr) {
        return;
    }

    auto context = static_cast<AsyncContextInfo *>(data);
    if (!IsValidSlotId(context->asyncContext.slotId)) {
        TELEPHONY_LOGE("NativeGetEuiccInfo slotId is invalid");
        context->asyncContext.context.errorCode = ERROR_SLOT_ID_INVALID;
        return;
    }
    std::unique_ptr<DeleteProfileResultCallback> callback = std::make_unique<DeleteProfileResultCallback>(context);
    int32_t errorCode = DelayedRefSingleton<EsimServiceClient>::GetInstance().DeleteProfile(
        context->asyncContext.slotId, context->inputStr, callback.release());
    std::unique_lock<std::mutex> callbackLock(context->asyncContext.callbackMutex);
    TELEPHONY_LOGI("NAPI NativeDeleteProfile %{public}d", errorCode);
    context->asyncContext.context.errorCode = errorCode;
    if (errorCode == TELEPHONY_SUCCESS) {
        context->asyncContext.cv.wait_for(callbackLock, std::chrono::seconds(WAIT_TIME_SECOND),
            [context] { return context->asyncContext.callbackEnd; });
        TELEPHONY_LOGI("NativeDeleteProfile after callback end");
    }
}

void DeleteProfileCallback(napi_env env, napi_status status, void *data)
{
    NAPI_CALL_RETURN_VOID(env, (data == nullptr ? napi_invalid_arg : napi_ok));
    std::unique_ptr<AsyncContextInfo> context(static_cast<AsyncContextInfo *>(data));
    if (context == nullptr) {
        TELEPHONY_LOGE("DeleteProfileCallback context is nullptr");
        return;
    }
    NapiAsyncPermissionCompleteCallback(
        env, status, context->asyncContext, false, { "DeleteProfile", Permission::SET_TELEPHONY_ESIM_STATE });
}

napi_value DeleteProfile(napi_env env, napi_callback_info info)
{
    auto asyncContext = new (std::nothrow) AsyncContextInfo();
    if (asyncContext == nullptr) {
        return nullptr;
    }
    BaseContext &context = asyncContext->asyncContext.context;

    char inputTmpStr[ARRAY_SIZE] = {0};
    auto initPara = std::make_tuple(&asyncContext->asyncContext.slotId, inputTmpStr, &context.callbackRef);
    AsyncPara para {
        .funcName = "DeleteProfile",
        .env = env,
        .info = info,
        .execute = NativeDeleteProfile,
        .complete = DeleteProfileCallback,
    };
    napi_value result = NapiCreateAsyncWork2<AsyncContextInfo>(para, asyncContext, initPara);
    if (result) {
        asyncContext->inputStr = std::string(inputTmpStr);
        NAPI_CALL(env, napi_queue_async_work_with_qos(env, context.work, napi_qos_default));
    }
    return result;
}

void NativeResetMemory(napi_env env, void *data)
{
    if (data == nullptr) {
        return;
    }

    auto profileContext = static_cast<AsyncResetMemory *>(data);
    if (!IsValidSlotId(profileContext->asyncContext.slotId)) {
        TELEPHONY_LOGE("NativeGetEuiccInfo slotId is invalid");
        profileContext->asyncContext.context.errorCode = ERROR_SLOT_ID_INVALID;
        return;
    }

    std::unique_ptr<ResetMemoryResultCallback> callback = std::make_unique<ResetMemoryResultCallback>(profileContext);
    if (resetParameterCount == PARAMETER_COUNT_ONE) {
        profileContext->option = static_cast<int32_t>(GetDefaultResetOption());
    }
    int32_t errorCode = DelayedRefSingleton<EsimServiceClient>::GetInstance().ResetMemory(
        profileContext->asyncContext.slotId, profileContext->option, callback.release());
    std::unique_lock<std::mutex> callbackLock(profileContext->asyncContext.callbackMutex);
    TELEPHONY_LOGI("NAPI NativeResetMemory %{public}d", errorCode);
    profileContext->asyncContext.context.errorCode = errorCode;
    if (errorCode == TELEPHONY_SUCCESS) {
        profileContext->asyncContext.cv.wait_for(callbackLock, std::chrono::seconds(WAIT_TIME_SECOND),
            [profileContext] { return profileContext->asyncContext.callbackEnd; });
        TELEPHONY_LOGI("NativeResetMemory after callback end");
    }
}

void ResetMemoryCallback(napi_env env, napi_status status, void *data)
{
    NAPI_CALL_RETURN_VOID(env, (data == nullptr ? napi_invalid_arg : napi_ok));
    std::unique_ptr<AsyncResetMemory> context(static_cast<AsyncResetMemory *>(data));
    if (context == nullptr) {
        TELEPHONY_LOGE("ResetMemoryCallback context is nullptr");
        return;
    }
    NapiAsyncPermissionCompleteCallback(
        env, status, context->asyncContext, false, { "ResetMemory", Permission::SET_TELEPHONY_ESIM_STATE });
}

napi_value ResetMemory(napi_env env, napi_callback_info info)
{
    resetParameterCount = 0;
    napi_value parameters[PARAMETER_COUNT_TWO] = { 0 };
    napi_value thisVar = nullptr;
    void *data = nullptr;
    napi_get_cb_info(env, info, &resetParameterCount, parameters, &thisVar, &data);
    if (resetParameterCount == PARAMETER_COUNT_ONE) {
        return NapiCreateAsyncWork<int32_t, NativeResetMemory, ResetMemoryCallback>(env, info, "ResetMemory");
    }

    auto profileContext = new (std::nothrow) AsyncResetMemory();
    if (profileContext == nullptr) {
        return nullptr;
    }
    BaseContext &context = profileContext->asyncContext.context;
    auto initPara = std::make_tuple(&profileContext->asyncContext.slotId,
        &profileContext->option, &context.callbackRef);

    AsyncPara para {
        .funcName = "ResetMemory",
        .env = env,
        .info = info,
        .execute = NativeResetMemory,
        .complete = ResetMemoryCallback,
    };
    napi_value result = NapiCreateAsyncWork2<AsyncResetMemory>(para, profileContext, initPara);
    if (result) {
        NAPI_CALL(env, napi_queue_async_work_with_qos(env, context.work, napi_qos_default));
    }
    return result;
}

void NativeDownloadProfile(napi_env env, void *data)
{
    if (data == nullptr) {
        return;
    }

    auto profileContext = static_cast<AsyncDownloadProfileInfo *>(data);
    if (!IsValidSlotId(profileContext->asyncContext.slotId)) {
        TELEPHONY_LOGE("NativeGetEuiccInfo slotId is invalid");
        profileContext->asyncContext.context.errorCode = ERROR_SLOT_ID_INVALID;
        return;
    }

    std::unique_ptr<DownloadProfileResultCallback> callback =
        std::make_unique<DownloadProfileResultCallback>(profileContext);
    DownloadProfileResult result;
    DownloadProfileConfigInfo configInfo;
    configInfo.portIndex_ = profileContext->portIndex;
    configInfo.isSwitchAfterDownload_ = profileContext->configuration.switchAfterDownload;
    configInfo.isForceDeactivateSim_ = profileContext->configuration.forceDisableProfile;
    configInfo.isPprAllowed_ = profileContext->configuration.isPprAllowed;
    DownloadableProfile profile = GetProfileInfo(profileContext->profile);
    int32_t errorCode = DelayedRefSingleton<EsimServiceClient>::GetInstance().DownloadProfile(
        profileContext->asyncContext.slotId, configInfo, profile, callback.release());
    std::unique_lock<std::mutex> callbackLock(profileContext->asyncContext.callbackMutex);
    TELEPHONY_LOGI("NAPI NativeDownloadProfile %{public}d", errorCode);
    profileContext->asyncContext.context.errorCode = errorCode;
    if (errorCode == TELEPHONY_SUCCESS) {
        profileContext->asyncContext.cv.wait_for(callbackLock, std::chrono::seconds(WAIT_TIME_SECOND),
            [profileContext] { return profileContext->asyncContext.callbackEnd; });
        TELEPHONY_LOGI("NativeDownloadProfile after callback end");
    }
}

void DownloadProfileCallback(napi_env env, napi_status status, void *data)
{
    NAPI_CALL_RETURN_VOID(env, (data == nullptr ? napi_invalid_arg : napi_ok));
    std::unique_ptr<AsyncDownloadProfileInfo> context(static_cast<AsyncDownloadProfileInfo *>(data));
    if (context == nullptr) {
        TELEPHONY_LOGE("DownloadProfileCallback context is nullptr");
        return;
    }
    AsyncContext<napi_value> &asyncContext = context->asyncContext;
    if (asyncContext.context.resolved) {
        asyncContext.callbackVal =  DownloadProfileResultConversion(env, context->result);
    }
    NapiAsyncPermissionCompleteCallback(
        env, status, context->asyncContext, false, { "DownloadProfile", Permission::SET_TELEPHONY_ESIM_STATE });
}

napi_value DownloadProfile(napi_env env, napi_callback_info info)
{
    auto profileContext = new (std::nothrow) AsyncDownloadProfileInfo();
    if (profileContext == nullptr) {
        return nullptr;
    }
    BaseContext &context = profileContext->asyncContext.context;
    napi_value profileObject = NapiUtil::CreateUndefined(env);
    napi_value configurationObject = NapiUtil::CreateUndefined(env);
    auto initPara = std::make_tuple(&profileContext->asyncContext.slotId, &profileContext->portIndex, &profileObject,
        &configurationObject, &context.callbackRef);

    AsyncPara para {
        .funcName = "DownloadProfile",
        .env = env,
        .info = info,
        .execute = NativeDownloadProfile,
        .complete = DownloadProfileCallback,
    };
    napi_value result = NapiCreateAsyncWork2<AsyncDownloadProfileInfo>(para, profileContext, initPara);
    if (result) {
        ProfileInfoAnalyze(env, profileObject, profileContext->profile);
        ConfigurationInfoAnalyze(env, configurationObject, profileContext->configuration);
        NAPI_CALL(env, napi_queue_async_work_with_qos(env, context.work, napi_qos_default));
    }
    return result;
}

void NativeGetDownloadableProfiles(napi_env env, void *data)
{
    if (data == nullptr) {
        return;
    }

    auto profileContext = static_cast<AsyncDefaultProfileList *>(data);
    if (!IsValidSlotId(profileContext->asyncContext.slotId)) {
        TELEPHONY_LOGE("NativeGetEuiccInfo slotId is invalid");
        profileContext->asyncContext.context.errorCode = ERROR_SLOT_ID_INVALID;
        return;
    }

    std::unique_ptr<GetDownloadableProfilesResultCallback> callback =
        std::make_unique<GetDownloadableProfilesResultCallback>(profileContext);
    int32_t errorCode = DelayedRefSingleton<EsimServiceClient>::GetInstance().GetDownloadableProfiles(
        profileContext->asyncContext.slotId, profileContext->portIndex,
        profileContext->forceDisableProfile, callback.release());
    std::unique_lock<std::mutex> callbackLock(profileContext->asyncContext.callbackMutex);
    TELEPHONY_LOGI("NAPI NativeGetDownloadableProfiles %{public}d", errorCode);
    profileContext->asyncContext.context.errorCode = errorCode;
    if (errorCode == TELEPHONY_SUCCESS) {
        profileContext->asyncContext.cv.wait_for(callbackLock, std::chrono::seconds(WAIT_TIME_SECOND),
            [profileContext] { return profileContext->asyncContext.callbackEnd; });
        TELEPHONY_LOGI("NativeGetDownloadableProfiles after callback end");
    }
}

void GetDownloadableProfilesCallback(napi_env env, napi_status status, void *data)
{
    NAPI_CALL_RETURN_VOID(env, (data == nullptr ? napi_invalid_arg : napi_ok));
    std::unique_ptr<AsyncDefaultProfileList> context(static_cast<AsyncDefaultProfileList *>(data));
    if (context == nullptr) {
        TELEPHONY_LOGE("GetDownloadableProfilesCallback context is nullptr");
        return;
    }
    AsyncContext<napi_value> &asyncContext = context->asyncContext;
    if (asyncContext.context.resolved) {
        asyncContext.callbackVal = ProfileResultListConversion(env, context->result);
    }
    NapiAsyncPermissionCompleteCallback(env, status, context->asyncContext, false,
        { "GetDownloadableProfiles", Permission::GET_TELEPHONY_ESIM_STATE });
}

napi_value GetDownloadableProfiles(napi_env env, napi_callback_info info)
{
    auto profileContext = new (std::nothrow) AsyncDefaultProfileList();
    if (profileContext == nullptr) {
        return nullptr;
    }
    BaseContext &context = profileContext->asyncContext.context;

    auto initPara = std::make_tuple(&profileContext->asyncContext.slotId, &profileContext->portIndex,
        &profileContext->forceDisableProfile, &context.callbackRef);

    AsyncPara para {
        .funcName = "GetDownloadableProfiles",
        .env = env,
        .info = info,
        .execute = NativeGetDownloadableProfiles,
        .complete = GetDownloadableProfilesCallback,
    };
    napi_value result = NapiCreateAsyncWork2<AsyncDefaultProfileList>(para, profileContext, initPara);
    if (result) {
        NAPI_CALL(env, napi_queue_async_work_with_qos(env, context.work, napi_qos_default));
    }
    return result;
}

void NativeGetOsuStatus(napi_env env, void *data)
{
    if (data == nullptr) {
        return;
    }
    AsyncContext<int32_t> *asyncContext = static_cast<AsyncContext<int32_t> *>(data);
    if (!IsValidSlotId(asyncContext->slotId)) {
        TELEPHONY_LOGE("NativeGetOsuStatus slotId is invalid");
        asyncContext->context.errorCode = ERROR_SLOT_ID_INVALID;
        return;
    }
    int32_t result = UNDEFINED_VALUE;
    int32_t errorCode =
        DelayedRefSingleton<EsimServiceClient>::GetInstance().GetOsuStatus(asyncContext->slotId, result);
    TELEPHONY_LOGI("NAPI NativeGetOsuStatus %{public}d", errorCode);
    if (errorCode == ERROR_NONE) {
        asyncContext->callbackVal = result;
        asyncContext->context.resolved = true;
    } else {
        asyncContext->context.resolved = false;
    }
    asyncContext->context.errorCode = errorCode;
}

void GetOsuStatusCallback(napi_env env, napi_status status, void *data)
{
    NAPI_CALL_RETURN_VOID(env, (data == nullptr ? napi_invalid_arg : napi_ok));
    std::unique_ptr<AsyncContext<int32_t>> context(static_cast<AsyncContext<int32_t> *>(data));
    if (context == nullptr) {
        TELEPHONY_LOGE("GetOsuStatusCallback context is nullptr");
        return;
    }
    NapiAsyncPermissionCompleteCallback(
        env, status, *context, false, { "GetOsuStatus", Permission::GET_TELEPHONY_ESIM_STATE });
}

napi_value GetOsuStatus(napi_env env, napi_callback_info info)
{
    return NapiCreateAsyncWork<int32_t, NativeGetOsuStatus, GetOsuStatusCallback>(env, info, "GetOsuStatus");
}

void NativeStartOsu(napi_env env, void *data)
{
    if (data == nullptr) {
        return;
    }

    auto profileContext = static_cast<AsyncContext<int32_t> *>(data);
    if (!IsValidSlotId(profileContext->slotId)) {
        TELEPHONY_LOGE("NativeGetEuiccInfo slotId is invalid");
        profileContext->context.errorCode = ERROR_SLOT_ID_INVALID;
        return;
    }

    std::unique_ptr<StartOsuResultCallback> callback = std::make_unique<StartOsuResultCallback>(profileContext);
    int32_t errorCode =
        DelayedRefSingleton<EsimServiceClient>::GetInstance().StartOsu(profileContext->slotId, callback.release());
    std::unique_lock<std::mutex> callbackLock(profileContext->callbackMutex);
    TELEPHONY_LOGI("NAPI NativeStartOsu %{public}d", errorCode);
    profileContext->context.errorCode = errorCode;
    if (errorCode == TELEPHONY_SUCCESS) {
        profileContext->cv.wait_for(callbackLock, std::chrono::seconds(WAIT_TIME_SECOND),
            [profileContext] { return profileContext->callbackEnd; });
        TELEPHONY_LOGI("NativeStartOsu after callback end");
    }
}

void StartOsuCallback(napi_env env, napi_status status, void *data)
{
    NAPI_CALL_RETURN_VOID(env, (data == nullptr ? napi_invalid_arg : napi_ok));
    std::unique_ptr<AsyncContext<int32_t>> context(static_cast<AsyncContext<int32_t> *>(data));
    if (context == nullptr) {
        TELEPHONY_LOGE("StartOsuCallback context is nullptr");
        return;
    }
    NapiAsyncPermissionCompleteCallback(
        env, status, *context, false, { "StartOsu", Permission::SET_TELEPHONY_ESIM_STATE });
}

napi_value StartOsu(napi_env env, napi_callback_info info)
{
    return NapiCreateAsyncWork<int32_t, NativeStartOsu, StartOsuCallback>(env, info, "StartOsu");
}

void NativeSetProfileNickname(napi_env env, void *data)
{
    if (data == nullptr) {
        return;
    }
    AsyncProfileNickname *setprofileNickNameContext = static_cast<AsyncProfileNickname *>(data);
    if (!IsValidSlotId(setprofileNickNameContext->asyncContext.slotId)) {
        TELEPHONY_LOGE("NativeSetProfileNickname slotId is invalid");
        setprofileNickNameContext->asyncContext.context.errorCode = ERROR_SLOT_ID_INVALID;
        return;
    }

    std::unique_ptr<SetProfileNickNameResultCallback> callback =
        std::make_unique<SetProfileNickNameResultCallback>(setprofileNickNameContext);
    int32_t errorCode = DelayedRefSingleton<EsimServiceClient>::GetInstance().SetProfileNickname(
        setprofileNickNameContext->asyncContext.slotId, setprofileNickNameContext->iccid,
        setprofileNickNameContext->nickname, callback.release());
    std::unique_lock<std::mutex> callbackLock(setprofileNickNameContext->asyncContext.callbackMutex);
    TELEPHONY_LOGI("NAPI NativeSetProfileNickname %{public}d", errorCode);
    setprofileNickNameContext->asyncContext.context.errorCode = errorCode;
    if (errorCode == TELEPHONY_SUCCESS) {
        setprofileNickNameContext->asyncContext.cv.wait_for(callbackLock, std::chrono::seconds(WAIT_TIME_SECOND),
            [setprofileNickNameContext] { return setprofileNickNameContext->asyncContext.callbackEnd; });
        TELEPHONY_LOGI("NativeDeleteProfile after callback end");
    }
}

void SetProfileNicknameCallback(napi_env env, napi_status status, void *data)
{
    NAPI_CALL_RETURN_VOID(env, (data == nullptr ? napi_invalid_arg : napi_ok));
    std::unique_ptr<AsyncProfileNickname> context(static_cast<AsyncProfileNickname *>(data));
    if (context == nullptr) {
        TELEPHONY_LOGE("SetProfileNicknameCallback context is nullptr");
        return;
    }
    NapiAsyncPermissionCompleteCallback(
        env, status, context->asyncContext, false, { "SetProfileNickname", Permission::SET_TELEPHONY_ESIM_STATE });
}

napi_value SetProfileNickname(napi_env env, napi_callback_info info)
{
    auto profileContext = new (std::nothrow) AsyncProfileNickname();
    if (profileContext == nullptr) {
        return nullptr;
    }
    BaseContext &context = profileContext->asyncContext.context;

    char iccIdStr[ARRAY_SIZE] = {0};
    char nicknameStr[ARRAY_SIZE] = {0};
    auto initPara = std::make_tuple(&profileContext->asyncContext.slotId, iccIdStr, nicknameStr, &context.callbackRef);

    AsyncPara para {
        .funcName = "SetProfileNickname",
        .env = env,
        .info = info,
        .execute = NativeSetProfileNickname,
        .complete = SetProfileNicknameCallback,
    };
    napi_value result = NapiCreateAsyncWork2<AsyncProfileNickname>(para, profileContext, initPara);
    if (result) {
        profileContext->iccid = std::string(iccIdStr);
        profileContext->nickname = std::string(nicknameStr);
        NAPI_CALL(env, napi_queue_async_work_with_qos(env, context.work, napi_qos_default));
    }
    return result;
}

void NativeCancelSession(napi_env env, void *data)
{
    if (data == nullptr) {
        return;
    }
    auto cancelSessionContext = static_cast<AsyncCancelSession *>(data);
    if (!IsValidSlotId(cancelSessionContext->asyncContext.slotId)) {
        TELEPHONY_LOGE("NativeCancelSession slotId is invalid");
        cancelSessionContext->asyncContext.context.errorCode = ERROR_SLOT_ID_INVALID;
        return;
    }

    std::unique_ptr<CancelSessionCallback> callback = std::make_unique<CancelSessionCallback>(cancelSessionContext);
    int32_t errorCode = DelayedRefSingleton<EsimServiceClient>::GetInstance().CancelSession(
        cancelSessionContext->asyncContext.slotId, cancelSessionContext->transactionId, 
        cancelSessionContext->cancelReason, callback.release());
    std::unique_lock<std::mutex> callbackLock(cancelSessionContext->asyncContext.callbackMutex);
    TELEPHONY_LOGI("NAPI NativeCancelSession %{public}d", errorCode);
    cancelSessionContext->asyncContext.context.errorCode = errorCode;
    if (errorCode == TELEPHONY_SUCCESS) {
        cancelSessionContext->asyncContext.cv.wait_for(callbackLock, std::chrono::seconds(WAIT_TIME_SECOND),
            [cancelSessionContext] { return cancelSessionContext->asyncContext.callbackEnd; });
        TELEPHONY_LOGI("NativeCancelSession after callback end");
    }
}

void CancelSessionCallback(napi_env env, napi_status status, void *data)
{
    NAPI_CALL_RETURN_VOID(env, (data == nullptr ? napi_invalid_arg : napi_ok));
    std::unique_ptr<AsyncCancelSession> context(static_cast<AsyncCancelSession *>(data));
    if (context == nullptr) {
        TELEPHONY_LOGE("CancelSessionCallback context is nullptr");
        return;
    }
    NapiAsyncPermissionCompleteCallback(
        env, status, context->asyncContext, false, { "CancelSession", Permission::SET_TELEPHONY_ESIM_STATE });
}

napi_value CancelSession(napi_env env, napi_callback_info info)
{
    auto sessionContext = new (std::nothrow) AsyncCancelSession();
    if (sessionContext == nullptr) {
        return nullptr;
    }
    BaseContext &context = sessionContext->asyncContext.context;

    char transactionIdStr[ARRAY_SIZE] = {0};
    auto initPara = std::make_tuple(&sessionContext->asyncContext.slotId, transactionIdStr,
        &sessionContext->cancelReason, &context.callbackRef);

    AsyncPara para {
        .funcName = "CancelSession",
        .env = env,
        .info = info,
        .execute = NativeCancelSession,
        .complete = CancelSessionCallback,
    };
    napi_value result = NapiCreateAsyncWork2<AsyncCancelSession>(para, sessionContext, initPara);
    if (result) {
        sessionContext->transactionId = std::string(transactionIdStr);
        NAPI_CALL(env, napi_queue_async_work_with_qos(env, context.work, napi_qos_default));
    }
    return result;
}

void NativeGetDownloadableProfileMetadata(napi_env env, void *data)
{
    if (data == nullptr) {
        return;
    }

    auto metadata = static_cast<AsyncProfileMetadataInfo *>(data);
    if (!IsValidSlotId(metadata->asyncContext.slotId)) {
        TELEPHONY_LOGE("NativeGetDownloadableProfileMetadata slotId is invalid");
        metadata->asyncContext.context.errorCode = ERROR_SLOT_ID_INVALID;
        return;
    }

    std::unique_ptr<GetDownloadableProfileMetadataResultCallback> callback =
        std::make_unique<GetDownloadableProfileMetadataResultCallback>(metadata);
    DownloadableProfile profile = GetProfileInfo(metadata->profile);
    int32_t errorCode = DelayedRefSingleton<EsimServiceClient>::GetInstance().GetDownloadableProfileMetadata(
        metadata->asyncContext.slotId, metadata->portIndex, profile, metadata->forceDisableProfile, callback.release());
    std::unique_lock<std::mutex> callbackLock(metadata->asyncContext.callbackMutex);
    TELEPHONY_LOGI("NAPI NativeGetDownloadableProfileMetadata %{public}d", errorCode);
    metadata->asyncContext.context.errorCode = errorCode;
    if (errorCode == TELEPHONY_SUCCESS) {
        metadata->asyncContext.cv.wait_for(callbackLock, std::chrono::seconds(WAIT_TIME_SECOND),
            [metadata] { return metadata->asyncContext.callbackEnd; });
        TELEPHONY_LOGI("NativeGetDownloadableProfileMetadata after callback end");
    }
}

void GetDownloadableProfileMetadataCallback(napi_env env, napi_status status, void *data)
{
    NAPI_CALL_RETURN_VOID(env, (data == nullptr ? napi_invalid_arg : napi_ok));
    std::unique_ptr<AsyncProfileMetadataInfo> context(static_cast<AsyncProfileMetadataInfo *>(data));
    if (context == nullptr) {
        TELEPHONY_LOGE("GetDownloadableProfileMetadataCallback context is nullptr");
        return;
    }
    AsyncContext<napi_value> &asyncContext = context->asyncContext;
    if (asyncContext.context.resolved) {
        asyncContext.callbackVal = MetadataResultConversion(env, context->result);
    }
    NapiAsyncPermissionCompleteCallback(env, status, context->asyncContext, false,
        { "GetDownloadableProfileMetadata", Permission::SET_TELEPHONY_ESIM_STATE });
}

napi_value GetDownloadableProfileMetadata(napi_env env, napi_callback_info info)
{
    auto metadata = new (std::nothrow) AsyncProfileMetadataInfo();
    if (metadata == nullptr) {
        return nullptr;
    }
    BaseContext &context = metadata->asyncContext.context;
    napi_value object = NapiUtil::CreateUndefined(env);
    auto initPara = std::make_tuple(&metadata->asyncContext.slotId, &metadata->portIndex,
        &object, &metadata->forceDisableProfile, &context.callbackRef);

    AsyncPara para {
        .funcName = "GetDownloadableProfileMetadata",
        .env = env,
        .info = info,
        .execute = NativeGetDownloadableProfileMetadata,
        .complete = GetDownloadableProfileMetadataCallback,
    };
    napi_value result = NapiCreateAsyncWork2<AsyncProfileMetadataInfo>(para, metadata, initPara);
    if (result) {
        ProfileInfoAnalyze(env, object, metadata->profile);
        NAPI_CALL(env, napi_queue_async_work_with_qos(env, context.work, napi_qos_default));
    }
    return result;
}

void NativeGetEuiccProfileInfoList(napi_env env, void *data)
{
    if (data == nullptr) {
        return;
    }

    auto profileContext = static_cast<AsyncEuiccProfileInfoList *>(data);
    if (!IsValidSlotId(profileContext->asyncContext.slotId)) {
        TELEPHONY_LOGE("NativeGetEuiccProfileInfoList slotId is invalid");
        profileContext->asyncContext.context.errorCode = ERROR_SLOT_ID_INVALID;
        return;
    }
    std::unique_ptr<GetEuiccProfileInfoListResultCallback> callback =
        std::make_unique<GetEuiccProfileInfoListResultCallback>(profileContext);
    int32_t errorCode = DelayedRefSingleton<EsimServiceClient>::GetInstance().GetEuiccProfileInfoList(
        profileContext->asyncContext.slotId, callback.release());
    std::unique_lock<std::mutex> callbackLock(profileContext->asyncContext.callbackMutex);
    TELEPHONY_LOGI("NAPI NativeGetEuiccProfileInfoList %{public}d", errorCode);
    profileContext->asyncContext.context.errorCode = errorCode;
    if (errorCode == TELEPHONY_SUCCESS) {
        profileContext->asyncContext.cv.wait_for(callbackLock, std::chrono::seconds(WAIT_TIME_SECOND),
            [profileContext] { return profileContext->asyncContext.callbackEnd; });
        TELEPHONY_LOGI("NativeDeleteProfile after callback end");
    }
}

void GetEuiccProfileInfoListCallback(napi_env env, napi_status status, void *data)
{
    NAPI_CALL_RETURN_VOID(env, (data == nullptr ? napi_invalid_arg : napi_ok));
    std::unique_ptr<AsyncEuiccProfileInfoList> context(static_cast<AsyncEuiccProfileInfoList *>(data));
    if (context == nullptr) {
        TELEPHONY_LOGE("GetEuiccProfileInfoListCallback context is nullptr");
        return;
    }
    AsyncContext<napi_value> &asyncContext = context->asyncContext;
    if (asyncContext.context.resolved) {
        asyncContext.callbackVal = EuiccProfileListConversion(env, context->result);
    }
    NapiAsyncPermissionCompleteCallback(
        env, status, asyncContext, false, { "GetEuiccProfileInfoList", Permission::GET_TELEPHONY_ESIM_STATE });
}

napi_value GetEuiccProfileInfoList(napi_env env, napi_callback_info info)
{
    auto euiccInfo = new (std::nothrow) AsyncEuiccProfileInfoList();
    if (euiccInfo == nullptr) {
        return nullptr;
    }
    BaseContext &context = euiccInfo->asyncContext.context;

    auto initPara = std::make_tuple(&euiccInfo->asyncContext.slotId, &context.callbackRef);
    AsyncPara para {
        .funcName = "GetEuiccProfileInfoList",
        .env = env,
        .info = info,
        .execute = NativeGetEuiccProfileInfoList,
        .complete = GetEuiccProfileInfoListCallback,
    };
    napi_value result = NapiCreateAsyncWork2<AsyncEuiccProfileInfoList>(para, euiccInfo, initPara);
    if (result) {
        NAPI_CALL(env, napi_queue_async_work_with_qos(env, context.work, napi_qos_default));
    }
    return result;
}

void NativeReserveProfilesForFactoryRestore(napi_env env, void *data)
{
    if (data == nullptr) {
        return;
    }

    AsyncCommonInfo *profileContext = static_cast<AsyncCommonInfo *>(data);
    AsyncContext<int32_t> &asyncContext = profileContext->asyncContext;
    if (!IsValidSlotId(asyncContext.slotId)) {
        TELEPHONY_LOGE("NativeReserveProfilesForFactoryRestore slotId is invalid");
        asyncContext.context.errorCode = ERROR_SLOT_ID_INVALID;
        return;
    }

    int32_t result = UNDEFINED_VALUE;
    int32_t errorCode = DelayedRefSingleton<EsimServiceClient>::GetInstance().ReserveProfilesForFactoryRestore(
        asyncContext.slotId, result);
    TELEPHONY_LOGI("NAPI NativeReserveProfilesForFactoryRestore %{public}d", errorCode);
    if (errorCode == ERROR_NONE) {
        asyncContext.callbackVal = result;
        asyncContext.context.resolved = true;
    } else {
        asyncContext.context.resolved = false;
    }
    asyncContext.context.errorCode = errorCode;
}

void ReserveProfilesForFactoryRestoreCallback(napi_env env, napi_status status, void *data)
{
    NAPI_CALL_RETURN_VOID(env, (data == nullptr ? napi_invalid_arg : napi_ok));
    std::unique_ptr<AsyncCommonInfo> context(static_cast<AsyncCommonInfo *>(data));
    if (context == nullptr) {
        TELEPHONY_LOGE("ReserveProfilesForFactoryRestoreCallback context is nullptr");
        return;
    }
    NapiAsyncPermissionCompleteCallback(env, status, context->asyncContext, false,
        { "ReserveProfilesForFactoryRestore", Permission::SET_TELEPHONY_ESIM_STATE});
}

napi_value ReserveProfilesForFactoryRestore(napi_env env, napi_callback_info info)
{
    auto asyncContext = new (std::nothrow) AsyncCommonInfo();
    if (asyncContext == nullptr) {
        return nullptr;
    }
    BaseContext &context = asyncContext->asyncContext.context;

    auto initPara = std::make_tuple(&asyncContext->asyncContext.slotId, &context.callbackRef);
    AsyncPara para {
        .funcName = "ReserveProfilesForFactoryRestore",
        .env = env,
        .info = info,
        .execute = NativeReserveProfilesForFactoryRestore,
        .complete = ReserveProfilesForFactoryRestoreCallback,
    };
    napi_value result = NapiCreateAsyncWork2<AsyncCommonInfo>(para, asyncContext, initPara);
    if (result) {
        NAPI_CALL(env, napi_queue_async_work_with_qos(env, context.work, napi_qos_default));
    }
    return result;
}

napi_status InitEnumResetOption(napi_env env, napi_value exports)
{
    napi_property_descriptor desc[] = {
        DECLARE_NAPI_STATIC_PROPERTY("DELETE_OPERATIONAL_PROFILES",
            GetNapiValue(env, static_cast<int32_t>(ResetOption::DELETE_OPERATIONAL_PROFILES))),
        DECLARE_NAPI_STATIC_PROPERTY("DELETE_FIELD_LOADED_TEST_PROFILES",
            GetNapiValue(env, static_cast<int32_t>(ResetOption::DELETE_FIELD_LOADED_TEST_PROFILES))),
        DECLARE_NAPI_STATIC_PROPERTY("RESET_DEFAULT_SMDP_ADDRESS",
            GetNapiValue(env, static_cast<int32_t>(ResetOption::RESET_DEFAULT_SMDP_ADDRESS))),
    };

    constexpr size_t arrSize = sizeof(desc) / sizeof(desc[0]);
    NapiUtil::DefineEnumClassByName(env, exports, "ResetOption", arrSize, desc);
    return napi_define_properties(env, exports, arrSize, desc);
}

napi_status InitEnumCancelReason(napi_env env, napi_value exports)
{
    napi_property_descriptor desc[] = {
        DECLARE_NAPI_STATIC_PROPERTY("CANCEL_REASON_END_USER_REJECTION",
            GetNapiValue(env, static_cast<int32_t>(CancelReason::CANCEL_REASON_END_USER_REJECTION))),
        DECLARE_NAPI_STATIC_PROPERTY("CANCEL_REASON_POSTPONED",
            GetNapiValue(env, static_cast<int32_t>(CancelReason::CANCEL_REASON_POSTPONED))),
        DECLARE_NAPI_STATIC_PROPERTY("CANCEL_REASON_TIMEOUT",
            GetNapiValue(env, static_cast<int32_t>(CancelReason::CANCEL_REASON_TIMEOUT))),
        DECLARE_NAPI_STATIC_PROPERTY("CANCEL_REASON_PPR_NOT_ALLOWED",
            GetNapiValue(env, static_cast<int32_t>(CancelReason::CANCEL_REASON_PPR_NOT_ALLOWED))),
    };

    constexpr size_t arrSize = sizeof(desc) / sizeof(desc[0]);
    NapiUtil::DefineEnumClassByName(env, exports, "CancelReason", arrSize, desc);
    return napi_define_properties(env, exports, arrSize, desc);
}

napi_status InitEnumOsuStatus(napi_env env, napi_value exports)
{
    napi_property_descriptor desc[] = {
        DECLARE_NAPI_STATIC_PROPERTY("EUICC_UPGRADE_IN_PROGRESS",
            GetNapiValue(env, static_cast<int32_t>(OsuStatus::EUICC_UPGRADE_IN_PROGRESS))),
        DECLARE_NAPI_STATIC_PROPERTY("EUICC_UPGRADE_FAILED",
            GetNapiValue(env, static_cast<int32_t>(OsuStatus::EUICC_UPGRADE_FAILED))),
        DECLARE_NAPI_STATIC_PROPERTY("EUICC_UPGRADE_SUCCESSFUL",
            GetNapiValue(env, static_cast<int32_t>(OsuStatus::EUICC_UPGRADE_SUCCESSFUL))),
        DECLARE_NAPI_STATIC_PROPERTY("EUICC_UPGRADE_ALREADY_LATEST",
            GetNapiValue(env, static_cast<int32_t>(OsuStatus::EUICC_UPGRADE_ALREADY_LATEST))),
        DECLARE_NAPI_STATIC_PROPERTY("EUICC_UPGRADE_SERVICE_UNAVAILABLE",
            GetNapiValue(env, static_cast<int32_t>(OsuStatus::EUICC_UPGRADE_SERVICE_UNAVAILABLE))),
    };

    constexpr size_t arrSize = sizeof(desc) / sizeof(desc[0]);
    NapiUtil::DefineEnumClassByName(env, exports, "OsuStatus", arrSize, desc);
    return napi_define_properties(env, exports, arrSize, desc);
}

napi_status InitEnumProfileState(napi_env env, napi_value exports)
{
    napi_property_descriptor desc[] = {
        DECLARE_NAPI_STATIC_PROPERTY("PROFILE_STATE_UNSPECIFIED",
            GetNapiValue(env, static_cast<int32_t>(ProfileState::PROFILE_STATE_UNSPECIFIED))),
        DECLARE_NAPI_STATIC_PROPERTY("PROFILE_STATE_DISABLED",
            GetNapiValue(env, static_cast<int32_t>(ProfileState::PROFILE_STATE_DISABLED))),
        DECLARE_NAPI_STATIC_PROPERTY("PROFILE_STATE_ENABLED",
            GetNapiValue(env, static_cast<int32_t>(ProfileState::PROFILE_STATE_ENABLED))),
    };

    constexpr size_t arrSize = sizeof(desc) / sizeof(desc[0]);
    NapiUtil::DefineEnumClassByName(env, exports, "ProfileState", arrSize, desc);
    return napi_define_properties(env, exports, arrSize, desc);
}

napi_status InitEnumProfileClass(napi_env env, napi_value exports)
{
    napi_property_descriptor desc[] = {
        DECLARE_NAPI_STATIC_PROPERTY("PROFILE_CLASS_UNSPECIFIED",
            GetNapiValue(env, static_cast<int32_t>(ProfileClass::PROFILE_CLASS_UNSPECIFIED))),
        DECLARE_NAPI_STATIC_PROPERTY("PROFILE_CLASS_TEST",
            GetNapiValue(env, static_cast<int32_t>(ProfileClass::PROFILE_CLASS_TEST))),
        DECLARE_NAPI_STATIC_PROPERTY("PROFILE_CLASS_PROVISIONING",
            GetNapiValue(env, static_cast<int32_t>(ProfileClass::PROFILE_CLASS_PROVISIONING))),
        DECLARE_NAPI_STATIC_PROPERTY("PROFILE_CLASS_OPERATIONAL",
            GetNapiValue(env, static_cast<int32_t>(ProfileClass::PROFILE_CLASS_OPERATIONAL))),
    };

    constexpr size_t arrSize = sizeof(desc) / sizeof(desc[0]);
    NapiUtil::DefineEnumClassByName(env, exports, "ProfileClass", arrSize, desc);
    return napi_define_properties(env, exports, arrSize, desc);
}

napi_status InitEnumPolicyRules(napi_env env, napi_value exports)
{
    napi_property_descriptor desc[] = {
        DECLARE_NAPI_STATIC_PROPERTY("POLICY_RULE_DISABLE_NOT_ALLOWED",
            GetNapiValue(env, static_cast<int32_t>(PolicyRules::POLICY_RULE_DISABLE_NOT_ALLOWED))),
        DECLARE_NAPI_STATIC_PROPERTY("POLICY_RULE_DELETE_NOT_ALLOWED",
            GetNapiValue(env, static_cast<int32_t>(PolicyRules::POLICY_RULE_DELETE_NOT_ALLOWED))),
        DECLARE_NAPI_STATIC_PROPERTY("POLICY_RULE_DISABLE_AND_DELETE",
            GetNapiValue(env, static_cast<int32_t>(PolicyRules::POLICY_RULE_DISABLE_AND_DELETE))),
    };

    constexpr size_t arrSize = sizeof(desc) / sizeof(desc[0]);
    NapiUtil::DefineEnumClassByName(env, exports, "PolicyRules", arrSize, desc);
    return napi_define_properties(env, exports, arrSize, desc);
}

napi_status InitEnumResultCode(napi_env env, napi_value exports)
{
    napi_property_descriptor desc[] = {
        DECLARE_NAPI_STATIC_PROPERTY(
            "RESULT_SOLVABLE_ERRORS", GetNapiValue(env, static_cast<int32_t>(ResultCode::RESULT_SOLVABLE_ERRORS))),
        DECLARE_NAPI_STATIC_PROPERTY(
            "RESULT_MUST_DISABLE_PROFILE",
            GetNapiValue(env, static_cast<int32_t>(ResultCode::RESULT_MUST_DISABLE_PROFILE))),
        DECLARE_NAPI_STATIC_PROPERTY("RESULT_OK", GetNapiValue(env, static_cast<int32_t>(ResultCode::RESULT_OK))),
        DECLARE_NAPI_STATIC_PROPERTY(
            "RESULT_GET_EID_FAILED", GetNapiValue(env, static_cast<int32_t>(ResultCode::RESULT_GET_EID_FAILED))),
        DECLARE_NAPI_STATIC_PROPERTY(
            "RESULT_ACTIVATION_CODE_CHANGED",
            GetNapiValue(env, static_cast<int32_t>(ResultCode::RESULT_ACTIVATION_CODE_CHANGED))),
        DECLARE_NAPI_STATIC_PROPERTY(
            "RESULT_ACTIVATION_CODE_INVALID",
            GetNapiValue(env, static_cast<int32_t>(ResultCode::RESULT_ACTIVATION_CODE_INVALID))),
        DECLARE_NAPI_STATIC_PROPERTY(
            "RESULT_SMDP_ADDRESS_INVALID",
            GetNapiValue(env, static_cast<int32_t>(ResultCode::RESULT_SMDP_ADDRESS_INVALID))),
        DECLARE_NAPI_STATIC_PROPERTY(
            "RESULT_EUICC_INFO_INVALID",
            GetNapiValue(env, static_cast<int32_t>(ResultCode::RESULT_EUICC_INFO_INVALID))),
        DECLARE_NAPI_STATIC_PROPERTY(
            "RESULT_TLS_HANDSHAKE_FAILED",
            GetNapiValue(env, static_cast<int32_t>(ResultCode::RESULT_TLS_HANDSHAKE_FAILED))),
        DECLARE_NAPI_STATIC_PROPERTY(
            "RESULT_CERTIFICATE_IO_ERROR",
            GetNapiValue(env, static_cast<int32_t>(ResultCode::RESULT_CERTIFICATE_IO_ERROR))),
        DECLARE_NAPI_STATIC_PROPERTY(
            "RESULT_CERTIFICATE_RESPONSE_TIMEOUT",
            GetNapiValue(env, static_cast<int32_t>(ResultCode::RESULT_CERTIFICATE_RESPONSE_TIMEOUT))),
        DECLARE_NAPI_STATIC_PROPERTY(
            "RESULT_AUTHENTICATION_FAILED",
            GetNapiValue(env, static_cast<int32_t>(ResultCode::RESULT_AUTHENTICATION_FAILED))),
        DECLARE_NAPI_STATIC_PROPERTY(
            "RESULT_RESPONSE_HTTP_FAILED",
            GetNapiValue(env, static_cast<int32_t>(ResultCode::RESULT_RESPONSE_HTTP_FAILED))),
        DECLARE_NAPI_STATIC_PROPERTY(
            "RESULT_CONFIRMATION_CODE_INCORRECT",
            GetNapiValue(env, static_cast<int32_t>(ResultCode::RESULT_CONFIRMATION_CODE_INCORRECT))),
        DECLARE_NAPI_STATIC_PROPERTY(
            "RESULT_EXCEEDED_CONFIRMATION_CODE_TRY_LIMIT",
            GetNapiValue(env, static_cast<int32_t>(ResultCode::RESULT_EXCEEDED_CONFIRMATION_CODE_TRY_LIMIT))),
        DECLARE_NAPI_STATIC_PROPERTY(
            "RESULT_NO_PROFILE_ON_SERVER",
            GetNapiValue(env, static_cast<int32_t>(ResultCode::RESULT_NO_PROFILE_ON_SERVER))),
        DECLARE_NAPI_STATIC_PROPERTY(
            "RESULT_TRANSACTION_ID_INVALID",
            GetNapiValue(env, static_cast<int32_t>(ResultCode::RESULT_TRANSACTION_ID_INVALID))),
        DECLARE_NAPI_STATIC_PROPERTY(
            "RESULT_SERVER_ADDRESS_INVALID",
            GetNapiValue(env, static_cast<int32_t>(ResultCode::RESULT_SERVER_ADDRESS_INVALID))),
        DECLARE_NAPI_STATIC_PROPERTY(
            "RESULT_GET_BOUND_PROFILE_PACKAGE_FAILED",
            GetNapiValue(env, static_cast<int32_t>(ResultCode::RESULT_GET_BOUND_PROFILE_PACKAGE_FAILED))),
        DECLARE_NAPI_STATIC_PROPERTY(
            "RESULT_USER_CANCEL_DOWNLOAD",
            GetNapiValue(env, static_cast<int32_t>(ResultCode::RESULT_USER_CANCEL_DOWNLOAD))),
        DECLARE_NAPI_STATIC_PROPERTY(
            "RESULT_SERVER_UNAVAILABLE",
            GetNapiValue(env, static_cast<int32_t>(ResultCode::RESULT_SERVER_UNAVAILABLE))),
        DECLARE_NAPI_STATIC_PROPERTY(
            "RESULT_PROFILE_NON_DELETE",
            GetNapiValue(env, static_cast<int32_t>(ResultCode::RESULT_PROFILE_NON_DELETE))),
        DECLARE_NAPI_STATIC_PROPERTY(
            "RESULT_SMDP_ADDRESS_INCORRECT",
            GetNapiValue(env, static_cast<int32_t>(ResultCode::RESULT_SMDP_ADDRESS_INCORRECT))),
        DECLARE_NAPI_STATIC_PROPERTY(
            "RESULT_ANALYZE_AUTHENTICATION_SERVER_RESPONSE_FAILED",
            GetNapiValue(env, static_cast<int32_t>(ResultCode::RESULT_ANALYZE_AUTHENTICATION_SERVER_RESPONSE_FAILED))),
        DECLARE_NAPI_STATIC_PROPERTY(
            "RESULT_ANALYZE_AUTHENTICATION_CLIENT_RESPONSE_FAILED",
            GetNapiValue(env, static_cast<int32_t>(ResultCode::RESULT_ANALYZE_AUTHENTICATION_CLIENT_RESPONSE_FAILED))),
        DECLARE_NAPI_STATIC_PROPERTY(
            "RESULT_ANALYZE_AUTHENTICATION_CLIENT_MATCHING_ID_REFUSED",
            GetNapiValue(
                env, static_cast<int32_t>(ResultCode::RESULT_ANALYZE_AUTHENTICATION_CLIENT_MATCHING_ID_REFUSED))),
        DECLARE_NAPI_STATIC_PROPERTY(
            "RESULT_PROFILE_TYPE_ERROR_AUTHENTICATION_STOPPED",
            GetNapiValue(env, static_cast<int32_t>(ResultCode::RESULT_PROFILE_TYPE_ERROR_AUTHENTICATION_STOPPED))),
        DECLARE_NAPI_STATIC_PROPERTY(
            "RESULT_CARRIER_SERVER_REFUSED_ERRORS",
            GetNapiValue(env, static_cast<int32_t>(ResultCode::RESULT_CARRIER_SERVER_REFUSED_ERRORS))),
        DECLARE_NAPI_STATIC_PROPERTY(
            "RESULT_CERTIFICATE_INVALID",
            GetNapiValue(env, static_cast<int32_t>(ResultCode::RESULT_CERTIFICATE_INVALID))),
        DECLARE_NAPI_STATIC_PROPERTY(
            "RESULT_OUT_OF_MEMORY",
            GetNapiValue(env, static_cast<int32_t>(ResultCode::RESULT_OUT_OF_MEMORY))),
        DECLARE_NAPI_STATIC_PROPERTY(
            "RESULT_PPR_FORBIDDEN", GetNapiValue(env, static_cast<int32_t>(ResultCode::RESULT_PPR_FORBIDDEN))),
        DECLARE_NAPI_STATIC_PROPERTY(
            "RESULT_NOTHING_TO_DELETE", GetNapiValue(env, static_cast<int32_t>(ResultCode::RESULT_NOTHING_TO_DELETE))),
        DECLARE_NAPI_STATIC_PROPERTY(
            "RESULT_PPR_NOT_MATCH", GetNapiValue(env, static_cast<int32_t>(ResultCode::RESULT_PPR_NOT_MATCH))),
        DECLARE_NAPI_STATIC_PROPERTY(
            "RESULT_CAT_BUSY", GetNapiValue(env, static_cast<int32_t>(ResultCode::RESULT_CAT_BUSY))),
        DECLARE_NAPI_STATIC_PROPERTY(
            "RESULT_PROFILE_EID_INVALID",
            GetNapiValue(env, static_cast<int32_t>(ResultCode::RESULT_PROFILE_EID_INVALID))),
        DECLARE_NAPI_STATIC_PROPERTY(
            "RESULT_DOWNLOAD_TIMEOUT", GetNapiValue(env, static_cast<int32_t>(ResultCode::RESULT_DOWNLOAD_TIMEOUT))),
        DECLARE_NAPI_STATIC_PROPERTY(
            "RESULT_SGP_22_OTHER", GetNapiValue(env, static_cast<int32_t>(ResultCode::RESULT_SGP_22_OTHER))),
    };

    constexpr size_t arrSize = sizeof(desc) / sizeof(desc[0]);
    NapiUtil::DefineEnumClassByName(env, exports, "ResultCode", arrSize, desc);
    return napi_define_properties(env, exports, arrSize, desc);
}

napi_status InitEnumResolvableErrors(napi_env env, napi_value exports)
{
    napi_property_descriptor desc[] = {
        DECLARE_NAPI_STATIC_PROPERTY("SOLVABLE_ERROR_NEED_CONFIRMATION_CODE",
            GetNapiValue(env, static_cast<int32_t>(SolvableErrors::SOLVABLE_ERROR_NEED_CONFIRMATION_CODE))),
        DECLARE_NAPI_STATIC_PROPERTY("SOLVABLE_ERROR_NEED_POLICY_RULE",
            GetNapiValue(env, static_cast<int32_t>(SolvableErrors::SOLVABLE_ERROR_NEED_POLICY_RULE))),
    };

    constexpr size_t arrSize = sizeof(desc) / sizeof(desc[0]);
    NapiUtil::DefineEnumClassByName(env, exports, "SolvableErrors", arrSize, desc);
    return napi_define_properties(env, exports, arrSize, desc);
}

napi_status InitEuiccServiceInterface(napi_env env, napi_value exports)
{
    napi_property_descriptor desc[] = {
        DECLARE_NAPI_FUNCTION("isSupported", IsSupported),
        DECLARE_NAPI_FUNCTION("addProfile", AddProfile),
        DECLARE_NAPI_FUNCTION("getEid", GetEid),
        DECLARE_NAPI_FUNCTION("getOsuStatus", GetOsuStatus),
        DECLARE_NAPI_FUNCTION("startOsu", StartOsu),
        DECLARE_NAPI_FUNCTION("getDownloadableProfileMetadata", GetDownloadableProfileMetadata),
        DECLARE_NAPI_FUNCTION("getDownloadableProfiles", GetDownloadableProfiles),
        DECLARE_NAPI_FUNCTION("downloadProfile", DownloadProfile),
        DECLARE_NAPI_FUNCTION("getEuiccProfileInfoList", GetEuiccProfileInfoList),
        DECLARE_NAPI_FUNCTION("getEuiccInfo", GetEuiccInfo),
        DECLARE_NAPI_FUNCTION("deleteProfile", DeleteProfile),
        DECLARE_NAPI_FUNCTION("switchToProfile", SwitchToProfile),
        DECLARE_NAPI_FUNCTION("setProfileNickname", SetProfileNickname),
        DECLARE_NAPI_FUNCTION("resetMemory", ResetMemory),
        DECLARE_NAPI_FUNCTION("reserveProfilesForFactoryRestore", ReserveProfilesForFactoryRestore),
        DECLARE_NAPI_FUNCTION("setDefaultSmdpAddress", SetDefaultSmdpAddress),
        DECLARE_NAPI_FUNCTION("getDefaultSmdpAddress", GetDefaultSmdpAddress),
        DECLARE_NAPI_FUNCTION("cancelSession", CancelSession),
    };
    return napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[0]), desc);
}
} // namespace

EXTERN_C_START
napi_value InitNapiEsim(napi_env env, napi_value exports)
{
    NAPI_CALL(env, InitEuiccServiceInterface(env, exports));
    NAPI_CALL(env, InitEnumResetOption(env, exports));
    NAPI_CALL(env, InitEnumCancelReason(env, exports));
    NAPI_CALL(env, InitEnumOsuStatus(env, exports));
    NAPI_CALL(env, InitEnumProfileState(env, exports));
    NAPI_CALL(env, InitEnumProfileClass(env, exports));
    NAPI_CALL(env, InitEnumPolicyRules(env, exports));
    NAPI_CALL(env, InitEnumResultCode(env, exports));
    NAPI_CALL(env, InitEnumResolvableErrors(env, exports));
    return exports;
}
EXTERN_C_END

static napi_module _esimModule = {
    .nm_version = 1,
    .nm_flags = 0,
    .nm_filename = nullptr,
    .nm_register_func = InitNapiEsim,
    .nm_modname = "telephony.esim",
    .nm_priv = ((void *)0),
    .reserved = {0},
};

extern "C" __attribute__((constructor)) void RegisterEsimCardModule(void)
{
    napi_module_register(&_esimModule);
}
} // namespace Telephony
} // namespace OHOS