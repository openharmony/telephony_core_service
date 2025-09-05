/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#include "ani_esim_service_callback.h"
#include "telephony_errors.h"
#include "telephony_log_wrapper.h"
#include "napi_util.h"

namespace OHOS {
namespace Telephony {
namespace EsimAni {

AniCancelSessionCallback::AniCancelSessionCallback(std::shared_ptr<AniCallbackContext<int32_t>> context)
    : context_(context)
{}

void AniCancelSessionCallback::OnCancelSession(const ResponseEsimResult &result, const int32_t errorCode)
{
    if (context_ == nullptr) {
        TELEPHONY_LOGE("OnCancelSession context_ null");
        return;
    }
    std::unique_lock<ffrt::mutex> callbackLock(context_->callbackMutex);
    if (errorCode == TELEPHONY_ERR_SUCCESS) {
        context_->resultValue = static_cast<int32_t>(result.resultCode_);
        context_->errorCode = TELEPHONY_ERR_SUCCESS;
    } else {
        context_->errorCode = TELEPHONY_ERR_RIL_CMD_FAIL;
    }
    context_->isCallbackEnd = true;
    context_->cv.notify_all();
}

AniGetDefaultSmdpAddressCallback::AniGetDefaultSmdpAddressCallback(
    std::shared_ptr<AniCallbackContext<std::string>> context): context_(context)
{}

void AniGetDefaultSmdpAddressCallback::OnGetDefaultSmdpAddress(const std::string &result, const int32_t errorCode)
{
    if (context_ == nullptr) {
        TELEPHONY_LOGE("OnGetDefaultSmdpAddress context_ null");
        return;
    }
    std::unique_lock<ffrt::mutex> callbackLock(context_->callbackMutex);
    if (errorCode == TELEPHONY_ERR_SUCCESS) {
        context_->resultValue = result;
        context_->errorCode = TELEPHONY_ERR_SUCCESS;
    } else {
        context_->errorCode = TELEPHONY_ERR_RIL_CMD_FAIL;
    }
    context_->isCallbackEnd = true;
    context_->cv.notify_all();
}

AniSetDefaultSmdpAddressCallback::AniSetDefaultSmdpAddressCallback(
    std::shared_ptr<AniCallbackContext<int32_t>> context): context_(context)
{}

void AniSetDefaultSmdpAddressCallback::OnSetDefaultSmdpAddress(const int32_t &result, const int32_t errorCode)
{
    if (context_ == nullptr) {
        TELEPHONY_LOGE("OnSetDefaultSmdpAddress context_ null");
        return;
    }
    std::unique_lock<ffrt::mutex> callbackLock(context_->callbackMutex);
    if (errorCode == TELEPHONY_ERR_SUCCESS) {
        context_->resultValue = result;
        context_->errorCode = TELEPHONY_ERR_SUCCESS;
    } else {
        context_->errorCode = TELEPHONY_ERR_RIL_CMD_FAIL;
    }
    context_->isCallbackEnd = true;
    context_->cv.notify_all();
}

AniSetProfileNickNameCallback::AniSetProfileNickNameCallback(std::shared_ptr<AniCallbackContext<int32_t>> context)
    : context_(context)
{}

void AniSetProfileNickNameCallback::OnSetProfileNickName(const int32_t &result, const int32_t errorCode)
{
    if (context_ == nullptr) {
        TELEPHONY_LOGE("OnSetProfileNickName context_ null");
        return;
    }
    std::unique_lock<ffrt::mutex> callbackLock(context_->callbackMutex);
    if (errorCode == TELEPHONY_ERR_SUCCESS) {
        context_->resultValue = result;
        context_->errorCode = TELEPHONY_ERR_SUCCESS;
    } else {
        context_->errorCode = TELEPHONY_ERR_RIL_CMD_FAIL;
    }
    context_->isCallbackEnd = true;
    context_->cv.notify_all();
}

AniSwitchToProfileCallback::AniSwitchToProfileCallback(std::shared_ptr<AniCallbackContext<int32_t>> context)
    : context_(context)
{}

void AniSwitchToProfileCallback::OnSwitchToProfile(const int32_t &result, const int32_t errorCode)
{
    if (context_ == nullptr) {
        TELEPHONY_LOGE("OnSwitchToProfile context_ null");
        return;
    }
    std::unique_lock<ffrt::mutex> callbackLock(context_->callbackMutex);
    if (errorCode == TELEPHONY_ERR_SUCCESS) {
        context_->resultValue = result;
        context_->errorCode = TELEPHONY_ERR_SUCCESS;
    } else {
        context_->errorCode = TELEPHONY_ERR_RIL_CMD_FAIL;
    }
    context_->isCallbackEnd = true;
    context_->cv.notify_all();
}

AniDeleteProfileCallback::AniDeleteProfileCallback(std::shared_ptr<AniCallbackContext<int32_t>> context)
    : context_(context)
{}

void AniDeleteProfileCallback::OnDeleteProfile(const int32_t &result, const int32_t errorCode)
{
    if (context_ == nullptr) {
        TELEPHONY_LOGE("OnDeleteProfile context_ null");
        return;
    }
    std::unique_lock<ffrt::mutex> callbackLock(context_->callbackMutex);
    if (errorCode == TELEPHONY_ERR_SUCCESS) {
        context_->resultValue = result;
        context_->errorCode = TELEPHONY_ERR_SUCCESS;
    } else {
        context_->errorCode = TELEPHONY_ERR_RIL_CMD_FAIL;
    }
    context_->isCallbackEnd = true;
    context_->cv.notify_all();
}

AniGetEuiccInfoCallback::AniGetEuiccInfoCallback(std::shared_ptr<AniCallbackContext<std::string>> context)
    : context_(context)
{}

void AniGetEuiccInfoCallback::OnGetEuiccInfo(const EuiccInfo &result, const int32_t errorCode)
{
    if (context_ == nullptr) {
        TELEPHONY_LOGE("OnGetEuiccInfo context_ null");
        return;
    }
    std::unique_lock<ffrt::mutex> callbackLock(context_->callbackMutex);
    std::string osVersion = NapiUtil::ToUtf8(result.osVersion_);
    if (errorCode == TELEPHONY_ERR_SUCCESS) {
        context_->resultValue = std::move(osVersion);
        context_->errorCode = TELEPHONY_ERR_SUCCESS;
    } else {
        context_->errorCode = TELEPHONY_ERR_RIL_CMD_FAIL;
    }
    context_->isCallbackEnd = true;
    context_->cv.notify_all();
}

AniGetEuiccProfileInfoListCallback::AniGetEuiccProfileInfoListCallback(
    std::shared_ptr<AniCallbackContext<GetEuiccProfileInfoListResult>> context)
    : context_(context)
{}

void AniGetEuiccProfileInfoListCallback::OnGetEuiccProfileInfoList(const GetEuiccProfileInfoListResult &result,
    const int32_t errorCode)
{
    if (context_ == nullptr) {
        TELEPHONY_LOGE("OnGetEuiccProfileInfoList context_ null");
        return;
    }
    std::unique_lock<ffrt::mutex> callbackLock(context_->callbackMutex);
    if (errorCode == TELEPHONY_ERR_SUCCESS) {
        context_->resultValue = result;
        context_->errorCode = TELEPHONY_ERR_SUCCESS;
    } else {
        context_->errorCode = TELEPHONY_ERR_RIL_CMD_FAIL;
    }
    context_->isCallbackEnd = true;
    context_->cv.notify_all();
}

AniDownloadProfileResultCallback::AniDownloadProfileResultCallback(
    std::shared_ptr<AniCallbackContext<DownloadProfileResult>> context): context_(context)
{}

void AniDownloadProfileResultCallback::OnDownloadProfile(const DownloadProfileResult &result, const int32_t errorCode)
{
    if (context_ == nullptr) {
        TELEPHONY_LOGE("OnDownloadProfile context_ null");
        return;
    }
    std::unique_lock<ffrt::mutex> callbackLock(context_->callbackMutex);
    if (errorCode == TELEPHONY_ERR_SUCCESS) {
        context_->resultValue = result;
        context_->errorCode = TELEPHONY_ERR_SUCCESS;
    } else {
        context_->errorCode = TELEPHONY_ERR_RIL_CMD_FAIL;
    }
    context_->isCallbackEnd = true;
    context_->cv.notify_all();
}

AniGetDownloadableProfilesCallback::AniGetDownloadableProfilesCallback(
    std::shared_ptr<AniCallbackContext<GetDownloadableProfilesResult>> context): context_(context)
{}

void AniGetDownloadableProfilesCallback::OnGetDownloadableProfiles(const GetDownloadableProfilesResult &result,
    const int32_t errorCode)
{
    if (context_ == nullptr) {
        TELEPHONY_LOGE("OnGetDownloadableProfiles context_ null");
        return;
    }
    std::unique_lock<ffrt::mutex> callbackLock(context_->callbackMutex);
    if (errorCode == TELEPHONY_ERR_SUCCESS) {
        context_->resultValue = result;
        context_->errorCode = TELEPHONY_ERR_SUCCESS;
    } else {
        context_->errorCode = TELEPHONY_ERR_RIL_CMD_FAIL;
    }
    context_->isCallbackEnd = true;
    context_->cv.notify_all();
}

AniGetDownloadableProfileMetadataCallback::AniGetDownloadableProfileMetadataCallback(
    std::shared_ptr<AniCallbackContext<GetDownloadableProfileMetadataResult>> context): context_(context)
{}

void AniGetDownloadableProfileMetadataCallback::OnGetDownloadableProfileMetadata(
    const GetDownloadableProfileMetadataResult &result, const int32_t errorCode)
{
    if (context_ == nullptr) {
        TELEPHONY_LOGE("OnGetDownloadableProfileMetadata context_ null");
        return;
    }
    std::unique_lock<ffrt::mutex> callbackLock(context_->callbackMutex);
    if (errorCode == TELEPHONY_ERR_SUCCESS) {
        context_->resultValue = result;
        context_->errorCode = TELEPHONY_ERR_SUCCESS;
    } else {
        context_->errorCode = TELEPHONY_ERR_RIL_CMD_FAIL;
    }
    context_->isCallbackEnd = true;
    context_->cv.notify_all();
}

AniStartOsuCallback::AniStartOsuCallback(std::shared_ptr<AniCallbackContext<int32_t>> context): context_(context)
{}

void AniStartOsuCallback::OnStartOsu(const OsuStatus &result, const int32_t errorCode)
{
    if (context_ == nullptr) {
        TELEPHONY_LOGE("OnStartOsu context_ null");
        return;
    }
    std::unique_lock<ffrt::mutex> callbackLock(context_->callbackMutex);
    if (errorCode == TELEPHONY_ERR_SUCCESS) {
        context_->resultValue = static_cast<int32_t>(result);
        context_->errorCode = TELEPHONY_ERR_SUCCESS;
    } else {
        context_->errorCode = TELEPHONY_ERR_RIL_CMD_FAIL;
    }
    context_->isCallbackEnd = true;
    context_->cv.notify_all();
}

AniGetEidCallback::AniGetEidCallback(std::shared_ptr<AniCallbackContext<std::string>> context): context_(context)
{}

void AniGetEidCallback::OnGetEid(const std::string &eidstring, const int32_t errorCode)
{
    if (context_ == nullptr) {
        TELEPHONY_LOGE("OnGetEid context_ null");
        return;
    }
    std::unique_lock<ffrt::mutex> callbackLock(context_->callbackMutex);
    if (errorCode == TELEPHONY_ERR_SUCCESS) {
        context_->resultValue = eidstring;
        context_->errorCode = TELEPHONY_ERR_SUCCESS;
    } else {
        context_->errorCode = TELEPHONY_ERR_RIL_CMD_FAIL;
    }
    context_->isCallbackEnd = true;
    context_->cv.notify_all();
}
} // namespace EsimAni
} // namespace Telephony
} // namespace OHOS