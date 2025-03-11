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

#include "euicc_info_parcel.h"
#include "iesim_service_callback_stub.h"
#include "string_ex.h"
#include "telephony_errors.h"
#include "telephony_log_wrapper.h"
#include "telephony_types.h"
#include <codecvt>
#include <locale>
#include "response_esim_result.h"

namespace OHOS {
namespace Telephony {
int32_t IEsimServiceCallbackStub::OnEsimServiceCallback(EsimServiceCallback requestId, MessageParcel &data)
{
    TELEPHONY_LOGI("recv callback reqId:%{public}d", requestId);
    auto callbackType = requestId;
    switch (callbackType) {
        case IEsimServiceCallback::EsimServiceCallback::GET_EUICCINFO_RESULT:
            OnGetEuiccInfo(data);
            break;
        case IEsimServiceCallback::EsimServiceCallback::GET_EID_RESULT:
            OnGetEid(data);
            break;
        case IEsimServiceCallback::EsimServiceCallback::GET_DOWNLOADABLE_PROFILE_METADATA_RESULT:
            OnGetDownloadableProfileMetadata(data);
            break;
        case IEsimServiceCallback::EsimServiceCallback::GET_DOWNLOADABLE_PROFILES_RESULT:
            OnGetDownloadableProfiles(data);
            break;
        case IEsimServiceCallback::EsimServiceCallback::GET_EUICC_PROFILE_INFO_LIST_RESULT:
            OnGetEuiccProfileInfoList(data);
            break;
        case IEsimServiceCallback::EsimServiceCallback::GET_DEFAULT_SMDP_ADDRESS_RESULT:
            OnGetDefaultSmdpAddress(data);
            break;
        case IEsimServiceCallback::EsimServiceCallback::SET_DEFAULT_SMDP_ADDRESS_RESULT:
            OnSetDefaultSmdpAddress(data);
            break;
        case IEsimServiceCallback::EsimServiceCallback::SET_PROFILE_NICKNAME_RESULT:
            OnSetProfileNickname(data);
            break;
        case IEsimServiceCallback::EsimServiceCallback::CANCEL_SESSION_CALLBACK_RESULT:
            OnCancelSession(data);
            break;
        case IEsimServiceCallback::EsimServiceCallback::DOWNLOAD_PROFILE_RESULT:
            OnDownloadProfile(data);
            break;
        case IEsimServiceCallback::EsimServiceCallback::DELETE_PROFILE_RESULT:
            OnDeleteProfile(data);
            break;
        case IEsimServiceCallback::EsimServiceCallback::START_OSU_RESULT:
            OnStartOsu(data);
            break;
        case IEsimServiceCallback::EsimServiceCallback::SWITCH_PROFILE_RESULT:
            OnSwitchToProfile(data);
            break;
        case IEsimServiceCallback::EsimServiceCallback::RESET_MEMORY_RESULT:
            OnResetMemory(data);
            break;
        default:
            return DEFAULT_ERROR;
    }
    return DEFAULT_RESULT;
}

void IEsimServiceCallbackStub::OnGetEuiccInfo(MessageParcel &data)
{
    int32_t errorCode = data.ReadInt32();
    if (FAILED(errorCode)) {
        TELEPHONY_LOGE("Read Int32 failed!");
        return;
    }

    std::unique_ptr<EuiccInfo> info(data.ReadParcelable<EuiccInfo>());
    EuiccInfo result;
    if (info != nullptr) {
        result = *info;
    }
    OnGetEuiccInfo(result, errorCode);
}

void IEsimServiceCallbackStub::OnGetEid(MessageParcel &data)
{
    ErrCode errCode = data.ReadInt32();
    if (FAILED(errCode)) {
        TELEPHONY_LOGE("Read Int32 failed!");
        return;
    }

    std::string eId = Str16ToStr8(data.ReadString16());
    OnGetEid(eId, errCode);
}

void IEsimServiceCallbackStub::OnGetDownloadableProfileMetadata(MessageParcel &data)
{
    ErrCode errCode = data.ReadInt32();
    if (FAILED(errCode)) {
        TELEPHONY_LOGE("Read Int32 failed!");
        return;
    }

    std::unique_ptr<GetDownloadableProfileMetadataResult> info(
        data.ReadParcelable<GetDownloadableProfileMetadataResult>());
    GetDownloadableProfileMetadataResult profileMetadataResult;
    if (info != nullptr) {
        profileMetadataResult = *info;
    }
    OnGetDownloadableProfileMetadata(profileMetadataResult, errCode);
}

void IEsimServiceCallbackStub::OnGetDownloadableProfiles(MessageParcel &data)
{
    ErrCode errCode = data.ReadInt32();
    if (FAILED(errCode)) {
        TELEPHONY_LOGE("Read Int32 failed!");
        return;
    }

    std::unique_ptr<GetDownloadableProfilesResult> info(data.ReadParcelable<GetDownloadableProfilesResult>());
    GetDownloadableProfilesResult profileListResult;
    if (info != nullptr) {
        profileListResult = *info;
    }
    OnGetDownloadableProfiles(profileListResult, errCode);
}

void IEsimServiceCallbackStub::OnGetEuiccProfileInfoList(MessageParcel &data)
{
    ErrCode errCode = data.ReadInt32();
    if (FAILED(errCode)) {
        TELEPHONY_LOGE("Read Int32 failed!");
        return;
    }

    std::unique_ptr<GetEuiccProfileInfoListResult> info(data.ReadParcelable<GetEuiccProfileInfoListResult>());
    GetEuiccProfileInfoListResult euiccProfileInfoList;
    if (info != nullptr) {
        euiccProfileInfoList = *info;
    }
    OnGetEuiccProfileInfoList(euiccProfileInfoList, errCode);
}
void IEsimServiceCallbackStub::OnGetDefaultSmdpAddress(MessageParcel &data)
{
    ErrCode errCode = data.ReadInt32();
    if (FAILED(errCode)) {
        TELEPHONY_LOGE("Read Int32 failed!");
        return;
    }

    std::string defaultSmdpAddress = Str16ToStr8(data.ReadString16());
    OnGetDefaultSmdpAddress(defaultSmdpAddress, errCode);
}
void IEsimServiceCallbackStub::OnSetDefaultSmdpAddress(MessageParcel &data)
{
    ErrCode errCode = data.ReadInt32();
    if (FAILED(errCode)) {
        TELEPHONY_LOGE("Read Int32 failed!");
        return;
    }

    int32_t setDefaultSmdpAddressResult = data.ReadInt32();
    OnSetDefaultSmdpAddress(setDefaultSmdpAddressResult, errCode);
}
void IEsimServiceCallbackStub::OnSetProfileNickname(MessageParcel &data)
{
    ErrCode errCode = data.ReadInt32();
    if (FAILED(errCode)) {
        TELEPHONY_LOGE("Read Int32 failed!");
        return;
    }

    int32_t setProfileNicknameResult = data.ReadInt32();
    OnSetProfileNickName(setProfileNicknameResult, errCode);
}
void IEsimServiceCallbackStub::OnCancelSession(MessageParcel &data)
{
    ErrCode errCode = data.ReadInt32();
    if (FAILED(errCode)) {
        TELEPHONY_LOGE("Read Int32 failed!");
        return;
    }

    std::unique_ptr<ResponseEsimResult> info(data.ReadParcelable<ResponseEsimResult>());
    ResponseEsimResult responseResult;
    if (info != nullptr) {
        responseResult = *info;
    }
    OnCancelSession(responseResult, errCode);
}
void IEsimServiceCallbackStub::OnDownloadProfile(MessageParcel &data)
{
    ErrCode errCode = data.ReadInt32();
    if (FAILED(errCode)) {
        TELEPHONY_LOGE("Read Int32 failed!");
        return;
    }

    std::unique_ptr<DownloadProfileResult> info(data.ReadParcelable<DownloadProfileResult>());
    DownloadProfileResult downloadProfileResult;
    if (info != nullptr) {
        downloadProfileResult = *info;
    }

    OnDownloadProfile(downloadProfileResult, errCode);
}
void IEsimServiceCallbackStub::OnDeleteProfile(MessageParcel &data)
{
    ErrCode errCode = data.ReadInt32();
    if (FAILED(errCode)) {
        TELEPHONY_LOGE("Read Int32 failed!");
        return;
    }
    int32_t deleteProfileResult = data.ReadInt32();
    OnDeleteProfile(deleteProfileResult, errCode);
}
void IEsimServiceCallbackStub::OnStartOsu(MessageParcel &data)
{
    ErrCode errCode = data.ReadInt32();
    if (FAILED(errCode)) {
        TELEPHONY_LOGE("Read Int32 failed!");
        return;
    }

    OsuStatus osuStatus = (OsuStatus)data.ReadInt32();
    OnStartOsu(osuStatus, errCode);
}
void IEsimServiceCallbackStub::OnSwitchToProfile(MessageParcel &data)
{
    ErrCode errCode = data.ReadInt32();
    if (FAILED(errCode)) {
        TELEPHONY_LOGE("Read Int32 failed!");
        return;
    }

    int32_t switchToProfileResult = data.ReadInt32();
    OnSwitchToProfile(switchToProfileResult, errCode);
}
void IEsimServiceCallbackStub::OnResetMemory(MessageParcel &data)
{
    ErrCode errCode = data.ReadInt32();
    if (FAILED(errCode)) {
        TELEPHONY_LOGE("Read Int32 failed!");
        return;
    }

    int32_t resetMemoryResult = data.ReadInt32();
    OnResetMemory(resetMemoryResult, errCode);
}

int IEsimServiceCallbackStub::OnRemoteRequest(
    uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    TELEPHONY_LOGI("IEsimServiceCallbackStub::OnRemoteRequest requestId:%{public}d", code);
    std::u16string myDescriptor = IEsimServiceCallbackStub::GetDescriptor();
    std::u16string remoteDescriptor = data.ReadInterfaceToken();
    if (myDescriptor != remoteDescriptor) {
        TELEPHONY_LOGE("descriptor check fail!");
        return TELEPHONY_ERR_DESCRIPTOR_MISMATCH;
    }
    return OnEsimServiceCallback(static_cast<EsimServiceCallback>(code), data);
}
void IEsimServiceCallbackStub::OnGetEuiccInfo(const EuiccInfo &result, const int32_t errorCode)
{
}
void IEsimServiceCallbackStub::OnDeleteProfile(const int32_t &result, const int32_t errorCode)
{
}
void IEsimServiceCallbackStub::OnDownloadProfile(const DownloadProfileResult &result, const int32_t errorCode)
{
}
void IEsimServiceCallbackStub::OnGetDownloadableProfileMetadata(
    const GetDownloadableProfileMetadataResult &result, const int32_t errorCode)
{
}
void IEsimServiceCallbackStub::OnGetDownloadableProfiles(
    const GetDownloadableProfilesResult &result, const int32_t errorCode)
{
}
void IEsimServiceCallbackStub::OnResetMemory(const int32_t &result, const int32_t errorCode)
{
}
void IEsimServiceCallbackStub::OnStartOsu(const OsuStatus &result, const int32_t errorCode)
{
}
void IEsimServiceCallbackStub::OnSwitchToProfile(const int32_t &result, const int32_t errorCode)
{
}
void IEsimServiceCallbackStub::OnCancelSession(const ResponseEsimResult &result, const int32_t errorCode)
{
}
void IEsimServiceCallbackStub::OnGetDefaultSmdpAddress(const std::string &result, const int32_t errorCode)
{
}
void IEsimServiceCallbackStub::OnGetEid(const std::string &result, const int32_t errorCode)
{
}
void IEsimServiceCallbackStub::OnGetEuiccProfileInfoList(
    const GetEuiccProfileInfoListResult &result, const int32_t errorCode)
{
}
void IEsimServiceCallbackStub::OnSetDefaultSmdpAddress(const int32_t &result, const int32_t errorCode)
{
}
void IEsimServiceCallbackStub::OnSetProfileNickName(const int32_t &result, const int32_t errorCode)
{
}
} // namespace Telephonyd
} // namespace OHOS