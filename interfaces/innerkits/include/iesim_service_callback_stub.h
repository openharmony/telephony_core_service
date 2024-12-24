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

#ifndef I_ESIM_SERVICE_CALLBACK_STUB_H
#define I_ESIM_SERVICE_CALLBACK_STUB_H

#include <cstdint>
#include "iesim_service_callback.h"
#include "iremote_stub.h"
#include "download_profile_config_info_parcel.h"
#include "download_profile_result_parcel.h"
#include "downloadable_profile_parcel.h"
#include "esim_state_type.h"
#include "euicc_info_parcel.h"
#include "get_downloadable_profiles_result_parcel.h"
#include "iesim_service_callback.h"
#include "iremote_stub.h"
#include "profile_info_list_parcel.h"
#include "profile_metadata_result_parcel.h"
#include "response_esim_result.h"

namespace OHOS {
namespace Telephony {
class IEsimServiceCallbackStub : public IRemoteStub<IEsimServiceCallback> {
public:
    static const int32_t DEFAULT_ERROR = -1;
    static const int32_t DEFAULT_RESULT = 0;
    IEsimServiceCallbackStub() = default;
    virtual ~IEsimServiceCallbackStub() = default;
    int32_t OnEsimServiceCallback(EsimServiceCallback requestId, MessageParcel &data) override;
    int OnRemoteRequest(
        uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override;
    virtual void OnGetEuiccInfo(const EuiccInfo &result, const int32_t errorCode);
    virtual void OnDeleteProfile(const int32_t &result, const int32_t errorCode);
    virtual void OnDownloadProfile(const DownloadProfileResult &result, const int32_t errorCode);
    virtual void OnGetDownloadableProfileMetadata(
        const GetDownloadableProfileMetadataResult &result, const int32_t errorCode);
    virtual void OnGetDownloadableProfiles(
        const GetDownloadableProfilesResult &result, const int32_t errorCode);
    virtual void OnResetMemory(const int32_t &result, const int32_t errorCode);
    virtual void OnStartOsu(const OsuStatus &result, const int32_t errorCode);
    virtual void OnSwitchToProfile(const int32_t &result, const int32_t errorCode);
    virtual void OnCancelSession(const ResponseEsimResult &result, const int32_t errorCode);
    virtual void OnGetDefaultSmdpAddress(const std::string &result, const int32_t errorCode);
    virtual void OnGetEid(const std::string &result, const int32_t errorCode);
    virtual void OnGetEuiccProfileInfoList(const GetEuiccProfileInfoListResult &result, const int32_t errorCode);
    virtual void OnSetDefaultSmdpAddress(const int32_t &result, const int32_t errorCode);
    virtual void OnSetProfileNickName(const int32_t &result, const int32_t errorCode);
private:
    void OnGetEuiccInfo(MessageParcel &data);
    void OnGetEid(MessageParcel &data);
    void OnGetDownloadableProfileMetadata(MessageParcel &data);
    void OnGetDownloadableProfiles(MessageParcel &data);
    void OnGetEuiccProfileInfoList(MessageParcel &data);
    void OnGetDefaultSmdpAddress(MessageParcel &data);
    void OnSetDefaultSmdpAddress(MessageParcel &data);
    void OnSetProfileNickname(MessageParcel &data);
    void OnCancelSession(MessageParcel &data);
    void OnDownloadProfile(MessageParcel &data);
    void OnDeleteProfile(MessageParcel &data);
    void OnStartOsu(MessageParcel &data);
    void OnSwitchToProfile(MessageParcel &data);
    void OnResetMemory(MessageParcel &data);
};
} // namespace Telephony
} // namespace OHOS
#endif // I_ESIM_CALLBACK_STUB_H