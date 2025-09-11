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

#ifndef ANI_RS_ESIM_SERVICE_CALLBACK_H
#define ANI_RS_ESIM_SERVICE_CALLBACK_H

#include <cstdint>
#include "ffrt.h"
#include "iesim_service_callback_stub.h"
#include "telephony_errors.h"

namespace OHOS {
namespace Telephony {
namespace EsimAni {

template<typename T>
struct AniCallbackContext {
    ffrt::mutex callbackMutex;
    ffrt::condition_variable cv;
    bool isCallbackEnd = false;
    int32_t errorCode = TELEPHONY_ERR_FAIL;
    T resultValue;
};

class AniCancelSessionCallback : public IEsimServiceCallbackStub {
public:
    explicit AniCancelSessionCallback(std::shared_ptr<AniCallbackContext<int32_t>> context);
    void OnCancelSession(const ResponseEsimResult &result, const int32_t errorCode) override;

private:
    std::shared_ptr<AniCallbackContext<int32_t>> context_ = nullptr;
};

class AniGetDefaultSmdpAddressCallback : public IEsimServiceCallbackStub {
public:
    explicit AniGetDefaultSmdpAddressCallback(std::shared_ptr<AniCallbackContext<std::string>> context);
    void OnGetDefaultSmdpAddress(const std::string &result, const int32_t errorCode) override;

private:
    std::shared_ptr<AniCallbackContext<std::string>> context_ = nullptr;
};

class AniSetDefaultSmdpAddressCallback : public IEsimServiceCallbackStub {
public:
    explicit AniSetDefaultSmdpAddressCallback(std::shared_ptr<AniCallbackContext<int32_t>> context);
    void OnSetDefaultSmdpAddress(const int32_t &result, const int32_t errorCode) override;

private:
    std::shared_ptr<AniCallbackContext<int32_t>> context_ = nullptr;
};

class AniSetProfileNickNameCallback : public IEsimServiceCallbackStub {
public:
    explicit AniSetProfileNickNameCallback(std::shared_ptr<AniCallbackContext<int32_t>> context);
    void OnSetProfileNickName(const int32_t &result, const int32_t errorCode) override;

private:
    std::shared_ptr<AniCallbackContext<int32_t>> context_ = nullptr;
};

class AniSwitchToProfileCallback : public IEsimServiceCallbackStub {
public:
    explicit AniSwitchToProfileCallback(std::shared_ptr<AniCallbackContext<int32_t>> context);
    void OnSwitchToProfile(const int32_t &result, const int32_t errorCode) override;

private:
    std::shared_ptr<AniCallbackContext<int32_t>> context_ = nullptr;
};

class AniDeleteProfileCallback : public IEsimServiceCallbackStub {
public:
    explicit AniDeleteProfileCallback(std::shared_ptr<AniCallbackContext<int32_t>> context);
    void OnDeleteProfile(const int32_t &result, const int32_t errorCode) override;

private:
    std::shared_ptr<AniCallbackContext<int32_t>> context_ = nullptr;
};

class AniGetEuiccInfoCallback : public IEsimServiceCallbackStub {
public:
    explicit AniGetEuiccInfoCallback(std::shared_ptr<AniCallbackContext<std::string>> context);
    void OnGetEuiccInfo(const EuiccInfo &result, const int32_t errorCode) override;

private:
    std::shared_ptr<AniCallbackContext<std::string>> context_ = nullptr;
};

class AniGetEuiccProfileInfoListCallback : public IEsimServiceCallbackStub {
public:
    explicit AniGetEuiccProfileInfoListCallback(
        std::shared_ptr<AniCallbackContext<GetEuiccProfileInfoListResult>> context);
    void OnGetEuiccProfileInfoList(const GetEuiccProfileInfoListResult &result, const int32_t errorCode) override;

private:
    std::shared_ptr<AniCallbackContext<GetEuiccProfileInfoListResult>> context_ = nullptr;
};


class AniDownloadProfileResultCallback : public IEsimServiceCallbackStub {
public:
    explicit AniDownloadProfileResultCallback(std::shared_ptr<AniCallbackContext<DownloadProfileResult>> context);
    void OnDownloadProfile(const DownloadProfileResult &result, const int32_t errorCode) override;

private:
    std::shared_ptr<AniCallbackContext<DownloadProfileResult>> context_ = nullptr;
};

class AniGetDownloadableProfilesCallback : public IEsimServiceCallbackStub {
public:
    explicit AniGetDownloadableProfilesCallback(
        std::shared_ptr<AniCallbackContext<GetDownloadableProfilesResult>> context);
    void OnGetDownloadableProfiles(const GetDownloadableProfilesResult &result, const int32_t errorCode) override;

private:
    std::shared_ptr<AniCallbackContext<GetDownloadableProfilesResult>> context_ = nullptr;
};

class AniGetDownloadableProfileMetadataCallback : public IEsimServiceCallbackStub {
public:
    explicit AniGetDownloadableProfileMetadataCallback(
        std::shared_ptr<AniCallbackContext<GetDownloadableProfileMetadataResult>> context);
    void OnGetDownloadableProfileMetadata(const GetDownloadableProfileMetadataResult &result,
        const int32_t errorCode) override;

private:
    std::shared_ptr<AniCallbackContext<GetDownloadableProfileMetadataResult>> context_ = nullptr;
};

class AniStartOsuCallback : public IEsimServiceCallbackStub {
public:
    explicit AniStartOsuCallback(std::shared_ptr<AniCallbackContext<int32_t>> context);
    void OnStartOsu(const OsuStatus &result, const int32_t errorCode) override;

private:
    std::shared_ptr<AniCallbackContext<int32_t>> context_ = nullptr;
};

class AniGetEidCallback : public IEsimServiceCallbackStub {
public:
    explicit AniGetEidCallback(std::shared_ptr<AniCallbackContext<std::string>> context);
    void OnGetEid(const std::string &eidstring, const int32_t errorCode) override;

private:
    std::shared_ptr<AniCallbackContext<std::string>> context_ = nullptr;
};
} // namespace EsimAni
} // namespace Telephony
} // namespace OHOS

#endif
