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

#ifndef OHOS_NAPI_ESIM_H
#define OHOS_NAPI_ESIM_H

#include <array>
#include <string>
#include <vector>
#include "base_context.h"
#include "download_profile_config_info_parcel.h"
#include "download_profile_result_parcel.h"
#include "downloadable_profile_parcel.h"
#include "esim_state_type.h"
#include "euicc_info_parcel.h"
#include "get_downloadable_profiles_result_parcel.h"
#include "profile_info_list_parcel.h"
#include "profile_metadata_result_parcel.h"
#include "response_esim_result.h"
#include "telephony_napi_common_error.h"
#include "telephony_types.h"

namespace OHOS {
namespace Telephony {
const int32_t DEFAULT_ERROR = -1;

template<typename T>
struct AsyncContext {
    BaseContext context;
    int32_t slotId = ERROR_DEFAULT;
    T callbackVal;
};

struct AsyncContextInfo {
    AsyncContext<int32_t> asyncContext;
    std::string inputStr = "";
};

struct AsyncCommonInfo {
    AsyncContext<int32_t> asyncContext;
};

struct AsyncEuiccInfo {
    AsyncContext<napi_value> asyncContext;
    EuiccInfo result;
};

struct AsyncEuiccProfileInfoList {
    AsyncContext<napi_value> asyncContext;
    GetEuiccProfileInfoListResult result;
};

struct AsyncSwitchProfileInfo {
    AsyncContext<int32_t> asyncContext;
    int32_t portIndex = ERROR_DEFAULT;
    std::string iccid = "";
    bool forceDeactivateSim = false;
};

struct AsyncAccessRule {
    std::string certificateHashHexStr = "";
    std::string packageName = "";
    int32_t accessType = ERROR_DEFAULT;
};

struct AsyncDownloadableProfile {
    std::string encodedActivationCode = "";
    std::string confirmationCode = "";
    std::string carrierName = "";
    std::vector<AsyncAccessRule> accessRules{};
};

struct AsyncDownloadProfileInfo {
    AsyncContext<napi_value> asyncContext;
    int32_t portIndex = ERROR_DEFAULT;
    AsyncDownloadableProfile profile;
    bool switchAfterDownload = false;
    bool forceDeactivateSim = false;
    DownloadProfileResult result;
};

struct AsyncDefaultProfileList {
    AsyncContext<napi_value> asyncContext;
    int32_t portIndex = ERROR_DEFAULT;
    bool forceDeactivateSim = false;
    GetDownloadableProfilesResult result;
};

struct AsyncProfileNickname {
    AsyncContext<int32_t> asyncContext;
    std::string iccid = "";
    std::string nickname = "";
};

struct AsyncCancelSession {
    AsyncContext<napi_value> asyncContext;
    std::string transactionId = "";
    int32_t cancelReason = static_cast<int32_t>(CancelReason::CANCEL_REASON_POSTPONED);
    ResponseEsimResult responseResult;
};

struct AsyncProfileMetadataInfo {
    AsyncContext<napi_value> asyncContext;
    int32_t portIndex = ERROR_DEFAULT;
    AsyncDownloadableProfile profile;
    bool forceDeactivateSim = false;
    GetDownloadableProfileMetadataResult result;
};

struct AsyncResetMemory {
    AsyncContext<int32_t> asyncContext;
    int32_t option = ERROR_DEFAULT;
};
} // namespace Telephony
} // namespace OHOS
#endif // OHOS_NAPI_ESIM_H
