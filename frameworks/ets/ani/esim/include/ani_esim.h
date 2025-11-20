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

#ifndef ANI_RS_ESIM_H
#define ANI_RS_ESIM_H

#include <cstdint>
#include "cxx.h"
#include "downloadable_profile_parcel.h"

namespace OHOS {
namespace Telephony {
namespace EsimAni {
struct ArktsError;
struct GetEuiccProfileInfoListResultAni;
struct EuiccProfileAni;
struct OperatorIdAni;
struct AccessRuleAni;
struct DownloadableProfileAni;
struct DownloadConfigurationAni;
struct DownloadProfileResultAni;
struct GetDownloadableProfileMetadataResultAni;

constexpr int WAIT_TIME_SECOND = 30;
constexpr int WAIT_LONG_TERM_TASK_SECOND = 180;
ArktsError ResetMemory(int32_t slotId, int32_t options, int32_t &resultCode);
ArktsError IsSupported(int32_t slotId, bool &isSupportedResult);
ArktsError AddProfile(const DownloadableProfileAni &profileAni, bool &addProfileResult);
ArktsError GetEid(int32_t slotId, rust::String &eid);
ArktsError GetOsuStatus(int32_t slotId, int32_t &osuStatus);
ArktsError StartOsu(int32_t slotId, int32_t &osuStatus);
ArktsError GetDownloadableProfileMetadata(int32_t slotId, int32_t portIndex, const DownloadableProfileAni &profileAni,
    bool forceDisableProfile, GetDownloadableProfileMetadataResultAni &metadataResult);
ArktsError GetDownloadableProfiles(int32_t slotId, int32_t portIndex, bool forceDisableProfile, int32_t &resultCode,
    rust::Vec<DownloadableProfileAni> &downloadableProfiles);
ArktsError DownloadProfile(int32_t slotId, int32_t portIndex, const DownloadableProfileAni &profileAni,
    const DownloadConfigurationAni &configAni, DownloadProfileResultAni &resultAni);
ArktsError GetEuiccProfileInfoList(int32_t slotId, GetEuiccProfileInfoListResultAni &profileList);
ArktsError GetEuiccInfo(int32_t slotId, rust::String &euiccInfo);
ArktsError DeleteProfile(int32_t slotId, rust::String iccid, int32_t &resultCode);
ArktsError SwitchToProfile(int32_t slotId, int32_t portIndex, rust::String iccid, bool forceDisableProfile,
    int32_t &resultCode);
ArktsError SetProfileNickname(int32_t slotId, rust::String iccid, rust::String nickname, int32_t &resultCode);
ArktsError ReserveProfilesForFactoryRestore(int32_t slotId, int32_t &resultCode);
ArktsError SetDefaultSmdpAddress(int32_t slotId, rust::String address, int32_t &resultCode);
ArktsError GetDefaultSmdpAddress(int32_t slotId, rust::String &address);
ArktsError CancelSession(int32_t slotId, rust::String transactionId, int32_t cancelReason, int32_t &resultCode);
} // namespace EsimAni
} // namespace Telephony
} // namespace OHOS

#endif
