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

#ifndef I_BASE_ESIM_SERVICE_H
#define I_BASE_ESIM_SERVICE_H

#include "esim_state_type.h"
#include "iremote_object.h"
#include "iremote_broker.h"
#include "iremote_proxy.h"

namespace OHOS {
namespace Telephony {
class IEsimService : public IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.telephony.IEsimService");

public:
    virtual ~IEsimService() = default;
    virtual int32_t GetEid(int32_t slotId, std::u16string &eId) = 0;
    virtual int32_t GetOsuStatus(int32_t slotId, OsuStatus &osuStatus) = 0;
    virtual int32_t StartOsu(int32_t slotId, Result &enumResult) = 0;
    virtual int32_t GetDownloadableProfileMetadata(
        int32_t slotId, int32_t portIndex, const DownloadableProfile &profile,
        bool forceDeactivateSim, GetDownloadableProfileMetadataResult &profileMetadataResult) = 0;
    virtual int32_t GetAvailableDownloadableProfileList(
        int32_t slotId, bool forceDeactivateSim, GetAvailableDownloadableProfileListResult &profileListResult) = 0;
    virtual int32_t DownloadProfile(int32_t slotId, int32_t portIndex, const DownloadableProfile &profile,
        bool switchAfterDownload, bool forceDeactivateSim, DownloadProfileResult &downloadProfileResult) = 0;
    virtual int32_t GetEuiccProfileInfoList(int32_t slotId, GetEuiccProfileInfoListResult &euiccProfileInfoList) = 0;
    virtual int32_t GetEuiccInfo(int32_t slotId, EuiccInfo &eUiccInfo) = 0;
    virtual int32_t DeleteProfile(int32_t slotId, const std::u16string &iccId, Result &enumResult) = 0;
    virtual int32_t SwitchToProfile(int32_t slotId,
        int32_t portIndex, const std::u16string &iccId, bool forceDeactivateSim, Result &enumResult) = 0;
    virtual int32_t SetProfileNickname(
        int32_t slotId, const std::u16string &iccId, const std::u16string &nickname, Result &enumResult) = 0;
    virtual int32_t ResetMemory(int32_t slotId, ResetOption resetOption, Result &enumResult) = 0;
    virtual int32_t ReserveProfilesForFactoryRestore(int32_t slotId, Result &enumResult) = 0;
    virtual int32_t SetDefaultSmdpAddress(
        int32_t slotId, const std::u16string &defaultSmdpAddress, Result &enumResult) = 0;
    virtual int32_t GetDefaultSmdpAddress(int32_t slotId, std::u16string &defaultSmdpAddress) = 0;
    virtual int32_t CancelSession(int32_t slotId, const std::u16string &transactionId,
        CancelReason cancelReason, ResponseEsimResult &responseResult) = 0;
    virtual bool IsEsimSupported(int32_t slotId) = 0;
};
} // namespace Telephony
} // namespace OHOS
#endif // I_BASE_ESIM_SERVICE_H
