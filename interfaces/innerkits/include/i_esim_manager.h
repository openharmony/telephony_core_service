/*
 * Copyright (C) 2025-2025 Huawei Device Co., Ltd.
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

#ifndef OHOS_I_ESIM_MANAGER_H
#define OHOS_I_ESIM_MANAGER_H

#include "download_profile_config_info_parcel.h"
#include "download_profile_result_parcel.h"
#include "downloadable_profile_parcel.h"
#include "esim_state_type.h"
#include "euicc_info_parcel.h"
#include "get_downloadable_profiles_result_parcel.h"
#include "profile_info_list_parcel.h"
#include "profile_metadata_result_parcel.h"
#include "response_esim_result.h"

namespace OHOS {
namespace Telephony {
class IEsimManager {
public:
    // Init
    virtual bool OnInit(int32_t slotCount) = 0;
    virtual int32_t GetEid(int32_t slotId, std::u16string &eId) = 0;
    virtual int32_t GetEuiccProfileInfoList(int32_t slotId,
        GetEuiccProfileInfoListInnerResult &euiccProfileInfoList) = 0;
    virtual int32_t GetEuiccInfo(int32_t slotId, EuiccInfo &eUiccInfo) = 0;
    virtual int32_t DisableProfile(
        int32_t slotId, int32_t portIndex, const std::u16string &iccId, bool refresh, int32_t &enumResult) = 0;
    virtual int32_t GetSmdsAddress(int32_t slotId, int32_t portIndex, std::u16string &smdsAddress) = 0;
    virtual int32_t GetRulesAuthTable(
        int32_t slotId, int32_t portIndex, EuiccRulesAuthTable &eUiccRulesAuthTable) = 0;
    virtual int32_t GetEuiccChallenge(
        int32_t slotId, int32_t portIndex, ResponseEsimInnerResult &responseResult) = 0;
    virtual int32_t GetDefaultSmdpAddress(int32_t slotId, std::u16string &defaultSmdpAddress) = 0;
    virtual int32_t CancelSession(int32_t slotId, const std::u16string &transactionId, CancelReason cancelReason,
        ResponseEsimInnerResult &responseResult) = 0;
    virtual int32_t GetProfile(
        int32_t slotId, int32_t portIndex, const std::u16string &iccId, EuiccProfile &eUiccProfile) = 0;
    virtual int32_t ResetMemory(int32_t slotId, ResetOption resetOption, int32_t &enumResult) = 0;
    virtual int32_t SetDefaultSmdpAddress(
        int32_t slotId, const std::u16string &defaultSmdpAddress, int32_t &enumResult) = 0;
    virtual bool IsSupported(int32_t slotId) = 0;
    virtual int32_t SendApduData(int32_t slotId, const std::u16string &aid, const EsimApduData &apduData,
        ResponseEsimInnerResult &responseResult) = 0;
    virtual int32_t PrepareDownload(int32_t slotId, const DownLoadConfigInfo &downLoadConfigInfo,
        ResponseEsimInnerResult &responseResult) = 0;
    virtual int32_t LoadBoundProfilePackage(int32_t slotId, int32_t portIndex,
        const std::u16string &boundProfilePackage, ResponseEsimBppResult &responseResult) = 0;
    virtual int32_t ListNotifications(int32_t slotId, int32_t portIndex, EsimEvent events,
        EuiccNotificationList &notificationList) = 0;
    virtual int32_t RetrieveNotificationList(
        int32_t slotId, int32_t portIndex, EsimEvent events, EuiccNotificationList &notificationList) = 0;
    virtual int32_t RetrieveNotification(
        int32_t slotId, int32_t portIndex, int32_t seqNumber, EuiccNotification &notification) = 0;
    virtual int32_t RemoveNotificationFromList(
        int32_t slotId, int32_t portIndex, int32_t seqNumber, int32_t &enumResult) = 0;
    virtual int32_t DeleteProfile(int32_t slotId, const std::u16string &iccId, int32_t &enumResult) = 0;
    virtual int32_t SwitchToProfile(int32_t slotId, int32_t portIndex,
        const std::u16string &iccId, bool forceDisableProfile, int32_t &enumResult) = 0;
    virtual int32_t SetProfileNickname(
        int32_t slotId, const std::u16string &iccId, const std::u16string &nickname, int32_t &enumResult) = 0;
    virtual int32_t GetEuiccInfo2(int32_t slotId, int32_t portIndex, EuiccInfo2 &euiccInfo2) = 0;
    virtual int32_t AuthenticateServer(int32_t slotId, const AuthenticateConfigInfo &authenticateConfigInfo,
        ResponseEsimInnerResult &responseResult) = 0;
    virtual int32_t GetContractInfo(int32_t slotId, const GetContractInfoRequest &contractInfoRequest,
        std::string &response) = 0;
    virtual int32_t GetEsimCaVerifyResult(int32_t slotId, bool &verifyResult) = 0;
};
} // namespace Telephony
} // namespace OHOS
#endif // OHOS_I_ESIM_MANAGER_H
