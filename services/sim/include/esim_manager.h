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

#ifndef OHOS_ESIM_MANAGER_H
#define OHOS_ESIM_MANAGER_H

#include "i_esim_manager.h"
#include "i_tel_ril_manager.h"

#ifdef CORE_SERVICE_SUPPORT_ESIM
#include "esim_file.h"
#endif

namespace OHOS {
namespace Telephony {
const int32_t ESIM_SLOT_ID_ZERO = 0;
const int32_t ESIM_MAX_SLOT_COUNT = 3;
class EsimManager : public IEsimManager {
public:
    explicit EsimManager(std::shared_ptr<ITelRilManager> telRilManager);
    virtual ~EsimManager();
    // Init
    bool OnInit(int32_t slotCount) override;
    int32_t GetEid(int32_t slotId, std::u16string &eId) override;
    int32_t GetEuiccProfileInfoList(int32_t slotId, GetEuiccProfileInfoListInnerResult &euiccProfileInfoList) override;
    int32_t GetEuiccInfo(int32_t slotId, EuiccInfo &eUiccInfo) override;
    int32_t DisableProfile(
        int32_t slotId, int32_t portIndex, const std::u16string &iccId, bool refresh, int32_t &enumResult) override;
    int32_t GetSmdsAddress(int32_t slotId, int32_t portIndex, std::u16string &smdsAddress) override;
    int32_t GetRulesAuthTable(int32_t slotId, int32_t portIndex, EuiccRulesAuthTable &eUiccRulesAuthTable) override;
    int32_t GetEuiccChallenge(int32_t slotId, int32_t portIndex, ResponseEsimInnerResult &responseResult) override;
    int32_t GetDefaultSmdpAddress(int32_t slotId, std::u16string &defaultSmdpAddress) override;
    int32_t CancelSession(int32_t slotId, const std::u16string &transactionId, CancelReason cancelReason,
        ResponseEsimInnerResult &responseResult) override;
    int32_t GetProfile(
        int32_t slotId, int32_t portIndex, const std::u16string &iccId, EuiccProfile &eUiccProfile) override;
    int32_t ResetMemory(int32_t slotId, ResetOption resetOption, int32_t &enumResult) override;
    int32_t SetDefaultSmdpAddress(
        int32_t slotId, const std::u16string &defaultSmdpAddress, int32_t &enumResult) override;
    bool IsSupported(int32_t slotId) override;
    int32_t SendApduData(int32_t slotId, const std::u16string &aid, const EsimApduData &apduData,
        ResponseEsimInnerResult &responseResult) override;
    int32_t PrepareDownload(int32_t slotId, const DownLoadConfigInfo &downLoadConfigInfo,
        ResponseEsimInnerResult &responseResult) override;
    int32_t LoadBoundProfilePackage(int32_t slotId, int32_t portIndex, const std::u16string &boundProfilePackage,
        ResponseEsimBppResult &responseResult) override;
    int32_t ListNotifications(int32_t slotId, int32_t portIndex, EsimEvent events,
        EuiccNotificationList &notificationList) override;
    int32_t RetrieveNotificationList(
        int32_t slotId, int32_t portIndex, EsimEvent events, EuiccNotificationList &notificationList) override;
    int32_t RetrieveNotification(
        int32_t slotId, int32_t portIndex, int32_t seqNumber, EuiccNotification &notification) override;
    int32_t RemoveNotificationFromList(
        int32_t slotId, int32_t portIndex, int32_t seqNumber, int32_t &enumResult) override;
    int32_t GetEuiccInfo2(int32_t slotId, int32_t portIndex, EuiccInfo2 &euiccInfo2) override;
    int32_t AuthenticateServer(int32_t slotId, const AuthenticateConfigInfo &authenticateConfigInfo,
        ResponseEsimInnerResult &responseResult) override;
    int32_t DeleteProfile(int32_t slotId, const std::u16string &iccId, int32_t &enumResult) override;
    int32_t SwitchToProfile(int32_t slotId, int32_t portIndex, const std::u16string &iccId,
        bool forceDisableProfile, int32_t &enumResult) override;
    int32_t SetProfileNickname(
        int32_t slotId, const std::u16string &iccId, const std::u16string &nickname, int32_t &enumResult) override;
    int32_t GetContractInfo(
        int32_t slotId, const GetContractInfoRequest &getContractInfoRequest, std::string& response) override;

private:
    template<class N>
    bool IsValidSlotId(int32_t slotId, std::vector<N> vec);
private:
    std::shared_ptr<Telephony::ITelRilManager> telRilManager_ = nullptr;
    int32_t slotCount_ = ESIM_MAX_SLOT_COUNT;
    int32_t slotId_ = ESIM_SLOT_ID_ZERO;
#ifdef CORE_SERVICE_SUPPORT_ESIM
    std::vector<std::shared_ptr<Telephony::EsimFile>> esimFiles_;
#endif
};
} // namespace Telephony
} // namespace OHOS
#endif // OHOS_ESIM_MANAGER_H