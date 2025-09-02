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
#ifndef MOCK_ESIM_MANAGER_H
#define MOCK_ESIM_MANAGER_H

#include "i_esim_manager.h"
#include <gmock/gmock.h>
namespace OHOS {
namespace Telephony {
class MockEsimManager : public IEsimManager {
public:
    MockEsimManager() = default;
    virtual ~MockEsimManager() = default;
    MOCK_METHOD1(OnInit, bool(int32_t));
    MOCK_METHOD2(GetEid, int32_t(int32_t, std::u16string &));
    MOCK_METHOD2(GetEuiccProfileInfoList, int32_t(int32_t, GetEuiccProfileInfoListInnerResult &));
    MOCK_METHOD2(GetEuiccInfo, int32_t(int32_t, EuiccInfo &));
    MOCK_METHOD5(DisableProfile, int32_t(int32_t, int32_t, const std::u16string &, bool, int32_t &));
    MOCK_METHOD3(GetSmdsAddress, int32_t(int32_t, int32_t, std::u16string &));
    MOCK_METHOD3(GetRulesAuthTable, int32_t(int32_t, int32_t, EuiccRulesAuthTable &));
    MOCK_METHOD3(GetEuiccChallenge, int32_t(int32_t, int32_t, ResponseEsimInnerResult &));
    MOCK_METHOD2(GetDefaultSmdpAddress, int32_t(int32_t, std::u16string &));
    MOCK_METHOD4(CancelSession, int32_t(int32_t, const std::u16string &, CancelReason, ResponseEsimInnerResult &));
    MOCK_METHOD4(GetProfile, int32_t(int32_t, int32_t, const std::u16string &, EuiccProfile &));
    MOCK_METHOD3(ResetMemory, int32_t(int32_t, ResetOption, int32_t &));
    MOCK_METHOD3(SetDefaultSmdpAddress, int32_t(int32_t, const std::u16string &, int32_t &));
    MOCK_METHOD1(IsSupported, bool(int32_t));
    MOCK_METHOD4(SendApduData,
                 int32_t(int32_t, const std::u16string &, const EsimApduData &, ResponseEsimInnerResult &));
    MOCK_METHOD3(PrepareDownload, int32_t(int32_t, const DownLoadConfigInfo &, ResponseEsimInnerResult &));
    MOCK_METHOD4(LoadBoundProfilePackage, int32_t(int32_t, int32_t, const std::u16string &, ResponseEsimBppResult &));
    MOCK_METHOD4(ListNotifications, int32_t(int32_t, int32_t, EsimEvent, EuiccNotificationList &));
    MOCK_METHOD4(RetrieveNotificationList, int32_t(int32_t, int32_t, EsimEvent, EuiccNotificationList &));
    MOCK_METHOD4(RetrieveNotification, int32_t(int32_t, int32_t, int32_t, EuiccNotification &));
    MOCK_METHOD4(RemoveNotificationFromList, int32_t(int32_t, int32_t, int32_t, int32_t &));
    MOCK_METHOD3(DeleteProfile, int32_t(int32_t, const std::u16string &, int32_t &));
    MOCK_METHOD5(SwitchToProfile, int32_t(int32_t, int32_t, const std::u16string &, bool, int32_t &));
    MOCK_METHOD4(SetProfileNickname, int32_t(int32_t, const std::u16string &, const std::u16string &, int32_t &));
    MOCK_METHOD3(GetEuiccInfo2, int32_t(int32_t, int32_t, EuiccInfo2 &));
    MOCK_METHOD3(AuthenticateServer, int32_t(int32_t, const AuthenticateConfigInfo &, ResponseEsimInnerResult &));
    MOCK_METHOD3(GetContractInfo, int32_t(int32_t, const GetContractInfoRequest &, std::string &));
    MOCK_METHOD2(GetEsimCaVerifyResult, int32_t(int32_t, bool &));
};
} // Telephony
} // OHOS
#endif // MOCK_ESIM_MANAGER_H
