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

#define private public
#define protected public

#include <string>
#include <unistd.h>

#include "core_service_client.h"
#include "esim_state_type.h"
#include "if_system_ability_manager_mock.h"
#include "iservice_registry.h"
#include "securec.h"
#include "str_convert.h"
#include "string_ex.h"
#include "telephony_errors.h"
#include "telephony_log_wrapper.h"
#include "gtest/gtest.h"

namespace OHOS {
namespace Telephony {
using namespace testing::ext;
class EsimCoreServiceClientBranchTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

    static inline std::shared_ptr<ISystemAbilityManagerMock> samgr = std::make_shared<ISystemAbilityManagerMock>();
};

void EsimCoreServiceClientBranchTest::SetUpTestCase()
{
    SystemAbilityManagerClient::GetInstance().systemAbilityManager_ = sptr<ISystemAbilityManager>(samgr.get());
}

void EsimCoreServiceClientBranchTest::TearDownTestCase()
{
    samgr = nullptr;
    SystemAbilityManagerClient::GetInstance().systemAbilityManager_ = nullptr;
}

void EsimCoreServiceClientBranchTest::SetUp() {}

void EsimCoreServiceClientBranchTest::TearDown() {}

HWTEST_F(EsimCoreServiceClientBranchTest, GetEid_0002, Function | MediumTest | Level1)
{
    int32_t slotId = 0;
    std::u16string eId = Str8ToStr16("1A2B3C4D");
    EXPECT_CALL(*samgr, CheckSystemAbility(testing::_)).WillOnce(testing::Return(nullptr));
    int32_t result = CoreServiceClient::GetInstance().GetEid(slotId, eId);
    EXPECT_EQ(result, TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL);
}

HWTEST_F(EsimCoreServiceClientBranchTest, GetEuiccProfileInfoList_0001, Function | MediumTest | Level1)
{
    int32_t slotId = 0;
    GetEuiccProfileInfoListResult euiccProfileInfoList;
    EXPECT_CALL(*samgr, CheckSystemAbility(testing::_)).WillOnce(testing::Return(nullptr));
    int32_t result = CoreServiceClient::GetInstance().GetEuiccProfileInfoList(slotId, euiccProfileInfoList);
    EXPECT_EQ(result, TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL);
}

HWTEST_F(EsimCoreServiceClientBranchTest, GetEuiccInfo_0001, Function | MediumTest | Level1)
{
    int32_t slotId = 0;
    EuiccInfo euiccInfo;
    euiccInfo.osVersion_ = Str8ToStr16("BF2003010203");
    EXPECT_CALL(*samgr, CheckSystemAbility(testing::_)).WillOnce(testing::Return(nullptr));
    int32_t result = CoreServiceClient::GetInstance().GetEuiccInfo(slotId, euiccInfo);
    EXPECT_EQ(result, TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL);
}

HWTEST_F(EsimCoreServiceClientBranchTest, DisableProfile_0100, Function | MediumTest | Level1)
{
    int32_t slotId = 0;
    int32_t portIndex = 0;
    std::u16string iccId = Str8ToStr16("98760000000000543210");
    bool refresh = true;
    ResultCode disableProfileResult;
    EXPECT_CALL(*samgr, CheckSystemAbility(testing::_)).WillOnce(testing::Return(nullptr));
    int32_t result =
        CoreServiceClient::GetInstance().DisableProfile(slotId, portIndex, iccId, refresh, disableProfileResult);
    EXPECT_EQ(result, TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL);
}

HWTEST_F(EsimCoreServiceClientBranchTest, GetSmdsAddress_0100, Function | MediumTest | Level1)
{
    int32_t slotId = 0;
    int32_t portIndex = 0;
    std::u16string smdsAddress;
    EXPECT_CALL(*samgr, CheckSystemAbility(testing::_)).WillOnce(testing::Return(nullptr));
    int32_t result = CoreServiceClient::GetInstance().GetSmdsAddress(slotId, portIndex, smdsAddress);
    EXPECT_EQ(result, TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL);
}

HWTEST_F(EsimCoreServiceClientBranchTest, GetRulesAuthTable_0100, Function | MediumTest | Level1)
{
    int32_t slotId = 0;
    int32_t portIndex = 0;
    EuiccRulesAuthTable eUiccRulesAuthTable;
    EXPECT_CALL(*samgr, CheckSystemAbility(testing::_)).WillOnce(testing::Return(nullptr));
    int32_t result = CoreServiceClient::GetInstance().GetRulesAuthTable(slotId, portIndex, eUiccRulesAuthTable);
    EXPECT_EQ(result, TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL);
}

HWTEST_F(EsimCoreServiceClientBranchTest, GetEuiccChallenge_0100, Function | MediumTest | Level1)
{
    int32_t slotId = 0;
    int32_t portIndex = 0;
    ResponseEsimResult responseResult;
    EXPECT_CALL(*samgr, CheckSystemAbility(testing::_)).WillOnce(testing::Return(nullptr));
    int32_t result = CoreServiceClient::GetInstance().GetEuiccChallenge(slotId, portIndex, responseResult);
    EXPECT_EQ(result, TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL);
}

HWTEST_F(EsimCoreServiceClientBranchTest, RequestDefaultSmdpAddress_0100, Function | MediumTest | Level1)
{
    int32_t slotId = 0;
    std::u16string address = Str8ToStr16("test.com");
    EXPECT_CALL(*samgr, CheckSystemAbility(testing::_)).WillOnce(testing::Return(nullptr));
    int32_t result = CoreServiceClient::GetInstance().GetDefaultSmdpAddress(slotId, address);
    EXPECT_EQ(result, TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL);
}

HWTEST_F(EsimCoreServiceClientBranchTest, CancelSession_0100, Function | MediumTest | Level1)
{
    int32_t slotId = 0;
    std::u16string transactionId = Str8ToStr16("A1B2C3");
    const CancelReason cancelReason = CancelReason::CANCEL_REASON_POSTPONED;
    ResponseEsimResult responseResult;
    EXPECT_CALL(*samgr, CheckSystemAbility(testing::_)).WillOnce(testing::Return(nullptr));
    int32_t result =
        CoreServiceClient::GetInstance().CancelSession(slotId, transactionId, cancelReason, responseResult);
    EXPECT_EQ(result, TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL);
}

HWTEST_F(EsimCoreServiceClientBranchTest, GetProfile_0100, Function | MediumTest | Level1)
{
    int32_t slotId = 0;
    int32_t portIndex = 0;
    std::u16string iccId = Str8ToStr16("5A0A89670000000000216954");
    EuiccProfile eUiccProfile;
    EXPECT_CALL(*samgr, CheckSystemAbility(testing::_)).WillOnce(testing::Return(nullptr));
    int32_t result = CoreServiceClient::GetInstance().GetProfile(slotId, portIndex, iccId, eUiccProfile);
    EXPECT_EQ(result, TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL);
}

HWTEST_F(EsimCoreServiceClientBranchTest, ResetMemory_0100, Function | MediumTest | Level1)
{
    int32_t slotId = 0;
    ResultCode ResetMemoryResult;
    const ResetOption resetOption = ResetOption::DELETE_OPERATIONAL_PROFILES;
    EXPECT_CALL(*samgr, CheckSystemAbility(testing::_)).WillOnce(testing::Return(nullptr));
    int32_t result = CoreServiceClient::GetInstance().ResetMemory(slotId, resetOption, ResetMemoryResult);
    EXPECT_EQ(result, TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL);
}

HWTEST_F(EsimCoreServiceClientBranchTest, SetDefaultSmdpAddress_0100, Function | MediumTest | Level1)
{
    int32_t slotId = 0;
    std::u16string defaultSmdpAddress = Str8ToStr16("test.com");
    ResultCode SetAddressResult;
    EXPECT_CALL(*samgr, CheckSystemAbility(testing::_)).WillOnce(testing::Return(nullptr));
    int32_t result = CoreServiceClient::GetInstance().
        SetDefaultSmdpAddress(slotId, defaultSmdpAddress, SetAddressResult);
    EXPECT_EQ(result, TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL);
}

HWTEST_F(EsimCoreServiceClientBranchTest, IsEsimSupported_0100, Function | MediumTest | Level1)
{
    int32_t slotId = 0;
    EXPECT_CALL(*samgr, CheckSystemAbility(testing::_)).WillOnce(testing::Return(nullptr));
    int32_t result = CoreServiceClient::GetInstance().IsSupported(slotId);
    EXPECT_EQ(result, false);
}

HWTEST_F(EsimCoreServiceClientBranchTest, SendApduData_0100, Function | MediumTest | Level1)
{
    int32_t slotId = 0;
    std::u16string aid = Str8ToStr16("aid test");
    EsimApduData apduData;
    ResponseEsimResult responseResult;
    EXPECT_CALL(*samgr, CheckSystemAbility(testing::_)).WillOnce(testing::Return(nullptr));
    int32_t result = CoreServiceClient::GetInstance().SendApduData(slotId, aid, apduData, responseResult);
    EXPECT_EQ(result, TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL);
}

HWTEST_F(EsimCoreServiceClientBranchTest, PrepareDownload_0100, Function | MediumTest | Level1)
{
    DownLoadConfigInfo downLoadConfigInfo;
    int32_t slotId = 0;
    downLoadConfigInfo.portIndex_ = 0;
    downLoadConfigInfo.hashCc_ = Str8ToStr16("4131423243332D583459355A36");
    ResponseEsimResult responseResult;
    EXPECT_CALL(*samgr, CheckSystemAbility(testing::_)).WillOnce(testing::Return(nullptr));
    int32_t result = CoreServiceClient::GetInstance().PrepareDownload(slotId, downLoadConfigInfo, responseResult);
    EXPECT_EQ(result, TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL);
}

HWTEST_F(EsimCoreServiceClientBranchTest, LoadBoundProfilePackage_0100, Function | MediumTest | Level1)
{
    int32_t slotId = 0;
    int32_t portIndex = 0;
    std::u16string boundProfilePackage = Str8ToStr16("0");
    ResponseEsimBppResult responseResult;
    EXPECT_CALL(*samgr, CheckSystemAbility(testing::_)).WillOnce(testing::Return(nullptr));
    int32_t result = CoreServiceClient::GetInstance().LoadBoundProfilePackage(
        slotId, portIndex, boundProfilePackage, responseResult);
    EXPECT_EQ(result, TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL);
}

HWTEST_F(EsimCoreServiceClientBranchTest, ListNotifications_0100, Function | MediumTest | Level1)
{
    int32_t slotId = 0;
    int32_t portIndex = 0;
    const Event events = Event::EVENT_DELETE;
    EuiccNotificationList notificationList1;
    EXPECT_CALL(*samgr, CheckSystemAbility(testing::_)).WillOnce(testing::Return(nullptr));
    int32_t result = CoreServiceClient::GetInstance().ListNotifications(slotId, portIndex, events, notificationList1);
    EXPECT_EQ(result, TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL);
}

HWTEST_F(EsimCoreServiceClientBranchTest, RetrieveNotificationList_0100, Function | MediumTest | Level1)
{
    int32_t slotId = 0;
    int32_t portIndex = 0;
    const Event events = Event::EVENT_DELETE;
    EuiccNotificationList notificationList;

    EXPECT_CALL(*samgr, CheckSystemAbility(testing::_)).WillOnce(testing::Return(nullptr));
    int32_t result = CoreServiceClient::GetInstance().RetrieveNotificationList(slotId, portIndex,
        events, notificationList);
    EXPECT_EQ(result, TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL);
}

HWTEST_F(EsimCoreServiceClientBranchTest, RetrieveNotification_0100, Function | MediumTest | Level1)
{
    int32_t slotId = 0;
    int32_t portIndex = 0;
    int32_t seqNumber = 5;
    EuiccNotification notification;

    EXPECT_CALL(*samgr, CheckSystemAbility(testing::_)).WillOnce(testing::Return(nullptr));
    int32_t result = CoreServiceClient::GetInstance().RetrieveNotification(slotId, portIndex, seqNumber, notification);
    EXPECT_EQ(result, TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL);
}

HWTEST_F(EsimCoreServiceClientBranchTest, RemoveNotificationFromList_0100, Function | MediumTest | Level1)
{
    int32_t slotId = 0;
    int32_t portIndex = 0;
    int32_t seqNumber = 5;
    ResultCode enumResult;

    EXPECT_CALL(*samgr, CheckSystemAbility(testing::_)).WillOnce(testing::Return(nullptr));
    int32_t result = CoreServiceClient::GetInstance().RemoveNotificationFromList(slotId, portIndex,
        seqNumber, enumResult);
    EXPECT_EQ(result, TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL);
}

HWTEST_F(EsimCoreServiceClientBranchTest, DeleteProfile_0001, Function | MediumTest | Level1)
{
    int32_t slotId = 0;
    std::u16string iccId = Str8ToStr16("98760000000000543210");
    ResultCode DeleteProfileResult;
    EXPECT_CALL(*samgr, CheckSystemAbility(testing::_)).WillOnce(testing::Return(nullptr));
    int32_t result = CoreServiceClient::GetInstance().DeleteProfile(slotId, iccId, DeleteProfileResult);
    EXPECT_EQ(result, TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL);
}

HWTEST_F(EsimCoreServiceClientBranchTest, SwitchToProfile_0100, Function | MediumTest | Level1)
{
    int32_t slotId = 0;
    int32_t portIndex = 1;
    std::u16string iccId = Str8ToStr16("98760000000000543210");
    bool forceDisableProfile = true;
    ResultCode SwitchProfileResult;
    EXPECT_CALL(*samgr, CheckSystemAbility(testing::_)).WillOnce(testing::Return(nullptr));
    int32_t result = CoreServiceClient::GetInstance().SwitchToProfile(
        slotId, portIndex, iccId, forceDisableProfile, SwitchProfileResult);
    EXPECT_EQ(result, TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL);
}

HWTEST_F(EsimCoreServiceClientBranchTest, SetProfileNickname_0100, Function | MediumTest | Level1)
{
    int32_t slotId = 0;
    std::u16string iccId = Str8ToStr16("98760000000000543210");
    std::u16string nickname = Str8ToStr16("nick");
    ResultCode UpdateResult;
    EXPECT_CALL(*samgr, CheckSystemAbility(testing::_)).WillOnce(testing::Return(nullptr));
    int32_t result = CoreServiceClient::GetInstance().SetProfileNickname(slotId, iccId, nickname, UpdateResult);
    EXPECT_EQ(result, TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL);
}

HWTEST_F(EsimCoreServiceClientBranchTest, GetEuiccInfo2_0100, Function | MediumTest | Level1)
{
    int32_t slotId = 0;
    int32_t portIndex = 0;
    EuiccInfo2 euiccInfo2;
    EXPECT_CALL(*samgr, CheckSystemAbility(testing::_)).WillOnce(testing::Return(nullptr));
    int32_t result = CoreServiceClient::GetInstance().GetEuiccInfo2(slotId, portIndex, euiccInfo2);
    EXPECT_EQ(result, TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL);
}

HWTEST_F(EsimCoreServiceClientBranchTest, AuthenticateServer_0100, Function | MediumTest | Level1)
{
    int32_t slotId = 0;
    AuthenticateConfigInfo authenticateConfigInfo;
    authenticateConfigInfo.portIndex_ = 0;
    authenticateConfigInfo.matchingId_ = Str8ToStr16("4131423243332D583459355A36");
    ResponseEsimResult responseResult;
    EXPECT_CALL(*samgr, CheckSystemAbility(testing::_)).WillOnce(testing::Return(nullptr));
    int32_t result = CoreServiceClient::GetInstance().AuthenticateServer(slotId, authenticateConfigInfo,
        responseResult);
    EXPECT_EQ(result, TELEPHONY_ERR_IPC_CONNECT_STUB_FAIL);
}
} // namespace Telephony
} // namespace OHOS