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
#define private public
#define protected public
#include <gtest/gtest.h>

#include "core_manager_inner.h"
#include "mock_esim_manager.h"
#include "string_ex.h"

namespace OHOS {
namespace Telephony {
using namespace testing;
using namespace testing::ext;
class CoreManagerInnerTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

    CoreManagerInner mInner;
    std::shared_ptr<MockEsimManager> mockesimManager = std::make_shared<MockEsimManager>();
};

void CoreManagerInnerTest::SetUpTestCase() {}

void CoreManagerInnerTest::TearDownTestCase() {}

void CoreManagerInnerTest::SetUp() {}

void CoreManagerInnerTest::TearDown() {}

HWTEST_F(CoreManagerInnerTest, GetEid_001, Function | MediumTest | Level1)
{
    mInner.esimManager_ = nullptr;
    int32_t slotId = 0;
    std::u16string eId;
    int32_t ret = mInner.GetEid(slotId, eId);
    EXPECT_EQ(ret, TELEPHONY_ERR_LOCAL_PTR_NULL);

    mInner.esimManager_ = mockesimManager;
    EXPECT_CALL(*mockesimManager, GetEid(_, _)).WillOnce(Return(TELEPHONY_ERR_SUCCESS));
    ret = mInner.GetEid(slotId, eId);
    EXPECT_EQ(ret, TELEPHONY_ERR_SUCCESS);
}

HWTEST_F(CoreManagerInnerTest, GetEuiccProfileInfoList_001, Function | MediumTest | Level1)
{
    mInner.esimManager_ = nullptr;
    int32_t slotId = 0;
    GetEuiccProfileInfoListInnerResult result;
    int32_t ret = mInner.GetEuiccProfileInfoList(slotId, result);
    EXPECT_EQ(ret, TELEPHONY_ERR_LOCAL_PTR_NULL);

    mInner.esimManager_ = mockesimManager;
    EXPECT_CALL(*mockesimManager, GetEuiccProfileInfoList(_, _)).WillOnce(Return(TELEPHONY_ERR_SUCCESS));
    ret = mInner.GetEuiccProfileInfoList(slotId, result);
    EXPECT_EQ(ret, TELEPHONY_ERR_SUCCESS);
}

HWTEST_F(CoreManagerInnerTest, GetEuiccInfo_001, Function | MediumTest | Level1)
{
    mInner.esimManager_ = nullptr;
    int32_t slotId = 0;
    EuiccInfo result;
    int32_t ret = mInner.GetEuiccInfo(slotId, result);
    EXPECT_EQ(ret, TELEPHONY_ERR_LOCAL_PTR_NULL);

    mInner.esimManager_ = mockesimManager;
    EXPECT_CALL(*mockesimManager, GetEuiccInfo(_, _)).WillOnce(Return(TELEPHONY_ERR_SUCCESS));
    ret = mInner.GetEuiccInfo(slotId, result);
    EXPECT_EQ(ret, TELEPHONY_ERR_SUCCESS);
}

HWTEST_F(CoreManagerInnerTest, DisableProfile_001, Function | MediumTest | Level1)
{
    mInner.esimManager_ = nullptr;
    int32_t slotId = 0;
    int32_t portIndex = 0;
    std::u16string iccId = Str8ToStr16("98760000000000543210");
    bool refresh = true;
    int32_t enumResult;
    int32_t ret = mInner.DisableProfile(slotId, portIndex, iccId, refresh, enumResult);
    EXPECT_EQ(ret, TELEPHONY_ERR_LOCAL_PTR_NULL);

    mInner.esimManager_ = mockesimManager;
    EXPECT_CALL(*mockesimManager, DisableProfile(_, _, _, _, _)).WillOnce(Return(TELEPHONY_ERR_SUCCESS));
    ret = mInner.DisableProfile(slotId, portIndex, iccId, refresh, enumResult);
    EXPECT_EQ(ret, TELEPHONY_ERR_SUCCESS);
}

HWTEST_F(CoreManagerInnerTest, GetSmdsAddress_001, Function | MediumTest | Level1)
{
    mInner.esimManager_ = nullptr;
    int32_t slotId = 0;
    int32_t portIndex = 0;
    std::u16string smdsAddress;
    int32_t ret = mInner.GetSmdsAddress(slotId, portIndex, smdsAddress);
    EXPECT_EQ(ret, TELEPHONY_ERR_LOCAL_PTR_NULL);

    mInner.esimManager_ = mockesimManager;
    EXPECT_CALL(*mockesimManager, GetSmdsAddress(_, _, _)).WillOnce(Return(TELEPHONY_ERR_SUCCESS));
    ret = mInner.GetSmdsAddress(slotId, portIndex, smdsAddress);
    EXPECT_EQ(ret, TELEPHONY_ERR_SUCCESS);
}

HWTEST_F(CoreManagerInnerTest, GetRulesAuthTable_001, Function | MediumTest | Level1)
{
    mInner.esimManager_ = nullptr;
    int32_t slotId = 0;
    int32_t portIndex = 0;
    EuiccRulesAuthTable eUiccRulesAuthTable;
    int32_t ret = mInner.GetRulesAuthTable(slotId, portIndex, eUiccRulesAuthTable);
    EXPECT_EQ(ret, TELEPHONY_ERR_LOCAL_PTR_NULL);

    mInner.esimManager_ = mockesimManager;
    EXPECT_CALL(*mockesimManager, GetRulesAuthTable(_, _, _)).WillOnce(Return(TELEPHONY_ERR_SUCCESS));
    ret = mInner.GetRulesAuthTable(slotId, portIndex, eUiccRulesAuthTable);
    EXPECT_EQ(ret, TELEPHONY_ERR_SUCCESS);
}

HWTEST_F(CoreManagerInnerTest, GetEuiccChallenge_001, Function | MediumTest | Level1)
{
    mInner.esimManager_ = nullptr;
    int32_t slotId = 0;
    int32_t portIndex = 0;
    ResponseEsimInnerResult result;
    int32_t ret = mInner.GetEuiccChallenge(slotId, portIndex, result);
    EXPECT_EQ(ret, TELEPHONY_ERR_LOCAL_PTR_NULL);

    mInner.esimManager_ = mockesimManager;
    EXPECT_CALL(*mockesimManager, GetEuiccChallenge(_, _, _)).WillOnce(Return(TELEPHONY_ERR_SUCCESS));
    ret = mInner.GetEuiccChallenge(slotId, portIndex, result);
    EXPECT_EQ(ret, TELEPHONY_ERR_SUCCESS);
}

HWTEST_F(CoreManagerInnerTest, GetDefaultSmdpAddress_001, Function | MediumTest | Level1)
{
    mInner.esimManager_ = nullptr;
    int32_t slotId = 0;
    std::u16string defaultSmdpAddress;
    int32_t ret = mInner.GetDefaultSmdpAddress(slotId, defaultSmdpAddress);
    EXPECT_EQ(ret, TELEPHONY_ERR_LOCAL_PTR_NULL);

    mInner.esimManager_ = mockesimManager;
    EXPECT_CALL(*mockesimManager, GetDefaultSmdpAddress(_, _)).WillOnce(Return(TELEPHONY_ERR_SUCCESS));
    ret = mInner.GetDefaultSmdpAddress(slotId, defaultSmdpAddress);
    EXPECT_EQ(ret, TELEPHONY_ERR_SUCCESS);
}

HWTEST_F(CoreManagerInnerTest, CancelSession_001, Function | MediumTest | Level1)
{
    mInner.esimManager_ = nullptr;
    int32_t slotId = 0;
    std::u16string transactionId = Str8ToStr16("A1B2C3");
    CancelReason cancelReason = CancelReason::CANCEL_REASON_POSTPONED;
    ResponseEsimInnerResult responseResult;
    int32_t ret = mInner.CancelSession(slotId, transactionId, cancelReason, responseResult);
    EXPECT_EQ(ret, TELEPHONY_ERR_LOCAL_PTR_NULL);

    mInner.esimManager_ = mockesimManager;
    EXPECT_CALL(*mockesimManager, CancelSession(_, _, _, _)).WillOnce(Return(TELEPHONY_ERR_SUCCESS));
    ret = mInner.CancelSession(slotId, transactionId, cancelReason, responseResult);
    EXPECT_EQ(ret, TELEPHONY_ERR_SUCCESS);
}

HWTEST_F(CoreManagerInnerTest, GetProfile_001, Function | MediumTest | Level1)
{
    mInner.esimManager_ = nullptr;
    int32_t slotId = 0;
    int32_t portIndex = 0;
    std::u16string iccId = Str8ToStr16("5A0A89670000000000216954");
    EuiccProfile eUiccProfile;
    int32_t ret = mInner.GetProfile(slotId, portIndex, iccId, eUiccProfile);
    EXPECT_EQ(ret, TELEPHONY_ERR_LOCAL_PTR_NULL);

    mInner.esimManager_ = mockesimManager;
    EXPECT_CALL(*mockesimManager, GetProfile(_, _, _, _)).WillOnce(Return(TELEPHONY_ERR_SUCCESS));
    ret = mInner.GetProfile(slotId, portIndex, iccId, eUiccProfile);
    EXPECT_EQ(ret, TELEPHONY_ERR_SUCCESS);
}

HWTEST_F(CoreManagerInnerTest, ResetMemory_001, Function | MediumTest | Level1)
{
    mInner.esimManager_ = nullptr;
    int32_t slotId = 0;
    int32_t resetMemoryResult;
    const ResetOption resetOption = ResetOption::DELETE_OPERATIONAL_PROFILES;
    int32_t ret = mInner.ResetMemory(slotId, resetOption, resetMemoryResult);
    EXPECT_EQ(ret, TELEPHONY_ERR_LOCAL_PTR_NULL);

    mInner.esimManager_ = mockesimManager;
    EXPECT_CALL(*mockesimManager, ResetMemory(_, _, _)).WillOnce(Return(TELEPHONY_ERR_SUCCESS));
    ret = mInner.ResetMemory(slotId, resetOption, resetMemoryResult);
    EXPECT_EQ(ret, TELEPHONY_ERR_SUCCESS);
}

HWTEST_F(CoreManagerInnerTest, SetDefaultSmdpAddress_001, Function | MediumTest | Level1)
{
    mInner.esimManager_ = nullptr;
    int32_t slotId = 0;
    std::u16string defaultSmdpAddress = Str8ToStr16("test.com");
    int32_t setAddressResult;
    int32_t ret = mInner.SetDefaultSmdpAddress(slotId, defaultSmdpAddress, setAddressResult);
    EXPECT_EQ(ret, TELEPHONY_ERR_LOCAL_PTR_NULL);

    mInner.esimManager_ = mockesimManager;
    EXPECT_CALL(*mockesimManager, SetDefaultSmdpAddress(_, _, _)).WillOnce(Return(TELEPHONY_ERR_SUCCESS));
    ret = mInner.SetDefaultSmdpAddress(slotId, defaultSmdpAddress, setAddressResult);
    EXPECT_EQ(ret, TELEPHONY_ERR_SUCCESS);
}

HWTEST_F(CoreManagerInnerTest, IsSupported_001, Function | MediumTest | Level1)
{
    mInner.esimManager_ = nullptr;
    int32_t slotId = 0;
    bool ret = mInner.IsSupported(slotId);
    EXPECT_EQ(ret, false);

    mInner.esimManager_ = mockesimManager;
    EXPECT_CALL(*mockesimManager, IsSupported(_)).WillOnce(Return(true));
    ret = mInner.IsSupported(slotId);
    EXPECT_EQ(ret, true);
}

HWTEST_F(CoreManagerInnerTest, SendApduData_001, Function | MediumTest | Level1)
{
    mInner.esimManager_ = nullptr;
    int32_t slotId = 0;
    std::u16string aid = Str8ToStr16("aid test");
    EsimApduData apduData;
    ResponseEsimInnerResult responseResult;
    int32_t ret = mInner.SendApduData(slotId, aid, apduData, responseResult);
    EXPECT_EQ(ret, TELEPHONY_ERR_LOCAL_PTR_NULL);

    mInner.esimManager_ = mockesimManager;
    EXPECT_CALL(*mockesimManager, SendApduData(_, _, _, _)).WillOnce(Return(TELEPHONY_ERR_SUCCESS));
    ret = mInner.SendApduData(slotId, aid, apduData, responseResult);
    EXPECT_EQ(ret, TELEPHONY_ERR_SUCCESS);
}

HWTEST_F(CoreManagerInnerTest, PrepareDownload_001, Function | MediumTest | Level1)
{
    mInner.esimManager_ = nullptr;
    int32_t slotId = 0;
    DownLoadConfigInfo downLoadConfigInfo;
    downLoadConfigInfo.portIndex_ = 0;
    downLoadConfigInfo.hashCc_ = Str8ToStr16("4131423243332D583459355A36");
    ResponseEsimInnerResult responseResult;
    int32_t ret = mInner.PrepareDownload(slotId, downLoadConfigInfo, responseResult);
    EXPECT_EQ(ret, TELEPHONY_ERR_LOCAL_PTR_NULL);

    mInner.esimManager_ = mockesimManager;
    EXPECT_CALL(*mockesimManager, PrepareDownload(_, _, _)).WillOnce(Return(TELEPHONY_ERR_SUCCESS));
    ret = mInner.PrepareDownload(slotId, downLoadConfigInfo, responseResult);
    EXPECT_EQ(ret, TELEPHONY_ERR_SUCCESS);
}

HWTEST_F(CoreManagerInnerTest, LoadBoundProfilePackage_001, Function | MediumTest | Level1)
{
    mInner.esimManager_ = nullptr;
    int32_t slotId = 0;
    int32_t portIndex = 0;
    std::u16string boundProfilePackage;
    ResponseEsimBppResult responseResult;
    int32_t ret = mInner.LoadBoundProfilePackage(slotId, portIndex, boundProfilePackage, responseResult);
    EXPECT_EQ(ret, TELEPHONY_ERR_LOCAL_PTR_NULL);

    mInner.esimManager_ = mockesimManager;
    EXPECT_CALL(*mockesimManager, LoadBoundProfilePackage(_, _, _, _)).WillOnce(Return(TELEPHONY_ERR_SUCCESS));
    ret = mInner.LoadBoundProfilePackage(slotId, portIndex, boundProfilePackage, responseResult);
    EXPECT_EQ(ret, TELEPHONY_ERR_SUCCESS);
}


HWTEST_F(CoreManagerInnerTest, ListNotifications_001, Function | MediumTest | Level1)
{
    mInner.esimManager_ = nullptr;
    int32_t slotId = 0;
    int32_t portIndex = 0;
    const EsimEvent events = EsimEvent::EVENT_DELETE;
    EuiccNotificationList notificationList;
    int32_t ret = mInner.ListNotifications(slotId, portIndex, events, notificationList);
    EXPECT_EQ(ret, TELEPHONY_ERR_LOCAL_PTR_NULL);

    mInner.esimManager_ = mockesimManager;
    EXPECT_CALL(*mockesimManager, ListNotifications(_, _, _, _)).WillOnce(Return(TELEPHONY_ERR_SUCCESS));
    ret = mInner.ListNotifications(slotId, portIndex, events, notificationList);
    EXPECT_EQ(ret, TELEPHONY_ERR_SUCCESS);
}

HWTEST_F(CoreManagerInnerTest, RetrieveNotificationList_001, Function | MediumTest | Level1)
{
    mInner.esimManager_ = nullptr;
    int32_t slotId = 0;
    int32_t portIndex = 0;
    const EsimEvent events = EsimEvent::EVENT_DISABLE;
    EuiccNotificationList notificationList;
    int32_t ret = mInner.RetrieveNotificationList(slotId, portIndex, events, notificationList);
    EXPECT_EQ(ret, TELEPHONY_ERR_LOCAL_PTR_NULL);

    mInner.esimManager_ = mockesimManager;
    EXPECT_CALL(*mockesimManager, RetrieveNotificationList(_, _, _, _)).WillOnce(Return(TELEPHONY_ERR_SUCCESS));
    ret = mInner.RetrieveNotificationList(slotId, portIndex, events, notificationList);
    EXPECT_EQ(ret, TELEPHONY_ERR_SUCCESS);
}

HWTEST_F(CoreManagerInnerTest, RetrieveNotification_001, Function | MediumTest | Level1)
{
    mInner.esimManager_ = nullptr;
    int32_t slotId = 0;
    int32_t portIndex = 0;
    int32_t seqNumber = 5;
    EuiccNotification notification;
    int32_t ret = mInner.RetrieveNotification(slotId, portIndex, seqNumber, notification);
    EXPECT_EQ(ret, TELEPHONY_ERR_LOCAL_PTR_NULL);

    mInner.esimManager_ = mockesimManager;
    EXPECT_CALL(*mockesimManager, RetrieveNotification(_, _, _, _)).WillOnce(Return(TELEPHONY_ERR_SUCCESS));
    ret = mInner.RetrieveNotification(slotId, portIndex, seqNumber, notification);
    EXPECT_EQ(ret, TELEPHONY_ERR_SUCCESS);
}

HWTEST_F(CoreManagerInnerTest, RemoveNotificationFromList_001, Function | MediumTest | Level1)
{
    mInner.esimManager_ = nullptr;
    int32_t slotId = 0;
    int32_t portIndex = 0;
    int32_t seqNumber = 5;
    int32_t enumResult;
    int32_t ret = mInner.RemoveNotificationFromList(slotId, portIndex, seqNumber, enumResult);
    EXPECT_EQ(ret, TELEPHONY_ERR_LOCAL_PTR_NULL);

    mInner.esimManager_ = mockesimManager;
    EXPECT_CALL(*mockesimManager, RemoveNotificationFromList(_, _, _, _)).WillOnce(Return(TELEPHONY_ERR_SUCCESS));
    ret = mInner.RemoveNotificationFromList(slotId, portIndex, seqNumber, enumResult);
    EXPECT_EQ(ret, TELEPHONY_ERR_SUCCESS);
}

HWTEST_F(CoreManagerInnerTest, DeleteProfile_001, Function | MediumTest | Level1)
{
    mInner.esimManager_ = nullptr;
    int32_t slotId = 0;
    std::u16string iccId = Str8ToStr16("98760000000000543210");
    int32_t deleteProfileResult;
    int32_t ret = mInner.DeleteProfile(slotId, iccId, deleteProfileResult);
    EXPECT_EQ(ret, TELEPHONY_ERR_LOCAL_PTR_NULL);

    mInner.esimManager_ = mockesimManager;
    EXPECT_CALL(*mockesimManager, DeleteProfile(_, _, _)).WillOnce(Return(TELEPHONY_ERR_SUCCESS));
    ret = mInner.DeleteProfile(slotId, iccId, deleteProfileResult);
    EXPECT_EQ(ret, TELEPHONY_ERR_SUCCESS);
}

HWTEST_F(CoreManagerInnerTest, SwitchToProfile_001, Function | MediumTest | Level1)
{
    mInner.esimManager_ = nullptr;
    int32_t slotId = 0;
    int32_t portIndex = 1;
    std::u16string iccId = Str8ToStr16("98760000000000543210");
    bool forceDisableProfile = true;
    int32_t switchProfileResult;
    int32_t ret = mInner.SwitchToProfile(slotId, portIndex, iccId, forceDisableProfile, switchProfileResult);
    EXPECT_EQ(ret, TELEPHONY_ERR_LOCAL_PTR_NULL);

    mInner.esimManager_ = mockesimManager;
    EXPECT_CALL(*mockesimManager, SwitchToProfile(_, _, _, _, _)).WillOnce(Return(TELEPHONY_ERR_SUCCESS));
    ret = mInner.SwitchToProfile(slotId, portIndex, iccId, forceDisableProfile, switchProfileResult);
    EXPECT_EQ(ret, TELEPHONY_ERR_SUCCESS);
}

HWTEST_F(CoreManagerInnerTest, SetProfileNickname_001, Function | MediumTest | Level1)
{
    mInner.esimManager_ = nullptr;
    int32_t slotId = 0;
    std::u16string iccId = Str8ToStr16("98760000000000543210");
    std::u16string nickname = Str8ToStr16("nick");
    int32_t updateResult;
    int32_t ret = mInner.SetProfileNickname(slotId, iccId, nickname, updateResult);
    EXPECT_EQ(ret, TELEPHONY_ERR_LOCAL_PTR_NULL);

    mInner.esimManager_ = mockesimManager;
    EXPECT_CALL(*mockesimManager, SetProfileNickname(_, _, _, _)).WillOnce(Return(TELEPHONY_ERR_SUCCESS));
    ret = mInner.SetProfileNickname(slotId, iccId, nickname, updateResult);
    EXPECT_EQ(ret, TELEPHONY_ERR_SUCCESS);
}

HWTEST_F(CoreManagerInnerTest, GetEuiccInfo2_002, Function | MediumTest | Level1)
{
    mInner.esimManager_ = nullptr;
    int32_t slotId = 0;
    int32_t portIndex = 0;
    EuiccInfo2 euiccInfo2;
    int32_t ret = mInner.GetEuiccInfo2(slotId, portIndex, euiccInfo2);
    EXPECT_EQ(ret, TELEPHONY_ERR_LOCAL_PTR_NULL);

    mInner.esimManager_ = mockesimManager;
    EXPECT_CALL(*mockesimManager, GetEuiccInfo2(_, _, _)).WillOnce(Return(TELEPHONY_ERR_SUCCESS));
    ret = mInner.GetEuiccInfo2(slotId, portIndex, euiccInfo2);
    EXPECT_EQ(ret, TELEPHONY_ERR_SUCCESS);
}

HWTEST_F(CoreManagerInnerTest, AuthenticateServer_001, Function | MediumTest | Level1)
{
    mInner.esimManager_ = nullptr;
    int32_t slotId = 0;
    AuthenticateConfigInfo authenticateConfigInfo;
    authenticateConfigInfo.matchingId_ = Str8ToStr16("4131423243332D583459355A36");
    ResponseEsimInnerResult responseResult;
    int32_t ret = mInner.AuthenticateServer(slotId, authenticateConfigInfo, responseResult);
    EXPECT_EQ(ret, TELEPHONY_ERR_LOCAL_PTR_NULL);

    mInner.esimManager_ = mockesimManager;
    EXPECT_CALL(*mockesimManager, AuthenticateServer(_, _, _)).WillOnce(Return(TELEPHONY_ERR_SUCCESS));
    ret = mInner.AuthenticateServer(slotId, authenticateConfigInfo, responseResult);
    EXPECT_EQ(ret, TELEPHONY_ERR_SUCCESS);
}

HWTEST_F(CoreManagerInnerTest, GetContractInfo_001, Function | MediumTest | Level1)
{
    mInner.esimManager_ = nullptr;
    int32_t slotId = 0;
    GetContractInfoRequest request;
    std::string response = "";
    int32_t ret = mInner.GetContractInfo(slotId, request, response);
    EXPECT_EQ(ret, TELEPHONY_ERR_LOCAL_PTR_NULL);

    mInner.esimManager_ = mockesimManager;
    EXPECT_CALL(*mockesimManager, GetContractInfo(_, _, _)).WillOnce(Return(TELEPHONY_ERR_SUCCESS));
    ret = mInner.GetContractInfo(slotId, request, response);
    EXPECT_EQ(ret, TELEPHONY_ERR_SUCCESS);
}

HWTEST_F(CoreManagerInnerTest, GetEsimCaVerifyResult_001, Function | MediumTest | Level1)
{
    mInner.esimManager_ = nullptr;
    int32_t slotId = 0;
    bool verifyResult = false;
    int32_t ret = mInner.GetEsimCaVerifyResult(slotId, verifyResult);
    EXPECT_EQ(ret, TELEPHONY_ERR_LOCAL_PTR_NULL);

    mInner.esimManager_ = mockesimManager;
    EXPECT_CALL(*mockesimManager, GetEsimCaVerifyResult(_, _)).WillOnce(Return(TELEPHONY_ERR_SUCCESS));
    ret = mInner.GetEsimCaVerifyResult(slotId, verifyResult);
    EXPECT_EQ(ret, TELEPHONY_ERR_SUCCESS);
}

HWTEST_F(CoreManagerInnerTest, SetEsimCaVerifyResult_001, Function | MediumTest | Level1)
{
    mInner.esimManager_ = nullptr;
    int32_t slotId = 0;
    bool verifyResult = false;
    int32_t ret = mInner.SetEsimCaVerifyResult(slotId, verifyResult);
    EXPECT_EQ(ret, TELEPHONY_ERR_LOCAL_PTR_NULL);

    mInner.esimManager_ = mockesimManager;
    EXPECT_CALL(*mockesimManager, SetEsimCaVerifyResult(_, _)).WillOnce(Return(TELEPHONY_ERR_SUCCESS));
    ret = mInner.SetEsimCaVerifyResult(slotId, verifyResult);
    EXPECT_EQ(ret, TELEPHONY_ERR_SUCCESS);
}
} // Telephony
} // OHOS
