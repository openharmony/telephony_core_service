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

#include "core_service.h"
#include "esim_state_type.h"
#include "gmock/gmock.h"
#include "string_ex.h"
#include "str_convert.h"
#include "sim_manager.h"
#include "telephony_errors.h"
#include "telephony_log_wrapper.h"
#include "telephony_permission.h"
#include "gtest/gtest.h"

namespace OHOS {
namespace Telephony {
using namespace testing::ext;
class EsimCoreServiceTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void EsimCoreServiceTest::SetUpTestCase() {}

void EsimCoreServiceTest::TearDownTestCase() {}

void EsimCoreServiceTest::SetUp() {}

void EsimCoreServiceTest::TearDown() {}

HWTEST_F(EsimCoreServiceTest, GetEid_0001, Function | MediumTest | Level1)
{
    std::shared_ptr<CoreService> mCoreService = std::make_shared<CoreService>();
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    mCoreService->simManager_ = std::make_shared<SimManager>(telRilManager);
    int32_t slotId = 0;
    std::u16string eId;
    EXPECT_NE(mCoreService->GetEid(slotId, eId), TELEPHONY_ERR_SUCCESS);
    mCoreService->simManager_ = nullptr;
    EXPECT_EQ(mCoreService->GetEid(slotId, eId), TELEPHONY_ERR_LOCAL_PTR_NULL);
}

HWTEST_F(EsimCoreServiceTest, GetEuiccProfileInfoList_0001, Function | MediumTest | Level1)
{
    std::shared_ptr<CoreService> mCoreService = std::make_shared<CoreService>();
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    mCoreService->simManager_ = std::make_shared<SimManager>(telRilManager);
    int32_t slotId = 0;
    GetEuiccProfileInfoListResult euiccProfileInfoList;
    EXPECT_NE(mCoreService->GetEuiccProfileInfoList(slotId, euiccProfileInfoList), TELEPHONY_ERR_SUCCESS);
    mCoreService->simManager_ = nullptr;
    EXPECT_EQ(mCoreService->GetEuiccProfileInfoList(slotId, euiccProfileInfoList), TELEPHONY_ERR_LOCAL_PTR_NULL);
}

HWTEST_F(EsimCoreServiceTest, GetEuiccInfo_0001, Function | MediumTest | Level1)
{
    std::shared_ptr<CoreService> mCoreService = std::make_shared<CoreService>();
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    mCoreService->simManager_ = std::make_shared<SimManager>(telRilManager);
    int32_t slotId = 0;
    EuiccInfo euiccInfo;
    euiccInfo.osVersion = Str8ToStr16("BF2003010203");
    EXPECT_NE(mCoreService->GetEuiccInfo(slotId, euiccInfo), TELEPHONY_ERR_SUCCESS);
    mCoreService->simManager_ = nullptr;
    EXPECT_EQ(mCoreService->GetEuiccInfo(slotId, euiccInfo), TELEPHONY_ERR_LOCAL_PTR_NULL);
}

HWTEST_F(EsimCoreServiceTest, DisableProfile_0001, Function | MediumTest | Level1)
{
    std::shared_ptr<CoreService> mCoreService = std::make_shared<CoreService>();
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    mCoreService->simManager_ = std::make_shared<SimManager>(telRilManager);
    int32_t slotId = 0;
    int32_t portIndex = 0;
    std::u16string iccId = Str8ToStr16("98760000000000543210");
    bool refresh = true;
    ResultState disableProfileResult;
    EXPECT_NE(mCoreService->DisableProfile(
        slotId, portIndex, iccId, refresh, disableProfileResult), TELEPHONY_ERR_SUCCESS);
    mCoreService->simManager_ = nullptr;
    EXPECT_EQ(mCoreService->DisableProfile(
        slotId, portIndex, iccId, refresh, disableProfileResult), TELEPHONY_ERR_LOCAL_PTR_NULL);
}

HWTEST_F(EsimCoreServiceTest, GetSmdsAddress_0001, Function | MediumTest | Level1)
{
    std::shared_ptr<CoreService> mCoreService = std::make_shared<CoreService>();
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    mCoreService->simManager_ = std::make_shared<SimManager>(telRilManager);
    int32_t slotId = 0;
    int32_t portIndex = 0;
    std::u16string smdsAddress;
    EXPECT_NE(mCoreService->GetSmdsAddress(
        slotId, portIndex, smdsAddress), TELEPHONY_ERR_SUCCESS);
    mCoreService->simManager_ = nullptr;
    EXPECT_EQ(mCoreService->GetSmdsAddress(
        slotId, portIndex, smdsAddress), TELEPHONY_ERR_LOCAL_PTR_NULL);
}

HWTEST_F(EsimCoreServiceTest, GetRulesAuthTable_0001, Function | MediumTest | Level1)
{
    std::shared_ptr<CoreService> mCoreService = std::make_shared<CoreService>();
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    mCoreService->simManager_ = std::make_shared<SimManager>(telRilManager);
    int32_t slotId = 0;
    int32_t portIndex = 0;
    EuiccRulesAuthTable eUiccRulesAuthTable;
    EXPECT_NE(mCoreService->GetRulesAuthTable(
        slotId, portIndex, eUiccRulesAuthTable), TELEPHONY_ERR_SUCCESS);
    mCoreService->simManager_ = nullptr;
    EXPECT_EQ(mCoreService->GetRulesAuthTable(
        slotId, portIndex, eUiccRulesAuthTable), TELEPHONY_ERR_LOCAL_PTR_NULL);
}

HWTEST_F(EsimCoreServiceTest, GetEuiccChallenge_0001, Function | MediumTest | Level1)
{
    std::shared_ptr<CoreService> mCoreService = std::make_shared<CoreService>();
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    mCoreService->simManager_ = std::make_shared<SimManager>(telRilManager);
    int32_t slotId = 0;
    int32_t portIndex = 0;
    ResponseEsimResult responseResult;
    EXPECT_NE(mCoreService->GetEuiccChallenge(
        slotId, portIndex, responseResult), TELEPHONY_ERR_SUCCESS);
    mCoreService->simManager_ = nullptr;
    EXPECT_EQ(mCoreService->GetEuiccChallenge(
        slotId, portIndex, responseResult), TELEPHONY_ERR_LOCAL_PTR_NULL);
}

HWTEST_F(EsimCoreServiceTest, RequestDefaultSmdpAddress_0001, Function | MediumTest | Level1)
{
    std::shared_ptr<CoreService> mCoreService = std::make_shared<CoreService>();
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    mCoreService->simManager_ = std::make_shared<SimManager>(telRilManager);
    int32_t slotId = 0;
    std::u16string address = Str8ToStr16("test.com");
    EXPECT_NE(mCoreService->GetDefaultSmdpAddress(slotId, address), TELEPHONY_ERR_SUCCESS);
    mCoreService->simManager_ = nullptr;
    EXPECT_EQ(mCoreService->GetDefaultSmdpAddress(slotId, address), TELEPHONY_ERR_LOCAL_PTR_NULL);
}

HWTEST_F(EsimCoreServiceTest, CancelSession_0001, Function | MediumTest | Level1)
{
    std::shared_ptr<CoreService> mCoreService = std::make_shared<CoreService>();
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    mCoreService->simManager_ = std::make_shared<SimManager>(telRilManager);
    int32_t slotId = 0;
    std::u16string transactionId = Str8ToStr16("A1B2C3");
    const CancelReason cancelReason = CancelReason::CANCEL_REASON_POSTPONED;
    ResponseEsimResult responseResult;
    EXPECT_NE(mCoreService->CancelSession(
        slotId, transactionId, cancelReason, responseResult), TELEPHONY_ERR_SUCCESS);
    mCoreService->simManager_ = nullptr;
    EXPECT_EQ(mCoreService->CancelSession(
        slotId, transactionId, cancelReason, responseResult), TELEPHONY_ERR_LOCAL_PTR_NULL);
}

HWTEST_F(EsimCoreServiceTest, GetProfile_0001, Function | MediumTest | Level1)
{
    std::shared_ptr<CoreService> mCoreService = std::make_shared<CoreService>();
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    mCoreService->simManager_ = std::make_shared<SimManager>(telRilManager);
    int32_t slotId = 0;
    int32_t portIndex = 0;
    std::u16string iccId = Str8ToStr16("5A0A89670000000000216954");
    EuiccProfile eUiccProfile;
    EXPECT_NE(mCoreService->GetProfile(
        slotId, portIndex, iccId, eUiccProfile), TELEPHONY_ERR_SUCCESS);
    mCoreService->simManager_ = nullptr;
    EXPECT_EQ(mCoreService->GetProfile(
        slotId, portIndex, iccId, eUiccProfile), TELEPHONY_ERR_LOCAL_PTR_NULL);
}

HWTEST_F(EsimCoreServiceTest, ResetMemory_0001, Function | MediumTest | Level1)
{
    std::shared_ptr<CoreService> mCoreService = std::make_shared<CoreService>();
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    mCoreService->simManager_ = std::make_shared<SimManager>(telRilManager);
    int32_t slotId = 0;
    ResultState ResetMemoryResult;
    const ResetOption resetOption = ResetOption::DELETE_OPERATIONAL_PROFILES;
    EXPECT_NE(mCoreService->ResetMemory(
        slotId, resetOption, ResetMemoryResult), TELEPHONY_ERR_SUCCESS);
    mCoreService->simManager_ = nullptr;
    EXPECT_EQ(mCoreService->ResetMemory(
        slotId, resetOption, ResetMemoryResult), TELEPHONY_ERR_LOCAL_PTR_NULL);
}

HWTEST_F(EsimCoreServiceTest, SetDefaultSmdpAddress_0001, Function | MediumTest | Level1)
{
    std::shared_ptr<CoreService> mCoreService = std::make_shared<CoreService>();
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    mCoreService->simManager_ = std::make_shared<SimManager>(telRilManager);
    int32_t slotId = 0;
    std::u16string defaultSmdpAddress = Str8ToStr16("test.com");
    ResultState SetAddressResult;
    EXPECT_NE(mCoreService->SetDefaultSmdpAddress(
        slotId, defaultSmdpAddress, SetAddressResult), TELEPHONY_ERR_SUCCESS);
    mCoreService->simManager_ = nullptr;
    EXPECT_EQ(mCoreService->SetDefaultSmdpAddress(
        slotId, defaultSmdpAddress, SetAddressResult), TELEPHONY_ERR_LOCAL_PTR_NULL);
}

HWTEST_F(EsimCoreServiceTest, IsEsimSupported_0001, Function | MediumTest | Level1)
{
    std::shared_ptr<CoreService> mCoreService = std::make_shared<CoreService>();
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    mCoreService->simManager_ = std::make_shared<SimManager>(telRilManager);
    int32_t slotId = 0;
    EXPECT_FALSE(mCoreService->IsEsimSupported(slotId));
    mCoreService->simManager_ = nullptr;
    EXPECT_FALSE(mCoreService->IsEsimSupported(slotId));
}

HWTEST_F(EsimCoreServiceTest, SendApduData_0001, Function | MediumTest | Level1)
{
    std::shared_ptr<CoreService> mCoreService = std::make_shared<CoreService>();
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    mCoreService->simManager_ = std::make_shared<SimManager>(telRilManager);
    int32_t slotId = 0;
    std::u16string aid = Str8ToStr16("aid test");
    std::u16string apduData = Str8ToStr16("apduData test");
    ResponseEsimResult responseResult;
    EXPECT_NE(mCoreService->SendApduData(
        slotId, aid, apduData, responseResult), TELEPHONY_ERR_SUCCESS);
    mCoreService->simManager_ = nullptr;
    EXPECT_EQ(mCoreService->SendApduData(
        slotId, aid, apduData, responseResult), TELEPHONY_ERR_LOCAL_PTR_NULL);
}

HWTEST_F(EsimCoreServiceTest, PrepareDownload_0001, Function | MediumTest | Level1)
{
    std::shared_ptr<CoreService> mCoreService = std::make_shared<CoreService>();
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    mCoreService->simManager_ = std::make_shared<SimManager>(telRilManager);
    int32_t slotId = 0;
    DownLoadConfigInfo downLoadConfigInfo;
    downLoadConfigInfo.portIndex = 0;
    downLoadConfigInfo.hashCc = Str8ToStr16("4131423243332D583459355A36");
    ResponseEsimResult responseResult;
    EXPECT_NE(mCoreService->PrepareDownload(slotId, downLoadConfigInfo, responseResult), TELEPHONY_ERR_SUCCESS);
    mCoreService->simManager_ = nullptr;
    EXPECT_EQ(mCoreService->PrepareDownload(slotId, downLoadConfigInfo, responseResult), TELEPHONY_ERR_LOCAL_PTR_NULL);
}

HWTEST_F(EsimCoreServiceTest, LoadBoundProfilePackage_0001, Function | MediumTest | Level1)
{
    std::shared_ptr<CoreService> mCoreService = std::make_shared<CoreService>();
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    mCoreService->simManager_ = std::make_shared<SimManager>(telRilManager);
    int32_t slotId = 0;
    int32_t portIndex = 0;
    std::u16string boundProfilePackage = Str8ToStr16("0");
    ResponseEsimBppResult responseResult;
    EXPECT_NE(mCoreService->LoadBoundProfilePackage(
        slotId, portIndex, boundProfilePackage, responseResult), TELEPHONY_ERR_SUCCESS);
    mCoreService->simManager_ = nullptr;
    EXPECT_EQ(mCoreService->LoadBoundProfilePackage(
        slotId, portIndex, boundProfilePackage, responseResult), TELEPHONY_ERR_LOCAL_PTR_NULL);
}

HWTEST_F(EsimCoreServiceTest, ListNotifications_0001, Function | MediumTest | Level1)
{
    std::shared_ptr<CoreService> mCoreService = std::make_shared<CoreService>();
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    mCoreService->simManager_ = std::make_shared<SimManager>(telRilManager);
    int32_t slotId = 0;
    int32_t portIndex = 0;
    const Event events = Event::EVENT_DELETE;
    EuiccNotificationList notificationList1;
    EXPECT_NE(mCoreService->ListNotifications(
        slotId, portIndex, events, notificationList1), TELEPHONY_ERR_SUCCESS);
    mCoreService->simManager_ = nullptr;
    EXPECT_EQ(mCoreService->ListNotifications(
        slotId, portIndex, events, notificationList1), TELEPHONY_ERR_LOCAL_PTR_NULL);
}
} // namespace Telephony
} // namespace OHOS