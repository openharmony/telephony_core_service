/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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
#include <thread>

#include "esim_manager.h"
#include "string_ex.h"
#include "tel_ril_manager.h"

namespace OHOS {
namespace Telephony {
using namespace testing::ext;
class EsimManagerTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<EsimManager> esimManager = std::make_shared<EsimManager>(telRilManager);
};

void EsimManagerTest::SetUpTestCase() {}

void EsimManagerTest::TearDownTestCase() {}

void EsimManagerTest::SetUp()
{
    esimManager->esimFiles_.resize(ESIM_MAX_SLOT_COUNT);
    esimManager->esimFiles_[0] = std::make_shared<EsimFile>(telRilManager);
    esimManager->esimFiles_[1] = nullptr;
}

void EsimManagerTest::TearDown() {}

#ifdef CORE_SERVICE_SUPPORT_ESIM
HWTEST_F(EsimManagerTest, OnInit_001, Function | MediumTest | Level1)
{
    int32_t slotCount = 4;
    bool ret = esimManager->OnInit(slotCount);
    EXPECT_FALSE(ret);

    slotCount = -1;
    ret = esimManager->OnInit(slotCount);
    EXPECT_FALSE(ret);

    slotCount = 0;
    ret = esimManager->OnInit(slotCount);
    EXPECT_TRUE(ret);
}

HWTEST_F(EsimManagerTest, GetEid_001, Function | MediumTest | Level1)
{
    int32_t slotId = -1;
    std::u16string eId;
    int32_t ret = esimManager->GetEid(slotId, eId);
    EXPECT_EQ(ret, TELEPHONY_ERR_LOCAL_PTR_NULL);

    slotId = 1;
    ret = esimManager->GetEid(slotId, eId);
    EXPECT_EQ(ret, TELEPHONY_ERR_LOCAL_PTR_NULL);

    slotId = 0;
    ret = esimManager->GetEid(slotId, eId);
    EXPECT_EQ(ret, TELEPHONY_ERR_SUCCESS);
}

HWTEST_F(EsimManagerTest, GetEuiccProfileInfoList_001, Function | MediumTest | Level1)
{
    int32_t slotId = -1;
    GetEuiccProfileInfoListInnerResult result;
    int32_t ret = esimManager->GetEuiccProfileInfoList(slotId, result);
    EXPECT_EQ(ret, TELEPHONY_ERR_LOCAL_PTR_NULL);

    slotId = 1;
    ret = esimManager->GetEuiccProfileInfoList(slotId, result);
    EXPECT_EQ(ret, TELEPHONY_ERR_LOCAL_PTR_NULL);

    slotId = 0;
    ret = esimManager->GetEuiccProfileInfoList(slotId, result);
    EXPECT_EQ(ret, TELEPHONY_ERR_SUCCESS);
}

HWTEST_F(EsimManagerTest, GetEuiccInfo_001, Function | MediumTest | Level1)
{
    int32_t slotId = -1;
    EuiccInfo result;
    int32_t ret = esimManager->GetEuiccInfo(slotId, result);
    EXPECT_EQ(ret, TELEPHONY_ERR_LOCAL_PTR_NULL);

    slotId = 1;
    ret = esimManager->GetEuiccInfo(slotId, result);
    EXPECT_EQ(ret, TELEPHONY_ERR_LOCAL_PTR_NULL);

    slotId = 0;
    ret = esimManager->GetEuiccInfo(slotId, result);
    EXPECT_EQ(ret, TELEPHONY_ERR_SUCCESS);
}

HWTEST_F(EsimManagerTest, DisableProfile_001, Function | MediumTest | Level1)
{
    int32_t slotId = -1;
    int32_t portIndex = 0;
    std::u16string iccId = Str8ToStr16("98760000000000543210");
    bool refresh = true;
    int32_t enumResult;
    int32_t ret = esimManager->DisableProfile(slotId, portIndex, iccId, refresh, enumResult);
    EXPECT_EQ(ret, TELEPHONY_ERR_LOCAL_PTR_NULL);

    slotId = 1;
    ret = esimManager->DisableProfile(slotId, portIndex, iccId, refresh, enumResult);
    EXPECT_EQ(ret, TELEPHONY_ERR_LOCAL_PTR_NULL);

    slotId = 0;
    ret = esimManager->DisableProfile(slotId, portIndex, iccId, refresh, enumResult);
    EXPECT_EQ(ret, TELEPHONY_ERR_SUCCESS);
}

HWTEST_F(EsimManagerTest, GetSmdsAddress_001, Function | MediumTest | Level1)
{
    int32_t slotId = -1;
    int32_t portIndex = 0;
    std::u16string smdsAddress;
    int32_t ret = esimManager->GetSmdsAddress(slotId, portIndex, smdsAddress);
    EXPECT_EQ(ret, TELEPHONY_ERR_LOCAL_PTR_NULL);

    slotId = 1;
    ret = esimManager->GetSmdsAddress(slotId, portIndex, smdsAddress);
    EXPECT_EQ(ret, TELEPHONY_ERR_LOCAL_PTR_NULL);

    slotId = 0;
    ret = esimManager->GetSmdsAddress(slotId, portIndex, smdsAddress);
    EXPECT_EQ(ret, TELEPHONY_ERR_SUCCESS);
}

HWTEST_F(EsimManagerTest, GetRulesAuthTable_001, Function | MediumTest | Level1)
{
    int32_t slotId = -1;
    int32_t portIndex = 0;
    EuiccRulesAuthTable eUiccRulesAuthTable;
    int32_t ret = esimManager->GetRulesAuthTable(slotId, portIndex, eUiccRulesAuthTable);
    EXPECT_EQ(ret, TELEPHONY_ERR_LOCAL_PTR_NULL);

    slotId = 1;
    ret = esimManager->GetRulesAuthTable(slotId, portIndex, eUiccRulesAuthTable);
    EXPECT_EQ(ret, TELEPHONY_ERR_LOCAL_PTR_NULL);

    slotId = 0;
    ret = esimManager->GetRulesAuthTable(slotId, portIndex, eUiccRulesAuthTable);
    EXPECT_EQ(ret, TELEPHONY_ERR_SUCCESS);
}

HWTEST_F(EsimManagerTest, GetEuiccChallenge_001, Function | MediumTest | Level1)
{
    int32_t slotId = -1;
    int32_t portIndex = 0;
    ResponseEsimInnerResult result;
    int32_t ret = esimManager->GetEuiccChallenge(slotId, portIndex, result);
    EXPECT_EQ(ret, TELEPHONY_ERR_LOCAL_PTR_NULL);

    slotId = 1;
    ret = esimManager->GetEuiccChallenge(slotId, portIndex, result);
    EXPECT_EQ(ret, TELEPHONY_ERR_LOCAL_PTR_NULL);

    slotId = 0;
    ret = esimManager->GetEuiccChallenge(slotId, portIndex, result);
    EXPECT_EQ(ret, TELEPHONY_ERR_SUCCESS);
}

HWTEST_F(EsimManagerTest, GetDefaultSmdpAddress_001, Function | MediumTest | Level1)
{
    int32_t slotId = -1;
    std::u16string defaultSmdpAddress;
    int32_t ret = esimManager->GetDefaultSmdpAddress(slotId, defaultSmdpAddress);
    EXPECT_EQ(ret, TELEPHONY_ERR_LOCAL_PTR_NULL);

    slotId = 1;
    ret = esimManager->GetDefaultSmdpAddress(slotId, defaultSmdpAddress);
    EXPECT_EQ(ret, TELEPHONY_ERR_LOCAL_PTR_NULL);

    slotId = 0;
    ret = esimManager->GetDefaultSmdpAddress(slotId, defaultSmdpAddress);
    EXPECT_EQ(ret, TELEPHONY_ERR_FAIL);
}

HWTEST_F(EsimManagerTest, CancelSession_001, Function | MediumTest | Level1)
{
    int32_t slotId = -1;
    std::u16string transactionId = Str8ToStr16("A1B2C3");
    CancelReason cancelReason = CancelReason::CANCEL_REASON_POSTPONED;
    ResponseEsimInnerResult responseResult;
    int32_t ret = esimManager->CancelSession(slotId, transactionId, cancelReason, responseResult);
    EXPECT_EQ(ret, TELEPHONY_ERR_LOCAL_PTR_NULL);

    slotId = 1;
    ret = esimManager->CancelSession(slotId, transactionId, cancelReason, responseResult);
    EXPECT_EQ(ret, TELEPHONY_ERR_LOCAL_PTR_NULL);

    slotId = 0;
    ret = esimManager->CancelSession(slotId, transactionId, cancelReason, responseResult);
    EXPECT_EQ(ret, TELEPHONY_ERR_FAIL);
}

HWTEST_F(EsimManagerTest, GetProfile_001, Function | MediumTest | Level1)
{
    int32_t slotId = -1;
    int32_t portIndex = 0;
    std::u16string iccId = Str8ToStr16("5A0A89670000000000216954");
    EuiccProfile eUiccProfile;
    int32_t ret = esimManager->GetProfile(slotId, portIndex, iccId, eUiccProfile);
    EXPECT_EQ(ret, TELEPHONY_ERR_LOCAL_PTR_NULL);

    slotId = 1;
    ret = esimManager->GetProfile(slotId, portIndex, iccId, eUiccProfile);
    EXPECT_EQ(ret, TELEPHONY_ERR_LOCAL_PTR_NULL);

    slotId = 0;
    ret = esimManager->GetProfile(slotId, portIndex, iccId, eUiccProfile);
    EXPECT_EQ(ret, TELEPHONY_ERR_FAIL);
}

HWTEST_F(EsimManagerTest, ResetMemory_001, Function | MediumTest | Level1)
{
    int32_t slotId = -1;
    int32_t resetMemoryResult;
    const ResetOption resetOption = ResetOption::DELETE_OPERATIONAL_PROFILES;
    int32_t ret = esimManager->ResetMemory(slotId, resetOption, resetMemoryResult);
    EXPECT_EQ(ret, TELEPHONY_ERR_LOCAL_PTR_NULL);

    slotId = 1;
    ret = esimManager->ResetMemory(slotId, resetOption, resetMemoryResult);
    EXPECT_EQ(ret, TELEPHONY_ERR_LOCAL_PTR_NULL);

    slotId = 0;
    ret = esimManager->ResetMemory(slotId, resetOption, resetMemoryResult);
    EXPECT_EQ(ret, TELEPHONY_ERR_SUCCESS);
}

HWTEST_F(EsimManagerTest, SetDefaultSmdpAddress_001, Function | MediumTest | Level1)
{
    int32_t slotId = -1;
    std::u16string defaultSmdpAddress = Str8ToStr16("test.com");
    int32_t setAddressResult;
    int32_t ret = esimManager->SetDefaultSmdpAddress(slotId, defaultSmdpAddress, setAddressResult);
    EXPECT_EQ(ret, TELEPHONY_ERR_LOCAL_PTR_NULL);

    slotId = 1;
    ret = esimManager->SetDefaultSmdpAddress(slotId, defaultSmdpAddress, setAddressResult);
    EXPECT_EQ(ret, TELEPHONY_ERR_LOCAL_PTR_NULL);

    slotId = 0;
    ret = esimManager->SetDefaultSmdpAddress(slotId, defaultSmdpAddress, setAddressResult);
    EXPECT_EQ(ret, TELEPHONY_ERR_SUCCESS);
}

HWTEST_F(EsimManagerTest, IsSupported_001, Function | MediumTest | Level1)
{
    int32_t slotId = -1;
    bool ret = esimManager->IsSupported(slotId);
    EXPECT_EQ(ret, false);

    slotId = 1;
    ret = esimManager->IsSupported(slotId);
    EXPECT_EQ(ret, false);

    slotId = 0;
    ret = esimManager->IsSupported(slotId);
    EXPECT_EQ(ret, false);
}

HWTEST_F(EsimManagerTest, SendApduData_001, Function | MediumTest | Level1)
{
    int32_t slotId = -1;
    std::u16string aid = Str8ToStr16("aid test");
    EsimApduData apduData;
    ResponseEsimInnerResult responseResult;
    int32_t ret = esimManager->SendApduData(slotId, aid, apduData, responseResult);
    EXPECT_EQ(ret, TELEPHONY_ERR_LOCAL_PTR_NULL);

    slotId = 1;
    ret = esimManager->SendApduData(slotId, aid, apduData, responseResult);
    EXPECT_EQ(ret, TELEPHONY_ERR_LOCAL_PTR_NULL);

    slotId = 0;
    ret = esimManager->SendApduData(slotId, aid, apduData, responseResult);
    EXPECT_EQ(ret, TELEPHONY_ERR_SUCCESS);
}

HWTEST_F(EsimManagerTest, PrepareDownload_001, Function | MediumTest | Level1)
{
    int32_t slotId = -1;
    DownLoadConfigInfo downLoadConfigInfo;
    downLoadConfigInfo.portIndex_ = 0;
    downLoadConfigInfo.hashCc_ = Str8ToStr16("4131423243332D583459355A36");
    ResponseEsimInnerResult responseResult;
    int32_t ret = esimManager->PrepareDownload(slotId, downLoadConfigInfo, responseResult);
    EXPECT_EQ(ret, TELEPHONY_ERR_LOCAL_PTR_NULL);

    slotId = 1;
    ret = esimManager->PrepareDownload(slotId, downLoadConfigInfo, responseResult);
    EXPECT_EQ(ret, TELEPHONY_ERR_LOCAL_PTR_NULL);

    slotId = 0;
    ret = esimManager->PrepareDownload(slotId, downLoadConfigInfo, responseResult);
    EXPECT_EQ(ret, TELEPHONY_ERR_SUCCESS);
}

HWTEST_F(EsimManagerTest, LoadBoundProfilePackage_001, Function | MediumTest | Level1)
{
    int32_t slotId = -1;
    int32_t portIndex = 0;
    std::u16string boundProfilePackage;
    ResponseEsimBppResult responseResult;
    int32_t ret = esimManager->LoadBoundProfilePackage(slotId, portIndex, boundProfilePackage, responseResult);
    EXPECT_EQ(ret, TELEPHONY_ERR_LOCAL_PTR_NULL);

    slotId = 1;
    ret = esimManager->LoadBoundProfilePackage(slotId, portIndex, boundProfilePackage, responseResult);
    EXPECT_EQ(ret, TELEPHONY_ERR_LOCAL_PTR_NULL);

    slotId = 0;
    ret = esimManager->LoadBoundProfilePackage(slotId, portIndex, boundProfilePackage, responseResult);
    EXPECT_EQ(ret, TELEPHONY_ERR_SUCCESS);
}

HWTEST_F(EsimManagerTest, ListNotifications_001, Function | MediumTest | Level1)
{
    int32_t slotId = -1;
    int32_t portIndex = 0;
    const EsimEvent events = EsimEvent::EVENT_DELETE;
    EuiccNotificationList notificationList;
    int32_t ret = esimManager->ListNotifications(slotId, portIndex, events, notificationList);
    EXPECT_EQ(ret, TELEPHONY_ERR_LOCAL_PTR_NULL);

    slotId = 1;
    ret = esimManager->ListNotifications(slotId, portIndex, events, notificationList);
    EXPECT_EQ(ret, TELEPHONY_ERR_LOCAL_PTR_NULL);

    slotId = 0;
    ret = esimManager->ListNotifications(slotId, portIndex, events, notificationList);
    EXPECT_EQ(ret, TELEPHONY_ERR_SUCCESS);
}

HWTEST_F(EsimManagerTest, RetrieveNotificationList_001, Function | MediumTest | Level1)
{
    int32_t slotId = -1;
    int32_t portIndex = 0;
    const EsimEvent events = EsimEvent::EVENT_DISABLE;
    EuiccNotificationList notificationList;
    int32_t ret = esimManager->RetrieveNotificationList(slotId, portIndex, events, notificationList);
    EXPECT_EQ(ret, TELEPHONY_ERR_LOCAL_PTR_NULL);

    slotId = 1;
    ret = esimManager->RetrieveNotificationList(slotId, portIndex, events, notificationList);
    EXPECT_EQ(ret, TELEPHONY_ERR_LOCAL_PTR_NULL);

    slotId = 0;
    ret = esimManager->RetrieveNotificationList(slotId, portIndex, events, notificationList);
    EXPECT_EQ(ret, TELEPHONY_ERR_SUCCESS);
}

HWTEST_F(EsimManagerTest, RetrieveNotification_001, Function | MediumTest | Level1)
{
    int32_t slotId = -1;
    int32_t portIndex = 0;
    int32_t seqNumber = 5;
    EuiccNotification notification;
    int32_t ret = esimManager->RetrieveNotification(slotId, portIndex, seqNumber, notification);
    EXPECT_EQ(ret, TELEPHONY_ERR_LOCAL_PTR_NULL);

    slotId = 1;
    ret = esimManager->RetrieveNotification(slotId, portIndex, seqNumber, notification);
    EXPECT_EQ(ret, TELEPHONY_ERR_LOCAL_PTR_NULL);

    slotId = 0;
    ret = esimManager->RetrieveNotification(slotId, portIndex, seqNumber, notification);
    EXPECT_EQ(ret, TELEPHONY_ERR_SUCCESS);
}

HWTEST_F(EsimManagerTest, RemoveNotificationFromList_001, Function | MediumTest | Level1)
{
    int32_t slotId = -1;
    int32_t portIndex = 0;
    int32_t seqNumber = 5;
    int32_t enumResult;
    int32_t ret = esimManager->RemoveNotificationFromList(slotId, portIndex, seqNumber, enumResult);
    EXPECT_EQ(ret, TELEPHONY_ERR_LOCAL_PTR_NULL);

    slotId = 1;
    ret = esimManager->RemoveNotificationFromList(slotId, portIndex, seqNumber, enumResult);
    EXPECT_EQ(ret, TELEPHONY_ERR_LOCAL_PTR_NULL);

    slotId = 0;
    ret = esimManager->RemoveNotificationFromList(slotId, portIndex, seqNumber, enumResult);
    EXPECT_EQ(ret, TELEPHONY_ERR_SUCCESS);
}

HWTEST_F(EsimManagerTest, DeleteProfile_001, Function | MediumTest | Level1)
{
    int32_t slotId = -1;
    std::u16string iccId = Str8ToStr16("98760000000000543210");
    int32_t deleteProfileResult;
    int32_t ret = esimManager->DeleteProfile(slotId, iccId, deleteProfileResult);
    EXPECT_EQ(ret, TELEPHONY_ERR_LOCAL_PTR_NULL);

    slotId = 1;
    ret = esimManager->DeleteProfile(slotId, iccId, deleteProfileResult);
    EXPECT_EQ(ret, TELEPHONY_ERR_LOCAL_PTR_NULL);

    slotId = 0;
    ret = esimManager->DeleteProfile(slotId, iccId, deleteProfileResult);
    EXPECT_EQ(ret, TELEPHONY_ERR_SUCCESS);
}

HWTEST_F(EsimManagerTest, SwitchToProfile_001, Function | MediumTest | Level1)
{
    int32_t slotId = -1;
    int32_t portIndex = 1;
    std::u16string iccId = Str8ToStr16("98760000000000543210");
    bool forceDisableProfile = true;
    int32_t switchProfileResult;
    int32_t ret = esimManager->SwitchToProfile(slotId, portIndex, iccId, forceDisableProfile, switchProfileResult);
    EXPECT_EQ(ret, TELEPHONY_ERR_LOCAL_PTR_NULL);

    slotId = 1;
    ret = esimManager->SwitchToProfile(slotId, portIndex, iccId, forceDisableProfile, switchProfileResult);
    EXPECT_EQ(ret, TELEPHONY_ERR_LOCAL_PTR_NULL);

    slotId = 0;
    ret = esimManager->SwitchToProfile(slotId, portIndex, iccId, forceDisableProfile, switchProfileResult);
    EXPECT_EQ(ret, TELEPHONY_ERR_SUCCESS);
}

HWTEST_F(EsimManagerTest, SetProfileNickname_001, Function | MediumTest | Level1)
{
    int32_t slotId = -1;
    std::u16string iccId = Str8ToStr16("98760000000000543210");
    std::u16string nickname = Str8ToStr16("nick");
    int32_t updateResult;
    int32_t ret = esimManager->SetProfileNickname(slotId, iccId, nickname, updateResult);
    EXPECT_EQ(ret, TELEPHONY_ERR_LOCAL_PTR_NULL);

    slotId = 1;
    ret = esimManager->SetProfileNickname(slotId, iccId, nickname, updateResult);
    EXPECT_EQ(ret, TELEPHONY_ERR_LOCAL_PTR_NULL);

    slotId = 0;
    ret = esimManager->SetProfileNickname(slotId, iccId, nickname, updateResult);
    EXPECT_EQ(ret, TELEPHONY_ERR_SUCCESS);
}

HWTEST_F(EsimManagerTest, GetEuiccInfo2_001, Function | MediumTest | Level1)
{
    int32_t slotId = -1;
    int32_t portIndex = 0;
    EuiccInfo2 euiccInfo2;
    int32_t ret = esimManager->GetEuiccInfo2(slotId, portIndex, euiccInfo2);
    EXPECT_EQ(ret, TELEPHONY_ERR_LOCAL_PTR_NULL);

    slotId = 1;
    ret = esimManager->GetEuiccInfo2(slotId, portIndex, euiccInfo2);
    EXPECT_EQ(ret, TELEPHONY_ERR_LOCAL_PTR_NULL);

    slotId = 0;
    ret = esimManager->GetEuiccInfo2(slotId, portIndex, euiccInfo2);
    EXPECT_EQ(ret, TELEPHONY_ERR_SUCCESS);
}

HWTEST_F(EsimManagerTest, AuthenticateServer_001, Function | MediumTest | Level1)
{
    int32_t slotId = -1;
    AuthenticateConfigInfo authenticateConfigInfo;
    authenticateConfigInfo.matchingId_ = Str8ToStr16("4131423243332D583459355A36");
    ResponseEsimInnerResult responseResult;
    int32_t ret = esimManager->AuthenticateServer(slotId, authenticateConfigInfo, responseResult);
    EXPECT_EQ(ret, TELEPHONY_ERR_LOCAL_PTR_NULL);

    slotId = 1;
    ret = esimManager->AuthenticateServer(slotId, authenticateConfigInfo, responseResult);
    EXPECT_EQ(ret, TELEPHONY_ERR_LOCAL_PTR_NULL);

    slotId = 0;
    ret = esimManager->AuthenticateServer(slotId, authenticateConfigInfo, responseResult);
    EXPECT_EQ(ret, TELEPHONY_ERR_SUCCESS);
}

HWTEST_F(EsimManagerTest, GetContractInfo_001, Function | MediumTest | Level1)
{
    int32_t slotId = -1;
    GetContractInfoRequest request;
    std::string response = "";
    int32_t ret = esimManager->GetContractInfo(slotId, request, response);
    EXPECT_EQ(ret, TELEPHONY_ERR_LOCAL_PTR_NULL);

    slotId = 1;
    ret = esimManager->GetContractInfo(slotId, request, response);
    EXPECT_EQ(ret, TELEPHONY_ERR_LOCAL_PTR_NULL);

    slotId = 0;
    ret = esimManager->GetContractInfo(slotId, request, response);
    EXPECT_EQ(ret, TELEPHONY_ERR_SUCCESS);
}
#else
HWTEST_F(EsimManagerTest, OnInit_002, Function | MediumTest | Level1)
{
    int32_t slotCount = 4;
    bool ret = esimManager->OnInit(slotCount);
    EXPECT_FALSE(ret);
}

HWTEST_F(EsimManagerTest, GetEid_002, Function | MediumTest | Level1)
{
    int32_t slotId = -1;
    std::u16string eId;
    int32_t ret = esimManager->GetEid(slotId, eId);
    EXPECT_EQ(ret, TELEPHONY_ERR_CORE_SERVICE_NOT_SUPPORTED_ESIM);
}

HWTEST_F(EsimManagerTest, GetEuiccProfileInfoList_002, Function | MediumTest | Level1)
{
    int32_t slotId = -1;
    GetEuiccProfileInfoListInnerResult result;
    int32_t ret = esimManager->GetEuiccProfileInfoList(slotId, result);
    EXPECT_EQ(ret, TELEPHONY_ERR_CORE_SERVICE_NOT_SUPPORTED_ESIM);
}

HWTEST_F(EsimManagerTest, GetEuiccInfo_002, Function | MediumTest | Level1)
{
    int32_t slotId = -1;
    EuiccInfo result;
    int32_t ret = esimManager->GetEuiccInfo(slotId, result);
    EXPECT_EQ(ret, TELEPHONY_ERR_CORE_SERVICE_NOT_SUPPORTED_ESIM);
}

HWTEST_F(EsimManagerTest, DisableProfile_002, Function | MediumTest | Level1)
{
    int32_t slotId = -1;
    int32_t portIndex = 0;
    std::u16string iccId = Str8ToStr16("98760000000000543210");
    bool refresh = true;
    int32_t enumResult;
    int32_t ret = esimManager->DisableProfile(slotId, portIndex, iccId, refresh, enumResult);
    EXPECT_EQ(ret, TELEPHONY_ERR_CORE_SERVICE_NOT_SUPPORTED_ESIM);
}

HWTEST_F(EsimManagerTest, GetSmdsAddress_002, Function | MediumTest | Level1)
{
    int32_t slotId = -1;
    int32_t portIndex = 0;
    std::u16string smdsAddress;
    int32_t ret = esimManager->GetSmdsAddress(slotId, portIndex, smdsAddress);
    EXPECT_EQ(ret, TELEPHONY_ERR_CORE_SERVICE_NOT_SUPPORTED_ESIM);
}

HWTEST_F(EsimManagerTest, GetRulesAuthTable_002, Function | MediumTest | Level1)
{
    int32_t slotId = -1;
    int32_t portIndex = 0;
    EuiccRulesAuthTable eUiccRulesAuthTable;
    int32_t ret = esimManager->GetRulesAuthTable(slotId, portIndex, eUiccRulesAuthTable);
    EXPECT_EQ(ret, TELEPHONY_ERR_CORE_SERVICE_NOT_SUPPORTED_ESIM);
}

HWTEST_F(EsimManagerTest, GetEuiccChallenge_002, Function | MediumTest | Level1)
{
    int32_t slotId = -1;
    int32_t portIndex = 0;
    ResponseEsimInnerResult result;
    int32_t ret = esimManager->GetEuiccChallenge(slotId, portIndex, result);
    EXPECT_EQ(ret, TELEPHONY_ERR_CORE_SERVICE_NOT_SUPPORTED_ESIM);
}

HWTEST_F(EsimManagerTest, GetDefaultSmdpAddress_002, Function | MediumTest | Level1)
{
    int32_t slotId = -1;
    std::u16string defaultSmdpAddress;
    int32_t ret = esimManager->GetDefaultSmdpAddress(slotId, defaultSmdpAddress);
    EXPECT_EQ(ret, TELEPHONY_ERR_CORE_SERVICE_NOT_SUPPORTED_ESIM);
}

HWTEST_F(EsimManagerTest, CancelSession_002, Function | MediumTest | Level1)
{
    int32_t slotId = -1;
    std::u16string transactionId = Str8ToStr16("A1B2C3");
    CancelReason cancelReason = CancelReason::CANCEL_REASON_POSTPONED;
    ResponseEsimInnerResult responseResult;
    int32_t ret = esimManager->CancelSession(slotId, transactionId, cancelReason, responseResult);
    EXPECT_EQ(ret, TELEPHONY_ERR_CORE_SERVICE_NOT_SUPPORTED_ESIM);
}

HWTEST_F(EsimManagerTest, GetProfile_002, Function | MediumTest | Level1)
{
    int32_t slotId = -1;
    int32_t portIndex = 0;
    std::u16string iccId = Str8ToStr16("5A0A89670000000000216954");
    EuiccProfile eUiccProfile;
    int32_t ret = esimManager->GetProfile(slotId, portIndex, iccId, eUiccProfile);
    EXPECT_EQ(ret, TELEPHONY_ERR_CORE_SERVICE_NOT_SUPPORTED_ESIM);
}

HWTEST_F(EsimManagerTest, ResetMemory_002, Function | MediumTest | Level1)
{
    int32_t slotId = -1;
    int32_t resetMemoryResult;
    ResetOption resetOption = ResetOption::DELETE_OPERATIONAL_PROFILES;
    int32_t ret = esimManager->ResetMemory(slotId, resetOption, resetMemoryResult);
    EXPECT_EQ(ret, TELEPHONY_ERR_CORE_SERVICE_NOT_SUPPORTED_ESIM);
}

HWTEST_F(EsimManagerTest, SetDefaultSmdpAddress_002, Function | MediumTest | Level1)
{
    int32_t slotId = -1;
    std::u16string defaultSmdpAddress = Str8ToStr16("test.com");
    int32_t setAddressResult;
    int32_t ret = esimManager->SetDefaultSmdpAddress(slotId, defaultSmdpAddress, setAddressResult);
    EXPECT_EQ(ret, TELEPHONY_ERR_CORE_SERVICE_NOT_SUPPORTED_ESIM);
}

HWTEST_F(EsimManagerTest, IsSupported_002, Function | MediumTest | Level1)
{
    int32_t slotId = -1;
    bool ret = esimManager->IsSupported(slotId);
    EXPECT_EQ(ret, false);
}

HWTEST_F(EsimManagerTest, SendApduData_002, Function | MediumTest | Level1)
{
    int32_t slotId = -1;
    std::u16string aid = Str8ToStr16("aid test");
    EsimApduData apduData;
    ResponseEsimInnerResult responseResult;
    int32_t ret = esimManager->SendApduData(slotId, aid, apduData, responseResult);
    EXPECT_EQ(ret, TELEPHONY_ERR_CORE_SERVICE_NOT_SUPPORTED_ESIM);
}

HWTEST_F(EsimManagerTest, PrepareDownload_002, Function | MediumTest | Level1)
{
    int32_t slotId = -1;
    DownLoadConfigInfo downLoadConfigInfo;
    downLoadConfigInfo.portIndex_ = 0;
    downLoadConfigInfo.hashCc_ = Str8ToStr16("4131423243332D583459355A36");
    ResponseEsimInnerResult responseResult;
    int32_t ret = esimManager->PrepareDownload(slotId, downLoadConfigInfo, responseResult);
    EXPECT_EQ(ret, TELEPHONY_ERR_CORE_SERVICE_NOT_SUPPORTED_ESIM);
}

HWTEST_F(EsimManagerTest, LoadBoundProfilePackage_002, Function | MediumTest | Level1)
{
    int32_t slotId = -1;
    int32_t portIndex = 0;
    std::u16string boundProfilePackage;
    ResponseEsimBppResult responseResult;
    int32_t ret = esimManager->LoadBoundProfilePackage(slotId, portIndex, boundProfilePackage, responseResult);
    EXPECT_EQ(ret, TELEPHONY_ERR_CORE_SERVICE_NOT_SUPPORTED_ESIM);
}

HWTEST_F(EsimManagerTest, ListNotifications_002, Function | MediumTest | Level1)
{
    int32_t slotId = -1;
    int32_t portIndex = 0;
    const EsimEvent events = EsimEvent::EVENT_DELETE;
    EuiccNotificationList notificationList;
    int32_t ret = esimManager->ListNotifications(slotId, portIndex, events, notificationList);
    EXPECT_EQ(ret, TELEPHONY_ERR_CORE_SERVICE_NOT_SUPPORTED_ESIM);
}

HWTEST_F(EsimManagerTest, RetrieveNotificationList_002, Function | MediumTest | Level1)
{
    int32_t slotId = -1;
    int32_t portIndex = 0;
    const EsimEvent events = EsimEvent::EVENT_DISABLE;
    EuiccNotificationList notificationList;
    int32_t ret = esimManager->RetrieveNotificationList(slotId, portIndex, events, notificationList);
    EXPECT_EQ(ret, TELEPHONY_ERR_CORE_SERVICE_NOT_SUPPORTED_ESIM);
}

HWTEST_F(EsimManagerTest, RetrieveNotification_002, Function | MediumTest | Level1)
{
    int32_t slotId = -1;
    int32_t portIndex = 0;
    int32_t seqNumber = 5;
    EuiccNotification notification;
    int32_t ret = esimManager->RetrieveNotification(slotId, portIndex, seqNumber, notification);
    EXPECT_EQ(ret, TELEPHONY_ERR_CORE_SERVICE_NOT_SUPPORTED_ESIM);
}

HWTEST_F(EsimManagerTest, RemoveNotificationFromList_002, Function | MediumTest | Level1)
{
    int32_t slotId = -1;
    int32_t portIndex = 0;
    int32_t seqNumber = 5;
    int32_t enumResult;
    int32_t ret = esimManager->RemoveNotificationFromList(slotId, portIndex, seqNumber, enumResult);
    EXPECT_EQ(ret, TELEPHONY_ERR_CORE_SERVICE_NOT_SUPPORTED_ESIM);
}

HWTEST_F(EsimManagerTest, DeleteProfile_002, Function | MediumTest | Level1)
{
    int32_t slotId = -1;
    std::u16string iccId = Str8ToStr16("98760000000000543210");
    int32_t deleteProfileResult;
    int32_t ret = esimManager->DeleteProfile(slotId, iccId, deleteProfileResult);
    EXPECT_EQ(ret, TELEPHONY_ERR_CORE_SERVICE_NOT_SUPPORTED_ESIM);
}

HWTEST_F(EsimManagerTest, SwitchToProfile_002, Function | MediumTest | Level1)
{
    int32_t slotId = -1;
    int32_t portIndex = 1;
    std::u16string iccId = Str8ToStr16("98760000000000543210");
    bool forceDisableProfile = true;
    int32_t switchProfileResult;
    int32_t ret = esimManager->SwitchToProfile(slotId, portIndex, iccId, forceDisableProfile, switchProfileResult);
    EXPECT_EQ(ret, TELEPHONY_ERR_CORE_SERVICE_NOT_SUPPORTED_ESIM);
}

HWTEST_F(EsimManagerTest, SetProfileNickname_002, Function | MediumTest | Level1)
{
    int32_t slotId = -1;
    std::u16string iccId = Str8ToStr16("98760000000000543210");
    std::u16string nickname = Str8ToStr16("nick");
    int32_t updateResult;
    int32_t ret = esimManager->esimManager->SetProfileNickname(slotId, iccId, nickname, updateResult);
    EXPECT_EQ(ret, TELEPHONY_ERR_CORE_SERVICE_NOT_SUPPORTED_ESIM);
}

HWTEST_F(EsimManagerTest, GetEuiccInfo2_002, Function | MediumTest | Level1)
{
    int32_t slotId = -1;
    int32_t portIndex = 0;
    EuiccInfo2 euiccInfo2;
    int32_t ret = esimManager->GetEuiccInfo2(slotId, portIndex, euiccInfo2);
    EXPECT_EQ(ret, TELEPHONY_ERR_CORE_SERVICE_NOT_SUPPORTED_ESIM);
}

HWTEST_F(EsimManagerTest, AuthenticateServer_002, Function | MediumTest | Level1)
{
    int32_t slotId = -1;
    AuthenticateConfigInfo authenticateConfigInfo;
    authenticateConfigInfo.matchingId_ = Str8ToStr16("4131423243332D583459355A36");
    ResponseEsimInnerResult responseResult;
    int32_t ret = esimManager->AuthenticateServer(slotId, authenticateConfigInfo, responseResult);
    EXPECT_EQ(ret, TELEPHONY_ERR_CORE_SERVICE_NOT_SUPPORTED_ESIM);
}

HWTEST_F(EsimManagerTest, GetContractInfo_002, Function | MediumTest | Level1)
{
    int32_t slotId = -1;
    GetContractInfoRequest request;
    std::string response = "";
    int32_t ret = esimManager->GetContractInfo(slotId, request, response);
    EXPECT_EQ(ret, TELEPHONY_ERR_CORE_SERVICE_NOT_SUPPORTED_ESIM);
}
#endif
} // Telephony
} // OHOS