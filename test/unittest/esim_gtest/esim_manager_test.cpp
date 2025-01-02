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

#include "core_manager_inner.h"
#include "core_service.h"
#include "core_service_client.h"
#include "enum_convert.h"
#include "operator_config_cache.h"
#include "operator_file_parser.h"
#include "sim_manager.h"
#include "sim_state_type.h"
#include "str_convert.h"
#include "string_ex.h"
#include "tel_profile_util.h"
#include "telephony_ext_wrapper.h"
#include "tel_ril_manager.h"
#include "gtest/gtest.h"

namespace OHOS {
namespace Telephony {
using namespace testing::ext;
class EsimManagerTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void EsimManagerTest::TearDownTestCase() {}

void EsimManagerTest::SetUp() {}

void EsimManagerTest::TearDown() {}

void EsimManagerTest::SetUpTestCase() {}

HWTEST_F(EsimManagerTest, GetEid, Function | MediumTest | Level1)
{
    int32_t slotId = 0;
    std::u16string eId;
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimManager> simManager = std::make_shared<SimManager>(telRilManager);
    int32_t ret = simManager->GetEid(slotId, eId);
    EXPECT_NE(ret, TELEPHONY_ERR_SUCCESS);
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    simManager->simStateManager_.push_back(simStateManager);
    simManager->simStateManager_[slotId]->Init(slotId);
    simManager->simStateManager_[slotId]->simStateHandle_->iccState_.simStatus_ = -1;
    ret = simManager->GetEid(slotId, eId);
    EXPECT_EQ(ret, TELEPHONY_ERR_LOCAL_PTR_NULL);
    EventFwk::CommonEventSubscribeInfo sp;
    std::weak_ptr<Telephony::ITelRilManager> iTelRilManager = telRilManager;
    std::weak_ptr<Telephony::SimStateManager> state = simStateManager;
    std::shared_ptr<Telephony::SimFileManager> simFileManager =
        std::make_shared<SimFileManager>(sp, iTelRilManager, state);
    simManager->simFileManager_.push_back(simFileManager);
    simManager->simFileManager_[slotId]->Init(slotId);
    ret = simManager->GetEid(slotId, eId);
    EXPECT_EQ(ret, TELEPHONY_ERR_SUCCESS);
}

HWTEST_F(EsimManagerTest, GetEuiccProfileInfoList, Function | MediumTest | Level1)
{
    int32_t slotId = 0;
    GetEuiccProfileInfoListInnerResult result;
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimManager> simManager = std::make_shared<SimManager>(telRilManager);
    int32_t ret = simManager->GetEuiccProfileInfoList(slotId, result);
    EXPECT_NE(ret, TELEPHONY_ERR_SUCCESS);
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    simManager->simStateManager_.push_back(simStateManager);
    simManager->simStateManager_[slotId]->Init(slotId);
    simManager->simStateManager_[slotId]->simStateHandle_->iccState_.simStatus_ = -1;
    ret = simManager->GetEuiccProfileInfoList(slotId, result);
    EXPECT_EQ(ret, TELEPHONY_ERR_LOCAL_PTR_NULL);
    EventFwk::CommonEventSubscribeInfo sp;
    std::weak_ptr<Telephony::ITelRilManager> iTelRilManager = telRilManager;
    std::weak_ptr<Telephony::SimStateManager> state = simStateManager;
    std::shared_ptr<Telephony::SimFileManager> simFileManager =
        std::make_shared<SimFileManager>(sp, iTelRilManager, state);
    simManager->simFileManager_.push_back(simFileManager);
    simManager->simFileManager_[slotId]->Init(slotId);
    ret = simManager->GetEuiccProfileInfoList(slotId, result);
    EXPECT_EQ(ret, TELEPHONY_ERR_SUCCESS);
}

HWTEST_F(EsimManagerTest, GetEuiccInfo, Function | MediumTest | Level1)
{
    int32_t slotId = 0;
    EuiccInfo eUiccInfo;
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimManager> simManager = std::make_shared<SimManager>(telRilManager);
    int32_t ret = simManager->GetEuiccInfo(slotId, eUiccInfo);
    EXPECT_NE(ret, TELEPHONY_ERR_SUCCESS);
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    simManager->simStateManager_.push_back(simStateManager);
    simManager->simStateManager_[slotId]->Init(slotId);
    simManager->simStateManager_[slotId]->simStateHandle_->iccState_.simStatus_ = -1;
    ret = simManager->GetEuiccInfo(slotId, eUiccInfo);
    EXPECT_EQ(ret, TELEPHONY_ERR_LOCAL_PTR_NULL);
    EventFwk::CommonEventSubscribeInfo sp;
    std::weak_ptr<Telephony::ITelRilManager> iTelRilManager = telRilManager;
    std::weak_ptr<Telephony::SimStateManager> state = simStateManager;
    std::shared_ptr<Telephony::SimFileManager> simFileManager =
        std::make_shared<SimFileManager>(sp, iTelRilManager, state);
    simManager->simFileManager_.push_back(simFileManager);
    simManager->simFileManager_[slotId]->Init(slotId);
    ret = simManager->GetEuiccInfo(slotId, eUiccInfo);
    EXPECT_EQ(ret, TELEPHONY_ERR_SUCCESS);
}

HWTEST_F(EsimManagerTest, DisableProfile, Function | MediumTest | Level1)
{
    int32_t slotId = 0;
    int32_t portIndex = 0;
    std::u16string iccId = Str8ToStr16("98760000000000543210");
    bool refresh = true;
    int32_t disableProfileResult;
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimManager> simManager = std::make_shared<SimManager>(telRilManager);
    int32_t ret = simManager->DisableProfile(slotId, portIndex, iccId, refresh, disableProfileResult);
    EXPECT_NE(ret, TELEPHONY_ERR_SUCCESS);

    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    simManager->simStateManager_.push_back(simStateManager);
    simManager->simStateManager_[slotId]->Init(slotId);
    simManager->simStateManager_[slotId]->simStateHandle_->iccState_.simStatus_ = -1;
    ret = simManager->DisableProfile(slotId, portIndex, iccId, refresh, disableProfileResult);
    EXPECT_EQ(ret, TELEPHONY_ERR_LOCAL_PTR_NULL);

    EventFwk::CommonEventSubscribeInfo sp;
    std::weak_ptr<Telephony::ITelRilManager> iTelRilManager = telRilManager;
    std::weak_ptr<Telephony::SimStateManager> state = simStateManager;
    std::shared_ptr<Telephony::SimFileManager> simFileManager =
        std::make_shared<SimFileManager>(sp, iTelRilManager, state);
    simManager->simFileManager_.push_back(simFileManager);
    simManager->simFileManager_[slotId]->Init(slotId);
    ret = simManager->DisableProfile(slotId, portIndex, iccId, refresh, disableProfileResult);
    EXPECT_EQ(ret, TELEPHONY_ERR_SUCCESS);
}

HWTEST_F(EsimManagerTest, GetSmdsAddress, Function | MediumTest | Level1)
{
    int32_t slotId = 0;
    int32_t portIndex = 0;
    std::u16string smdsAddress;
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimManager> simManager = std::make_shared<SimManager>(telRilManager);
    int32_t ret = simManager->GetSmdsAddress(slotId, portIndex, smdsAddress);
    EXPECT_NE(ret, TELEPHONY_ERR_SUCCESS);

    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    simManager->simStateManager_.push_back(simStateManager);
    simManager->simStateManager_[slotId]->Init(slotId);
    simManager->simStateManager_[slotId]->simStateHandle_->iccState_.simStatus_ = -1;
    ret = simManager->GetSmdsAddress(slotId, portIndex, smdsAddress);
    EXPECT_EQ(ret, TELEPHONY_ERR_LOCAL_PTR_NULL);

    EventFwk::CommonEventSubscribeInfo sp;
    std::weak_ptr<Telephony::ITelRilManager> iTelRilManager = telRilManager;
    std::weak_ptr<Telephony::SimStateManager> state = simStateManager;
    std::shared_ptr<Telephony::SimFileManager> simFileManager =
        std::make_shared<SimFileManager>(sp, iTelRilManager, state);
    simManager->simFileManager_.push_back(simFileManager);
    simManager->simFileManager_[slotId]->Init(slotId);
    ret = simManager->GetSmdsAddress(slotId, portIndex, smdsAddress);
    EXPECT_EQ(ret, TELEPHONY_ERR_SUCCESS);
}

HWTEST_F(EsimManagerTest, GetRulesAuthTable, Function | MediumTest | Level1)
{
    int32_t slotId = 0;
    int32_t portIndex = 0;
    EuiccRulesAuthTable eUiccRulesAuthTable;
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimManager> simManager = std::make_shared<SimManager>(telRilManager);
    int32_t ret = simManager->GetRulesAuthTable(slotId, portIndex, eUiccRulesAuthTable);
    EXPECT_NE(ret, TELEPHONY_ERR_SUCCESS);

    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    simManager->simStateManager_.push_back(simStateManager);
    simManager->simStateManager_[slotId]->Init(slotId);
    simManager->simStateManager_[slotId]->simStateHandle_->iccState_.simStatus_ = -1;
    ret = simManager->GetRulesAuthTable(slotId, portIndex, eUiccRulesAuthTable);
    EXPECT_EQ(ret, TELEPHONY_ERR_LOCAL_PTR_NULL);

    EventFwk::CommonEventSubscribeInfo sp;
    std::weak_ptr<Telephony::ITelRilManager> iTelRilManager = telRilManager;
    std::weak_ptr<Telephony::SimStateManager> state = simStateManager;
    std::shared_ptr<Telephony::SimFileManager> simFileManager =
        std::make_shared<SimFileManager>(sp, iTelRilManager, state);
    simManager->simFileManager_.push_back(simFileManager);
    simManager->simFileManager_[slotId]->Init(slotId);
    ret = simManager->GetRulesAuthTable(slotId, portIndex, eUiccRulesAuthTable);
    EXPECT_EQ(ret, TELEPHONY_ERR_SUCCESS);
}

HWTEST_F(EsimManagerTest, GetEuiccChallenge, Function | MediumTest | Level1)
{
    int32_t slotId = 0;
    int32_t portIndex = 0;
    ResponseEsimInnerResult responseResult;
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimManager> simManager = std::make_shared<SimManager>(telRilManager);
    int32_t ret = simManager->GetEuiccChallenge(slotId, portIndex, responseResult);
    EXPECT_NE(ret, TELEPHONY_ERR_SUCCESS);

    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    simManager->simStateManager_.push_back(simStateManager);
    simManager->simStateManager_[slotId]->Init(slotId);
    simManager->simStateManager_[slotId]->simStateHandle_->iccState_.simStatus_ = -1;
    ret = simManager->GetEuiccChallenge(slotId, portIndex, responseResult);
    EXPECT_EQ(ret, TELEPHONY_ERR_LOCAL_PTR_NULL);

    EventFwk::CommonEventSubscribeInfo sp;
    std::weak_ptr<Telephony::ITelRilManager> iTelRilManager = telRilManager;
    std::weak_ptr<Telephony::SimStateManager> state = simStateManager;
    std::shared_ptr<Telephony::SimFileManager> simFileManager =
        std::make_shared<SimFileManager>(sp, iTelRilManager, state);
    simManager->simFileManager_.push_back(simFileManager);
    simManager->simFileManager_[slotId]->Init(slotId);
    ret = simManager->GetEuiccChallenge(slotId, portIndex, responseResult);
    EXPECT_EQ(ret, TELEPHONY_ERR_SUCCESS);
}

HWTEST_F(EsimManagerTest, GetDefaultSmdpAddress, Function | MediumTest | Level1)
{
    int32_t slotId = 0;
    std::u16string actualAddress;
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimManager> simManager = std::make_shared<SimManager>(telRilManager);
    int32_t ret = simManager->GetDefaultSmdpAddress(slotId, actualAddress);
    EXPECT_NE(ret, TELEPHONY_ERR_SUCCESS);
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    simManager->simStateManager_.push_back(simStateManager);
    simManager->simStateManager_[slotId]->Init(slotId);
    simManager->simStateManager_[slotId]->simStateHandle_->iccState_.simStatus_ = -1;
    ret = simManager->GetDefaultSmdpAddress(slotId, actualAddress);
    EXPECT_EQ(ret, TELEPHONY_ERR_LOCAL_PTR_NULL);
    EventFwk::CommonEventSubscribeInfo sp;
    std::weak_ptr<Telephony::ITelRilManager> iTelRilManager = telRilManager;
    std::weak_ptr<Telephony::SimStateManager> state = simStateManager;
    std::shared_ptr<Telephony::SimFileManager> simFileManager =
        std::make_shared<SimFileManager>(sp, iTelRilManager, state);
    simManager->simFileManager_.push_back(simFileManager);
    simManager->simFileManager_[slotId]->Init(slotId);
    ret = simManager->GetDefaultSmdpAddress(slotId, actualAddress);
    EXPECT_EQ(ret, TELEPHONY_ERR_SUCCESS);
}

HWTEST_F(EsimManagerTest, CancelSession, Function | MediumTest | Level1)
{
    int32_t slotId = 0;
    std::u16string transactionId = Str8ToStr16("A1B2C3");
    const CancelReason cancelReason = CancelReason::CANCEL_REASON_POSTPONED;
    ResponseEsimInnerResult responseResult;
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimManager> simManager = std::make_shared<SimManager>(telRilManager);
    int32_t ret = simManager->CancelSession(slotId, transactionId, cancelReason, responseResult);
    EXPECT_NE(ret, TELEPHONY_ERR_SUCCESS);
    std::shared_ptr<Telephony::SimStateManager> simStateManager =
        std::make_shared<SimStateManager>(telRilManager);
    simManager->simStateManager_.push_back(simStateManager);
    simManager->simStateManager_[slotId]->Init(slotId);
    simManager->simStateManager_[slotId]->simStateHandle_->iccState_.simStatus_ = -1;
    ret = simManager->CancelSession(slotId, transactionId, cancelReason, responseResult);
    EXPECT_EQ(ret, TELEPHONY_ERR_LOCAL_PTR_NULL);
    EventFwk::CommonEventSubscribeInfo sp;
    std::weak_ptr<Telephony::ITelRilManager> iTelRilManager = telRilManager;
    std::weak_ptr<Telephony::SimStateManager> state = simStateManager;
    std::shared_ptr<Telephony::SimFileManager> simFileManager =
        std::make_shared<SimFileManager>(sp, iTelRilManager, state);
    simManager->simFileManager_.push_back(simFileManager);
    simManager->simFileManager_[slotId]->Init(slotId);
    ret = simManager->CancelSession(slotId, transactionId, cancelReason, responseResult);
    EXPECT_EQ(ret, TELEPHONY_ERR_SUCCESS);
}

HWTEST_F(EsimManagerTest, GetProfile, Function | MediumTest | Level1)
{
    int32_t slotId = 0;
    int32_t portIndex = 0;
    std::u16string iccId = Str8ToStr16("5A0A89670000000000216954");
    EuiccProfile eUiccProfile;
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimManager> simManager = std::make_shared<SimManager>(telRilManager);
    int32_t ret = simManager->GetProfile(slotId, portIndex, iccId, eUiccProfile);
    EXPECT_NE(ret, TELEPHONY_ERR_SUCCESS);

    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    simManager->simStateManager_.push_back(simStateManager);
    simManager->simStateManager_[slotId]->Init(slotId);
    simManager->simStateManager_[slotId]->simStateHandle_->iccState_.simStatus_ = -1;
    ret = simManager->GetProfile(slotId, portIndex, iccId, eUiccProfile);
    EXPECT_EQ(ret, TELEPHONY_ERR_LOCAL_PTR_NULL);

    EventFwk::CommonEventSubscribeInfo sp;
    std::weak_ptr<Telephony::ITelRilManager> iTelRilManager = telRilManager;
    std::weak_ptr<Telephony::SimStateManager> state = simStateManager;
    std::shared_ptr<Telephony::SimFileManager> simFileManager =
        std::make_shared<SimFileManager>(sp, iTelRilManager, state);
    simManager->simFileManager_.push_back(simFileManager);
    simManager->simFileManager_[slotId]->Init(slotId);
    ret = simManager->GetProfile(slotId, portIndex, iccId, eUiccProfile);
    EXPECT_EQ(ret, TELEPHONY_ERR_SUCCESS);
}

HWTEST_F(EsimManagerTest, ResetMemory, Function | MediumTest | Level1)
{
    int32_t slotId = 0;
    int32_t resetMemoryResult;
    const ResetOption resetOption = ResetOption::DELETE_OPERATIONAL_PROFILES;
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimManager> simManager = std::make_shared<SimManager>(telRilManager);
    int32_t ret = simManager->ResetMemory(slotId, resetOption, resetMemoryResult);
    EXPECT_NE(ret, TELEPHONY_ERR_SUCCESS);
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    simManager->simStateManager_.push_back(simStateManager);
    simManager->simStateManager_[slotId]->Init(slotId);
    simManager->simStateManager_[slotId]->simStateHandle_->iccState_.simStatus_ = -1;
    ret = simManager->ResetMemory(slotId, resetOption, resetMemoryResult);
    EXPECT_EQ(ret, TELEPHONY_ERR_LOCAL_PTR_NULL);
    EventFwk::CommonEventSubscribeInfo sp;
    std::weak_ptr<Telephony::ITelRilManager> iTelRilManager = telRilManager;
    std::weak_ptr<Telephony::SimStateManager> state = simStateManager;
    std::shared_ptr<Telephony::SimFileManager> simFileManager =
        std::make_shared<SimFileManager>(sp, iTelRilManager, state);
    simManager->simFileManager_.push_back(simFileManager);
    simManager->simFileManager_[slotId]->Init(slotId);
    ret = simManager->ResetMemory(slotId, resetOption, resetMemoryResult);
    EXPECT_EQ(ret, TELEPHONY_ERR_SUCCESS);
}

HWTEST_F(EsimManagerTest, SetDefaultSmdpAddress, Function | MediumTest | Level1)
{
    int32_t slotId = 0;
    std::u16string defaultSmdpAddress = Str8ToStr16("test.com");
    int32_t setAddressResult;
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimManager> simManager = std::make_shared<SimManager>(telRilManager);
    int32_t ret = simManager->SetDefaultSmdpAddress(slotId, defaultSmdpAddress, setAddressResult);
    EXPECT_NE(ret, TELEPHONY_ERR_SUCCESS);
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    simManager->simStateManager_.push_back(simStateManager);
    simManager->simStateManager_[slotId]->Init(slotId);
    simManager->simStateManager_[slotId]->simStateHandle_->iccState_.simStatus_ = -1;
    ret = simManager->SetDefaultSmdpAddress(slotId, defaultSmdpAddress, setAddressResult);
    EXPECT_EQ(ret, TELEPHONY_ERR_LOCAL_PTR_NULL);
    EventFwk::CommonEventSubscribeInfo sp;
    std::weak_ptr<Telephony::ITelRilManager> iTelRilManager = telRilManager;
    std::weak_ptr<Telephony::SimStateManager> state = simStateManager;
    std::shared_ptr<Telephony::SimFileManager> simFileManager =
        std::make_shared<SimFileManager>(sp, iTelRilManager, state);
    simManager->simFileManager_.push_back(simFileManager);
    simManager->simFileManager_[slotId]->Init(slotId);
    ret = simManager->SetDefaultSmdpAddress(slotId, defaultSmdpAddress, setAddressResult);
    EXPECT_EQ(ret, TELEPHONY_ERR_SUCCESS);
}

HWTEST_F(EsimManagerTest, IsSupported, Function | MediumTest | Level1)
{
    int32_t slotId = 0;
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimManager> simManager = std::make_shared<SimManager>(telRilManager);
    EXPECT_FALSE(simManager->IsSupported(slotId));
}

HWTEST_F(EsimManagerTest, SendApduData, Function | MediumTest | Level1)
{
    int32_t slotId = 0;
    std::u16string aid = Str8ToStr16("aid test");
    EsimApduData apduData;
    ResponseEsimInnerResult responseResult;
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimManager> simManager = std::make_shared<SimManager>(telRilManager);
    int32_t ret = simManager->SendApduData(slotId, aid, apduData, responseResult);
    EXPECT_NE(ret, TELEPHONY_ERR_SUCCESS);
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    simManager->simStateManager_.push_back(simStateManager);
    simManager->simStateManager_[slotId]->Init(slotId);
    simManager->simStateManager_[slotId]->simStateHandle_->iccState_.simStatus_ = -1;
    ret = simManager->SendApduData(slotId, aid, apduData, responseResult);
    EXPECT_EQ(ret, TELEPHONY_ERR_LOCAL_PTR_NULL);
    EventFwk::CommonEventSubscribeInfo sp;
    std::weak_ptr<Telephony::ITelRilManager> iTelRilManager = telRilManager;
    std::weak_ptr<Telephony::SimStateManager> state = simStateManager;
    std::shared_ptr<Telephony::SimFileManager> simFileManager =
        std::make_shared<SimFileManager>(sp, iTelRilManager, state);
    simManager->simFileManager_.push_back(simFileManager);
    simManager->simFileManager_[slotId]->Init(slotId);
    ret = simManager->SendApduData(slotId, aid, apduData, responseResult);
    EXPECT_EQ(ret, TELEPHONY_ERR_SUCCESS);
}

HWTEST_F(EsimManagerTest, PrepareDownload, Function | MediumTest | Level1)
{
    int32_t slotId = 0;
    DownLoadConfigInfo downLoadConfigInfo;
    downLoadConfigInfo.portIndex_ = 0;
    downLoadConfigInfo.hashCc_ = Str8ToStr16("4131423243332D583459355A36");
    ResponseEsimInnerResult responseResult;
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimManager> simManager = std::make_shared<SimManager>(telRilManager);
    int32_t ret = simManager->PrepareDownload(slotId, downLoadConfigInfo, responseResult);
    EXPECT_NE(ret, TELEPHONY_ERR_SUCCESS);
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    simManager->simStateManager_.push_back(simStateManager);
    simManager->simStateManager_[slotId]->Init(slotId);
    simManager->simStateManager_[slotId]->simStateHandle_->iccState_.simStatus_ = -1;
    ret = simManager->PrepareDownload(slotId, downLoadConfigInfo, responseResult);
    EXPECT_EQ(ret, TELEPHONY_ERR_LOCAL_PTR_NULL);
    EventFwk::CommonEventSubscribeInfo sp;
    std::weak_ptr<Telephony::ITelRilManager> iTelRilManager = telRilManager;
    std::weak_ptr<Telephony::SimStateManager> state = simStateManager;
    std::shared_ptr<Telephony::SimFileManager> simFileManager =
        std::make_shared<SimFileManager>(sp, iTelRilManager, state);
    simManager->simFileManager_.push_back(simFileManager);
    simManager->simFileManager_[slotId]->Init(slotId);
    ret = simManager->PrepareDownload(slotId, downLoadConfigInfo, responseResult);
    EXPECT_EQ(ret, TELEPHONY_ERR_SUCCESS);
}

HWTEST_F(EsimManagerTest, LoadBoundProfilePackage, Function | MediumTest | Level1)
{
    int32_t slotId = 0;
    int32_t portIndex = 0;
    std::u16string boundProfilePackage;
    ResponseEsimBppResult responseResult;
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimManager> simManager = std::make_shared<SimManager>(telRilManager);
    int32_t ret = simManager->LoadBoundProfilePackage(slotId, portIndex, boundProfilePackage, responseResult);
    EXPECT_NE(ret, TELEPHONY_ERR_SUCCESS);
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    simManager->simStateManager_.push_back(simStateManager);
    simManager->simStateManager_[slotId]->Init(slotId);
    simManager->simStateManager_[slotId]->simStateHandle_->iccState_.simStatus_ = -1;
    ret = simManager->LoadBoundProfilePackage(slotId, portIndex, boundProfilePackage, responseResult);
    EXPECT_EQ(ret, TELEPHONY_ERR_LOCAL_PTR_NULL);
    EventFwk::CommonEventSubscribeInfo sp;
    std::weak_ptr<Telephony::ITelRilManager> iTelRilManager = telRilManager;
    std::weak_ptr<Telephony::SimStateManager> state = simStateManager;
    std::shared_ptr<Telephony::SimFileManager> simFileManager =
        std::make_shared<SimFileManager>(sp, iTelRilManager, state);
    simManager->simFileManager_.push_back(simFileManager);
    simManager->simFileManager_[slotId]->Init(slotId);
    ret = simManager->LoadBoundProfilePackage(slotId, portIndex, boundProfilePackage, responseResult);
    EXPECT_EQ(ret, TELEPHONY_ERR_SUCCESS);
}

HWTEST_F(EsimManagerTest, ListNotifications, Function | MediumTest | Level1)
{
    int32_t slotId = 0;
    int32_t portIndex = 0;
    const Event events = Event::EVENT_DELETE;
    EuiccNotificationList notificationList;
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimManager> simManager = std::make_shared<SimManager>(telRilManager);
    int32_t ret = simManager->ListNotifications(slotId, portIndex, events, notificationList);
    EXPECT_NE(ret, TELEPHONY_ERR_SUCCESS);
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    simManager->simStateManager_.push_back(simStateManager);
    simManager->simStateManager_[slotId]->Init(slotId);
    simManager->simStateManager_[slotId]->simStateHandle_->iccState_.simStatus_ = -1;
    ret = simManager->ListNotifications(slotId, portIndex, events, notificationList);
    EXPECT_EQ(ret, TELEPHONY_ERR_LOCAL_PTR_NULL);
    EventFwk::CommonEventSubscribeInfo sp;
    std::weak_ptr<Telephony::ITelRilManager> iTelRilManager = telRilManager;
    std::weak_ptr<Telephony::SimStateManager> state = simStateManager;
    std::shared_ptr<Telephony::SimFileManager> simFileManager =
        std::make_shared<SimFileManager>(sp, iTelRilManager, state);
    simManager->simFileManager_.push_back(simFileManager);
    simManager->simFileManager_[slotId]->Init(slotId);
    ret = simManager->ListNotifications(slotId, portIndex, events, notificationList);
    EXPECT_EQ(ret, TELEPHONY_ERR_SUCCESS);
}

HWTEST_F(EsimManagerTest, RetrieveNotificationList, Function | MediumTest | Level1)
{
    int32_t slotId = 0;
    int32_t portIndex = 0;
    const Event events = Event::EVENT_DISABLE;
    EuiccNotificationList notificationList;
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimManager> simManager = std::make_shared<SimManager>(telRilManager);
    int32_t ret = simManager->RetrieveNotificationList(slotId, portIndex, events, notificationList);
    EXPECT_NE(ret, TELEPHONY_ERR_SUCCESS);

    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    simManager->simStateManager_.push_back(simStateManager);
    simManager->simStateManager_[slotId]->Init(slotId);
    simManager->simStateManager_[slotId]->simStateHandle_->iccState_.simStatus_ = -1;
    ret = simManager->RetrieveNotificationList(slotId, portIndex, events, notificationList);
    EXPECT_EQ(ret, TELEPHONY_ERR_LOCAL_PTR_NULL);

    EventFwk::CommonEventSubscribeInfo sp;
    std::weak_ptr<Telephony::ITelRilManager> iTelRilManager = telRilManager;
    std::weak_ptr<Telephony::SimStateManager> state = simStateManager;
    std::shared_ptr<Telephony::SimFileManager> simFileManager =
        std::make_shared<SimFileManager>(sp, iTelRilManager, state);
    simManager->simFileManager_.push_back(simFileManager);
    simManager->simFileManager_[slotId]->Init(slotId);
    ret = simManager->RetrieveNotificationList(slotId, portIndex, events, notificationList);
    EXPECT_EQ(ret, TELEPHONY_ERR_SUCCESS);
}

HWTEST_F(EsimManagerTest, RetrieveNotification, Function | MediumTest | Level1)
{
    int32_t slotId = 0;
    int32_t portIndex = 0;
    int32_t seqNumber = 5;
    EuiccNotification notification;
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimManager> simManager = std::make_shared<SimManager>(telRilManager);
    int32_t ret = simManager->RetrieveNotification(slotId, portIndex, seqNumber, notification);
    EXPECT_NE(ret, TELEPHONY_ERR_SUCCESS);

    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    simManager->simStateManager_.push_back(simStateManager);
    simManager->simStateManager_[slotId]->Init(slotId);
    simManager->simStateManager_[slotId]->simStateHandle_->iccState_.simStatus_ = -1;
    ret = simManager->RetrieveNotification(slotId, portIndex, seqNumber, notification);
    EXPECT_EQ(ret, TELEPHONY_ERR_LOCAL_PTR_NULL);

    EventFwk::CommonEventSubscribeInfo sp;
    std::weak_ptr<Telephony::ITelRilManager> iTelRilManager = telRilManager;
    std::weak_ptr<Telephony::SimStateManager> state = simStateManager;
    std::shared_ptr<Telephony::SimFileManager> simFileManager =
        std::make_shared<SimFileManager>(sp, iTelRilManager, state);
    simManager->simFileManager_.push_back(simFileManager);
    simManager->simFileManager_[slotId]->Init(slotId);
    ret = simManager->RetrieveNotification(slotId, portIndex, seqNumber, notification);
    EXPECT_EQ(ret, TELEPHONY_ERR_SUCCESS);
}

HWTEST_F(EsimManagerTest, RemoveNotificationFromList, Function | MediumTest | Level1)
{
    int32_t slotId = 0;
    int32_t portIndex = 0;
    int32_t seqNumber = 5;
    int32_t enumResult;
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimManager> simManager = std::make_shared<SimManager>(telRilManager);
    int32_t ret = simManager->RemoveNotificationFromList(slotId, portIndex, seqNumber, enumResult);
    EXPECT_NE(ret, TELEPHONY_ERR_SUCCESS);

    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    simManager->simStateManager_.push_back(simStateManager);
    simManager->simStateManager_[slotId]->Init(slotId);
    simManager->simStateManager_[slotId]->simStateHandle_->iccState_.simStatus_ = -1;
    ret = simManager->RemoveNotificationFromList(slotId, portIndex, seqNumber, enumResult);
    EXPECT_EQ(ret, TELEPHONY_ERR_LOCAL_PTR_NULL);

    EventFwk::CommonEventSubscribeInfo sp;
    std::weak_ptr<Telephony::ITelRilManager> iTelRilManager = telRilManager;
    std::weak_ptr<Telephony::SimStateManager> state = simStateManager;
    std::shared_ptr<Telephony::SimFileManager> simFileManager =
        std::make_shared<SimFileManager>(sp, iTelRilManager, state);
    simManager->simFileManager_.push_back(simFileManager);
    simManager->simFileManager_[slotId]->Init(slotId);
    ret = simManager->RemoveNotificationFromList(slotId, portIndex, seqNumber, enumResult);
    EXPECT_EQ(ret, TELEPHONY_ERR_SUCCESS);
}

HWTEST_F(EsimManagerTest, DeleteProfile, Function | MediumTest | Level1)
{
    int32_t slotId = 0;
    std::u16string iccId = Str8ToStr16("98760000000000543210");
    int32_t deleteProfileResult;
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimManager> simManager = std::make_shared<SimManager>(telRilManager);
    int32_t ret = simManager->DeleteProfile(slotId, iccId, deleteProfileResult);
    EXPECT_NE(ret, TELEPHONY_ERR_SUCCESS);

    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    simManager->simStateManager_.push_back(simStateManager);
    simManager->simStateManager_[slotId]->Init(slotId);
    simManager->simStateManager_[slotId]->simStateHandle_->iccState_.simStatus_ = -1;
    ret = simManager->DeleteProfile(slotId, iccId, deleteProfileResult);
    EXPECT_EQ(ret, TELEPHONY_ERR_LOCAL_PTR_NULL);

    EventFwk::CommonEventSubscribeInfo sp;
    std::weak_ptr<Telephony::ITelRilManager> iTelRilManager = telRilManager;
    std::weak_ptr<Telephony::SimStateManager> state = simStateManager;
    std::shared_ptr<Telephony::SimFileManager> simFileManager =
        std::make_shared<SimFileManager>(sp, iTelRilManager, state);
    simManager->simFileManager_.push_back(simFileManager);
    simManager->simFileManager_[slotId]->Init(slotId);
    ret = simManager->DeleteProfile(slotId, iccId, deleteProfileResult);
    EXPECT_EQ(ret, TELEPHONY_ERR_SUCCESS);
}

HWTEST_F(EsimManagerTest, SwitchToProfile, Function | MediumTest | Level1)
{
    int32_t slotId = 0;
    int32_t portIndex = 1;
    std::u16string iccId = Str8ToStr16("98760000000000543210");
    bool forceDisableProfile = true;
    int32_t switchProfileResult;
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimManager> simManager = std::make_shared<SimManager>(telRilManager);
    int32_t ret = simManager->SwitchToProfile(slotId, portIndex, iccId, forceDisableProfile, switchProfileResult);
    EXPECT_NE(ret, TELEPHONY_ERR_SUCCESS);

    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    simManager->simStateManager_.push_back(simStateManager);
    simManager->simStateManager_[slotId]->Init(slotId);
    simManager->simStateManager_[slotId]->simStateHandle_->iccState_.simStatus_ = -1;
    ret = simManager->SwitchToProfile(slotId, portIndex, iccId, forceDisableProfile, switchProfileResult);
    EXPECT_EQ(ret, TELEPHONY_ERR_LOCAL_PTR_NULL);

    EventFwk::CommonEventSubscribeInfo sp;
    std::weak_ptr<Telephony::ITelRilManager> iTelRilManager = telRilManager;
    std::weak_ptr<Telephony::SimStateManager> state = simStateManager;
    std::shared_ptr<Telephony::SimFileManager> simFileManager =
        std::make_shared<SimFileManager>(sp, iTelRilManager, state);
    simManager->simFileManager_.push_back(simFileManager);
    simManager->simFileManager_[slotId]->Init(slotId);
    ret = simManager->SwitchToProfile(slotId, portIndex, iccId, forceDisableProfile, switchProfileResult);
    EXPECT_EQ(ret, TELEPHONY_ERR_SUCCESS);
}

HWTEST_F(EsimManagerTest, SetProfileNickname, Function | MediumTest | Level1)
{
    int32_t slotId = 0;
    std::u16string iccId = Str8ToStr16("98760000000000543210");
    std::u16string nickname = Str8ToStr16("nick");
    int32_t updateResult;
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimManager> simManager = std::make_shared<SimManager>(telRilManager);
    int32_t ret = simManager->SetProfileNickname(slotId, iccId, nickname, updateResult);
    EXPECT_NE(ret, TELEPHONY_ERR_SUCCESS);

    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    simManager->simStateManager_.push_back(simStateManager);
    simManager->simStateManager_[slotId]->Init(slotId);
    simManager->simStateManager_[slotId]->simStateHandle_->iccState_.simStatus_ = -1;
    ret = simManager->SetProfileNickname(slotId, iccId, nickname, updateResult);
    EXPECT_EQ(ret, TELEPHONY_ERR_LOCAL_PTR_NULL);

    EventFwk::CommonEventSubscribeInfo sp;
    std::weak_ptr<Telephony::ITelRilManager> iTelRilManager = telRilManager;
    std::weak_ptr<Telephony::SimStateManager> state = simStateManager;
    std::shared_ptr<Telephony::SimFileManager> simFileManager =
        std::make_shared<SimFileManager>(sp, iTelRilManager, state);
    simManager->simFileManager_.push_back(simFileManager);
    simManager->simFileManager_[slotId]->Init(slotId);
    ret = simManager->SetProfileNickname(slotId, iccId, nickname, updateResult);
    EXPECT_EQ(ret, TELEPHONY_ERR_SUCCESS);
}

HWTEST_F(EsimManagerTest, GetEuiccInfo2, Function | MediumTest | Level1)
{
    int32_t slotId = 0;
    int32_t portIndex = 0;
    EuiccInfo2 euiccInfo2;
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimManager> simManager = std::make_shared<SimManager>(telRilManager);
    int32_t ret = simManager->GetEuiccInfo2(slotId, portIndex, euiccInfo2);
    EXPECT_NE(ret, TELEPHONY_ERR_SUCCESS);
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    simManager->simStateManager_.push_back(simStateManager);
    simManager->simStateManager_[slotId]->Init(slotId);
    simManager->simStateManager_[slotId]->simStateHandle_->iccState_.simStatus_ = -1;
    ret = simManager->GetEuiccInfo2(slotId, portIndex, euiccInfo2);
    EXPECT_EQ(ret, TELEPHONY_ERR_LOCAL_PTR_NULL);
    EventFwk::CommonEventSubscribeInfo sp;
    std::weak_ptr<Telephony::ITelRilManager> iTelRilManager = telRilManager;
    std::weak_ptr<Telephony::SimStateManager> state = simStateManager;
    std::shared_ptr<Telephony::SimFileManager> simFileManager =
        std::make_shared<SimFileManager>(sp, iTelRilManager, state);
    simManager->simFileManager_.push_back(simFileManager);
    simManager->simFileManager_[slotId]->Init(slotId);
    ret = simManager->GetEuiccInfo2(slotId, portIndex, euiccInfo2);
    EXPECT_EQ(ret, TELEPHONY_ERR_SUCCESS);
}

HWTEST_F(EsimManagerTest, AuthenticateServer, Function | MediumTest | Level1)
{
    int32_t slotId = 0;
    AuthenticateConfigInfo authenticateConfigInfo;
    authenticateConfigInfo.matchingId_ = Str8ToStr16("4131423243332D583459355A36");
    ResponseEsimInnerResult responseResult;
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<Telephony::SimManager> simManager = std::make_shared<SimManager>(telRilManager);
    int32_t ret = simManager->AuthenticateServer(slotId, authenticateConfigInfo, responseResult);
    EXPECT_NE(ret, TELEPHONY_ERR_SUCCESS);
    std::shared_ptr<Telephony::SimStateManager> simStateManager = std::make_shared<SimStateManager>(telRilManager);
    simManager->simStateManager_.push_back(simStateManager);
    simManager->simStateManager_[slotId]->Init(slotId);
    simManager->simStateManager_[slotId]->simStateHandle_->iccState_.simStatus_ = -1;
    ret = simManager->AuthenticateServer(slotId, authenticateConfigInfo, responseResult);
    EXPECT_EQ(ret, TELEPHONY_ERR_LOCAL_PTR_NULL);
    EventFwk::CommonEventSubscribeInfo sp;
    std::weak_ptr<Telephony::ITelRilManager> iTelRilManager = telRilManager;
    std::weak_ptr<Telephony::SimStateManager> state = simStateManager;
    std::shared_ptr<Telephony::SimFileManager> simFileManager =
        std::make_shared<SimFileManager>(sp, iTelRilManager, state);
    simManager->simFileManager_.push_back(simFileManager);
    simManager->simFileManager_[slotId]->Init(slotId);
    ret = simManager->AuthenticateServer(slotId, authenticateConfigInfo, responseResult);
    EXPECT_EQ(ret, TELEPHONY_ERR_SUCCESS);
}
} // namespace Telephony
} // namespace OHOS
