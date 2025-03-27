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
#define private public
#define protected public
#include <gtest/gtest.h>
#include <string_ex.h>

#include "core_manager_inner.h"
#include "core_service.h"
#include "icc_dialling_numbers_handler.h"
#include "icc_dialling_numbers_manager.h"
#include "icc_file_controller.h"
#include "icc_operator_privilege_controller.h"
#include "mcc_pool.h"
#include "operator_config_cache.h"
#include "operator_config_loader.h"
#include "parcel.h"
#include "plmn_file.h"
#include "sim_account_manager.h"
#include "sim_data_type.h"
#include "sim_file_controller.h"
#include "sim_manager.h"
#include "sim_rdb_helper.h"
#include "sim_sms_manager.h"
#include "usim_dialling_numbers_service.h"
#include "want.h"
#include "sim_constant.h"

namespace OHOS {
namespace Telephony {
using namespace testing::ext;

class OperatorConfigLoaderTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};
void OperatorConfigLoaderTest::SetUpTestCase() {}

void OperatorConfigLoaderTest::TearDownTestCase() {}

void OperatorConfigLoaderTest::SetUp() {}

void OperatorConfigLoaderTest::TearDown() {}

/**
 * @tc.number   Telephony_GetMccFromMccMnc_001
 * @tc.name     test error branch
 * @tc.desc     Function test
 */
HWTEST_F(OperatorConfigLoaderTest, Telephony_GetMccFromMccMnc_001, Function | MediumTest | Level1)
{
    auto telRilManager = std::make_shared<TelRilManager>();
    auto simStateManager = std::make_shared<SimStateManager>(telRilManager);
    EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent(CommonEventSupport::COMMON_EVENT_OPERATOR_CONFIG_CHANGED);
    EventFwk::CommonEventSubscribeInfo subcribeInfo(matchingSkills);
    auto simFileManager = std::make_shared<SimFileManager>(subcribeInfo, telRilManager, simStateManager);
    auto operatorConfigCache = std::make_shared<OperatorConfigCache>(simFileManager, 0);
    auto operatorConfigLoader = std::make_shared<OperatorConfigLoader>(simFileManager, operatorConfigCache);
    std::string mccmnc = Str16ToStr8(simFileManager->GetSimOperatorNumeric());
    std::string ret = operatorConfigLoader->GetMccFromMccMnc(mccmnc);
    std::string result = operatorConfigLoader->GetMncFromMccMnc(mccmnc);
    EXPECT_EQ(ret, "");
}

/**
 * @tc.number   Telephony_SetMatchResultToSimFileManager_001
 * @tc.name     test error branch
 * @tc.desc     Function test
 */
HWTEST_F(OperatorConfigLoaderTest, Telephony_SetMatchResultToSimFileManager_001, Function | MediumTest | Level1)
{
    auto telRilManager = std::make_shared<TelRilManager>();
    auto simStateManager = std::make_shared<SimStateManager>(telRilManager);
    EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent(CommonEventSupport::COMMON_EVENT_OPERATOR_CONFIG_CHANGED);
    EventFwk::CommonEventSubscribeInfo subcribeInfo(matchingSkills);
    auto simFileManager = std::make_shared<SimFileManager>(subcribeInfo, telRilManager, simStateManager);
    auto operatorConfigCache = std::make_shared<OperatorConfigCache>(simFileManager, 0);
    auto operatorConfigLoader = std::make_shared<OperatorConfigLoader>(simFileManager, operatorConfigCache);
    operatorConfigLoader->mccmncFromSim_ = Str16ToStr8(simFileManager->GetSimOperatorNumeric());
    std::string opKeyVal = operatorConfigLoader->mccmncFromSim_;
    std::string opNameVal = "COMMON";
    std::string opKeyExtVal = "";
    int32_t slotId = 0;
    operatorConfigLoader->SetMatchResultToSimFileManager(opKeyVal, opNameVal, opKeyExtVal, slotId, simFileManager);
    EXPECT_EQ(operatorConfigLoader->mccmncFromSim_, "");
}

/**
 * @tc.number   Telephony_CreateSimHelper_001
 * @tc.name     test error branch
 * @tc.desc     Function test
 */
HWTEST_F(OperatorConfigLoaderTest, Telephony_CreateSimHelper_001, Function | MediumTest | Level1)
{
    auto telRilManager = std::make_shared<TelRilManager>();
    auto simStateManager = std::make_shared<SimStateManager>(telRilManager);
    EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent(CommonEventSupport::COMMON_EVENT_OPERATOR_CONFIG_CHANGED);
    EventFwk::CommonEventSubscribeInfo subcribeInfo(matchingSkills);
    auto simFileManager = std::make_shared<SimFileManager>(subcribeInfo, telRilManager, simStateManager);
    auto operatorConfigCache = std::make_shared<OperatorConfigCache>(simFileManager, 0);
    auto operatorConfigLoader = std::make_shared<OperatorConfigLoader>(simFileManager, operatorConfigCache);
    auto result = operatorConfigLoader->CreateSimHelper();
    EXPECT_EQ(result, nullptr);
}

/**
 * @tc.number   Telephony_UpdateIccidCache_001
 * @tc.name     test UpdateIccidCache
 * @tc.desc     Function test
 */
HWTEST_F(OperatorConfigLoaderTest, Telephony_UpdateIccidCache_001, Function | MediumTest | Level1)
{
    auto telRilManager = std::make_shared<TelRilManager>();
    auto simStateManager = std::make_shared<SimStateManager>(telRilManager);
    simStateManager->Init(0);
    simStateManager->simStateHandle_->iccid_ = "86890000000000000001";
    EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent(CommonEventSupport::COMMON_EVENT_OPERATOR_CONFIG_CHANGED);
    EventFwk::CommonEventSubscribeInfo subcribeInfo(matchingSkills);
    auto simFileManager = std::make_shared<SimFileManager>(subcribeInfo, telRilManager, simStateManager);
    auto operatorConfigCache = std::make_shared<OperatorConfigCache>(simFileManager, 0);
    auto operatorConfigLoader = std::make_shared<OperatorConfigLoader>(simFileManager, operatorConfigCache);
    operatorConfigCache->iccidCache_ = "";
    operatorConfigCache->UpdateIccidCache(0);
    EXPECT_EQ(operatorConfigCache->iccidCache_, "");
    operatorConfigCache->UpdateIccidCache(1);
    EXPECT_EQ(operatorConfigCache->iccidCache_, "86890000000000000001");
    operatorConfigCache->UpdateIccidCache(0);
    simFileManager = nullptr;
    operatorConfigCache->UpdateIccidCache(0);
}
 
/**
 * @tc.number   Telephony_SendSimMatchedOperatorInfo_001
 * @tc.name     test SendSimMatchedOperatorInfo
 * @tc.desc     Function test
 */
HWTEST_F(OperatorConfigLoaderTest, Telephony_SendSimMatchedOperatorInfo_001, Function | MediumTest | Level1)
{
    auto telRilManager = std::make_shared<TelRilManager>();
    auto simStateManager = std::make_shared<SimStateManager>(telRilManager);
    simStateManager->Init(0);
    simStateManager->simStateHandle_->iccid_ = "86890000000000000001";
    EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent(CommonEventSupport::COMMON_EVENT_OPERATOR_CONFIG_CHANGED);
    EventFwk::CommonEventSubscribeInfo subcribeInfo(matchingSkills);
    auto simFileManager = std::make_shared<SimFileManager>(subcribeInfo, telRilManager, simStateManager);
    auto operatorConfigCache = std::make_shared<OperatorConfigCache>(simFileManager, 0);
    auto operatorConfigLoader = std::make_shared<OperatorConfigLoader>(simFileManager, operatorConfigCache);
    operatorConfigCache->iccidCache_ = "";
    operatorConfigCache->UpdateIccidCache(1);
    simFileManager->SetOpKey("");
    operatorConfigCache->SendSimMatchedOperatorInfo(0, 1);
    EXPECT_EQ(operatorConfigCache->modemSimMatchedOpNameCache_, "");
    simFileManager->SetOpKey("46001");
    simFileManager->SetOpName("CUCC_CN");
    operatorConfigCache->SendSimMatchedOperatorInfo(0, 1);
    EXPECT_EQ(operatorConfigCache->modemSimMatchedOpNameCache_, "CUCC_CN");
    simFileManager->SetOpKey("20404F01");
    simFileManager->SetOpName("VDF_NL");
    operatorConfigCache->SendSimMatchedOperatorInfo(0, 1);
    EXPECT_EQ(operatorConfigCache->modemSimMatchedOpNameCache_, "CUCC_CN");
    simStateManager->simStateHandle_->iccid_ = "86890000000000000002";
    operatorConfigCache->UpdateIccidCache(1);
    operatorConfigCache->SendSimMatchedOperatorInfo(0, 1);
    EXPECT_EQ(operatorConfigCache->modemSimMatchedOpNameCache_, "VDF_NL");
}
} // namespace Telephony
} // namespace OHOS