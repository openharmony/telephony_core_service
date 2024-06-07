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

#include "core_manager_inner.h"
#include "core_service.h"
#include "core_service_client.h"
#include "operator_config_cache.h"
#include "sim_test_util.h"
#include "tel_ril_callback.h"
#include "telephony_ext_wrapper.h"

namespace OHOS {
namespace Telephony {
#ifndef TEL_TEST_UNSUPPORT
/**
 * @tc.number Telephony_VSim_InitExtraModule_0100
 * @tc.name InitExtraModule
 * @tc.desc Function test
 */
HWTEST_F(SimTest, Telephony_VSim_InitExtraModule_0100, Function | MediumTest | Level1)
{
    CoreManagerInner::GetInstance().isInitExtraObj_ = true;
    EXPECT_EQ(TELEPHONY_SUCCESS, CoreManagerInner::GetInstance().InitExtraModule(2));
    EXPECT_TRUE(CoreManagerInner::GetInstance().isInitExtraObj_);
}

/**
 * @tc.number Telephony_VSim_InitExtraModule_0200
 * @tc.name InitExtraModule
 * @tc.desc Function test
 */
HWTEST_F(SimTest, Telephony_VSim_InitExtraModule_0200, Function | MediumTest | Level1)
{
    CoreManagerInner::GetInstance().isInitExtraObj_ = true;
    EXPECT_EQ(TELEPHONY_SUCCESS, CoreManagerInner::GetInstance().InitExtraModule(0));
    EXPECT_TRUE(CoreManagerInner::GetInstance().isInitExtraObj_);
}

/**
 * @tc.number Telephony_VSim_InitExtraModule_0300
 * @tc.name InitExtraModule
 * @tc.desc Function test
 */
HWTEST_F(SimTest, Telephony_VSim_InitExtraModule_0300, Function | MediumTest | Level1)
{
    CoreManagerInner::GetInstance().isInitExtraObj_ = false;
    EXPECT_EQ(TELEPHONY_ERROR, CoreManagerInner::GetInstance().InitExtraModule(0));
    EXPECT_FALSE(CoreManagerInner::GetInstance().isInitExtraObj_);
}

/**
 * @tc.number Telephony_VSim_InitExtraModule_0400
 * @tc.name InitExtraModule
 * @tc.desc Function test
 */
HWTEST_F(SimTest, Telephony_VSim_InitExtraModule_0400, Function | MediumTest | Level1)
{
    CoreManagerInner::GetInstance().isInitExtraObj_ = false;
    EXPECT_EQ(TELEPHONY_ERROR, CoreManagerInner::GetInstance().InitExtraModule(1));
    EXPECT_FALSE(CoreManagerInner::GetInstance().isInitExtraObj_);
}

/**
 * @tc.number Telephony_VSim_InitExtraModule_0500
 * @tc.name InitExtraModule
 * @tc.desc Function test
 */
HWTEST_F(SimTest, Telephony_VSim_InitExtraModule_0500, Function | MediumTest | Level1)
{
    CoreManagerInner::GetInstance().isInitExtraObj_ = false;
    EXPECT_EQ(TELEPHONY_ERROR, CoreManagerInner::GetInstance().InitExtraModule(-1));
    EXPECT_FALSE(CoreManagerInner::GetInstance().isInitExtraObj_);
}

/**
 * @tc.number Telephony_VSim_InitExtraModule_0600
 * @tc.name InitExtraModule
 * @tc.desc Function test
 */
HWTEST_F(SimTest, Telephony_VSim_InitExtraModule_0600, Function | MediumTest | Level1)
{
    CoreManagerInner::GetInstance().isInitExtraObj_ = false;
    EXPECT_EQ(TELEPHONY_ERROR, CoreManagerInner::GetInstance().InitExtraModule(3));
    EXPECT_FALSE(CoreManagerInner::GetInstance().isInitExtraObj_);
}

/**
 * @tc.number Telephony_VSim_InitExtraModule_0700
 * @tc.name InitExtraModule
 * @tc.desc Function test
 */
HWTEST_F(SimTest, Telephony_VSim_InitExtraModule_0700, Function | MediumTest | Level1)
{
    CoreManagerInner::GetInstance().isInitExtraObj_ = false;
    EXPECT_EQ(TELEPHONY_ERROR, CoreManagerInner::GetInstance().InitExtraModule(2));
    EXPECT_FALSE(CoreManagerInner::GetInstance().isInitExtraObj_);
    EXPECT_EQ(TELEPHONY_ERROR, CoreManagerInner::GetInstance().InitExtraModule(2));
    EXPECT_FALSE(CoreManagerInner::GetInstance().isInitExtraObj_);
}

/**
 * @tc.number Telephony_VSim_InitExtraModule_0800
 * @tc.name InitExtraModule
 * @tc.desc Function test
 */
HWTEST_F(SimTest, Telephony_VSim_InitExtraModule_0800, Function | MediumTest | Level1)
{
#ifdef OHOS_BUILD_ENABLE_TELEPHONY_VSIM
    EXPECT_EQ(TELEPHONY_SUCCESS, CoreServiceClient::GetInstance().InitExtraModule(2));
#endif
}

/**
 * @tc.number Telephony_VSim_GetMaxSimSlot_0100
 * @tc.name InitExtraModule
 * @tc.desc Function test
 */
HWTEST_F(SimTest, Telephony_VSim_GetMaxSimSlot_0100, Function | MediumTest | Level1)
{
    auto telRilManager = std::make_shared<TelRilManager>();
    auto telRilCallback = std::make_shared<TelRilCallback>(telRilManager);
    auto maxSimSlot = telRilCallback->GetMaxSimSlot();
#ifdef OHOS_BUILD_ENABLE_TELEPHONY_VSIM
    if (SIM_SLOT_COUNT == 2) {
        EXPECT_EQ(3, maxSimSlot);
    } else {
        EXPECT_EQ(SIM_SLOT_COUNT, maxSimSlot);
    }
#else
    EXPECT_EQ(SIM_SLOT_COUNT, maxSimSlot);
#endif
}

/**
 * @tc.number Telephony_VSim_Wrapper_0100
 * @tc.name InitExtraModule
 * @tc.desc Function test
 */
HWTEST_F(SimTest, Telephony_VSim_Wrapper_0100, Function | MediumTest | Level1)
{
    TELEPHONY_EXT_WRAPPER.InitTelephonyExtWrapperForVSim();
    if (TELEPHONY_EXT_WRAPPER.telephonyVSimWrapperHandle_ != nullptr) {
        EXPECT_TRUE(TELEPHONY_EXT_WRAPPER.isVSimInStatus_ != nullptr);
        EXPECT_TRUE(TELEPHONY_EXT_WRAPPER.getVSimSlotId_ != nullptr);
        EXPECT_TRUE(TELEPHONY_EXT_WRAPPER.onAllFilesFetchedExt_ != nullptr);
        EXPECT_TRUE(TELEPHONY_EXT_WRAPPER.putVSimExtraInfo_ != nullptr);
        EXPECT_TRUE(TELEPHONY_EXT_WRAPPER.changeSpnAndRuleExt_ != nullptr);
        EXPECT_TRUE(TELEPHONY_EXT_WRAPPER.getVSimCardState_ != nullptr);
        EXPECT_TRUE(TELEPHONY_EXT_WRAPPER.getSimIdExt_ != nullptr);
        EXPECT_TRUE(TELEPHONY_EXT_WRAPPER.getSlotIdExt_ != nullptr);
        EXPECT_TRUE(TELEPHONY_EXT_WRAPPER.isHandleVSim_ != nullptr);
    }
}

/**
 * @tc.number Telephony_VSim_Wrapper_0200
 * @tc.name InitExtraModule
 * @tc.desc Function test
 */
HWTEST_F(SimTest, Telephony_VSim_Wrapper_0200, Function | MediumTest | Level1)
{
    TELEPHONY_EXT_WRAPPER.InitTelephonyExtWrapperForVSim();
    if (TELEPHONY_EXT_WRAPPER.telephonyVSimWrapperHandle_ == nullptr) {
        EXPECT_TRUE(TELEPHONY_EXT_WRAPPER.isVSimInStatus_ == nullptr);
        EXPECT_TRUE(TELEPHONY_EXT_WRAPPER.getVSimSlotId_ == nullptr);
        EXPECT_TRUE(TELEPHONY_EXT_WRAPPER.onAllFilesFetchedExt_ == nullptr);
        EXPECT_TRUE(TELEPHONY_EXT_WRAPPER.putVSimExtraInfo_ == nullptr);
        EXPECT_TRUE(TELEPHONY_EXT_WRAPPER.changeSpnAndRuleExt_ == nullptr);
        EXPECT_TRUE(TELEPHONY_EXT_WRAPPER.getVSimCardState_ == nullptr);
        EXPECT_TRUE(TELEPHONY_EXT_WRAPPER.getSimIdExt_ == nullptr);
        EXPECT_TRUE(TELEPHONY_EXT_WRAPPER.getSlotIdExt_ == nullptr);
        EXPECT_TRUE(TELEPHONY_EXT_WRAPPER.isHandleVSim_ == nullptr);
    }
}

#else // TEL_TEST_UNSUPPORT
/**
 * @tc.number   Telephony_Sim_MockTest_0100
 * @tc.name     A test mock for unsupported platform
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_MockTest_0100, Function | MediumTest | Level3)
{
    if (!(SimTest::HasSimCard(SimTest::slotId_))) {
        TELEPHONY_LOGI("TelephonyTestService has no sim card");
    }
    EXPECT_TRUE(true);
}

#endif // TEL_TEST_UNSUPPORT
} // namespace Telephony
} // namespace OHOS
