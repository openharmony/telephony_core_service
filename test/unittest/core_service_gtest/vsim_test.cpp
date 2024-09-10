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
#include "multi_sim_controller.h"
#include "operator_config_cache.h"
#include "sim_manager.h"
#include "sim_test_util.h"
#include "tel_ril_callback.h"
#include "tel_ril_manager.h"
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
        EXPECT_TRUE(TELEPHONY_EXT_WRAPPER.isVSimEnabled_ != nullptr);
        EXPECT_TRUE(TELEPHONY_EXT_WRAPPER.updateSubState_ != nullptr);
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
        EXPECT_TRUE(TELEPHONY_EXT_WRAPPER.isVSimEnabled_ == nullptr);
        EXPECT_TRUE(TELEPHONY_EXT_WRAPPER.updateSubState_ == nullptr);
    }
}

/**
 * @tc.number SavePrimarySlotId_0100
 * @tc.name InitExtraModule
 * @tc.desc Function test
 */
HWTEST_F(SimTest, SavePrimarySlotId_0100, Function | MediumTest | Level1)
{
    auto telRilManager = std::make_shared<TelRilManager>();
    auto simManager = std::make_shared<SimManager>(telRilManager);
    CoreManagerInner::GetInstance().OnInit(nullptr, simManager, telRilManager);
    int32_t result = CoreManagerInner::GetInstance().SavePrimarySlotId(0);
    EXPECT_EQ(TELEPHONY_ERR_ARGUMENT_INVALID, result);
}

/**
* @tc.number SavePrimarySlotId_0200
* @tc.name InitExtraModule
* @tc.desc Function test
*/
HWTEST_F(SimTest, SavePrimarySlotId_0200, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::vector<std::shared_ptr<Telephony::SimStateManager>> simStateManager = { nullptr, nullptr };
    std::vector<std::shared_ptr<Telephony::SimFileManager>> simFileManager = { nullptr, nullptr };
    std::shared_ptr<Telephony::MultiSimController> multiSimController =
    std::make_shared<MultiSimController>(telRilManager, simStateManager, simFileManager);
    EXPECT_EQ(TELEPHONY_ERR_SUCCESS, multiSimController->SavePrimarySlotId(0));
}

/**
* @tc.number SavePrimarySlotId_0300
* @tc.name InitExtraModule
* @tc.desc Function test
*/
HWTEST_F(SimTest, SavePrimarySlotId_0300, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::vector<std::shared_ptr<Telephony::SimStateManager>> simStateManager = { nullptr, nullptr };
    std::vector<std::shared_ptr<Telephony::SimFileManager>> simFileManager = { nullptr, nullptr };
    std::shared_ptr<Telephony::MultiSimController> multiSimController =
    std::make_shared<MultiSimController>(telRilManager, simStateManager, simFileManager);
    EXPECT_EQ(TELEPHONY_ERR_ARGUMENT_INVALID, multiSimController->SavePrimarySlotId(4));
}

HWTEST_F(SimTest, SavePrimarySlotId_0301, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    CoreManagerInner::GetInstance().telRilManager_ = telRilManager;

    std::shared_ptr<AppExecFwk::EventHandler> handler = std::make_shared<EventHandler>();
    int32_t status = CoreManagerInner::GetInstance().DelSimMessage(0, 0, 0, handler);
    EXPECT_EQ(status, TELEPHONY_ERR_LOCAL_PTR_NULL);
}

HWTEST_F(SimTest, SavePrimarySlotId_0302, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    CoreManagerInner::GetInstance().telRilManager_ = telRilManager;

    std::shared_ptr<AppExecFwk::EventHandler> handler = std::make_shared<EventHandler>();
    int32_t status = CoreManagerInner::GetInstance().GetSmscAddr(0, 0, handler);
    EXPECT_EQ(status, TELEPHONY_ERR_LOCAL_PTR_NULL);
}

HWTEST_F(SimTest, SavePrimarySlotId_0303, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    CoreManagerInner::GetInstance().telRilManager_ = telRilManager;

    std::shared_ptr<AppExecFwk::EventHandler> handler = std::make_shared<EventHandler>();
    int32_t status = CoreManagerInner::GetInstance().SetSmscAddr(0, 0, 0, "", handler);
    EXPECT_EQ(status, TELEPHONY_ERR_LOCAL_PTR_NULL);
}

HWTEST_F(SimTest, SavePrimarySlotId_0304, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    CoreManagerInner::GetInstance().telRilManager_ = telRilManager;

    std::shared_ptr<AppExecFwk::EventHandler> handler = std::make_shared<EventHandler>();
    CBConfigParam config;
    int32_t status = CoreManagerInner::GetInstance().SetCBConfig(0, 0, config, handler);
    EXPECT_EQ(status, TELEPHONY_ERR_LOCAL_PTR_NULL);
}

HWTEST_F(SimTest, SavePrimarySlotId_0305, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    CoreManagerInner::GetInstance().telRilManager_ = telRilManager;

    std::shared_ptr<AppExecFwk::EventHandler> handler = std::make_shared<EventHandler>();
    CdmaCBConfigInfoList configList;
    int32_t status = CoreManagerInner::GetInstance().SetCdmaCBConfig(0, 0, configList, handler);
    EXPECT_EQ(status, TELEPHONY_ERR_LOCAL_PTR_NULL);
}

HWTEST_F(SimTest, SavePrimarySlotId_0306, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    CoreManagerInner::GetInstance().telRilManager_ = telRilManager;

    std::shared_ptr<AppExecFwk::EventHandler> handler = std::make_shared<EventHandler>();
    int32_t status = CoreManagerInner::GetInstance().GetCBConfig(0, 0, handler);
    EXPECT_EQ(status, TELEPHONY_ERR_LOCAL_PTR_NULL);
}

HWTEST_F(SimTest, SavePrimarySlotId_0307, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    CoreManagerInner::GetInstance().telRilManager_ = telRilManager;

    std::shared_ptr<AppExecFwk::EventHandler> handler = std::make_shared<EventHandler>();
    int32_t status = CoreManagerInner::GetInstance().GetCdmaCBConfig(0, 0, handler);
    EXPECT_EQ(status, TELEPHONY_ERR_LOCAL_PTR_NULL);
}

HWTEST_F(SimTest, SavePrimarySlotId_0308, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    CoreManagerInner::GetInstance().telRilManager_ = telRilManager;

    std::shared_ptr<AppExecFwk::EventHandler> handler = std::make_shared<EventHandler>();
    GsmSimMessageParam message;
    int32_t status = CoreManagerInner::GetInstance().SendSmsMoreMode(0, 0, message, handler);
    EXPECT_EQ(status, TELEPHONY_ERR_LOCAL_PTR_NULL);
}

HWTEST_F(SimTest, SavePrimarySlotId_0309, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    CoreManagerInner::GetInstance().telRilManager_ = telRilManager;

    std::shared_ptr<AppExecFwk::EventHandler> handler = std::make_shared<EventHandler>();
    int32_t status = CoreManagerInner::GetInstance().SendSmsAck(0, 0, true, 0, handler);
    EXPECT_EQ(status, TELEPHONY_ERR_LOCAL_PTR_NULL);
}

HWTEST_F(SimTest, SavePrimarySlotId_0310, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    CoreManagerInner::GetInstance().telRilManager_ = telRilManager;

    std::shared_ptr<AppExecFwk::EventHandler> handler = std::make_shared<EventHandler>();
    int32_t status = CoreManagerInner::GetInstance().AddCdmaSimMessage(0, 0, 0, "", handler);
    EXPECT_EQ(status, TELEPHONY_ERR_LOCAL_PTR_NULL);
}

HWTEST_F(SimTest, SavePrimarySlotId_0311, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    CoreManagerInner::GetInstance().telRilManager_ = telRilManager;

    std::shared_ptr<AppExecFwk::EventHandler> handler = std::make_shared<EventHandler>();
    int32_t status = CoreManagerInner::GetInstance().DelCdmaSimMessage(0, 0, 0, handler);
    EXPECT_EQ(status, TELEPHONY_ERR_LOCAL_PTR_NULL);
}

HWTEST_F(SimTest, SavePrimarySlotId_0312, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    CoreManagerInner::GetInstance().telRilManager_ = telRilManager;

    std::shared_ptr<AppExecFwk::EventHandler> handler = std::make_shared<EventHandler>();
    CdmaSimMessageParam config;
    int32_t status = CoreManagerInner::GetInstance().UpdateCdmaSimMessage(0, 0, config, handler);
    EXPECT_EQ(status, TELEPHONY_ERR_LOCAL_PTR_NULL);
}

HWTEST_F(SimTest, SavePrimarySlotId_0313, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    CoreManagerInner::GetInstance().telRilManager_ = telRilManager;

    std::shared_ptr<AppExecFwk::EventHandler> handler = std::make_shared<EventHandler>();
    int32_t status = CoreManagerInner::GetInstance().GetNetworkSearchInformation(0, 0, handler);
    EXPECT_EQ(status, TELEPHONY_ERR_LOCAL_PTR_NULL);
}

HWTEST_F(SimTest, SavePrimarySlotId_0314, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    CoreManagerInner::GetInstance().telRilManager_ = telRilManager;

    std::shared_ptr<AppExecFwk::EventHandler> handler = std::make_shared<EventHandler>();
    int32_t status = CoreManagerInner::GetInstance().GetNetworkSelectionMode(0, 0, handler);
    EXPECT_EQ(status, TELEPHONY_ERR_LOCAL_PTR_NULL);
}

HWTEST_F(SimTest, SavePrimarySlotId_0315, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    CoreManagerInner::GetInstance().telRilManager_ = telRilManager;

    std::shared_ptr<AppExecFwk::EventHandler> handler = std::make_shared<EventHandler>();
    int32_t status = CoreManagerInner::GetInstance().SetNetworkSelectionMode(0, 0, 0, "", handler);
    EXPECT_EQ(status, TELEPHONY_ERR_LOCAL_PTR_NULL);
}

HWTEST_F(SimTest, SavePrimarySlotId_0316, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    CoreManagerInner::GetInstance().telRilManager_ = telRilManager;

    std::shared_ptr<AppExecFwk::EventHandler> handler = std::make_shared<EventHandler>();
    int32_t status = CoreManagerInner::GetInstance().GetRadioState(0, 0, handler);
    EXPECT_EQ(status, TELEPHONY_ERR_LOCAL_PTR_NULL);
}

HWTEST_F(SimTest, SavePrimarySlotId_0317, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    CoreManagerInner::GetInstance().telRilManager_ = telRilManager;

    std::shared_ptr<AppExecFwk::EventHandler> handler = std::make_shared<EventHandler>();
    int32_t status = CoreManagerInner::GetInstance().SetRadioState(0, 0, 0, 0, handler);
    EXPECT_EQ(status, TELEPHONY_ERR_LOCAL_PTR_NULL);
}

HWTEST_F(SimTest, SavePrimarySlotId_0318, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    CoreManagerInner::GetInstance().telRilManager_ = telRilManager;

    std::shared_ptr<AppExecFwk::EventHandler> handler = std::make_shared<EventHandler>();
    int32_t status = CoreManagerInner::GetInstance().ShutDown(0, 0, handler);
    EXPECT_EQ(status, TELEPHONY_ERR_LOCAL_PTR_NULL);
}

HWTEST_F(SimTest, SavePrimarySlotId_0319, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    CoreManagerInner::GetInstance().telRilManager_ = telRilManager;

    std::shared_ptr<AppExecFwk::EventHandler> handler = std::make_shared<EventHandler>();
    int32_t status = CoreManagerInner::GetInstance().Dial(0, 0, "", 0, handler);
    EXPECT_EQ(status, TELEPHONY_ERR_LOCAL_PTR_NULL);
}

HWTEST_F(SimTest, SavePrimarySlotId_0320, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    CoreManagerInner::GetInstance().telRilManager_ = telRilManager;

    std::shared_ptr<AppExecFwk::EventHandler> handler = std::make_shared<EventHandler>();
    int32_t status = CoreManagerInner::GetInstance().Reject(0, 0, handler);
    EXPECT_EQ(status, TELEPHONY_ERR_LOCAL_PTR_NULL);
}

HWTEST_F(SimTest, SavePrimarySlotId_0321, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    CoreManagerInner::GetInstance().telRilManager_ = telRilManager;

    std::shared_ptr<AppExecFwk::EventHandler> handler = std::make_shared<EventHandler>();
    int32_t status = CoreManagerInner::GetInstance().Hangup(0, 0, 0, handler);
    EXPECT_EQ(status, TELEPHONY_ERR_LOCAL_PTR_NULL);
}

HWTEST_F(SimTest, SavePrimarySlotId_0322, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    CoreManagerInner::GetInstance().telRilManager_ = telRilManager;

    std::shared_ptr<AppExecFwk::EventHandler> handler = std::make_shared<EventHandler>();
    int32_t status = CoreManagerInner::GetInstance().Answer(0, 0, handler);
    EXPECT_EQ(status, TELEPHONY_ERR_LOCAL_PTR_NULL);
}

HWTEST_F(SimTest, SavePrimarySlotId_0323, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    CoreManagerInner::GetInstance().telRilManager_ = telRilManager;

    std::shared_ptr<AppExecFwk::EventHandler> handler = std::make_shared<EventHandler>();
    int32_t status = CoreManagerInner::GetInstance().GetCallList(0, 0, handler);
    EXPECT_EQ(status, TELEPHONY_ERR_LOCAL_PTR_NULL);
}

HWTEST_F(SimTest, SavePrimarySlotId_0324, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    CoreManagerInner::GetInstance().telRilManager_ = telRilManager;

    std::shared_ptr<AppExecFwk::EventHandler> handler = std::make_shared<EventHandler>();
    int32_t status = CoreManagerInner::GetInstance().HoldCall(0, 0, handler);
    EXPECT_EQ(status, TELEPHONY_ERR_LOCAL_PTR_NULL);
}

HWTEST_F(SimTest, SavePrimarySlotId_0325, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    CoreManagerInner::GetInstance().telRilManager_ = telRilManager;

    std::shared_ptr<AppExecFwk::EventHandler> handler = std::make_shared<EventHandler>();
    int32_t status = CoreManagerInner::GetInstance().UnHoldCall(0, 0, handler);
    EXPECT_EQ(status, TELEPHONY_ERR_LOCAL_PTR_NULL);
}

HWTEST_F(SimTest, SavePrimarySlotId_0326, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    CoreManagerInner::GetInstance().telRilManager_ = telRilManager;

    std::shared_ptr<AppExecFwk::EventHandler> handler = std::make_shared<EventHandler>();
    int32_t status = CoreManagerInner::GetInstance().SwitchCall(0, 0, handler);
    EXPECT_EQ(status, TELEPHONY_ERR_LOCAL_PTR_NULL);
}

HWTEST_F(SimTest, SavePrimarySlotId_0327, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    CoreManagerInner::GetInstance().telRilManager_ = telRilManager;

    std::shared_ptr<AppExecFwk::EventHandler> handler = std::make_shared<EventHandler>();
    int32_t status = CoreManagerInner::GetInstance().CombineConference(0, 0, 0, handler);
    EXPECT_EQ(status, TELEPHONY_ERR_LOCAL_PTR_NULL);
}

HWTEST_F(SimTest, SavePrimarySlotId_0328, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    CoreManagerInner::GetInstance().telRilManager_ = telRilManager;

    std::shared_ptr<AppExecFwk::EventHandler> handler = std::make_shared<EventHandler>();
    int32_t status = CoreManagerInner::GetInstance().SeparateConference(0, 0, 0, 0, handler);
    EXPECT_EQ(status, TELEPHONY_ERR_LOCAL_PTR_NULL);
}

HWTEST_F(SimTest, SavePrimarySlotId_0329, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    CoreManagerInner::GetInstance().telRilManager_ = telRilManager;

    std::shared_ptr<AppExecFwk::EventHandler> handler = std::make_shared<EventHandler>();
    int32_t status = CoreManagerInner::GetInstance().CallSupplement(0, 0, 0, handler);
    EXPECT_EQ(status, TELEPHONY_ERR_LOCAL_PTR_NULL);
}

HWTEST_F(SimTest, SavePrimarySlotId_0330, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    CoreManagerInner::GetInstance().telRilManager_ = telRilManager;

    std::shared_ptr<AppExecFwk::EventHandler> handler = std::make_shared<EventHandler>();
    int32_t status = CoreManagerInner::GetInstance().SetVoNRSwitch(0, 0, 0, handler);
    EXPECT_EQ(status, TELEPHONY_ERR_LOCAL_PTR_NULL);
}
#else // TEL_TEST_UNSUPPORT
/**
 * @tc.number   Telephony_Sim_MockTest_0100
 * @tc.name     A test mock for unsupported platform
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_MockTest_0100, Function | MediumTest | Level3)
{
    bool isSupported = true;
    if (!(SimTest::HasSimCard(SimTest::slotId_))) {
        isSupported = fasle;
        TELEPHONY_LOGI("TelephonyTestService has no sim card");
    }
    EXPECT_TRUE(isSupported);
}
#endif // TEL_TEST_UNSUPPORT
} // namespace Telephony
} // namespace OHOS
