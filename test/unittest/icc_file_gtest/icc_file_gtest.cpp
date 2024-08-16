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
#include "cell_info.h"
#include "cell_location.h"
#include "common_event_manager.h"
#include "common_event_support.h"
#include "core_manager_inner.h"
#include "core_service_client.h"
#include "csim_file_controller.h"
#include "gtest/gtest.h"
#include "tel_ril_base_parcel.h"
#include "icc_file.h"
#include "icc_file_controller.h"
#include "icc_operator_rule.h"
#include "ims_core_service_callback_proxy.h"
#include "ims_core_service_callback_stub.h"
#include "ims_core_service_proxy.h"
#include "ims_reg_info_callback_proxy.h"
#include "isim_file_controller.h"
#include "multi_sim_controller.h"
#include "multi_sim_monitor.h"
#include "network_register.h"
#include "network_search_manager.h"
#include "network_search_state.h"
#include "operator_matching_rule.h"
#include "operator_name.h"
#include "radio_protocol_controller.h"
#include "ruim_file_controller.h"
#include "sim_file_controller.h"
#include "sim_file_manager.h"
#include "sim_manager.h"
#include "sim_number_decode.h"
#include "sim_rdb_helper.h"
#include "sim_sms_controller.h"
#include "sim_state_manager.h"
#include "sim_utils.h"
#include "stk_controller.h"
#include "stk_manager.h"
#include "tag_service.h"
#include "tel_ril_manager.h"
#include "telephony_errors.h"
#include "telephony_hisysevent.h"
#include "telephony_log_wrapper.h"
#include "usim_file_controller.h"
#include "telephony_data_helper.h"
#include "sim_data.h"
#include "accesstoken_kit.h"
#include "token_setproc.h"
#include "nativetoken_kit.h"

namespace OHOS {
namespace Telephony {
using namespace testing::ext;

class IccFileTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void IccFileTest::TearDownTestCase() {}

void IccFileTest::SetUp() {}

void IccFileTest::TearDown() {}

void IccFileTest::SetUpTestCase() {}

/**
 * @tc.number   Telephony_IccFile_001
 * @tc.name     test IccFile
 * @tc.desc     Function test
 */
HWTEST_F(IccFileTest, Telephony_IccFile_001, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    auto simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<IccFile> iccFile = std::make_shared<IsimFile>(simStateManager);
    iccFile->Init();
    iccFile->ObtainMNC();
    EXPECT_TRUE(iccFile->imsi_.empty());
}

/**
 * @tc.number   Telephony_IccFile_002
 * @tc.name     test IccFile
 * @tc.desc     Function test
 */
HWTEST_F(IccFileTest, Telephony_IccFile_002, Function | MediumTest | Level1)
{
    std::string imsi = "ABC";
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    auto simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<IccFile> iccFile = std::make_shared<IsimFile>(simStateManager);
    iccFile->Init();
    iccFile->UpdateImsi(imsi);
    std::string ret = iccFile->ObtainMNC();
    EXPECT_TRUE(ret.empty());
}

/**
 * @tc.number   Telephony_IccFile_003
 * @tc.name     test IccFile
 * @tc.desc     Function test
 */
HWTEST_F(IccFileTest, Telephony_IccFile_003, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    auto simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<IccFile> iccFile = std::make_shared<IsimFile>(simStateManager);
    iccFile->Init();
    iccFile->ObtainMCC();
    EXPECT_TRUE(iccFile->imsi_.empty());
}

/**
 * @tc.number   Telephony_IccFile_004
 * @tc.name     test IccFile
 * @tc.desc     Function test
 */
HWTEST_F(IccFileTest, Telephony_IccFile_004, Function | MediumTest | Level1)
{
    std::string imsi = "ABC";
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    auto simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<IccFile> iccFile = std::make_shared<IsimFile>(simStateManager);
    iccFile->Init();
    iccFile->UpdateImsi(imsi);
    std::string ret = iccFile->ObtainMCC();
    EXPECT_TRUE(ret.empty());
}

/**
 * @tc.number   Telephony_IccFile_005
 * @tc.name     test IccFile
 * @tc.desc     Function test
 */
HWTEST_F(IccFileTest, Telephony_IccFile_005, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    auto simStateManager = std::make_shared<SimStateManager>(telRilManager);
    simStateManager = nullptr;
    std::shared_ptr<IccFile> iccFile = std::make_shared<IsimFile>(simStateManager);
    iccFile->Init();
    EXPECT_EQ(iccFile->stateManager_, nullptr);
}

/**
 * @tc.number   Telephony_IccFile_006
 * @tc.name     test IccFile
 * @tc.desc     Function test
 */
HWTEST_F(IccFileTest, Telephony_IccFile_006, Function | MediumTest | Level1)
{
    AppExecFwk::InnerEvent::Pointer event = AppExecFwk::InnerEvent::Get(0, 0);
    event = nullptr;
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    auto simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<IccFile> iccFile = std::make_shared<IsimFile>(simStateManager);
    iccFile->ProcessEvent(event);
    EXPECT_EQ(event, nullptr);
}

/**
 * @tc.number   Telephony_IccFile_007
 * @tc.name     test IccFile
 * @tc.desc     Function test
 */
HWTEST_F(IccFileTest, Telephony_IccFile_007, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    auto simStateManager = std::make_shared<SimStateManager>(telRilManager);
    simStateManager = nullptr;
    std::shared_ptr<IccFile> iccFile = std::make_shared<IsimFile>(simStateManager);
    iccFile->LoadVoiceMail();
    EXPECT_EQ(iccFile->voiceMailConfig_, nullptr);
}

/**
 * @tc.number   Telephony_IccFile_008
 * @tc.name     test IccFile
 * @tc.desc     Function test
 */
HWTEST_F(IccFileTest, Telephony_IccFile_008, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    auto simStateManager = std::make_shared<SimStateManager>(telRilManager);
    simStateManager = nullptr;
    std::shared_ptr<IccFile> iccFile = std::make_shared<IsimFile>(simStateManager);
    std::shared_ptr<AppExecFwk::EventHandler> handler = nullptr;
    iccFile->imsiReadyObser_ = nullptr;
    iccFile->UnregisterImsiLoaded(handler);
    EXPECT_EQ(iccFile->imsiReadyObser_, nullptr);
}

/**
 * @tc.number   Telephony_IccFile_009
 * @tc.name     test IccFile
 * @tc.desc     Function test
 */
HWTEST_F(IccFileTest, Telephony_IccFile_009, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    auto simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<IccFile> iccFile = std::make_shared<IsimFile>(simStateManager);
    iccFile->filesFetchedObser_ = nullptr;
    iccFile->fileQueried_ = true;
    std::shared_ptr<AppExecFwk::EventHandler> eventHandler = nullptr;
    iccFile->RegisterAllFilesLoaded(eventHandler);
    EXPECT_TRUE(iccFile->fileQueried_);
}

/**
 * @tc.number   Telephony_IccFile_010
 * @tc.name     test IccFile
 * @tc.desc     Function test
 */
HWTEST_F(IccFileTest, Telephony_IccFile_010, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    auto simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<IccFile> iccFile = std::make_shared<IsimFile>(simStateManager);
    iccFile->filesFetchedObser_ = nullptr;
    std::shared_ptr<AppExecFwk::EventHandler> eventHandler = nullptr;
    iccFile->UnregisterAllFilesLoaded(eventHandler);
    EXPECT_EQ(iccFile->filesFetchedObser_, nullptr);
}

/**
 * @tc.number   Telephony_IccFile_011
 * @tc.name     test IccFile
 * @tc.desc     Function test
 */
HWTEST_F(IccFileTest, Telephony_IccFile_011, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    auto simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<IccFile> iccFile = std::make_shared<IsimFile>(simStateManager);
    iccFile->opkeyLoadObser_ = nullptr;
    std::shared_ptr<AppExecFwk::EventHandler> eventHandler = nullptr;
    iccFile->RegisterOpkeyLoaded(eventHandler);
    EXPECT_EQ(iccFile->opkeyLoadObser_, nullptr);
}

/**
 * @tc.number   Telephony_IccFile_012
 * @tc.name     test IccFile
 * @tc.desc     Function test
 */
HWTEST_F(IccFileTest, Telephony_IccFile_012, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    auto simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<IccFile> iccFile = std::make_shared<IsimFile>(simStateManager);
    iccFile->operatorCacheDelObser_ = nullptr;
    std::shared_ptr<AppExecFwk::EventHandler> eventHandler = nullptr;
    iccFile->RegisterOperatorCacheDel(eventHandler);
    EXPECT_EQ(iccFile->operatorCacheDelObser_, nullptr);
}

/**
 * @tc.number   Telephony_IccFile_013
 * @tc.name     test IccFile
 * @tc.desc     Function test
 */
HWTEST_F(IccFileTest, Telephony_IccFile_013, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    auto simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<IccFile> iccFile = std::make_shared<IsimFile>(simStateManager);
    iccFile->iccidLoadObser_ = nullptr;
    std::string iccId = "ABCD";
    iccFile->iccId_ = iccId;
    std::shared_ptr<AppExecFwk::EventHandler> eventHandler = nullptr;
    iccFile->RegisterIccidLoaded(eventHandler);
    EXPECT_EQ(iccFile->iccidLoadObser_, nullptr);
}

/**
 * @tc.number   Telephony_IccFile_014
 * @tc.name     test IccFile
 * @tc.desc     Function test
 */
HWTEST_F(IccFileTest, Telephony_IccFile_014, Function | MediumTest | Level1)
{
    std::shared_ptr<AppExecFwk::EventHandler> eventHandler = nullptr;
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    auto simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<IccFile> iccFile = std::make_shared<IsimFile>(simStateManager);
    iccFile->opkeyLoadObser_ = nullptr;
    iccFile->UnregisterOpkeyLoaded(eventHandler);
    iccFile->operatorCacheDelObser_ = nullptr;
    iccFile->UnregisterOperatorCacheDel(eventHandler);
    iccFile->iccidLoadObser_ = nullptr;
    iccFile->UnregisterIccidLoaded(eventHandler);
    EXPECT_EQ(iccFile->opkeyLoadObser_, nullptr);
    EXPECT_EQ(iccFile->operatorCacheDelObser_, nullptr);
    EXPECT_EQ(iccFile->iccidLoadObser_, nullptr);
}

/**
 * @tc.number   Telephony_IccFile_015
 * @tc.name     test IccFile
 * @tc.desc     Function test
 */
HWTEST_F(IccFileTest, Telephony_IccFile_015, Function | MediumTest | Level1)
{
    int what1 = 528;
    int what2 = 529;
    int what3 = 531;
    std::shared_ptr<AppExecFwk::EventHandler> eventHandler = nullptr;
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    auto simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<IccFile> iccFile = std::make_shared<IsimFile>(simStateManager);
    iccFile->UnRegisterCoreNotify(eventHandler, what1);
    EXPECT_EQ(what1, RadioEvent::RADIO_SIM_OPKEY_LOADED);
    iccFile->UnRegisterCoreNotify(eventHandler, what2);
    EXPECT_EQ(what2, RadioEvent::RADIO_OPERATOR_CACHE_DELETE);
    iccFile->UnRegisterCoreNotify(eventHandler, what3);
    EXPECT_EQ(what3, RadioEvent::RADIO_QUERY_ICCID_DONE);
}

}
}