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

#define LENGTH_TWO 2

namespace OHOS {
namespace Telephony {
using namespace testing::ext;
constexpr const char *PREVIOUS_VERSION = "persist.telephony.previous_version";
constexpr const char *IS_BLOCK_LOAD_OPERATORCONFIG_SLOT0 = "telephony.is_block_load_operatorconfig0";
constexpr const char *IS_BLOCK_LOAD_OPERATORCONFIG_SLOT1 = "telephony.is_block_load_operatorconfig1";
constexpr const char *IS_UPDATE_OPERATORCONFIG_SLOT0 = "telephony.is_update_operatorconfig0";
constexpr const char *IS_UPDATE_OPERATORCONFIG_SLOT1 = "telephony.is_update_operatorconfig1";
static const int32_t SIM_COUNT = 2;

class IccFileTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
    void InitCoreService();
    void ResetCoreService();
 
    std::shared_ptr<Telephony::ITelRilManager> telRilManager_ = nullptr;
    std::shared_ptr<Telephony::SimManager> simManager_ = nullptr;
    std::vector<std::shared_ptr<Telephony::SimStateManager>> simStateManager_;
    std::vector<std::shared_ptr<Telephony::SimFileManager>> simFileManager_;
    std::vector<std::shared_ptr<Telephony::SimAccountManager>> simAccountManager_;
    std::shared_ptr<MultiSimController> multiSimController_ = nullptr;
    std::shared_ptr<MultiSimMonitor> multiSimMonitor_ = nullptr;
    std::shared_ptr<SimStateHandle> simStateHandle_ = nullptr;
    std::shared_ptr<IccFile> simFile_ = nullptr;
    std::shared_ptr<SimStateTracker> simStateTracker_ = nullptr;
    std::shared_ptr<INetworkSearch> networkSearchManager_ = nullptr;
};

void IccFileTest::InitCoreService()
{
    telRilManager_ = std::make_shared<TelRilManager>();
    simManager_ = std::make_shared<SimManager>(telRilManager_);
    simStateManager_.resize(SIM_COUNT);
    simFileManager_.resize(SIM_COUNT);
    simAccountManager_.resize(SIM_COUNT);
    for (int32_t slotId = 0; slotId < SIM_COUNT; slotId++) {
        simStateManager_[slotId] = std::make_shared<SimStateManager>(telRilManager_);
        simStateManager_[slotId]->Init(slotId);
        simFileManager_[slotId] = SimFileManager::CreateInstance(std::weak_ptr<ITelRilManager>(telRilManager_),
            std::weak_ptr<SimStateManager>(simStateManager_[slotId]));
        simFileManager_[slotId]->Init(slotId);
        simAccountManager_[slotId] =
            std::make_shared<SimAccountManager>(telRilManager_, simStateManager_[slotId], simFileManager_[slotId]);
        simAccountManager_[slotId]->Init(slotId);
    }
    multiSimController_ = std::make_shared<MultiSimController>(telRilManager_,simStateManager_,simFileManager_);
    std::vector<std::weak_ptr<Telephony::SimFileManager>> simFileManagerWeak;
    for (auto simFile : simFileManager_) {
        simFileManagerWeak.push_back(std::weak_ptr<Telephony::SimFileManager>(simFile));
    }
    multiSimMonitor_ = std::make_shared<MultiSimMonitor>(multiSimController_, simStateManager_,simFileManagerWeak);
    simManager_->simStateManager_ = simStateManager_;
    simManager_->simFileManager_ = simFileManager_;
    simManager_->simAccountManager_ = simAccountManager_;
    simManager_->multiSimController_ = multiSimController_;
    simManager_->multiSimMonitor_ = multiSimMonitor_;
    simStateHandle_ = simStateManager_[0]->simStateHandle_;
    simStateHandle_->iccState_.simStatus_ = ICC_CONTENT_READY;
    simStateHandle_->externalState_ = SimState::SIM_STATE_READY;
    simStateHandle_->externalType_ = CardType::SINGLE_MODE_USIM_CARD;
    simFile_ = simFileManager_[0]->simFile_;
    simStateTracker_ = simAccountManager_[0]->simStateTracker_;
    networkSearchManager_ = std::make_shared<NetworkSearchManager>(telRilManager_, simManager_);
    CoreManagerInner::GetInstance().OnInit(networkSearchManager_, simManager_, telRilManager_);
}

void IccFileTest::ResetCoreService()
{
    telRilManager_.reset();
    simManager_.reset();
    multiSimController_.reset();
    multiSimMonitor_.reset();
    simStateHandle_.reset();
    simFile_.reset();
    simStateTracker_.reset();
    networkSearchManager_.reset();
    for (int32_t slotId = 0; slotId < SIM_COUNT; slotId++) {
        simStateManager_[slotId].reset();
        simFileManager_[slotId].reset();
        simAccountManager_[slotId].reset();
    }
    SetParameter(IS_BLOCK_LOAD_OPERATORCONFIG_SLOT0, "false");
    SetParameter(IS_BLOCK_LOAD_OPERATORCONFIG_SLOT1, "false");
    SetParameter(IS_UPDATE_OPERATORCONFIG_SLOT0, "false");
    SetParameter(IS_UPDATE_OPERATORCONFIG_SLOT1, "false");
}

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
    iccFile->filesFetchedObser_ = nullptr;
    iccFile->UnregisterImsiLoaded(handler);
    EXPECT_EQ(iccFile->filesFetchedObser_, nullptr);
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
    iccFile->filesFetchedObser_ = nullptr;
    std::shared_ptr<AppExecFwk::EventHandler> eventHandler = nullptr;
    iccFile->RegisterOpkeyLoaded(eventHandler);
    EXPECT_EQ(iccFile->filesFetchedObser_, nullptr);
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
    iccFile->filesFetchedObser_ = nullptr;
    std::shared_ptr<AppExecFwk::EventHandler> eventHandler = nullptr;
    iccFile->RegisterOperatorCacheDel(eventHandler);
    EXPECT_EQ(iccFile->filesFetchedObser_, nullptr);
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
    iccFile->filesFetchedObser_ = nullptr;
    std::string iccId = "ABCD";
    iccFile->iccId_ = iccId;
    std::shared_ptr<AppExecFwk::EventHandler> eventHandler = nullptr;
    iccFile->RegisterIccidLoaded(eventHandler);
    EXPECT_EQ(iccFile->filesFetchedObser_, nullptr);
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
    iccFile->filesFetchedObser_ = nullptr;
    iccFile->UnregisterOpkeyLoaded(eventHandler);
    iccFile->filesFetchedObser_ = nullptr;
    iccFile->UnregisterOperatorCacheDel(eventHandler);
    iccFile->filesFetchedObser_ = nullptr;
    iccFile->UnregisterIccidLoaded(eventHandler);
    EXPECT_EQ(iccFile->filesFetchedObser_, nullptr);
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

/**
 * @tc.number   Telephony_IccFile_016
 * @tc.name     test IccFile
 * @tc.desc     Function test
 */
HWTEST_F(IccFileTest, Telephony_IccFile_016, Function | MediumTest | Level1)
{
    int eventId = 1;
    int arg1 = 1;
    int arg2 = 1;
    int eventParam = 0;
    std::unique_ptr<FileToControllerMsg> object = std::make_unique<FileToControllerMsg>();
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    auto simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<IccFile> iccFile = std::make_shared<IsimFile>(simStateManager);
    iccFile->BuildCallerInfo(eventId, arg1, arg2);
    AppExecFwk::InnerEvent::Pointer event = AppExecFwk::InnerEvent::Get(eventId, object, eventParam);
    ASSERT_NE(event, nullptr);
}

/**
 * @tc.number   Telephony_IccFile_017
 * @tc.name     test IccFile
 * @tc.desc     Function test
 */
HWTEST_F(IccFileTest, Telephony_IccFile_017, Function | MediumTest | Level1)
{
    int eventId = 1;
    int eventParam = 0;
    std::shared_ptr<void> loader = nullptr;
    std::unique_ptr<FileToControllerMsg> object = std::make_unique<FileToControllerMsg>();
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    auto simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<IccFile> iccFile = std::make_shared<IsimFile>(simStateManager);
    iccFile->BuildCallerInfo(eventId, loader);
    AppExecFwk::InnerEvent::Pointer event = AppExecFwk::InnerEvent::Get(eventId, object, eventParam);
    ASSERT_NE(event, nullptr);
}

/**
 * @tc.number   Telephony_IccFile_018
 * @tc.name     test IccFile
 * @tc.desc     Function test
 */
HWTEST_F(IccFileTest, Telephony_IccFile_018, Function | MediumTest | Level1)
{
    std::string langLi = "ABC";
    std::string langPl = "001";
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    auto simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<IccFile> iccFile = std::make_shared<IsimFile>(simStateManager);
    iccFile->UpdateIccLanguage(langLi, langPl);
    EXPECT_TRUE(iccFile->iccLanguage_.empty());
}

/**
 * @tc.number   Telephony_IccFile_019
 * @tc.name     test IccFile
 * @tc.desc     Function test
 */
HWTEST_F(IccFileTest, Telephony_IccFile_019, Function | MediumTest | Level1)
{
    std::string iccId = "1";
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    auto simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<IccFile> iccFile = std::make_shared<IsimFile>(simStateManager);
    iccFile->SwapPairsForIccId(iccId);
    EXPECT_FALSE(iccId.empty());
    EXPECT_TRUE(iccId.length() < LENGTH_TWO);
}

/**
 * @tc.number   Telephony_IccFile_020
 * @tc.name     test IccFile
 * @tc.desc     Function test
 */
HWTEST_F(IccFileTest, Telephony_IccFile_020, Function | MediumTest | Level1)
{
    std::string opkey = "";
    std::string opName = "";
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    auto simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<IccFile> iccFile = std::make_shared<IsimFile>(simStateManager);
    iccFile->OnOpkeyLoad(opkey, opName);
    ASSERT_NE(iccFile->filesFetchedObser_, nullptr);
}

HWTEST_F(IccFileTest, Telephony_IccFile_021, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    auto simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<IccFile> iccFile = std::make_shared<IsimFile>(simStateManager);
    AppExecFwk::InnerEvent::Pointer event = AppExecFwk::InnerEvent::Get(StateMessage::MSG_ICC_REFRESH, 1);
    iccFile->ProcessEvent(event);
    std::shared_ptr<AppExecFwk::EventHandler> handler = nullptr;
    iccFile->RegisterCoreNotify(handler, RadioEvent::RADIO_SIM_RECORDS_LOADED);
    iccFile->UnRegisterCoreNotify(handler, RadioEvent::RADIO_SIM_RECORDS_LOADED);
    iccFile->imsi_ = "46070";
    iccFile->RegisterCoreNotify(handler, RadioEvent::RADIO_IMSI_LOADED_READY);
    iccFile->UnRegisterCoreNotify(handler, RadioEvent::RADIO_IMSI_LOADED_READY);
    std::string eons = "";
    std::string plmn = "";
    std::vector<std::shared_ptr<OperatorPlmnInfo>> oplFiles = {};
    EXPECT_TRUE(iccFile->ObtainEonsExternRules(oplFiles, false, eons, true, plmn));
    std::string plmn1 = "46001";
    EXPECT_TRUE(iccFile->ObtainEonsExternRules(oplFiles, false, eons, true, plmn1));
}

/**
 * @tc.number   Telephony_IccFile_021
 * @tc.name     test IccFile
 * @tc.desc     Function test
 */
HWTEST_F(IccFileTest, Telephony_IccFile_022, Function | MediumTest | Level1)
{
    std::string opkey = "";
    std::string opName = "";
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    auto simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<IccFile> iccFile = std::make_shared<IsimFile>(simStateManager);
    std::vector<std::shared_ptr<OperatorPlmnInfo>> oplFiles;
    auto plmnNetworkName = std::make_shared<PlmnNetworkName>();
    bool roaming = false;
    std::string eons = "";
    bool longNameRequired = true;
    std::string plmn = "";
    iccFile->pnnFiles_.push_back(plmnNetworkName);
    ASSERT_TRUE(iccFile->ObtainEonsExternRules(oplFiles, roaming, eons, longNameRequired, plmn));
    longNameRequired = false;
    ASSERT_TRUE(iccFile->ObtainEonsExternRules(oplFiles, roaming, eons, longNameRequired, plmn));

    iccFile->spnCphs_ = "not null";
    iccFile->pnnFiles_.clear();
    roaming = false;
    ASSERT_TRUE(iccFile->ObtainEonsExternRules(oplFiles, roaming, eons, longNameRequired, plmn));

    iccFile->spnCphs_ = "";
    ASSERT_TRUE(iccFile->ObtainEonsExternRules(oplFiles, roaming, eons, longNameRequired, plmn));

    auto plmnInfo = std::make_shared<OperatorPlmnInfo>();
    oplFiles.push_back(plmnInfo);
    iccFile->pnnFiles_.push_back(plmnNetworkName);
    plmn = "not null";
    ASSERT_FALSE(iccFile->ObtainEonsExternRules(oplFiles, roaming, eons, longNameRequired, plmn));
}

/**
 * @tc.number   Telephony_IccFile_022
 * @tc.name     test IccFile
 * @tc.desc     Function test
 */
HWTEST_F(IccFileTest, Telephony_IccFile_023, Function | MediumTest | Level1)
{
    std::string opkey = "";
    std::string opName = "";
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    auto simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<IccFile> iccFile = std::make_shared<IsimFile>(simStateManager);
    int32_t lac = 123;
    std::string plmn = "";
    bool longNameRequired = true;
    iccFile->isOplFileResponsed_ = true;
    iccFile->isOpl5gFileResponsed_ = true;
    iccFile->isOpl5gFilesPresent_ = true;
    iccFile->ObtainEons(plmn, lac, longNameRequired);
    EXPECT_NE(iccFile, nullptr);
}

/**
 * @tc.number   Telephony_IccFile_024
 * @tc.name     test IccFile
 * @tc.desc     Function test
 */
HWTEST_F(IccFileTest, Telephony_IccFile_024, Function | MediumTest | Level1)
{
    InitCoreService();
    simFile_->iccId_ = "86890000000000000001";
    simFile_->imsi_ = "460990123456789";
    simFile_->mcc_ = "460";
    simFile_->mnc_ = "99";
    simFile_->isOnOpkeyLoaded_ = false;
    simFile_->isSimRecordLoaded_ = false;
    SetParameter(PREVIOUS_VERSION, " ");
    multiSimMonitor_->CheckOpcNeedUpdata(true);
    AppExecFwk::InnerEvent::Pointer event = AppExecFwk::InnerEvent::Get(MultiSimMonitor::RESET_OPKEY_CONFIG, 0);
    multiSimMonitor_->ProcessEvent(event);
    simFileManager_[0]->UpdateOpkeyConfig();
    event = AppExecFwk::InnerEvent::Get(RadioEvent::RADIO_OPERATOR_CONFIG_UPDATE, 0);
    simStateTracker_->ProcessEvent(event);
    simStateTracker_->ProcessOperatorConfigUpdate(event);
    char isBlockLoadOperatorConfig[SYSPARA_SIZE] = { 0 };
    GetParameter(IS_BLOCK_LOAD_OPERATORCONFIG_SLOT0, "false", isBlockLoadOperatorConfig, SYSPARA_SIZE);
    ASSERT_TRUE(strcmp(isBlockLoadOperatorConfig, "false") == 0);
    event = AppExecFwk::InnerEvent::Get(MultiSimMonitor::RESET_OPKEY_CONFIG, 0);
    multiSimMonitor_->ProcessEvent(event);
    simFile_->isSimRecordLoaded_ = true;
    simFile_->UpdateOpkeyConfig();
    simFile_->filesFetchedObser_ = nullptr;
    simFile_->UpdateOpkeyConfig();
    ResetCoreService();
}
 
/**
 * @tc.number   Telephony_IccFile_025
 * @tc.name     test IccFile
 * @tc.desc     Function test
 */
HWTEST_F(IccFileTest, Telephony_IccFile_025, Function | MediumTest | Level1)
{
    InitCoreService();
    AppExecFwk::InnerEvent::Pointer event = AppExecFwk::InnerEvent::Get(RadioEvent::RADIO_SIM_RECORDS_LOADED, 1);
    simStateTracker_->ProcessEvent(event);
    event = AppExecFwk::InnerEvent::Get(RadioEvent::RADIO_SIM_RECORDS_LOADED, 0);
    SetParameter(IS_BLOCK_LOAD_OPERATORCONFIG_SLOT0, "true");
    simStateTracker_->ProcessEvent(event);
    SetParameter(IS_BLOCK_LOAD_OPERATORCONFIG_SLOT0, "false");
    SetParameter(IS_UPDATE_OPERATORCONFIG_SLOT0, "true");
    simStateTracker_->ProcessEvent(event);
    char isNeedUpdateCarrierConfig[SYSPARA_SIZE] = { 0 };
    GetParameter(IS_UPDATE_OPERATORCONFIG_SLOT0, "", isNeedUpdateCarrierConfig, SYSPARA_SIZE);
    ASSERT_TRUE(strcmp(isNeedUpdateCarrierConfig, "false") == 0);
    simStateTracker_->ProcessEvent(event);
    simStateTracker_->operatorConfigLoader_ = nullptr;
    simStateTracker_->ProcessEvent(event);
    ResetCoreService();
}

/**
 * @tc.number   Telephony_IccFile_026
 * @tc.name     test IccFile
 * @tc.desc     Function test
 */
HWTEST_F(IccFileTest, Telephony_IccFile_026, Function | MediumTest | Level1)
{
    InitCoreService();
    std::vector<std::string> msg(2, "");
    auto objMsg = std::make_shared<std::vector<std::string>>(msg);
    AppExecFwk::InnerEvent::Pointer event = AppExecFwk::InnerEvent::Get(RadioEvent::RADIO_SIM_OPKEY_LOADED, objMsg);
    simStateTracker_->ProcessEvent(event);
    std::vector<std::string> vMsg(3, "");
    vMsg[0] = "slot";
    vMsg[1] = "46099";
    vMsg[2] = "TEST";
    auto obj = std::make_shared<std::vector<std::string>>(vMsg);
    event = AppExecFwk::InnerEvent::Get(RadioEvent::RADIO_SIM_OPKEY_LOADED, obj);
    simStateTracker_->ProcessEvent(event);
    vMsg[0] = std::to_string(1);
    obj = std::make_shared<std::vector<std::string>>(vMsg);
    event = AppExecFwk::InnerEvent::Get(RadioEvent::RADIO_SIM_OPKEY_LOADED, obj);
    simStateTracker_->ProcessEvent(event);
    vMsg[0] = std::to_string(0);
    obj = std::make_shared<std::vector<std::string>>(vMsg);
    event = AppExecFwk::InnerEvent::Get(RadioEvent::RADIO_SIM_OPKEY_LOADED, obj);
    SetParameter(IS_BLOCK_LOAD_OPERATORCONFIG_SLOT0, "true");
    simStateTracker_->ProcessEvent(event);
    SetParameter(IS_BLOCK_LOAD_OPERATORCONFIG_SLOT0, "false");
    SetParameter(IS_UPDATE_OPERATORCONFIG_SLOT0, "false");
    simStateTracker_->ProcessEvent(event);
    SetParameter(IS_UPDATE_OPERATORCONFIG_SLOT0, "true");
    simStateTracker_->ProcessEvent(event);
    char isNeedUpdateCarrierConfig[SYSPARA_SIZE] = { 0 };
    GetParameter(IS_UPDATE_OPERATORCONFIG_SLOT0, "", isNeedUpdateCarrierConfig, SYSPARA_SIZE);
    ASSERT_TRUE(strcmp(isNeedUpdateCarrierConfig, "false") == 0);
    simStateTracker_->operatorConfigCache_ = nullptr;
    simStateTracker_->ProcessEvent(event);
    vMsg[1] = "";
    vMsg[2] = "";
    obj = std::make_shared<std::vector<std::string>>(vMsg);
    event = AppExecFwk::InnerEvent::Get(RadioEvent::RADIO_SIM_OPKEY_LOADED, obj);
    SetParameter(IS_UPDATE_OPERATORCONFIG_SLOT0, "false");
    simStateTracker_->ProcessEvent(event);
    SetParameter(IS_UPDATE_OPERATORCONFIG_SLOT0, "true");
    simStateTracker_->ProcessEvent(event);
    simStateTracker_->operatorConfigLoader_ = nullptr;
    simStateTracker_->ProcessEvent(event);
    simStateHandle_->iccState_.simStatus_ = ICC_CARD_ABSENT;
    simStateTracker_->ProcessEvent(event);
    ResetCoreService();
}

/**
 * @tc.number   Telephony_IccFile_027
 * @tc.name     test IccFile
 * @tc.desc     Function test
 */
HWTEST_F(IccFileTest, Telephony_IccFile_027, Function | MediumTest | Level1)
{
    InitCoreService();
    AppExecFwk::InnerEvent::Pointer event = AppExecFwk::InnerEvent::Get(RadioEvent::RADIO_OPERATOR_CACHE_DELETE, 1);
    simStateTracker_->ProcessEvent(event);
    simFileManager_[0]->SetOpKey("46099");
    event = AppExecFwk::InnerEvent::Get(RadioEvent::RADIO_IMSI_LOADED_READY, 0);
    simStateTracker_->ProcessEvent(event);
    event = AppExecFwk::InnerEvent::Get(RadioEvent::RADIO_OPERATOR_CACHE_DELETE, 0);
    simStateTracker_->ProcessEvent(event);
    simStateTracker_->operatorConfigCache_ = nullptr;
    simStateTracker_->ProcessEvent(event);
    EXPECT_NE(simFileManager_[0]->GetOpKey(), Str8ToStr16("46099"));
    ResetCoreService();
}

/**
 * @tc.number   Telephony_IccFile_028
 * @tc.name     test IccFile
 * @tc.desc     Function test
 */
HWTEST_F(IccFileTest, Telephony_IccFile_028, Function | MediumTest | Level1)
{
    InitCoreService();
    AppExecFwk::InnerEvent::Pointer event = AppExecFwk::InnerEvent::Get(RadioEvent::RADIO_OPERATOR_CONFIG_UPDATE, 1);
    simStateTracker_->ProcessEvent(event);
    event = AppExecFwk::InnerEvent::Get(RadioEvent::RADIO_OPERATOR_CONFIG_UPDATE, 0);
    SetParameter(IS_BLOCK_LOAD_OPERATORCONFIG_SLOT0, "true");
    simStateTracker_->ProcessEvent(event);
    char isBlockLoadOperatorConfig[SYSPARA_SIZE] = { 0 };
    GetParameter(IS_BLOCK_LOAD_OPERATORCONFIG_SLOT0, "false", isBlockLoadOperatorConfig, SYSPARA_SIZE);
    ASSERT_TRUE(strcmp(isBlockLoadOperatorConfig, "false") == 0);
    simStateTracker_->operatorConfigCache_ = nullptr;
    simStateTracker_->ProcessEvent(event);
    ResetCoreService();
}

/**
 * @tc.number   Telephony_IccFile_029
 * @tc.name     test IccFile
 * @tc.desc     Function test
 */
HWTEST_F(IccFileTest, Telephony_IccFile_029, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    auto simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<IccFile> iccFile = std::make_shared<IsimFile>(simStateManager);
    bool ret = iccFile->ObtainFilesFetched();
    EXPECT_FALSE(ret);
}

/**
 * @tc.number   Telephony_IccFile_030
 * @tc.name     test IccFile
 * @tc.desc     Function test
 */
HWTEST_F(IccFileTest, Telephony_IccFile_030, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    auto simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<IccFile> iccFile = std::make_shared<IsimFile>(simStateManager);
    iccFile->SetId(0);
    iccFile->SetId(0);
    EXPECT_NE(iccFile->voiceMailConfig_, nullptr);
}
}
}