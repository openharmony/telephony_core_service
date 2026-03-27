/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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
#include <gmock/gmock.h>
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
#include "sim_file_init.h"
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
#include "telephony_ext_wrapper.h"
#include "sim_file_parse.h"
#include "network_utils.h"
#include "mock_sim_manager.h"
#include "mock_multi_sim_controller.h"
#include "network_search_test_callback_stub.h"

namespace OHOS {
namespace Telephony {
using namespace testing::ext;

class BranchTest2 : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void BranchTest2::TearDownTestCase()
{
}

void BranchTest2::SetUp() {}

void BranchTest2::TearDown() {}

void BranchTest2::SetUpTestCase()
{
}

class IOperatorConfigHisyseventImpl : public IOperatorConfigHisysevent {
public:
    IOperatorConfigHisyseventImpl() = default;
    ~IOperatorConfigHisyseventImpl() = default;
    void InitOperatorConfigHisysevent(int32_t slotId, int32_t simState) override
    {
    }
    void SetMatchSimResult(int32_t slotId, const char* opkey, const char* opname, int32_t matchSimState) override
    {
    }
    void SetMatchSimFile(int32_t slotId, MatchSimFileType simFileType, const std::string &simFile) override
    {
    }
    void SetMatchSimReason(int32_t slotId, MatchSimReason matchSimReason) override
    {
    }
    void SetMatchSimStateTracker(MatchSimState matchSimStateTracker, int32_t slotId = -1) override
    {
    }
    void SetMatchSimStateTracker(int8_t matchSimStateTracker, int32_t slotId) override
    {
    }
    void ReportMatchSimChr(int32_t slotId) override
    {
    }
};

class IIccFileExtImpl : public IIccFileExt {
public:
    IIccFileExtImpl() = default;
    ~IIccFileExtImpl() = default;
    void SetIccFile(std::shared_ptr<OHOS::Telephony::IIccFileExt> &iccFile) override
    {
    }
};

HWTEST_F(BranchTest2, Telephony_IccFile_Expand001, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    auto simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<IccFile> iccFile = std::make_shared<IsimFile>(simStateManager);
    AppExecFwk::InnerEvent::Pointer event = AppExecFwk::InnerEvent::Get(StateMessage::MSG_ICC_REFRESH, 1);

    iccFile->IccFile::StartLoad();

    iccFile->SetVoiceMailByOperator("");
    iccFile->voiceMailConfig_ = std::make_shared<VoiceMailConstants>(0);
    iccFile->SetId(0);

    iccFile->GetIsVoiceMailFixed();

    iccFile->SetVoiceMailByOperator("123");

    iccFile->ObtainGid2();
    iccFile->ObtainSimOperator();
    iccFile->IccFile::ObtainIsoCountryCode();
    iccFile->ObtainCallForwardStatus();
    iccFile->UpdateMsisdnNumber("", "");
    iccFile->ObtainDiallingNumberInfo();
    iccFile->ObtainNAI();
    iccFile->ObtainHomeNameOfPnn();
    iccFile->ObtainMsisdnAlphaStatus();
    iccFile->ObtainVoiceMailCount();
    iccFile->ObtainSPN();

    std::vector<std::shared_ptr<OperatorPlmnInfo>> oplFiles;
    std::string eons;
    auto plmnNetworkName = std::make_shared<PlmnNetworkName>();
    iccFile->pnnFiles_.push_back(plmnNetworkName);
    iccFile->ObtainEonsExternRules(oplFiles, false, eons, true, "");
    iccFile->ObtainEonsExternRules(oplFiles, false, eons, false, "");
    iccFile->pnnFiles_.clear();
    iccFile->spnCphs_ = "123";
    iccFile->ObtainEonsExternRules(oplFiles, false, eons, false, "");
    iccFile->spnCphs_ = "";
    iccFile->spnShortCphs_ = "123";
    iccFile->ObtainEonsExternRules(oplFiles, false, eons, false, "");
    iccFile->ObtainEonsExternRules(oplFiles, true, eons, false, "");
    iccFile->pnnFiles_.push_back(plmnNetworkName);
    auto opl = std::make_shared<OperatorPlmnInfo>();
    oplFiles.push_back(opl);
    EXPECT_FALSE(iccFile->ObtainEonsExternRules(oplFiles, true, eons, false, "123") == true);
}

HWTEST_F(BranchTest2, Telephony_IccFile_Expand002, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    auto simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<IccFile> iccFile = std::make_shared<IsimFile>(simStateManager);
    AppExecFwk::InnerEvent::Pointer event = AppExecFwk::InnerEvent::Get(StateMessage::MSG_ICC_REFRESH, 1);
    auto plmnNetworkName = std::make_shared<PlmnNetworkName>();
    iccFile->pnnFiles_.push_back(plmnNetworkName);
    iccFile->isOplFileResponsed_ = true;
    iccFile->isOpl5gFileResponsed_ = true;
    iccFile->oplFiles_.clear();
    iccFile->opl5gFiles_.clear();
    iccFile->operatorNumeric_ = "";
    iccFile->ObtainEons("", 0, true);

    iccFile->operatorNumeric_ = "123";
    auto opl = std::make_shared<OperatorPlmnInfo>();
    iccFile->oplFiles_.push_back(nullptr);
    iccFile->oplFiles_.push_back(opl);
    opl->lacStart = 0;
    opl->lacEnd = 0xfffe;
    iccFile->ObtainEons("123", 0, true);

    iccFile->ObtainVoiceMailInfo();
    iccFile->ObtainIccLanguage();
    iccFile->ObtainUsimFunctionHandle();
    iccFile->ObtainSpNameFromEfSpn();
    iccFile->ObtainLengthOfMnc();

    iccFile->voiceMailConfig_ = std::make_shared<VoiceMailConstants>(0);
    iccFile->LoadVoiceMail();
    std::shared_ptr<AppExecFwk::EventHandler> handler = nullptr;
    iccFile->imsi_ = "123";
    iccFile->RegisterImsiLoaded(handler);
    iccFile->iccId_ = "123";
    iccFile->RegisterIccidLoaded(handler);
    iccFile->UnregisterIccidLoaded(handler);
    iccFile->BuildCallerInfo(0, 0, 0);
    iccFile->BuildCallerInfo(0, nullptr);
    std::shared_ptr<ControllerToFileMsg> fd = std::make_shared<ControllerToFileMsg>(nullptr, nullptr);
    fd->iccLoader = nullptr;
    AppExecFwk::InnerEvent::Pointer testEvent2 = InnerEvent::Get(0, fd);
    iccFile->ProcessIccFileObtained(testEvent2);
    iccFile->iccLanguage_ = "123";
    iccFile->UpdateIccLanguage("", "");
    std::string iccId = "";
    iccFile->SwapPairsForIccId(iccId);
    iccFile->GetFullIccid(iccId);
    EXPECT_TRUE(iccFile->CreateDiallingNumberPointer(0, 0, 0, nullptr) != nullptr);
}

HWTEST_F(BranchTest2, Telephony_IccFile_Expand003, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    auto simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<IccFile> iccFile = std::make_shared<IsimFile>(simStateManager);
    AppExecFwk::InnerEvent::Pointer event = AppExecFwk::InnerEvent::Get(StateMessage::MSG_ICC_REFRESH, 1);

    std::shared_ptr<IccFileController> file = std::make_shared<SimFileController>(0);
    iccFile->SetRilAndFileController(nullptr, nullptr, nullptr);
    iccFile->SetRilAndFileController(telRilManager, file, nullptr);

    iccFile->stateManager_.reset();
    iccFile->HasSimCard();
    iccFile->stateManager_ = simStateManager;
    iccFile->HasSimCard();

    iccFile->SaveCountryCode();
    iccFile->ProcessExtGetFileResponse();

    iccFile->ProcessExtGetFileDone(event);
    iccFile->OnOpkeyLoad("123", "123");
    iccFile->ExecutOriginalSimIoRequest(0, 0);

    iccFile->recordsOverrideObser_.reset();
    iccFile->AddRecordsOverrideObser();
    iccFile->AddRecordsToLoadNum();
    iccFile->DeleteOperatorCache();

    iccFile->RegisterParamsListener();
    iccFile->UnRegisterParamsListener();

    iccFile->isOnOpkeyLoaded_ = true;
    iccFile->UpdateOpkeyConfig();
    iccFile->isOnOpkeyLoaded_ = false;
    iccFile->UpdateOpkeyConfig();
    iccFile->filesFetchedObser_.reset();
    iccFile->UpdateOpkeyConfig();
    EXPECT_TRUE(iccFile->isOnOpkeyLoaded_ == false);
}

HWTEST_F(BranchTest2, Telephony_IccFile_Expand004, Function | MediumTest | Level1)
{
    std::shared_ptr<TelRilManager> telRilManager = std::make_shared<TelRilManager>();
    auto simStateManager = std::make_shared<SimStateManager>(telRilManager);
    std::shared_ptr<IccFile> iccFile = std::make_shared<IsimFile>(simStateManager);
    AppExecFwk::InnerEvent::Pointer event = AppExecFwk::InnerEvent::Get(StateMessage::MSG_ICC_REFRESH, 1);

    IIccFileExt::FileChangeType fileChangeType = IIccFileExt::FileChangeType::INVALID_FILE_OPE;
    auto ioperatorConfigHisyseventImpl = std::make_shared<IOperatorConfigHisyseventImpl>();
    iccFile->operatorConfigHisysevent_ = ioperatorConfigHisyseventImpl;
    iccFile->ProcessIccFileObtained(event);

    std::shared_ptr<IIccFileExt> iiccFileExt = std::make_shared<IIccFileExtImpl>();
    iccFile->IccFile::SetIccFile(iiccFileExt);

    iccFile->SetMatchSimStateTracker(0);

    TELEPHONY_EXT_WRAPPER.InitTelephonyExtWrapper();
    iccFile->ResetVoiceMailVariable();
    iccFile->FileChangeToExt("", fileChangeType);
    TELEPHONY_EXT_WRAPPER.DeInitTelephonyExtWrapper();
    EXPECT_TRUE(iccFile->operatorConfigHisysevent_.lock() != nullptr);
}
} // namespace Telephony
} // namespace OHOS
