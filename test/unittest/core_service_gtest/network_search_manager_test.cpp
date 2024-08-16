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

#include "network_search_manager_test.h"

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
#include "ims_reg_info_callback_stub.h"

namespace OHOS {
namespace Telephony {
using namespace testing::ext;

namespace {
const int32_t SLOT_ID_0 = 0;
constexpr int32_t LTE_RSSI_GOOD = -80;
constexpr int32_t SLEEP_TIME_SECONDS = 3;
} // namespace

class NetworkSearchBranchTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void NetworkSearchBranchTest::TearDownTestCase()
{
    sleep(SLEEP_TIME_SECONDS);
}

void NetworkSearchBranchTest::SetUp() {}

void NetworkSearchBranchTest::TearDown() {}

void NetworkSearchBranchTest::SetUpTestCase()
{
    constexpr int permissionNum = 2;
    const char *perms[permissionNum] = {"ohos.permission.GET_TELEPHONY_STATE",
        "ohos.permission.SET_TELEPHONY_STATE"};
    NativeTokenInfoParams infoInstance = {.dcapsNum = 0, .permsNum = permissionNum, .aclsNum = 0, .dcaps = nullptr,
        .perms = perms, .acls = nullptr, .processName = "NetworkSearchBranchTest", .aplStr = "system_basic",
    };
    uint64_t tokenId = GetAccessTokenId(&infoInstance);
    SetSelfTokenID(tokenId);
    auto result = Security::AccessToken::AccessTokenKit::ReloadNativeTokenInfo();
    EXPECT_EQ(result, Security::AccessToken::RET_SUCCESS);
}

class ImsRegInfoCallbackTest : public ImsRegInfoCallbackStub {
public:
    int32_t OnImsRegInfoChanged(int32_t slotId, ImsServiceType imsSrvType, const ImsRegInfo &info) override;
};

int32_t ImsRegInfoCallbackTest::OnImsRegInfoChanged(int32_t slotId, ImsServiceType imsSrvType, const ImsRegInfo &info)
{
    TELEPHONY_LOGI("slotId: %{public}d, imsSrvType: %{public}d, ImsRegState: %{public}d, ImsRegTech: %{public}d",
        slotId, imsSrvType, info.imsRegState, info.imsRegTech);
    return TELEPHONY_SUCCESS;
}

/**
 * @tc.number   Telephony_NetworkSearchManager2_001
 * @tc.name     test branch
 * @tc.desc     Function test
 */
HWTEST_F(NetworkSearchBranchTest, Telephony_NetworkSearchManager2_001, Function | MediumTest | Level1)
{
    AccessToken token;
    auto telRilManager = std::make_shared<TelRilManager>();
    EXPECT_TRUE(telRilManager->OnInit());
    CoreManagerInner::GetInstance().SetTelRilMangerObj(telRilManager);
    auto &client = CoreServiceClient::GetInstance();
    auto slotCount = client.GetMaxSimCount();
    std::shared_ptr<SimManager> simManager = std::make_shared<SimManager>(telRilManager);
    EXPECT_TRUE(simManager->OnInit(slotCount));
    auto networkSearchManager = std::make_shared<NetworkSearchManager>(telRilManager, simManager);
    EXPECT_TRUE(networkSearchManager->OnInit());

    std::shared_ptr<NetworkSearchManagerInner> inner = std::make_shared<NetworkSearchManagerInner>();
    EXPECT_TRUE(networkSearchManager->InitPointer(inner, SLOT_ID_0));
    networkSearchManager->RegisterCellularDataObject(nullptr);
    networkSearchManager->RegisterCellularCallObject(nullptr);
    networkSearchManager->UnRegisterCellularCallObject(nullptr);
    networkSearchManager->SavePreferredNetworkValue(SLOT_ID_0,
        static_cast<int32_t>(PreferredNetworkMode::CORE_NETWORK_MODE_NR_LTE_TDSCDMA_WCDMA_GSM_EVDO_CDMA));
    EXPECT_EQ(networkSearchManager->UpdateRadioOn(SLOT_ID_0), TELEPHONY_ERR_LOCAL_PTR_NULL);

    Rssi signalIntensity;
    signalIntensity.lte.rsrp = LTE_RSSI_GOOD;
    EXPECT_EQ(networkSearchManager->ProcessSignalIntensity(SLOT_ID_0, signalIntensity), TELEPHONY_ERR_SUCCESS);

    sptr<ImsRegInfoCallback> callback = new ImsRegInfoCallbackTest;
    int32_t tokenId = 0;
    EXPECT_EQ(networkSearchManager->RegisterImsRegInfoCallback(
        SLOT_ID_0, ImsServiceType::TYPE_SMS, tokenId, callback), TELEPHONY_SUCCESS);
    EXPECT_EQ(networkSearchManager->UnregisterImsRegInfoCallback(
        SLOT_ID_0, ImsServiceType::TYPE_SMS, tokenId), TELEPHONY_SUCCESS);
    EXPECT_EQ(networkSearchManager->StartRadioOnState(SLOT_ID_0), TELEPHONY_SUCCESS);
    EXPECT_EQ(networkSearchManager->StartGetRilSignalIntensity(SLOT_ID_0), TELEPHONY_SUCCESS);
    bool isGsm = false;
    EXPECT_EQ(networkSearchManager->IsGsm(SLOT_ID_0, isGsm), TELEPHONY_SUCCESS);
    EXPECT_EQ(networkSearchManager->IsCdma(SLOT_ID_0, isGsm), TELEPHONY_SUCCESS);
}
} // namespace Telephony
} // namespace OHOS
