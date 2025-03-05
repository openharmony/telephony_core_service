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

namespace OHOS {
namespace Telephony {
using namespace testing::ext;

class SimUtilsTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

namespace {
static const int32_t SLEEP_TIME = 3;
} // namespace

void SimUtilsTest::TearDownTestCase()
{
    sleep(SLEEP_TIME);
}

void SimUtilsTest::SetUp() {}

void SimUtilsTest::TearDown() {}

void SimUtilsTest::SetUpTestCase()
{
    constexpr int permissionNum = 2;
    const char *perms[permissionNum] = {"ohos.permission.GET_TELEPHONY_STATE",
        "ohos.permission.SET_TELEPHONY_STATE"};
    NativeTokenInfoParams infoInstance = {.dcapsNum = 0, .permsNum = permissionNum, .aclsNum = 0, .dcaps = nullptr,
        .perms = perms, .acls = nullptr, .processName = "SimUtilsTest", .aplStr = "system_basic",
    };
    uint64_t tokenId = GetAccessTokenId(&infoInstance);
    SetSelfTokenID(tokenId);
    auto result = Security::AccessToken::AccessTokenKit::ReloadNativeTokenInfo();
    EXPECT_EQ(result, Security::AccessToken::RET_SUCCESS);
}

/**
 * @tc.number   Telephony_IsShowableAscii_001
 * @tc.name     test error branch
 * @tc.desc     Function test
 */
HWTEST_F(SimUtilsTest, Telephony_IsShowableAscii_001, Function | MediumTest | Level1)
{
    auto simUtils = std::make_shared<SIMUtils>();
    char c = ' ';
    bool result = simUtils->IsShowableAscii(c);
    EXPECT_TRUE(result);
}

/**
 * @tc.number   Telephony_IsShowableAsciiOnly_001
 * @tc.name     test error branch
 * @tc.desc     Function test
 */
HWTEST_F(SimUtilsTest, Telephony_IsShowableAsciiOnly_001, Function | MediumTest | Level1)
{
    auto simUtils = std::make_shared<SIMUtils>();
    std::string str1 = "HelloWorld";
    bool result1 = simUtils->IsShowableAsciiOnly(str1);
    EXPECT_TRUE(result1);
    std::string str2 = "HelloWorld123!";
    bool result2 = simUtils->IsShowableAsciiOnly(str2);
    EXPECT_TRUE(result2);
}

/**
 * @tc.number   Telephony_CharsConvertToChar16_001
 * @tc.name     test error branch
 * @tc.desc     Function test
 */
HWTEST_F(SimUtilsTest, Telephony_CharsConvertToChar16_001, Function | MediumTest | Level1)
{
    auto simUtils = std::make_shared<SIMUtils>();
    int outLen = 0;
    std::shared_ptr<char16_t> result = simUtils->CharsConvertToChar16(nullptr, 0, outLen, false);
    EXPECT_EQ(result, nullptr);
    unsigned char input[] = {0x01, 0x02, 0x03, 0x04};
    result = simUtils->CharsConvertToChar16(input, 4, outLen, false);
    EXPECT_EQ(outLen, 2);
}

/**
 * @tc.number   Telephony_UcsConvertToString_001
 * @tc.name     test error branch
 * @tc.desc     Function test
 */
HWTEST_F(SimUtilsTest, Telephony_UcsConvertToString_001, Function | MediumTest | Level1)
{
    auto simUtils = std::make_shared<SIMUtils>();
    std::u16string result = simUtils->UcsConvertToString(nullptr, 0, 0);
    EXPECT_TRUE(result.empty());
    unsigned char data[] = {0x00, 0x01, 0x00, 0x61, 0x00, 0x62, 0x00, 0x63};
    result = simUtils->UcsConvertToString(data, 10, 2);
    EXPECT_EQ(result, u"b");
}

/**
 * @tc.number   Telephony_UcsWideConvertToString_001
 * @tc.name     test error branch
 * @tc.desc     Function test
 */
HWTEST_F(SimUtilsTest, Telephony_UcsWideConvertToString_001, Function | MediumTest | Level1)
{
    auto simUtils = std::make_shared<SIMUtils>();
    std::u16string result = simUtils->UcsWideConvertToString(nullptr, 0, 0);
    EXPECT_TRUE(result.empty());
    unsigned char data[] = {0x00, 0x01, 0x00, 0x61};
    result = simUtils->UcsWideConvertToString(data, 4, 2);
    EXPECT_EQ(result, u"");
}

} // namespace Telephony
} // namespace OHOS