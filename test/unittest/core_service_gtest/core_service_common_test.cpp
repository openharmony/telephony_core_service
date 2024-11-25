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
#include <gtest/gtest.h>
#include <string_ex.h>

#include "hks_api.h"
#include "tel_aes_crypto_util.h"
#include "common_event_manager.h"
#include "common_event_support.h"
#include "core_service.h"
#include "core_service_client.h"
#include "core_service_dump_helper.h"
#include "core_service_hisysevent.h"
#include "enum_convert.h"
#include "network_search_manager.h"
#include "operator_name.h"
#include "operator_name_utils.h"
#include "security_token.h"
#include "sim_manager.h"
#include "tel_ril_manager.h"
#include "telephony_config.h"
#include "telephony_log_wrapper.h"


namespace OHOS {
namespace Telephony {
using namespace testing::ext;
constexpr int32_t NR_NSA_OPTION_ONLY = 1;
static const int32_t SLEEP_TIME = 3;
static const uint32_t MODEM_CAP_MIN_VALUE = 0;
static const uint32_t MODEM_CAP_MAX_VALUE = 32;
class CoreServiceCommonTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};
void CoreServiceCommonTest::SetUpTestCase() {}

void CoreServiceCommonTest::TearDownTestCase()
{
    sleep(SLEEP_TIME);
}

void CoreServiceCommonTest::SetUp() {}

void CoreServiceCommonTest::TearDown() {}

/**
 * @tc.number   CoreService_SetNrOptionMode_001
 * @tc.name     test normal branch
 * @tc.desc     Function test
 */
HWTEST_F(CoreServiceCommonTest, CoreService_SetNrOptionMode_001, Function | MediumTest | Level1)
{
    int32_t mode = NR_NSA_OPTION_ONLY;
    auto result = DelayedSingleton<CoreService>::GetInstance()->SetNrOptionMode(0, mode, nullptr);
    ASSERT_EQ(result, TELEPHONY_ERR_PERMISSION_ERR);
}

/**
 * @tc.number   CoreService_SetNrOptionMode_002
 * @tc.name     test normal branch
 * @tc.desc     Function test
 */
HWTEST_F(CoreServiceCommonTest, CoreService_SetNrOptionMode_002, Function | MediumTest | Level1)
{
    SecurityToken token;
    int32_t mode = NR_NSA_OPTION_ONLY;
    DelayedSingleton<CoreService>::GetInstance()->networkSearchManager_ = nullptr;
    auto result = DelayedSingleton<CoreService>::GetInstance()->SetNrOptionMode(0, mode, nullptr);
    ASSERT_EQ(result, TELEPHONY_ERR_LOCAL_PTR_NULL);
}

/**
 * @tc.number   CoreService_GetCellInfoList_001
 * @tc.name     test normal branch
 * @tc.desc     Function test
 */
HWTEST_F(CoreServiceCommonTest, CoreService_GetCellInfoList_001, Function | MediumTest | Level1)
{
    SecurityToken token;
    DelayedSingleton<CoreService>::GetInstance()->networkSearchManager_ = nullptr;
    std::vector<sptr<CellInformation>> cellInfo;
    auto result = DelayedSingleton<CoreService>::GetInstance()->GetCellInfoList(0, cellInfo);
    ASSERT_EQ(result, TELEPHONY_ERR_LOCAL_PTR_NULL);
}

/**
 * @tc.number   CoreService_GetNrSsbIdInfo_001
 * @tc.name     test normal branch
 * @tc.desc     Function test
 */
HWTEST_F(CoreServiceCommonTest, CoreService_GetNrSsbIdInfo_001, Function | MediumTest | Level1)
{
    std::shared_ptr<NrSsbInformation> nrSsbInformation;
    auto result = DelayedSingleton<CoreService>::GetInstance()->GetNrSsbIdInfo(0, nrSsbInformation);
    ASSERT_EQ(result, TELEPHONY_ERR_PERMISSION_ERR);
}

/**
 * @tc.number   CoreService_GetNrSsbIdInfo_002
 * @tc.name     test normal branch
 * @tc.desc     Function test
 */
HWTEST_F(CoreServiceCommonTest, CoreService_GetNrSsbIdInfo_002, Function | MediumTest | Level1)
{
    SecurityToken token;
    DelayedSingleton<CoreService>::GetInstance()->networkSearchManager_ = nullptr;
    std::shared_ptr<NrSsbInformation> nrSsbInformation;
    auto result = DelayedSingleton<CoreService>::GetInstance()->GetNrSsbIdInfo(0, nrSsbInformation);
    ASSERT_EQ(result, TELEPHONY_ERR_LOCAL_PTR_NULL);
}

/**
 * @tc.number   CoreService_GetNrSsbIdInfo_003
 * @tc.name     test normal branch
 * @tc.desc     Function test
 */
HWTEST_F(CoreServiceCommonTest, CoreService_GetNrSsbIdInfo_003, Function | MediumTest | Level1)
{
    SecurityToken token;
    std::shared_ptr<NrSsbInformation> nrSsbInformation;
    auto result = DelayedSingleton<CoreService>::GetInstance()->GetNrSsbIdInfo(0, nrSsbInformation);
    ASSERT_EQ(result, TELEPHONY_ERR_LOCAL_PTR_NULL);
}

/**
 * @tc.number   CoreService_IsAllowedInsertApn_001
 * @tc.name     test normal branch
 * @tc.desc     Function test
 */
HWTEST_F(CoreServiceCommonTest, CoreService_IsAllowedInsertApn_001, Function | MediumTest | Level1)
{
    SecurityToken token;
    std::string value = "";
    auto result = DelayedSingleton<CoreService>::GetInstance()->IsAllowedInsertApn(value);
    ASSERT_EQ(result, true);
}

/**
 * @tc.number   CoreService_GetTargetOpkey_001
 * @tc.name     test normal branch
 * @tc.desc     Function test
 */
HWTEST_F(CoreServiceCommonTest, CoreService_GetTargetOpkey_001, Function | MediumTest | Level1)
{
    SecurityToken token;
    std::u16string value = u"";
    auto result = DelayedSingleton<CoreService>::GetInstance()->GetTargetOpkey(0, value);
    ASSERT_EQ(result, TELEPHONY_ERR_SUCCESS);
}

/**
 * @tc.number   CoreService_GetOpkeyVersion_001
 * @tc.name     test normal branch
 * @tc.desc     Function test
 */
HWTEST_F(CoreServiceCommonTest, CoreService_GetOpkeyVersion_001, Function | MediumTest | Level1)
{
    SecurityToken token;
    std::string versionInfo = "";
    auto result = DelayedSingleton<CoreService>::GetInstance()->GetOpkeyVersion(versionInfo);
    ASSERT_EQ(result, TELEPHONY_ERR_LOCAL_PTR_NULL);
}

/**
 * @tc.number   CoreService_GetSimIO_001
 * @tc.name     test normal branch
 * @tc.desc     Function test
 */
HWTEST_F(CoreServiceCommonTest, CoreService_GetSimIO_001, Function | MediumTest | Level1)
{
    int32_t command = 0;
    int32_t fileId = 0;
    std::string data = "";
    std::string path = "";
    SimAuthenticationResponse response;
    auto result = DelayedSingleton<CoreService>::GetInstance()->GetSimIO(0, command, fileId, data, path, response);
    ASSERT_EQ(result, TELEPHONY_ERR_PERMISSION_ERR);
}

/**
 * @tc.number   CoreService_GetSimIO_002
 * @tc.name     test normal branch
 * @tc.desc     Function test
 */
HWTEST_F(CoreServiceCommonTest, CoreService_GetSimIO_002, Function | MediumTest | Level1)
{
    SecurityToken token;
    int32_t command = 0;
    int32_t fileId = 0;
    std::string data = "";
    std::string path = "";
    SimAuthenticationResponse response;
    DelayedSingleton<CoreService>::GetInstance()->simManager_ = nullptr;
    auto result = DelayedSingleton<CoreService>::GetInstance()->GetSimIO(0, command, fileId, data, path, response);
    ASSERT_EQ(result, TELEPHONY_ERR_LOCAL_PTR_NULL);
}

/**
 * @tc.number   CoreService_GetSimIO_003
 * @tc.name     test normal branch
 * @tc.desc     Function test
 */
HWTEST_F(CoreServiceCommonTest, CoreService_GetSimIO_003, Function | MediumTest | Level1)
{
    SecurityToken token;
    int32_t command = 0;
    int32_t fileId = 0;
    std::string data = "";
    std::string path = "";
    SimAuthenticationResponse response;
    auto result = DelayedSingleton<CoreService>::GetInstance()->GetSimIO(0, command, fileId, data, path, response);
    ASSERT_EQ(result, TELEPHONY_ERR_LOCAL_PTR_NULL);
}

/**
 * @tc.number   Enum_convert_GetCellularDataConnectionState_001
 * @tc.name     test normal branch
 * @tc.desc     Function test
 */
HWTEST_F(CoreServiceCommonTest, Enum_convert_GetCellularDataConnectionState_001, Function | MediumTest | Level1)
{
    int32_t state = static_cast<int32_t>(TelephonyDataConnectionStatus::DATA_STATE_DISCONNECTED);
    std::string result = GetCellularDataConnectionState(state);
    ASSERT_STREQ(result.c_str(), "DATA_STATE_DISCONNECTED");
    state = static_cast<int32_t>(TelephonyDataConnectionStatus::DATA_STATE_CONNECTING);
    result = GetCellularDataConnectionState(state);
    ASSERT_STREQ(result.c_str(), "DATA_STATE_CONNECTING");
    state = static_cast<int32_t>(TelephonyDataConnectionStatus::DATA_STATE_CONNECTED);
    result = GetCellularDataConnectionState(state);
    ASSERT_STREQ(result.c_str(), "DATA_STATE_CONNECTED");
    state = static_cast<int32_t>(TelephonyDataConnectionStatus::DATA_STATE_SUSPENDED);
    result = GetCellularDataConnectionState(state);
    ASSERT_STREQ(result.c_str(), "DATA_STATE_SUSPENDED");
}

/**
 * @tc.number   TelAesCryptoUtils_HexToDec_001
 * @tc.name     test normal branch
 * @tc.desc     Function test
 */
HWTEST_F(CoreServiceCommonTest, TelAesCryptoUtils_HexToDec_001, Function | MediumTest | Level1)
{
    uint8_t decodeValue;
    bool result = TelAesCryptoUtils::HexToDec('5', decodeValue);
    EXPECT_TRUE(result);
    EXPECT_EQ(decodeValue, 5);
}

/**
 * @tc.number   TelAesCryptoUtils_HexToDec_002
 * @tc.name     test normal branch
 * @tc.desc     Function test
 */
HWTEST_F(CoreServiceCommonTest, TelAesCryptoUtils_HexToDec_002, Function | MediumTest | Level1)
{
    uint8_t decodeValue;
    bool result = TelAesCryptoUtils::HexToDec('a', decodeValue);
    EXPECT_TRUE(result);
    EXPECT_EQ(decodeValue, 10);
}

/**
 * @tc.number   TelAesCryptoUtils_HexToDec_003
 * @tc.name     test normal branch
 * @tc.desc     Function test
 */
HWTEST_F(CoreServiceCommonTest, TelAesCryptoUtils_HexToDec_003, Function | MediumTest | Level1)
{
    uint8_t decodeValue;
    bool result = TelAesCryptoUtils::HexToDec('g', decodeValue);
    EXPECT_FALSE(result);
}

/**
 * @tc.number   TelAesCryptoUtils_DecToHexString_001
 * @tc.name     test normal branch
 * @tc.desc     Function test
 */
HWTEST_F(CoreServiceCommonTest, TelAesCryptoUtils_DecToHexString_001, Function | MediumTest | Level1)
{
    const uint8_t *data = nullptr;
    size_t len = 10;
    std::string result = TelAesCryptoUtils::DecToHexString(data, len);
    ASSERT_EQ(result, "");
}

/**
 * @tc.number   TelAesCryptoUtils_DecToHexString_002
 * @tc.name     test normal branch
 * @tc.desc     Function test
 */
HWTEST_F(CoreServiceCommonTest, TelAesCryptoUtils_DecToHexString_002, Function | MediumTest | Level1)
{
    uint8_t data[10] = {0};
    size_t len = 0;
    std::string result = TelAesCryptoUtils::DecToHexString(data, len);
    ASSERT_EQ(result, "");
}

/**
 * @tc.number   TelAesCryptoUtils_DecToHexString_003
 * @tc.name     test normal branch
 * @tc.desc     Function test
 */
HWTEST_F(CoreServiceCommonTest, TelAesCryptoUtils_DecToHexString_003, Function | MediumTest | Level1)
{
    uint8_t data[10] = {0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA};
    size_t len = 10;
    std::string result = TelAesCryptoUtils::DecToHexString(data, len);
    ASSERT_EQ(result, "0102030405060708090a");
}

/**
 * @tc.number   TelAesCryptoUtils_HexToDecString_001
 * @tc.name     test normal branch
 * @tc.desc     Function test
 */
HWTEST_F(CoreServiceCommonTest, TelAesCryptoUtils_HexToDecString_001, Function | MediumTest | Level1)
{
    std::string hexString = "";
    auto result = TelAesCryptoUtils::HexToDecString(hexString);
    ASSERT_EQ(result.first, nullptr);
    hexString = "12345";
    result = TelAesCryptoUtils::HexToDecString(hexString);
    ASSERT_EQ(result.first, nullptr);
    hexString = "123456";
    result = TelAesCryptoUtils::HexToDecString(hexString);
    ASSERT_NE(result.first, nullptr);
    hexString = "123456";
    result = TelAesCryptoUtils::HexToDecString(hexString);
    ASSERT_NE(result.first, nullptr);
    hexString = "123456";
    result = TelAesCryptoUtils::HexToDecString(hexString);
    ASSERT_NE(result.first, nullptr);
}

/**
 * @tc.number   TelephonyConfig_IsCapabilitySupport_001
 * @tc.name     test normal branch
 * @tc.desc     Function test
 */
HWTEST_F(CoreServiceCommonTest, TelephonyConfig_IsCapabilitySupport_001, Function | MediumTest | Level1)
{
    TelephonyConfig telephonyConfig;
    uint32_t capablity = MODEM_CAP_MIN_VALUE - 1;
    EXPECT_FALSE(telephonyConfig.IsCapabilitySupport(capablity));
    capablity = MODEM_CAP_MAX_VALUE;
    EXPECT_FALSE(telephonyConfig.IsCapabilitySupport(capablity));
}

/**
 * @tc.number   TelephonyConfig_ConvertCharToInt_001
 * @tc.name     test normal branch
 * @tc.desc     Function test
 */
HWTEST_F(CoreServiceCommonTest, TelephonyConfig_ConvertCharToInt_001, Function | MediumTest | Level1)
{
    TelephonyConfig telephonyConfig;
    uint32_t retValue = 0;
    std::string maxCap = "1234567890";
    uint32_t index = 11;
    int32_t result = telephonyConfig.ConvertCharToInt(retValue, maxCap, index);
    ASSERT_EQ(result, -1);
}

/**
 * @tc.number   TelephonyConfig_ConvertCharToInt_002
 * @tc.name     test normal branch
 * @tc.desc     Function test
 */
HWTEST_F(CoreServiceCommonTest, TelephonyConfig_ConvertCharToInt_002, Function | MediumTest | Level1)
{
    TelephonyConfig telephonyConfig;
    uint32_t retValue = 0;
    std::string maxCap = "12345678901";
    uint32_t index = 10;
    int32_t result = telephonyConfig.ConvertCharToInt(retValue, maxCap, index);
    ASSERT_EQ(result, 0);
}

/**
 * @tc.number   TelephonyConfig_ConvertCharToInt_003
 * @tc.name     test normal branch
 * @tc.desc     Function test
 */
HWTEST_F(CoreServiceCommonTest, TelephonyConfig_ConvertCharToInt_003, Function | MediumTest | Level1)
{
    TelephonyConfig telephonyConfig;
    uint32_t retValue = 0;
    std::string maxCap = "1234567890";
    uint32_t index = 0;
    int32_t result = telephonyConfig.ConvertCharToInt(retValue, maxCap, index);
    ASSERT_EQ(result, 0);
    ASSERT_EQ(retValue, 1);
}

/**
 * @tc.number   TelephonyConfig_ConvertCharToInt_004
 * @tc.name     test normal branch
 * @tc.desc     Function test
 */
HWTEST_F(CoreServiceCommonTest, TelephonyConfig_ConvertCharToInt_004, Function | MediumTest | Level1)
{
    TelephonyConfig telephonyConfig;
    uint32_t retValue = 0;
    std::string maxCap = "abcdef";
    uint32_t index = 0;
    int32_t result = telephonyConfig.ConvertCharToInt(retValue, maxCap, index);
    ASSERT_EQ(result, 0);
    ASSERT_EQ(retValue, 10);
}

/**
 * @tc.number   TelephonyConfig_ConvertCharToInt_005
 * @tc.name     test normal branch
 * @tc.desc     Function test
 */
HWTEST_F(CoreServiceCommonTest, TelephonyConfig_ConvertCharToInt_005, Function | MediumTest | Level1)
{
    TelephonyConfig telephonyConfig;
    uint32_t retValue = 0;
    std::string maxCap = "ABCDEF";
    uint32_t index = 0;
    int32_t result = telephonyConfig.ConvertCharToInt(retValue, maxCap, index);
    ASSERT_EQ(result, 0);
    ASSERT_EQ(retValue, 10);
}

/**
 * @tc.number   TelephonyConfig_ConvertCharToInt_006
 * @tc.name     test normal branch
 * @tc.desc     Function test
 */
HWTEST_F(CoreServiceCommonTest, TelephonyConfig_ConvertCharToInt_006, Function | MediumTest | Level1)
{
    TelephonyConfig telephonyConfig;
    uint32_t retValue = 0;
    std::string maxCap = "!@#$%^&*()";
    uint32_t index = 0;
    int32_t result = telephonyConfig.ConvertCharToInt(retValue, maxCap, index);
    ASSERT_EQ(result, -1);
}

} // namespace Telephony
} // namespace OHOS
