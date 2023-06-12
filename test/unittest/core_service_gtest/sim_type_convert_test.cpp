/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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
#include "sim_state_type.h"
#include "sim_test_util.h"
#include "str_convert.h"
#include "string_ex.h"
#include "tel_profile_util.h"

namespace OHOS {
namespace Telephony {
#ifndef TEL_TEST_UNSUPPORT
/**
 * @tc.number   Telephony_Sim_TestEnumCovert_0100
 * @tc.name     Enum_Covert
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_TestEnumCovert_0100, Function | MediumTest | Level3)
{
    int32_t errorSimState = 7;
    int32_t errorCallState = 9;
    int32_t errorTelephonyCardType = 1;
    EXPECT_EQ(GetBoolValue(0), "FALSE");
    EXPECT_EQ(GetBoolValue(1), "TRUE");
    EXPECT_EQ(GetSimState(static_cast<int32_t>(TelephonySimState::SIM_STATE_UNKNOWN)), "SIM_STATE_UNKNOWN");
    EXPECT_EQ(GetSimState(static_cast<int32_t>(TelephonySimState::SIM_STATE_NOT_PRESENT)), "SIM_STATE_NOT_PRESENT");
    EXPECT_EQ(GetSimState(static_cast<int32_t>(TelephonySimState::SIM_STATE_LOCKED)), "SIM_STATE_LOCKED");
    EXPECT_EQ(GetSimState(static_cast<int32_t>(TelephonySimState::SIM_STATE_NOT_READY)), "SIM_STATE_NOT_READY");
    EXPECT_EQ(GetSimState(static_cast<int32_t>(TelephonySimState::SIM_STATE_READY)), "SIM_STATE_READY");
    EXPECT_EQ(GetSimState(static_cast<int32_t>(TelephonySimState::SIM_STATE_LOADED)), "SIM_STATE_LOADED");
    EXPECT_EQ(GetSimState(errorSimState), "");
    EXPECT_EQ(GetCallState(static_cast<int32_t>(TelephonyCallState::CALL_STATUS_ACTIVE)), "CALL_STATUS_ACTIVE");
    EXPECT_EQ(GetCallState(static_cast<int32_t>(TelephonyCallState::CALL_STATUS_HOLDING)), "CALL_STATUS_HOLDING");
    EXPECT_EQ(GetCallState(static_cast<int32_t>(TelephonyCallState::CALL_STATUS_DIALING)), "CALL_STATUS_DIALING");
    EXPECT_EQ(GetCallState(static_cast<int32_t>(TelephonyCallState::CALL_STATUS_ALERTING)), "CALL_STATUS_ALERTING");
    EXPECT_EQ(GetCallState(static_cast<int32_t>(TelephonyCallState::CALL_STATUS_INCOMING)), "CALL_STATUS_INCOMING");
    EXPECT_EQ(GetCallState(static_cast<int32_t>(TelephonyCallState::CALL_STATUS_WAITING)), "CALL_STATUS_WAITING");
    EXPECT_EQ(
        GetCallState(static_cast<int32_t>(TelephonyCallState::CALL_STATUS_DISCONNECTED)), "CALL_STATUS_DISCONNECTED");
    EXPECT_EQ(
        GetCallState(static_cast<int32_t>(TelephonyCallState::CALL_STATUS_DISCONNECTING)), "CALL_STATUS_DISCONNECTING");
    EXPECT_EQ(GetCallState(static_cast<int32_t>(TelephonyCallState::CALL_STATUS_IDLE)), "CALL_STATUS_IDLE");
    EXPECT_EQ(GetCallState(errorCallState), "CALL_STATUS_IDLE");
    EXPECT_EQ(GetCardType(static_cast<int32_t>(TelephonyCardType::UNKNOWN_CARD)), "UNKNOWN_CARD");
    EXPECT_EQ(GetCardType(static_cast<int32_t>(TelephonyCardType::SINGLE_MODE_SIM_CARD)), "SINGLE_MODE_SIM_CARD");
    EXPECT_EQ(GetCardType(static_cast<int32_t>(TelephonyCardType::SINGLE_MODE_USIM_CARD)), "SINGLE_MODE_USIM_CARD");
    EXPECT_EQ(GetCardType(static_cast<int32_t>(TelephonyCardType::SINGLE_MODE_RUIM_CARD)), "SINGLE_MODE_RUIM_CARD");
    EXPECT_EQ(GetCardType(static_cast<int32_t>(TelephonyCardType::DUAL_MODE_CG_CARD)), "DUAL_MODE_CG_CARD");
    EXPECT_EQ(
        GetCardType(static_cast<int32_t>(TelephonyCardType::CT_NATIONAL_ROAMING_CARD)), "CT_NATIONAL_ROAMING_CARD");
    EXPECT_EQ(GetCardType(static_cast<int32_t>(TelephonyCardType::CU_DUAL_MODE_CARD)), "CU_DUAL_MODE_CARD");
    EXPECT_EQ(
        GetCardType(static_cast<int32_t>(TelephonyCardType::DUAL_MODE_TELECOM_LTE_CARD)), "DUAL_MODE_TELECOM_LTE_CARD");
    EXPECT_EQ(GetCardType(static_cast<int32_t>(TelephonyCardType::DUAL_MODE_UG_CARD)), "DUAL_MODE_UG_CARD");
    EXPECT_EQ(GetCardType(static_cast<int32_t>(TelephonyCardType::SINGLE_MODE_ISIM_CARD)), "SINGLE_MODE_ISIM_CARD");
    EXPECT_EQ(GetCardType(errorTelephonyCardType), "");
}

/**
 * @tc.number   Telephony_Sim_TestEnumCovert_0200
 * @tc.name     Enum_Covert
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_TestEnumCovert_0200, Function | MediumTest | Level3)
{
    int32_t errorTelephonyCellDataFlowType = 5;
    int32_t errorDataConnectStatus = 13;
    EXPECT_EQ(GetCellularDataFlow(static_cast<int32_t>(TelephonyCellDataFlowType::DATA_FLOW_TYPE_NONE)),
        "DATA_FLOW_TYPE_NONE");
    EXPECT_EQ(GetCellularDataFlow(static_cast<int32_t>(TelephonyCellDataFlowType::DATA_FLOW_TYPE_DOWN)),
        "DATA_FLOW_TYPE_DOWN");
    EXPECT_EQ(
        GetCellularDataFlow(static_cast<int32_t>(TelephonyCellDataFlowType::DATA_FLOW_TYPE_UP)), "DATA_FLOW_TYPE_UP");
    EXPECT_EQ(GetCellularDataFlow(static_cast<int32_t>(TelephonyCellDataFlowType::DATA_FLOW_TYPE_UP_DOWN)),
        "DATA_FLOW_TYPE_UP_DOWN");
    EXPECT_EQ(GetCellularDataFlow(static_cast<int32_t>(TelephonyCellDataFlowType::DATA_FLOW_TYPE_DORMANT)),
        "DATA_FLOW_TYPE_DORMANT");
    EXPECT_EQ(GetCellularDataFlow(errorTelephonyCellDataFlowType), "");
    EXPECT_EQ(GetCellularDataConnectionNetworkType(static_cast<int32_t>(TelephonyRadioTech::RADIO_TECHNOLOGY_UNKNOWN)),
        "RADIO_TECHNOLOGY_UNKNOWN");
    EXPECT_EQ(GetCellularDataConnectionNetworkType(static_cast<int32_t>(TelephonyRadioTech::RADIO_TECHNOLOGY_GSM)),
        "RADIO_TECHNOLOGY_GSM");
    EXPECT_EQ(GetCellularDataConnectionNetworkType(static_cast<int32_t>(TelephonyRadioTech::RADIO_TECHNOLOGY_1XRTT)),
        "RADIO_TECHNOLOGY_1XRTT");
    EXPECT_EQ(GetCellularDataConnectionNetworkType(static_cast<int32_t>(TelephonyRadioTech::RADIO_TECHNOLOGY_WCDMA)),
        "RADIO_TECHNOLOGY_WCDMA");
    EXPECT_EQ(GetCellularDataConnectionNetworkType(static_cast<int32_t>(TelephonyRadioTech::RADIO_TECHNOLOGY_HSPA)),
        "RADIO_TECHNOLOGY_HSPA");
    EXPECT_EQ(GetCellularDataConnectionNetworkType(static_cast<int32_t>(TelephonyRadioTech::RADIO_TECHNOLOGY_HSPAP)),
        "RADIO_TECHNOLOGY_HSPAP");
    EXPECT_EQ(GetCellularDataConnectionNetworkType(static_cast<int32_t>(TelephonyRadioTech::RADIO_TECHNOLOGY_TD_SCDMA)),
        "RADIO_TECHNOLOGY_TD_SCDMA");
    EXPECT_EQ(GetCellularDataConnectionNetworkType(static_cast<int32_t>(TelephonyRadioTech::RADIO_TECHNOLOGY_EVDO)),
        "RADIO_TECHNOLOGY_EVDO");
    EXPECT_EQ(GetCellularDataConnectionNetworkType(static_cast<int32_t>(TelephonyRadioTech::RADIO_TECHNOLOGY_EHRPD)),
        "RADIO_TECHNOLOGY_EHRPD");
    EXPECT_EQ(GetCellularDataConnectionNetworkType(static_cast<int32_t>(TelephonyRadioTech::RADIO_TECHNOLOGY_LTE)),
        "RADIO_TECHNOLOGY_LTE");
    EXPECT_EQ(GetCellularDataConnectionNetworkType(static_cast<int32_t>(TelephonyRadioTech::RADIO_TECHNOLOGY_LTE_CA)),
        "RADIO_TECHNOLOGY_LTE_CA");
    EXPECT_EQ(GetCellularDataConnectionNetworkType(static_cast<int32_t>(TelephonyRadioTech::RADIO_TECHNOLOGY_IWLAN)),
        "RADIO_TECHNOLOGY_IWLAN");
    EXPECT_EQ(GetCellularDataConnectionNetworkType(static_cast<int32_t>(TelephonyRadioTech::RADIO_TECHNOLOGY_NR)),
        "RADIO_TECHNOLOGY_NR");
    EXPECT_EQ(GetCellularDataConnectionNetworkType(errorDataConnectStatus), "");
}

/**
 * @tc.number   Telephony_Sim_TestEnumCovert_0300
 * @tc.name     Enum_Covert
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_TestEnumCovert_0300, Function | MediumTest | Level3)
{
    int32_t errorTelephonyLockReason = 13;
    EXPECT_EQ(GetLockReason(static_cast<int32_t>(TelephonyLockReason::SIM_NONE)), "SIM_NONE");
    EXPECT_EQ(GetLockReason(static_cast<int32_t>(TelephonyLockReason::SIM_PIN)), "SIM_PIN");
    EXPECT_EQ(GetLockReason(static_cast<int32_t>(TelephonyLockReason::SIM_PUK)), "SIM_PUK");
    EXPECT_EQ(GetLockReason(static_cast<int32_t>(TelephonyLockReason::SIM_PN_PIN)), "SIM_PN_PIN");
    EXPECT_EQ(GetLockReason(static_cast<int32_t>(TelephonyLockReason::SIM_PN_PUK)), "SIM_PN_PUK");
    EXPECT_EQ(GetLockReason(static_cast<int32_t>(TelephonyLockReason::SIM_PU_PIN)), "SIM_PU_PIN");
    EXPECT_EQ(GetLockReason(static_cast<int32_t>(TelephonyLockReason::SIM_PU_PUK)), "SIM_PU_PUK");
    EXPECT_EQ(GetLockReason(static_cast<int32_t>(TelephonyLockReason::SIM_PP_PIN)), "SIM_PP_PIN");
    EXPECT_EQ(GetLockReason(static_cast<int32_t>(TelephonyLockReason::SIM_PP_PUK)), "SIM_PP_PUK");
    EXPECT_EQ(GetLockReason(static_cast<int32_t>(TelephonyLockReason::SIM_PC_PIN)), "SIM_PC_PIN");
    EXPECT_EQ(GetLockReason(static_cast<int32_t>(TelephonyLockReason::SIM_PC_PUK)), "SIM_PC_PUK");
    EXPECT_EQ(GetLockReason(static_cast<int32_t>(TelephonyLockReason::SIM_SIM_PIN)), "SIM_SIM_PIN");
    EXPECT_EQ(GetLockReason(static_cast<int32_t>(TelephonyLockReason::SIM_SIM_PUK)), "SIM_SIM_PUK");
    EXPECT_EQ(GetLockReason(errorTelephonyLockReason), "");
}

/**
 * @tc.number   Telephony_Sim_TestStrCovert_0100
 * @tc.name     Enum_Covert
 * @tc.desc     Function test
 */
HWTEST_F(SimTest, Telephony_Sim_TestStrCovert_0100, Function | MediumTest | Level3)
{
    std::string testU8Str = "test";
    std::u16string testU16Str = u"test";
    std::u32string testU32Str = U"test";
    std::wstring testWstr = L"test";
    EXPECT_EQ(ToUtf16(testU8Str), testU16Str);
    EXPECT_EQ(ToUtf8(testU16Str), testU8Str);
    EXPECT_EQ(ToUtf32(testU8Str), testU32Str);
    EXPECT_EQ(ToUtf8(testU32Str), testU8Str);
    EXPECT_EQ(ToUtf8(testWstr), testU8Str);
}
#endif // TEL_TEST_UNSUPPORT
} // namespace Telephony
} // namespace OHOS
