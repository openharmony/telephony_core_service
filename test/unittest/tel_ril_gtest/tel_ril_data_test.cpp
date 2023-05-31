/*
 * Copyright (C) 2021-2022 Huawei Device Co., Ltd.
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

#include "tel_ril_test_util.h"

#include <fcntl.h>
#include <iostream>

#include "radio_event.h"

using namespace testing::ext;

namespace OHOS {
namespace Telephony {
#ifndef TEL_TEST_UNSUPPORT
/**
 * @tc.number Telephony_TelRil_DataSetInitApnInfoTest_0101 to do ...
 * @tc.name Set apn initialization information of the card 1
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_DataSetInitApnInfoTest_0101, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_RILCM_SET_INIT_APN_INFO), SLOT_ID_0, GetHandler());
    return;
}

/**
 * @tc.number Telephony_TelRil_DataSetInitApnInfoTest_0201 to do ...
 * @tc.name Set apn initialization information of the card 2
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_DataSetInitApnInfoTest_0201, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_RILCM_SET_INIT_APN_INFO), SLOT_ID_1, GetHandler());
    return;
}

/**
 * @tc.number Telephony_TelRil_DataSetupDataCallTest_0101 to do ...
 * @tc.name Set data call of the card 1
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_DataSetupDataCallTest_0101, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_RILCM_SETUP_DATA_CALL), SLOT_ID_0, GetHandler());
}

/**
 * @tc.number Telephony_TelRil_DataSetupDataCallTest_0201 to do ...
 * @tc.name Set data call of the card 2
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_DataSetupDataCallTest_0201, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_RILCM_SETUP_DATA_CALL), SLOT_ID_1, GetHandler());
}

/**
 * @tc.number Telephony_TelRil_DataDisableDataCallTest_0101 to do ...
 * @tc.name Disable data call of the card 1
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_DataDisableDataCallTest_0101, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_RILCM_DEACTIVATE_DATA_CALL), SLOT_ID_0, GetHandler());
}

/**
 * @tc.number Telephony_TelRil_DataDisableDataCallTest_0201 to do ...
 * @tc.name Disable data call of the card 2
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_DataDisableDataCallTest_0201, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_RILCM_DEACTIVATE_DATA_CALL), SLOT_ID_1, GetHandler());
}

/**
 * @tc.number Telephony_TelRil_GetDataCallListTest_0101 to do ...
 * @tc.name Get data call list of the card 1
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_GetDataCallListTest_0101, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_RILCM_GET_DATA_CALL_LIST), SLOT_ID_0, GetHandler());
}

/**
 * @tc.number Telephony_TelRil_GetDataCallListTest_0201 to do ...
 * @tc.name Get data call list of the card 2
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_GetDataCallListTest_0201, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_RILCM_GET_DATA_CALL_LIST), SLOT_ID_1, GetHandler());
}

/**
 * @tc.number Telephony_TelRil_GetLinkBandwidthInfoTest_0101 to do ...
 * @tc.name Get link bandwidth information of the card 1
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_GetLinkBandwidthInfoTest_0101, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_RILCM_GET_LINK_BANDWIDTH_INFO), SLOT_ID_0, GetHandler());
}

/**
 * @tc.number Telephony_TelRil_GetLinkBandwidthInfoTest_0201 to do ...
 * @tc.name Get link bandwidth information of the card 2
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_GetLinkBandwidthInfoTest_0201, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_RILCM_GET_LINK_BANDWIDTH_INFO), SLOT_ID_1, GetHandler());
}

/**
 * @tc.number Telephony_TelRil_GetLinkCapabilityTest_0101 to do ...
 * @tc.name Get link capability of the card 1
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_GetLinkCapabilityTest_0101, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_RILCM_GET_LINK_CAPABILITY_TEST), SLOT_ID_0, GetHandler());
}

/**
 * @tc.number Telephony_TelRil_GetLinkCapabilityTest_0201 to do ...
 * @tc.name Get data link capability of the card 2
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_GetLinkCapabilityTest_0201, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_RILCM_GET_LINK_CAPABILITY_TEST), SLOT_ID_1, GetHandler());
}

/**
 * @tc.number Telephony_TelRil_SetLinkBandwidthReportingRuleTest_0101 to do ...
 * @tc.name Setting link bandwidth reporting rules of the card 1
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_SetLinkBandwidthReportingRuleTest_0101, Function | MediumTest | Level3)
{
    ProcessTest(
        static_cast<int32_t>(DiffInterfaceId::TEST_RILCM_SET_LINK_BANDWIDTH_REPORTING_RULE), SLOT_ID_0, GetHandler());
}

/**
 * @tc.number Telephony_TelRil_SetLinkBandwidthReportingRuleTest_0201 to do ...
 * @tc.name Setting link bandwidth reporting rules of the card 2
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_SetLinkBandwidthReportingRuleTest_0201, Function | MediumTest | Level3)
{
    ProcessTest(
        static_cast<int32_t>(DiffInterfaceId::TEST_RILCM_SET_LINK_BANDWIDTH_REPORTING_RULE), SLOT_ID_1, GetHandler());
}

/**
 * @tc.number Telephony_TelRil_SetDataPermittedTest_0101 to do ...
 * @tc.name Set data permitted to modem
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_SetDataPermittedTest_0101, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_RILCM_SET_DATA_PERMITTED_TEST), SLOT_ID_0, GetHandler());
}
#endif // TEL_TEST_UNSUPPORT
} // namespace Telephony
} // namespace OHOS
