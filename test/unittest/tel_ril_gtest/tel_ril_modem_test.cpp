/*
 * Copyright (C) 2021-2023 Huawei Device Co., Ltd.
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
 * @tc.number Telephony_TelRil_NetworkGetRssiTest_0101 to do ...
 * @tc.name Get Rssi information of the card 1
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_NetworkGetRssiTest_0101, Function | MediumTest | Level3)
{
    ASSERT_TRUE(ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_GET_SIGNAL_STRENGTH), SLOT_ID_0, GetHandler()));
    return;
}

/**
 * @tc.number Telephony_TelRil_NetworkGetRssiTest_0201 to do ...
 * @tc.name Get Rssi information of the card 2
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_NetworkGetRssiTest_0201, Function | MediumTest | Level3)
{
    ASSERT_TRUE(ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_GET_SIGNAL_STRENGTH), SLOT_ID_1, GetHandler()));
    return;
}

/**
 * @tc.number Telephony_TelRil_SetRadioStateTest_0101 to do ...
 * @tc.name Set radio state of the card 1
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_SetRadioStateTest_0101, Function | MediumTest | Level3)
{
    ASSERT_TRUE(ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_SET_POWER_STATE), SLOT_ID_0, GetHandler()));
    return;
}

/**
 * @tc.number Telephony_TelRil_SetRadioStateTest_0201 to do ...
 * @tc.name Set radio state of the card 2
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_SetRadioStateTest_0201, Function | MediumTest | Level3)
{
    ASSERT_TRUE(ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_SET_POWER_STATE), SLOT_ID_1, GetHandler()));
    return;
}

/**
 * @tc.number Telephony_TelRil_GetRadioStateTest_0101 to do ...
 * @tc.name Get radio state of the card 1
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_GetRadioStateTest_0101, Function | MediumTest | Level3)
{
    ASSERT_TRUE(ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_GET_POWER_STATE), SLOT_ID_0, GetHandler()));
    return;
}

/**
 * @tc.number Telephony_TelRil_GetRadioStateTest_0201 to do ...
 * @tc.name Get radio state of the card 2
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_GetRadioStateTest_0201, Function | MediumTest | Level3)
{
    ASSERT_TRUE(ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_GET_POWER_STATE), SLOT_ID_1, GetHandler()));
    return;
}
#endif // TEL_TEST_UNSUPPORT
} // namespace Telephony
} // namespace OHOS
