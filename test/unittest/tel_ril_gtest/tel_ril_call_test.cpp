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
 * @tc.number Telephony_TelRil_CallGetCurrentCallsStatusTest_0101 to do ...
 * @tc.name Get current call status of the card 1
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_CallGetCurrentCallsStatusTest_0101, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_CURRENT_CALLS), SLOT_ID_0, GetHandler());
    return;
}

/**
 * @tc.number Telephony_TelRil_CallGetCurrentCallsStatusTest_0201 to do ...
 * @tc.name Get current call status of the card 2
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_CallGetCurrentCallsStatusTest_0201, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_CURRENT_CALLS), SLOT_ID_1, GetHandler());
    return;
}

/**
 * @tc.number Telephony_TelRil_CallDialTest_0101 to do ...
 * @tc.name Call dial of the card 1
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_CallDialTest_0101, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_CALL_DIAL), SLOT_ID_0, GetHandler());
    return;
}

/**
 * @tc.number Telephony_TelRil_CallDialTest_0201 to do ...
 * @tc.name Call dial of the card 2
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_CallDialTest_0201, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_CALL_DIAL), SLOT_ID_1, GetHandler());
    return;
}

/**
 * @tc.number Telephony_TelRil_CallHangupTest_0101 to do ...
 * @tc.name Call hangup of the card 1
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_CallHangupTest_0101, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_HANDUP_CONNECT), SLOT_ID_0, GetHandler());
    return;
}

/**
 * @tc.number Telephony_TelRil_CallHangupTest_0201 to do ...
 * @tc.name Call hangup of the card 2
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_CallHangupTest_0201, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_HANDUP_CONNECT), SLOT_ID_1, GetHandler());
    return;
}

/**
 * @tc.number Telephony_TelRil_CallAnswerTest_0101 to do ...
 * @tc.name Answer the call of the card 1
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_CallAnswerTest_0101, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_ACCEPT_CALL), SLOT_ID_0, GetHandler());
    return;
}

/**
 * @tc.number Telephony_TelRil_CallAnswerTest_0201 to do ...
 * @tc.name Answer the call of the card 2
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_CallAnswerTest_0201, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_ACCEPT_CALL), SLOT_ID_1, GetHandler());
    return;
}

/**
 * @tc.number Telephony_TelRil_CallHoldTest_0101 to do ...
 * @tc.name Call on hold of the card 1
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_CallHoldTest_0101, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_HOLD_CALL), SLOT_ID_0, GetHandler());
    return;
}

/**
 * @tc.number Telephony_TelRil_CallHoldTest_0201 to do ...
 * @tc.name Call on hold of the card 2
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_CallHoldTest_0201, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_HOLD_CALL), SLOT_ID_1, GetHandler());
    return;
}

/**
 * @tc.number Telephony_TelRil_CallActiveTest_0101 to do ...
 * @tc.name Call activation of the card 1
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_CallActiveTest_0101, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_ACTIVE_CALL), SLOT_ID_0, GetHandler());
    return;
}

/**
 * @tc.number Telephony_TelRil_CallActiveTest_0201 to do ...
 * @tc.name Call activation of the card 2
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_CallActiveTest_0201, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_ACTIVE_CALL), SLOT_ID_1, GetHandler());
    return;
}

/**
 * @tc.number Telephony_TelRil_CallSwapTest_0101 to do ...
 * @tc.name Call switch of the card 1
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_CallSwapTest_0101, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_SWAP_CALL), SLOT_ID_0, GetHandler());
    return;
}

/**
 * @tc.number Telephony_TelRil_CallSwapTest_0201 to do ...
 * @tc.name Call switch of the card 2
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_CallSwapTest_0201, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_SWAP_CALL), SLOT_ID_1, GetHandler());
    return;
}

/**
 * @tc.number Telephony_TelRil_CallJoinTest_0101 to do ...
 * @tc.name Call merge of the card 1
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_CallJoinTest_0101, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_JOIN_CALL), SLOT_ID_0, GetHandler());
    return;
}

/**
 * @tc.number Telephony_TelRil_CallJoinTest_0201 to do ...
 * @tc.name Call merge of the card 2
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_CallJoinTest_0201, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_JOIN_CALL), SLOT_ID_1, GetHandler());
    return;
}

/**
 * @tc.number Telephony_TelRil_CallSplitTest_0101 to do ...
 * @tc.name Call separation of the card 1
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_CallSplitTest_0101, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_SPLIT_CALL), SLOT_ID_0, GetHandler());
    return;
}

/**
 * @tc.number Telephony_TelRil_CallSplitTest_0201 to do ...
 * @tc.name Call separation of the card 2
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_CallSplitTest_0201, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_SPLIT_CALL), SLOT_ID_1, GetHandler());
    return;
}

/**
 * @tc.number Telephony_TelRil_RefusedCallTest_0101 to do ...
 * @tc.name Reject call of the card 1
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_RefusedCallTest_0101, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_REJECT_CALL), SLOT_ID_0, GetHandler());
    return;
}

/**
 * @tc.number Telephony_TelRil_RefusedCallTest_0201 to do ...
 * @tc.name Reject call of the card 2
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_RefusedCallTest_0201, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_REJECT_CALL), SLOT_ID_1, GetHandler());
    return;
}

/**
 * @tc.number Telephony_TelRil_GetCallWaitTest_0101 to do ...
 * @tc.name Get call waiting of the card 1
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_GetCallWaitTest_0101, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_GET_CALL_WAIT), SLOT_ID_0, GetHandler());
    return;
}

/**
 * @tc.number Telephony_TelRil_GetCallWaitTest_0201 to do ...
 * @tc.name Get call waiting of the card 2
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_GetCallWaitTest_0201, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_GET_CALL_WAIT), SLOT_ID_1, GetHandler());
    return;
}

/**
 * @tc.number Telephony_TelRil_SetCallWaitTest_0101 to do ...
 * @tc.name Set call waiting of the card 1
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_SetCallWaitTest_0101, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_SET_CALL_WAIT), SLOT_ID_0, GetHandler());
    return;
}

/**
 * @tc.number Telephony_TelRil_SetCallWaitTest_0201 to do ...
 * @tc.name Set call waiting of the card 2
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_SetCallWaitTest_0201, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_SET_CALL_WAIT), SLOT_ID_1, GetHandler());
    return;
}

/**
 * @tc.number Telephony_TelRil_GetCallForwardTest_0101 to do ...
 * @tc.name Get call forwarding of the card 1
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_GetCallForwardTest_0101, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_GET_CALL_FORWARD), SLOT_ID_0, GetHandler());
    return;
}

/**
 * @tc.number Telephony_TelRil_GetCallForwardTest_0201 to do ...
 * @tc.name Get call forwarding of the card 2
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_GetCallForwardTest_0201, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_GET_CALL_FORWARD), SLOT_ID_1, GetHandler());
    return;
}

/**
 * @tc.number Telephony_TelRil_SetCallForwardTest_0101 to do ...
 * @tc.name Set call forwarding of the card 1
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_SetCallForwardTest_0101, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_SET_CALL_FORWARD), SLOT_ID_0, GetHandler());
    return;
}

/**
 * @tc.number Telephony_TelRil_SetCallForwardTest_0201 to do ...
 * @tc.name Set call forwarding of the card 2
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_SetCallForwardTest_0201, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_SET_CALL_FORWARD), SLOT_ID_1, GetHandler());
    return;
}

/**
 * @tc.number Telephony_TelRil_GetClipTest_0101 to do ...
 * @tc.name Set Calling line Identification Presentation Supplementary Service of the card 1
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_GetClipTest_0101, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_GET_CALL_DEAL_CLIP), SLOT_ID_0, GetHandler());
    return;
}

/**
 * @tc.number Telephony_TelRil_GetClipTest_0201 to do ...
 * @tc.name Set Calling line Identification Presentation Supplementary Service of the card 2
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_GetClipTest_0201, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_GET_CALL_DEAL_CLIP), SLOT_ID_1, GetHandler());
    return;
}

/**
 * @tc.number Telephony_TelRil_SetClipTest_0101 to do ...
 * @tc.name Get Calling line Identification Presentation Supplementary Service of the card 1
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_SetClipTest_0101, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_SET_CALL_CLIP), SLOT_ID_0, GetHandler());
    return;
}

/**
 * @tc.number Telephony_TelRil_SetClipTest_0201 to do ...
 * @tc.name Get Calling line Identification Presentation Supplementary Service of the card 2
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_SetClipTest_0201, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_SET_CALL_CLIP), SLOT_ID_1, GetHandler());
    return;
}

/**
 * @tc.number Telephony_TelRil_GetCallRestrictionTest_0101 to do ...
 * @tc.name Get call barring of the card 1
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_GetCallRestrictionTest_0101, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_GET_CALL_RESTRICTION), SLOT_ID_0, GetHandler());
    return;
}

/**
 * @tc.number Telephony_TelRil_GetCallRestrictionTest_0201 to do ...
 * @tc.name Get call barring of the card 2
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_GetCallRestrictionTest_0201, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_GET_CALL_RESTRICTION), SLOT_ID_1, GetHandler());
    return;
}

/**
 * @tc.number Telephony_TelRil_SetCallRestrictionTest_0101 to do ...
 * @tc.name Set call barring of the card 1
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_SetCallRestrictionTest_0101, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_SET_CALL_RESTRICTION), SLOT_ID_0, GetHandler());
    return;
}

/**
 * @tc.number Telephony_TelRil_SetCallRestrictionTest_0201 to do ...
 * @tc.name Set call barring of the card 2
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_SetCallRestrictionTest_0201, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_SET_CALL_RESTRICTION), SLOT_ID_1, GetHandler());
    return;
}

/**
 * @tc.number Telephony_TelRil_SetBarringPasswordTest_0101 to do ...
 * @tc.name Set call barring password of the card 1
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_SetBarringPasswordTest_0101, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_SET_BARRING_PWD), SLOT_ID_0, GetHandler());
    return;
}

/**
 * @tc.number Telephony_TelRil_SetBarringPasswordTest_0201 to do ...
 * @tc.name Set call barring password of the card 2
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_SetBarringPasswordTest_0201, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_SET_BARRING_PWD), SLOT_ID_1, GetHandler());
    return;
}

/**
 * @tc.number Telephony_TelRil_SetUssdTest_0101 to do ...
 * @tc.name Set USSD information of the card 1
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_SetUssdTest_0101, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_SET_USSD), SLOT_ID_0, GetHandler());
    return;
}

/**
 * @tc.number Telephony_TelRil_SetUssdTest_0201 to do ...
 * @tc.name Set USSD information of the card 2
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_SetUssdTest_0201, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_SET_USSD), SLOT_ID_1, GetHandler());
    return;
}

/**
 * @tc.number Telephony_TelRil_GetUssdTest_0101 to do ...
 * @tc.name Get USSD information of the card 1
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_GetUssdTest_0101, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_GET_USSD), SLOT_ID_0, GetHandler());
    return;
}

/**
 * @tc.number Telephony_TelRil_GetUssdTest_0201 to do ...
 * @tc.name Get USSD information of the card 2
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_GetUssdTest_0201, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_GET_USSD), SLOT_ID_1, GetHandler());
    return;
}

/**
 * @tc.number Telephony_TelRil_SetMuteTest_0101 to do ...
 * @tc.name Set mute of the card 1
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_SetMuteTest_0101, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_SET_CMUT), SLOT_ID_0, GetHandler());
    return;
}

/**
 * @tc.number Telephony_TelRil_SetMuteTest_0201 to do ...
 * @tc.name Set mute of the card 2
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_SetMuteTest_0201, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_SET_CMUT), SLOT_ID_1, GetHandler());
    return;
}

/**
 * @tc.number Telephony_TelRil_GetMuteTest_0101 to do ...
 * @tc.name Get Mute of the card 1
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_GetMuteTest_0101, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_GET_CMUT), SLOT_ID_0, GetHandler());
    return;
}

/**
 * @tc.number Telephony_TelRil_GetMuteTest_0201 to do ...
 * @tc.name Get Mute of the card 2
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_GetMuteTest_0201, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_GET_CMUT), SLOT_ID_1, GetHandler());
    return;
}

/**
 * @tc.number Telephony_TelRil_GetEmergencyCallListTest_0101 to do ...
 * @tc.name Get emergency call list of the card 1
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_GetEmergencyCallListTest_0101, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_GET_EMERGENCY_CALL_LIST), SLOT_ID_0, GetHandler());
    return;
}

/**
 * @tc.number Telephony_TelRil_GetEmergencyCallListTest_0201 to do ...
 * @tc.name Get emergency call list of the card 2
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_GetEmergencyCallListTest_0201, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_GET_EMERGENCY_CALL_LIST), SLOT_ID_1, GetHandler());
    return;
}

/**
 * @tc.number Telephony_TelRil_SetVoNRSwitchTest_0101 to do ...
 * @tc.name Set vonr switch of the card 1
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_SetVoNRSwitchTest_0101, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_SET_VONR_STATUS), SLOT_ID_0, GetHandler());
    return;
}

/**
 * @tc.number Telephony_TelRil_SetVoNRSwitchTest_0201 to do ...
 * @tc.name Set vonr switch of the card 2
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_SetVoNRSwitchTest_0201, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_SET_VONR_STATUS), SLOT_ID_1, GetHandler());
    return;
}
#else // TEL_TEST_UNSUPPORT
/**
 * @tc.number Telephony_TelRil_MockTest_0101 to do ...
 * @tc.name Testcase for unsupported platform
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_MockTest_0101, Function | MediumTest | Level3)
{
    EXPECT_TRUE(true);
}
#endif // TEL_TEST_UNSUPPORT
} // namespace Telephony
} // namespace OHOS
