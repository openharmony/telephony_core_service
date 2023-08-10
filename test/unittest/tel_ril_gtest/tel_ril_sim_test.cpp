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
 * @tc.number Telephony_TelRil_SimGetSimStatusTest_0101 to do ...
 * @tc.name Get SIM card status of the card 1
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_SimGetSimStatusTest_0101, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_GET_SIM_CARD_STATUS), SLOT_ID_0, GetHandler());
    return;
}

/**
 * @tc.number Telephony_TelRil_SimGetSimStatusTest_0201 to do ...
 * @tc.name Get SIM card status of the card 2
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_SimGetSimStatusTest_0201, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_GET_SIM_CARD_STATUS), SLOT_ID_1, GetHandler());
    return;
}

/**
 * @tc.number Telephony_TelRil_SimIccIoTest_0101 to do ...
 * @tc.name Get SIM card IccIo of the card 1
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_SimIccIoTest_0101, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_SIM_IO), SLOT_ID_0, GetHandler());
    return;
}

/**
 * @tc.number Telephony_TelRil_SimIccIoTest_0201 to do ...
 * @tc.name Get SIM card IccIo of the card 2
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_SimIccIoTest_0201, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_SIM_IO), SLOT_ID_1, GetHandler());
    return;
}

/**
 * @tc.number Telephony_TelRil_SimGetImsiTest_0101 to do ...
 * @tc.name Get Imsi information of the card 1
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_SimGetImsiTest_0101, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_GET_IMSI), SLOT_ID_0, GetHandler());
    return;
}

/**
 * @tc.number Telephony_TelRil_SimGetImsiTest_0201 to do ...
 * @tc.name Get Imsi information of the card 2
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_SimGetImsiTest_0201, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_GET_IMSI), SLOT_ID_1, GetHandler());
    return;
}

/**
 * @tc.number Telephony_TelRil_GetSimLockStatusTest_0101 to do ...
 * @tc.name Get SIM card lock status of the card 1
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_GetSimLockStatusTest_0101, Function | MediumTest | Level3)
{
#ifdef TEL_TEST_PIN_PUK
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_GET_SIM_LOCK_STATUS), SLOT_ID_0, GetHandler());
#endif
    return;
}

/**
 * @tc.number Telephony_TelRil_SetSimLockTest_0101 to do ...
 * @tc.name Set SIM card lock status of the card 1
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_SetSimLockTest_0101, Function | MediumTest | Level3)
{
#ifdef TEL_TEST_PIN_PUK
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_SET_SIM_LOCK), SLOT_ID_0, GetHandler());
#endif
    return;
}

/**
 * @tc.number Telephony_TelRil_ChangeSimPasswordTest_0101 to do ...
 * @tc.name Change SIM card Password of the card 1
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_ChangeSimPasswordTest_0101, Function | MediumTest | Level3)
{
#ifdef TEL_TEST_PIN_PUK
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_GET_CHANGE_SIM_PASSWD), SLOT_ID_0, GetHandler());
#endif
    return;
}

/**
 * @tc.number Telephony_TelRil_RadioRestartTest_0101 to do ...
 * @tc.name Restart Radio of the card 1
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_RadioRestartTest_0101, Function | MediumTest | Level3)
{
#ifdef TEL_TEST_PIN_PUK
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_RADIO_RESTART), SLOT_ID_0, GetHandler());
#endif
    return;
}

/**
 * @tc.number Telephony_TelRil_EnterSimPinTest_0101 to do ...
 * @tc.name Enter SIM card pin code of the card 1
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_EnterSimPinTest_0101, Function | MediumTest | Level3)
{
#ifdef TEL_TEST_PIN_PUK
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_ENTER_SIM_PIN), SLOT_ID_0, GetHandler());
#endif
    return;
}

/**
 * @tc.number Telephony_TelRil_RadioRestartTest_0102 to do ...
 * @tc.name Restart Radio of the card 1
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_RadioRestartTest_0102, Function | MediumTest | Level3)
{
#ifdef TEL_TEST_PIN_PUK
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_RADIO_RESTART), SLOT_ID_0, GetHandler());
#endif
    return;
}

/**
 * @tc.number Telephony_TelRil_ErrorPINCodeTest_0101 to do ...
 * @tc.name Enter Error PIN of the card 1
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_EnterErrorPINTest_0101, Function | MediumTest | Level3)
{
#ifdef TEL_TEST_PIN_PUK
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_ENTER_ERROR_PIN), SLOT_ID_0, GetHandler());
#endif
    return;
}

/**
 * @tc.number Telephony_TelRil_ErrorPINCodeTest_0102 to do ...
 * @tc.name Enter Error PIN of the card 1
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_EnterErrorPINTest_0102, Function | MediumTest | Level3)
{
#ifdef TEL_TEST_PIN_PUK
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_ENTER_ERROR_PIN), SLOT_ID_0, GetHandler());
#endif
    return;
}

/**
 * @tc.number Telephony_TelRil_ErrorPINCodeTest_0103 to do ...
 * @tc.name Enter Error PIN of the card 1
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_EnterErrorPINTest_0103, Function | MediumTest | Level3)
{
#ifdef TEL_TEST_PIN_PUK
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_ENTER_ERROR_PIN), SLOT_ID_0, GetHandler());
#endif
    return;
}

/**
 * @tc.number Telephony_TelRil_UnlockSimPinTest_0101 to do ...
 * @tc.name Unlock SIM card pin code of the card 1
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_UnlockSimPinTest_0101, Function | MediumTest | Level3)
{
#ifdef TEL_TEST_PIN_PUK
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_UNLOCK_SIM_PIN), SLOT_ID_0, GetHandler());
#endif
    return;
}

/**
 * @tc.number Telephony_TelRil_UnSetSimLockTest_0101 to do ...
 * @tc.name UnSet SIM card lock status of the card 1
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_UnSetSimLockTest_0101, Function | MediumTest | Level3)
{
#ifdef TEL_TEST_PIN_PUK
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_UNSET_SIM_LOCK), SLOT_ID_0, GetHandler());
#endif
    return;
}

/**
 * @tc.number Telephony_TelRil_SetPIn2LockTest_0101 to do ...
 * @tc.name Set PIN2 lock status of the card 1
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_SetPIn2LockTest_0101, Function | MediumTest | Level3)
{
#ifdef TEL_TEST_PIN_PUK
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_SET_PIN2_LOCK), SLOT_ID_0, GetHandler());
#endif
    return;
}

/**
 * @tc.number Telephony_TelRil_RadioRestartTest_0103 to do ...
 * @tc.name Restart Radio of the card 1
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_RadioRestartTest_0103, Function | MediumTest | Level3)
{
#ifdef TEL_TEST_PIN_PUK
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_RADIO_RESTART), SLOT_ID_0, GetHandler());
#endif
    return;
}

/**
 * @tc.number Telephony_TelRil_EnterSimPin2Test_0101 to do ...
 * @tc.name Enter SIM card pin2 code of the card 1
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_EnterSimPin2Test_0101, Function | MediumTest | Level3)
{
#ifdef TEL_TEST_PIN_PUK
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_ENTER_SIM_PIN2), SLOT_ID_0, GetHandler());
#endif
    return;
}

/**
 * @tc.number Telephony_TelRil_SetPIn2LockTest_0102 to do ...
 * @tc.name Set PIN2 lock status of the card 1
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_SetPIn2LockTest_0102, Function | MediumTest | Level3)
{
#ifdef TEL_TEST_PIN_PUK
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_SET_PIN2_LOCK), SLOT_ID_0, GetHandler());
#endif
    return;
}

/**
 * @tc.number Telephony_TelRil_RadioRestartTest_0104 to do ...
 * @tc.name Restart Radio of the card 1
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_RadioRestartTest_0104, Function | MediumTest | Level3)
{
#ifdef TEL_TEST_PIN_PUK
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_RADIO_RESTART), SLOT_ID_0, GetHandler());
#endif
    return;
}

/**
 * @tc.number Telephony_TelRil_EnterErrorPin2Test_0101 to do ...
 * @tc.name Enter Error pin2 code of the card 1
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_EnterErrorPin2Test_0101, Function | MediumTest | Level3)
{
#ifdef TEL_TEST_PIN_PUK
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_ENTER_ERROR_PIN2), SLOT_ID_0, GetHandler());
#endif
    return;
}

/**
 * @tc.number Telephony_TelRil_EnterErrorPin2Test_0102 to do ...
 * @tc.name Enter Error pin2 code of the card 1
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_EnterErrorPin2Test_0102, Function | MediumTest | Level3)
{
#ifdef TEL_TEST_PIN_PUK
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_ENTER_ERROR_PIN2), SLOT_ID_0, GetHandler());
#endif
    return;
}

/**
 * @tc.number Telephony_TelRil_EnterErrorPin2Test_0103 to do ...
 * @tc.name Enter Error pin2 code of the card 1
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_EnterErrorPin2Test_0103, Function | MediumTest | Level3)
{
#ifdef TEL_TEST_PIN_PUK
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_ENTER_ERROR_PIN2), SLOT_ID_0, GetHandler());
#endif
    return;
}

/**
 * @tc.number Telephony_TelRil_UnlockSimPin2Test_0101 to do ...
 * @tc.name Unlock SIM card pin2 code of the card 1
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_UnlockSimPin2Test_0101, Function | MediumTest | Level3)
{
#ifdef TEL_TEST_PIN_PUK
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_UNLOCK_SIM_PIN2), SLOT_ID_0, GetHandler());
#endif
    return;
}

/**
 * @tc.number Telephony_TelRil_UnSetPIn2LockTest_0101 to do ...
 * @tc.name UnSet PIN2 lock status of the card 1
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_UnSetPIn2LockTest_0101, Function | MediumTest | Level3)
{
#ifdef TEL_TEST_PIN_PUK
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_UNSET_PIN2_LOCK), SLOT_ID_0, GetHandler());
#endif
    return;
}

/**
 * @tc.number Telephony_TelRil_EnableSimCardTest_0101 to do ...
 * @tc.name Enable SIM card of the card 1
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_EnableSimCardTest_0101, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_ENABLE_SIM_CARD), SLOT_ID_0, GetHandler());
    return;
}

/**
 * @tc.number Telephony_TelRil_GetSimLockStatusTest_0201 to do ...
 * @tc.name Get SIM card lock status of the card 2
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_GetSimLockStatusTest_0201, Function | MediumTest | Level3)
{
#ifdef TEL_TEST_PIN_PUK
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_GET_SIM_LOCK_STATUS), SLOT_ID_1, GetHandler());
#endif
    return;
}

/**
 * @tc.number Telephony_TelRil_SetSimLockTest_0201 to do ...
 * @tc.name Set SIM card lock status of the card 2
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_SetSimLockTest_0201, Function | MediumTest | Level3)
{
#ifdef TEL_TEST_PIN_PUK
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_SET_SIM_LOCK), SLOT_ID_1, GetHandler());
#endif
    return;
}

/**
 * @tc.number Telephony_TelRil_ChangeSimPasswordTest_0201 to do ...
 * @tc.name Change SIM card Password of the card 2
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_ChangeSimPasswordTest_0201, Function | MediumTest | Level3)
{
#ifdef TEL_TEST_PIN_PUK
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_GET_CHANGE_SIM_PASSWD), SLOT_ID_1, GetHandler());
#endif
    return;
}

/**
 * @tc.number Telephony_TelRil_RadioRestartTest_0201 to do ...
 * @tc.name Restart Radio of the card 2
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_RadioRestartTest_0201, Function | MediumTest | Level3)
{
#ifdef TEL_TEST_PIN_PUK
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_RADIO_RESTART), SLOT_ID_1, GetHandler());
#endif
    return;
}

/**
 * @tc.number Telephony_TelRil_EnterSimPinTest_0201 to do ...
 * @tc.name Enter SIM card pin code of the card 2
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_EnterSimPinTest_0201, Function | MediumTest | Level3)
{
#ifdef TEL_TEST_PIN_PUK
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_ENTER_SIM_PIN), SLOT_ID_1, GetHandler());
#endif
    return;
}

/**
 * @tc.number Telephony_TelRil_RadioRestartTest_0202 to do ...
 * @tc.name Restart Radio of the card 2
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_RadioRestartTest_0202, Function | MediumTest | Level3)
{
#ifdef TEL_TEST_PIN_PUK
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_RADIO_RESTART), SLOT_ID_1, GetHandler());
#endif
    return;
}

/**
 * @tc.number Telephony_TelRil_ErrorPINCodeTest_0201 to do ...
 * @tc.name Enter Error PIN of the card 2
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_EnterErrorPINTest_0201, Function | MediumTest | Level3)
{
#ifdef TEL_TEST_PIN_PUK
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_ENTER_ERROR_PIN), SLOT_ID_1, GetHandler());
#endif
    return;
}

/**
 * @tc.number Telephony_TelRil_ErrorPINCodeTest_0202 to do ...
 * @tc.name Enter Error PIN of the card 2
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_EnterErrorPINTest_0202, Function | MediumTest | Level3)
{
#ifdef TEL_TEST_PIN_PUK
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_ENTER_ERROR_PIN), SLOT_ID_1, GetHandler());
#endif
    return;
}

/**
 * @tc.number Telephony_TelRil_ErrorPINCodeTest_0203 to do ...
 * @tc.name Enter Error PIN of the card 2
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_EnterErrorPINTest_0203, Function | MediumTest | Level3)
{
#ifdef TEL_TEST_PIN_PUK
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_ENTER_ERROR_PIN), SLOT_ID_1, GetHandler());
#endif
    return;
}

/**
 * @tc.number Telephony_TelRil_UnlockSimPinTest_0201 to do ...
 * @tc.name Unlock SIM card pin code of the card 2
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_UnlockSimPinTest_0201, Function | MediumTest | Level3)
{
#ifdef TEL_TEST_PIN_PUK
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_UNLOCK_SIM_PIN), SLOT_ID_1, GetHandler());
#endif
    return;
}

/**
 * @tc.number Telephony_TelRil_UnSetSimLockTest_0201 to do ...
 * @tc.name UnSet SIM card lock status of the card 2
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_UnSetSimLockTest_0201, Function | MediumTest | Level3)
{
#ifdef TEL_TEST_PIN_PUK
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_UNSET_SIM_LOCK), SLOT_ID_1, GetHandler());
#endif
    return;
}

/**
 * @tc.number Telephony_TelRil_SetPIn2LockTest_0201 to do ...
 * @tc.name Set PIN2 lock status of the card 2
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_SetPIn2LockTest_0201, Function | MediumTest | Level3)
{
#ifdef TEL_TEST_PIN_PUK
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_SET_PIN2_LOCK), SLOT_ID_1, GetHandler());
#endif
    return;
}

/**
 * @tc.number Telephony_TelRil_RadioRestartTest_0203 to do ...
 * @tc.name Restart Radio of the card 2
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_RadioRestartTest_0203, Function | MediumTest | Level3)
{
#ifdef TEL_TEST_PIN_PUK
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_RADIO_RESTART), SLOT_ID_1, GetHandler());
#endif
    return;
}

/**
 * @tc.number Telephony_TelRil_EnterSimPin2Test_0201 to do ...
 * @tc.name Enter SIM card pin2 code of the card 2
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_EnterSimPin2Test_0201, Function | MediumTest | Level3)
{
#ifdef TEL_TEST_PIN_PUK
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_ENTER_SIM_PIN2), SLOT_ID_1, GetHandler());
#endif
    return;
}

/**
 * @tc.number Telephony_TelRil_SetPIn2LockTest_0202 to do ...
 * @tc.name Set PIN2 lock status of the card 2
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_SetPIn2LockTest_0202, Function | MediumTest | Level3)
{
#ifdef TEL_TEST_PIN_PUK
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_SET_PIN2_LOCK), SLOT_ID_1, GetHandler());
#endif
    return;
}

/**
 * @tc.number Telephony_TelRil_RadioRestartTest_0204 to do ...
 * @tc.name Restart Radio of the card 2
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_RadioRestartTest_0204, Function | MediumTest | Level3)
{
#ifdef TEL_TEST_PIN_PUK
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_RADIO_RESTART), SLOT_ID_1, GetHandler());
#endif
    return;
}

/**
 * @tc.number Telephony_TelRil_EnterErrorPin2Test_0201 to do ...
 * @tc.name Enter Error pin2 code of the card 2
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_EnterErrorPin2Test_0201, Function | MediumTest | Level3)
{
#ifdef TEL_TEST_PIN_PUK
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_ENTER_ERROR_PIN2), SLOT_ID_1, GetHandler());
#endif
    return;
}

/**
 * @tc.number Telephony_TelRil_EnterErrorPin2Test_0202 to do ...
 * @tc.name Enter Error pin2 code of the card 2
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_EnterErrorPin2Test_0202, Function | MediumTest | Level3)
{
#ifdef TEL_TEST_PIN_PUK
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_ENTER_ERROR_PIN2), SLOT_ID_1, GetHandler());
#endif
    return;
}

/**
 * @tc.number Telephony_TelRil_EnterErrorPin2Test_0203 to do ...
 * @tc.name Enter Error pin2 code of the card 2
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_EnterErrorPin2Test_0203, Function | MediumTest | Level3)
{
#ifdef TEL_TEST_PIN_PUK
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_ENTER_ERROR_PIN2), SLOT_ID_1, GetHandler());
#endif
    return;
}

/**
 * @tc.number Telephony_TelRil_UnlockSimPin2Test_0201 to do ...
 * @tc.name Unlock SIM card pin2 code of the card 2
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_UnlockSimPin2Test_0201, Function | MediumTest | Level3)
{
#ifdef TEL_TEST_PIN_PUK
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_UNLOCK_SIM_PIN2), SLOT_ID_1, GetHandler());
#endif
    return;
}

/**
 * @tc.number Telephony_TelRil_UnSetPIn2LockTest_0201 to do ...
 * @tc.name UnSet PIN2 lock status of the card 2
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_UnSetPIn2LockTest_0201, Function | MediumTest | Level3)
{
#ifdef TEL_TEST_PIN_PUK
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_UNSET_PIN2_LOCK), SLOT_ID_1, GetHandler());
#endif
    return;
}

/**
 * @tc.number Telephony_TelRil_EnableSimCardTest_0201 to do ...
 * @tc.name Enable SIM card of the card 2
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_EnableSimCardTest_0201, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_ENABLE_SIM_CARD), SLOT_ID_1, GetHandler());
    return;
}

/**
 * @tc.number Telephony_TelRil_GetRadioProtocolTest_0101 to do ...
 * @tc.name Get radio capability of the card 1
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_GetRadioProtocolTest_0101, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_GET_RADIO_PROTOCOL), SLOT_ID_0, GetHandler());
    return;
}

/**
 * @tc.number Telephony_TelRil_GetRadioProtocolTest_0201 to do ...
 * @tc.name Get radio capability of the card 2
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_GetRadioProtocolTest_0201, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_GET_RADIO_PROTOCOL), SLOT_ID_1, GetHandler());
    return;
}

/**
 * @tc.number Telephony_TelRil_SetRadioProtocolTest_0101 to do ...
 * @tc.name Set radio capability of the card 1
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_SetRadioProtocolTest_0101, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_SET_RADIO_PROTOCOL), SLOT_ID_0, GetHandler());
    return;
}

/**
 * @tc.number Telephony_TelRil_SetRadioProtocolTest_0201 to do ...
 * @tc.name Set radio capability of the card 2
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_SetRadioProtocolTest_0201, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_SET_RADIO_PROTOCOL), SLOT_ID_1, GetHandler());
    return;
}

/**
 * @tc.number Telephony_TelRil_SendTerminalResponseCmdTest_0101 to do ...
 * @tc.name Send terminal response command of the card 1
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_SendTerminalResponseCmdTest_0101, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_STK_SEND_TERMINAL_RESPONSE), SLOT_ID_0, GetHandler());
    return;
}

/**
 * @tc.number Telephony_TelRil_SendTerminalResponseCmdTest_0201 to do ...
 * @tc.name Send terminal response command of the card 2
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_SendTerminalResponseCmdTest_0201, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_STK_SEND_TERMINAL_RESPONSE), SLOT_ID_1, GetHandler());
    return;
}

/**
 * @tc.number Telephony_TelRil_SendEnvelopeCmdTest_0101 to do ...
 * @tc.name Send envelope command of the card 1
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_SendEnvelopeCmdTest_0101, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_STK_SEND_ENVELOPE), SLOT_ID_0, GetHandler());
    return;
}

/**
 * @tc.number Telephony_TelRil_SendEnvelopeCmdTest_0201 to do ...
 * @tc.name Send envelope command of the card 2
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_SendEnvelopeCmdTest_0201, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_STK_SEND_ENVELOPE), SLOT_ID_1, GetHandler());
    return;
}

/**
 * @tc.number Telephony_TelRil_SendCallSetupRequestResultTest_0101 to do ...
 * @tc.name Send Call Setup Request Result command of the card 1
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_SendCallSetupRequestResultTest_0101, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_STK_SEND_CALL_SETUP_REQUEST_RESULT), SLOT_ID_0,
                GetHandler());
    return;
}

/**
 * @tc.number Telephony_TelRil_SendCallSetupRequestResultTest_0201 to do ...
 * @tc.name Send Call Setup Request Result command of the card 2
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_SendCallSetupRequestResultTest_0201, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_STK_SEND_CALL_SETUP_REQUEST_RESULT), SLOT_ID_1,
                GetHandler());
    return;
}
#endif // TEL_TEST_UNSUPPORT
} // namespace Telephony
} // namespace OHOS
