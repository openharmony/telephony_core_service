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
 * @tc.number Telephony_TelRil_SendRilCmSmsTest_0101 to do ...
 * @tc.name Send SMS of the card 1
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_SendRilCmSmsTest_0101, Function | MediumTest | Level3)
{
    ASSERT_TRUE(ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_SEND_SMS), SLOT_ID_0, GetHandler()));
    return;
}

/**
 * @tc.number Telephony_TelRil_SendRilCmSmsTest_0201 to do ...
 * @tc.name Send SMS of the card 2
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_SendRilCmSmsTest_0201, Function | MediumTest | Level3)
{
    ASSERT_TRUE(ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_SEND_SMS), SLOT_ID_1, GetHandler()));
    return;
}

/**
 * @tc.number Telephony_TelRil_StorageRilCmSmsTest_0101 to do ...
 * @tc.name Storage SMS of the card 1
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_StorageRilCmSmsTest_0101, Function | MediumTest | Level3)
{
    ASSERT_TRUE(ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_STORAGE_SMS), SLOT_ID_0, GetHandler()));
    return;
}

/**
 * @tc.number Telephony_TelRil_StorageRilCmSmsTest_0201 to do ...
 * @tc.name Storage SMS of the card 2
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_StorageRilCmSmsTest_0201, Function | MediumTest | Level3)
{
    ASSERT_TRUE(ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_STORAGE_SMS), SLOT_ID_1, GetHandler()));
    return;
}

/**
 * @tc.number Telephony_TelRil_DeleteRilCmSmsTest_0101 to do ...
 * @tc.name Delete SMS of the card 1
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_DeleteRilCmSmsTest_0101, Function | MediumTest | Level3)
{
    ASSERT_TRUE(ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_DELETE_SMS), SLOT_ID_0, GetHandler()));
    return;
}

/**
 * @tc.number Telephony_TelRil_DeleteRilCmSmsTest_0201 to do ...
 * @tc.name Delete SMS of the card 2
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_DeleteRilCmSmsTest_0201, Function | MediumTest | Level3)
{
    ASSERT_TRUE(ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_DELETE_SMS), SLOT_ID_1, GetHandler()));
    return;
}

/**
 * @tc.number Telephony_TelRil_UpdateRilCmSmsTest_0101 to do ...
 * @tc.name Update SMS of the card 1
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_UpdateRilCmSmsTest_0101, Function | MediumTest | Level3)
{
    ASSERT_TRUE(ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_UPDATE_SMS), SLOT_ID_0, GetHandler()));
    return;
}

/**
 * @tc.number Telephony_TelRil_UpdateRilCmSmsTest_0201 to do ...
 * @tc.name Update SMS of the card 2
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_UpdateRilCmSmsTest_0201, Function | MediumTest | Level3)
{
    ASSERT_TRUE(ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_UPDATE_SMS), SLOT_ID_1, GetHandler()));
    return;
}

/**
 * @tc.number Telephony_TelRil_SetRilCmSmsCenterAddressTest_0101 to do ...
 * @tc.name Set SMS center address of the card 1
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_SetRilCmSmsCenterAddressTest_0101, Function | MediumTest | Level3)
{
    ASSERT_TRUE(
        ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_SET_SMS_CENTER_ADDRESS), SLOT_ID_0, GetHandler()));
    return;
}

/**
 * @tc.number Telephony_TelRil_SetRilCmSmsCenterAddressTest_0201 to do ...
 * @tc.name Set SMS center address of the card 2
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_SetRilCmSmsCenterAddressTest_0201, Function | MediumTest | Level3)
{
    ASSERT_TRUE(
        ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_SET_SMS_CENTER_ADDRESS), SLOT_ID_1, GetHandler()));
    return;
}

/**
 * @tc.number Telephony_TelRil_GetRilCmSmsCenterAddressTest_0101 to do ...
 * @tc.name Get SMS center address of the card 1
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_GetRilCmSmsCenterAddressTest_0101, Function | MediumTest | Level3)
{
    ASSERT_TRUE(
        ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_GET_SMS_CENTER_ADDRESS), SLOT_ID_0, GetHandler()));
    return;
}

/**
 * @tc.number Telephony_TelRil_GetRilCmSmsCenterAddressTest_0201 to do ...
 * @tc.name Get SMS center address of the card 2
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_GetRilCmSmsCenterAddressTest_0201, Function | MediumTest | Level3)
{
    ASSERT_TRUE(
        ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_GET_SMS_CENTER_ADDRESS), SLOT_ID_1, GetHandler()));
    return;
}

/**
 * @tc.number Telephony_TelRil_SetRilCmCBConfigTest_0101 to do ...
 * @tc.name Set SMS cell broadcast of the card 1
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_SetRilCmCBConfigTest_0101, Function | MediumTest | Level3)
{
    ASSERT_TRUE(ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_SET_CB_CONFIG), SLOT_ID_0, GetHandler()));
    return;
}

/**
 * @tc.number Telephony_TelRil_SetRilCmCBConfigTest_0201 to do ...
 * @tc.name Set SMS cell broadcast of the card 2
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_SetRilCmCBConfigTest_0201, Function | MediumTest | Level3)
{
    ASSERT_TRUE(ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_SET_CB_CONFIG), SLOT_ID_1, GetHandler()));
    return;
}

/**
 * @tc.number Telephony_TelRil_GetRilCmCBConfigTest_0101 to do ...
 * @tc.name Get SMS cell broadcast of the card 1
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_GetRilCmCBConfigTest_0101, Function | MediumTest | Level3)
{
    ASSERT_TRUE(ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_GET_CB_CONFIG), SLOT_ID_0, GetHandler()));
    return;
}

/**
 * @tc.number Telephony_TelRil_GetRilCmCBConfigTest_0201 to do ...
 * @tc.name Get SMS cell broadcast of the card 2
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_GetRilCmCBConfigTest_0201, Function | MediumTest | Level3)
{
    ASSERT_TRUE(ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_GET_CB_CONFIG), SLOT_ID_1, GetHandler()));
    return;
}

/**
 * @tc.number Telephony_TelRil_GetRilCmCdmaCBConfigTest_0101 to do ...
 * @tc.name Get CDMA SMS cell broadcast of the card 1
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_GetRilCmCdmaCBConfigTest_0101, Function | MediumTest | Level3)
{
    ASSERT_TRUE(ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_GET_CDMA_CB_CONFIG), SLOT_ID_0, GetHandler()));
    return;
}

/**
 * @tc.number Telephony_TelRil_GetRilCmCdmaCBConfigTest_0201 to do ...
 * @tc.name Get CDMA SMS cell broadcast of the card 2
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_GetRilCmCdmaCBConfigTest_0201, Function | MediumTest | Level3)
{
    ASSERT_TRUE(ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_GET_CDMA_CB_CONFIG), SLOT_ID_1, GetHandler()));
    return;
}

/**
 * @tc.number Telephony_TelRil_SmsSendSmsExpectMoreTest_0101 to do ...
 * @tc.name Send multiple SMS of the card 1
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_SmsSendSmsExpectMoreTest_0101, Function | MediumTest | Level3)
{
    ASSERT_TRUE(ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_SEND_SMS_EXPECT_MORE), SLOT_ID_0, GetHandler()));
    return;
}

/**
 * @tc.number Telephony_TelRil_SmsSendSmsExpectMoreTest_0201 to do ...
 * @tc.name Send multiple SMS of the card 2
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_SmsSendSmsExpectMoreTest_0201, Function | MediumTest | Level3)
{
    ASSERT_TRUE(ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_SEND_SMS_EXPECT_MORE), SLOT_ID_1, GetHandler()));
    return;
}

/**
 * @tc.number Telephony_TelRil_SmsAcknowledgeTest_0101 to do ...
 * @tc.name SMS Acknowledge of the card 1
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_SmsAcknowledgeTest_0101, Function | MediumTest | Level3)
{
    ASSERT_TRUE(ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_SEND_SMS_ACK), SLOT_ID_0, GetHandler()));
    return;
}

/**
 * @tc.number Telephony_TelRil_SmsAcknowledgeTest_0201 to do ...
 * @tc.name SMS Acknowledge of the card 2
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_SmsAcknowledgeTest_0201, Function | MediumTest | Level3)
{
    ASSERT_TRUE(ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_SEND_SMS_ACK), SLOT_ID_1, GetHandler()));
    return;
}

/**
 * @tc.number Telephony_TelRil_AddRilCmCdmaSmsTest_0101 to do ...
 * @tc.name Add CDMA SMS of the card 1
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_AddRilCmCdmaSmsTest_0101, Function | MediumTest | Level3)
{
    ASSERT_TRUE(ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_ADD_CDMA_SMS), SLOT_ID_0, GetHandler()));
    return;
}

/**
 * @tc.number Telephony_TelRil_AddRilCmCdmaSmsTest_0201 to do ...
 * @tc.name Add CDMA SMS of the card 2
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_AddRilCmCdmaSmsTest_0201, Function | MediumTest | Level3)
{
    ASSERT_TRUE(ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_ADD_CDMA_SMS), SLOT_ID_1, GetHandler()));
    return;
}

/**
 * @tc.number Telephony_TelRil_DelRilCmCdmaSmsTest_0101 to do ...
 * @tc.name Delete CDMA SMS of the card 1
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_DelRilCmCdmaSmsTest_0101, Function | MediumTest | Level3)
{
    ASSERT_TRUE(ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_DEL_CDMA_SMS), SLOT_ID_0, GetHandler()));
    return;
}

/**
 * @tc.number Telephony_TelRil_DelRilCmCdmaSmsTest_0201 to do ...
 * @tc.name Delete CDMA SMS of the card 2
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_DelRilCmCdmaSmsTest_0201, Function | MediumTest | Level3)
{
    ASSERT_TRUE(ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_DEL_CDMA_SMS), SLOT_ID_1, GetHandler()));
    return;
}

/**
 * @tc.number Telephony_TelRil_UpdateRilCmCdmaSmsTest_0101 to do ...
 * @tc.name Update CDMA SMS of the card 1
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_UpdateRilCmCdmaSmsTest_0101, Function | MediumTest | Level3)
{
    ASSERT_TRUE(ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_UPDATE_CDMA_SMS), SLOT_ID_0, GetHandler()));
    return;
}

/**
 * @tc.number Telephony_TelRil_UpdateRilCmCdmaSmsTest_0201 to do ...
 * @tc.name Update CDMA SMS of the card 2
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_UpdateRilCmCdmaSmsTest_0201, Function | MediumTest | Level3)
{
    ASSERT_TRUE(ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_UPDATE_CDMA_SMS), SLOT_ID_1, GetHandler()));
    return;
}
#endif // TEL_TEST_UNSUPPORT
} // namespace Telephony
} // namespace OHOS
