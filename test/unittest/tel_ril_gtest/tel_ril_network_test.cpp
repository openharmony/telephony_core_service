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
 * @tc.number Telephony_TelRil_NetworkOperatorTest_0101 to do ...
 * @tc.name Get operator information of the card 1
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_NetworkOperatorTest_0101, Function | MediumTest | Level3)
{
    ASSERT_TRUE(ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_OPERATOR), SLOT_ID_0, GetHandler()));
    return;
}

/**
 * @tc.number Telephony_TelRil_NetworkOperatorTest_0201 to do ...
 * @tc.name Get operator information of the card 2
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_NetworkOperatorTest_0201, Function | MediumTest | Level3)
{
    ASSERT_TRUE(ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_OPERATOR), SLOT_ID_1, GetHandler()));
    return;
}

/**
 * @tc.number Telephony_TelRil_NetworkVoiceRegistrationStateTest_0101 to do ...
 * @tc.name Voice registration state of the card 1
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_NetworkVoiceRegistrationStateTest_0101, Function | MediumTest | Level3)
{
    ASSERT_TRUE(ProcessTest(
        static_cast<int32_t>(DiffInterfaceId::TEST_GET_RILCM_VOICE_REGISTRATION_STATE), SLOT_ID_0, GetHandler()));
    return;
}

/**
 * @tc.number Telephony_TelRil_NetworkVoiceRegistrationStateTest_0201 to do ...
 * @tc.name Voice registration state of the card 2
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_NetworkVoiceRegistrationStateTest_0201, Function | MediumTest | Level3)
{
    ASSERT_TRUE(ProcessTest(
        static_cast<int32_t>(DiffInterfaceId::TEST_GET_RILCM_VOICE_REGISTRATION_STATE), SLOT_ID_1, GetHandler()));
    return;
}

/**
 * @tc.number Telephony_TelRil_NetworkDataRegistrationStateTest_0101 to do ...
 * @tc.name Data registration state of the card 1
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_NetworkDataRegistrationStateTest_0101, Function | MediumTest | Level3)
{
    ASSERT_TRUE(ProcessTest(
        static_cast<int32_t>(DiffInterfaceId::TEST_GET_RILCM_DATA_REGISTRATION_STATE), SLOT_ID_0, GetHandler()));
    return;
}

/**
 * @tc.number Telephony_TelRil_NetworkDataRegistrationStateTest_0201 to do ...
 * @tc.name Data registration state of the card 2
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_NetworkDataRegistrationStateTest_0201, Function | MediumTest | Level3)
{
    ASSERT_TRUE(ProcessTest(
        static_cast<int32_t>(DiffInterfaceId::TEST_GET_RILCM_DATA_REGISTRATION_STATE), SLOT_ID_1, GetHandler()));
    return;
}

/**
 * @tc.number Telephony_TelRil_GetNetworkSearchInformationTest_0101 to do ...
 * @tc.name Search for carrier information of the card 1
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_GetNetworkSearchInformationTest_0101, Function | MediumTest | Level3)
{
    ASSERT_TRUE(ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_GET_NETWORKS_TO_USE), SLOT_ID_0, GetHandler()));
    return;
}

/**
 * @tc.number Telephony_TelRil_GetNetworkSearchInformationTest_0201 to do ...
 * @tc.name Search for carrier information of the card 2
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_GetNetworkSearchInformationTest_0201, Function | MediumTest | Level3)
{
    ASSERT_TRUE(ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_GET_NETWORKS_TO_USE), SLOT_ID_1, GetHandler()));
    return;
}

/**
 * @tc.number Telephony_TelRil_GetNetworkSelectionModeTest_0101 to do ...
 * @tc.name Get network selection mode of the card 1
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_GetNetworkSelectionModeTest_0101, Function | MediumTest | Level3)
{
    ASSERT_TRUE(ProcessTest(
        static_cast<int32_t>(DiffInterfaceId::TEST_GET_SELECTION_MOD_FOR_NETWORKS), SLOT_ID_0, GetHandler()));
    return;
}

/**
 * @tc.number Telephony_TelRil_GetNetworkSelectionModeTest_0201 to do ...
 * @tc.name Get network selection mode of the card 2
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_GetNetworkSelectionModeTest_0201, Function | MediumTest | Level3)
{
    ASSERT_TRUE(ProcessTest(
        static_cast<int32_t>(DiffInterfaceId::TEST_GET_SELECTION_MOD_FOR_NETWORKS), SLOT_ID_1, GetHandler()));
    return;
}

/**
 * @tc.number Telephony_TelRil_SetNetworkSelectionModeTest_0101 to do ...
 * @tc.name Set network selection mode of the card 1
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_SetNetworkSelectionModeTest_0101, Function | MediumTest | Level3)
{
    ASSERT_TRUE(
        ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_SET_MODE_AUTOMATIC_NETWORKS), SLOT_ID_0, GetHandler()));
    return;
}

/**
 * @tc.number Telephony_TelRil_SetNetworkSelectionModeTest_0201 to do ...
 * @tc.name Set network selection mode of the card 2
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_SetNetworkSelectionModeTest_0201, Function | MediumTest | Level3)
{
    ASSERT_TRUE(
        ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_SET_MODE_AUTOMATIC_NETWORKS), SLOT_ID_1, GetHandler()));
    return;
}

/**
 * @tc.number Telephony_TelRil_GetPreferredNetworkParaTest_0101 to do ...
 * @tc.name Get preferred network parameters of the card 1
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_GetPreferredNetworkParaTest_0101, Function | MediumTest | Level3)
{
    ASSERT_TRUE(
        ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_GET_PREFERRED_NETWORK_TYPE), SLOT_ID_0, GetHandler()));
    return;
}

/**
 * @tc.number Telephony_TelRil_GetPreferredNetworkParaTest_0201 to do ...
 * @tc.name Get preferred network parameters of the card 2
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_GetPreferredNetworkParaTest_0201, Function | MediumTest | Level3)
{
    ASSERT_TRUE(
        ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_GET_PREFERRED_NETWORK_TYPE), SLOT_ID_1, GetHandler()));
    return;
}

/**
 * @tc.number Telephony_TelRil_SetPreferredNetworkParaTest_0101 to do ...
 * @tc.name Set preferred network parameters of the card 1
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_SetPreferredNetworkParaTest_0101, Function | MediumTest | Level3)
{
    ASSERT_TRUE(
        ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_SET_PREFERRED_NETWORK_TYPE), SLOT_ID_0, GetHandler()));
    return;
}

/**
 * @tc.number Telephony_TelRil_SetPreferredNetworkParaTest_0201 to do ...
 * @tc.name Set preferred network parameters of the card 2
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_SetPreferredNetworkParaTest_0201, Function | MediumTest | Level3)
{
    ASSERT_TRUE(
        ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_SET_PREFERRED_NETWORK_TYPE), SLOT_ID_1, GetHandler()));
    return;
}

/**
 * @tc.number Telephony_TelRil_GetImeiTest_0101 to do ...
 * @tc.name Get Imei information of the card 1
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_GetImeiTest_0101, Function | MediumTest | Level3)
{
    ASSERT_TRUE(ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_GET_IMEI), SLOT_ID_0, GetHandler()));
    return;
}

/**
 * @tc.number Telephony_TelRil_GetImeiTest_0201 to do ...
 * @tc.name Get Imei information of the card 2
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_GetImeiTest_0201, Function | MediumTest | Level3)
{
    ASSERT_TRUE(ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_GET_IMEI), SLOT_ID_1, GetHandler()));
    return;
}

/**
 * @tc.number Telephony_TelRil_GetMeidTest_0101 to do ...
 * @tc.name Get Meid information of the card 1
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_GetMeidTest_0101, Function | MediumTest | Level3)
{
    ASSERT_TRUE(ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_GET_MEID), SLOT_ID_0, GetHandler()));
    return;
}

/**
 * @tc.number Telephony_TelRil_GetMeidTest_0201 to do ...
 * @tc.name Get Meid information of the card 2
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_GetMeidTest_0201, Function | MediumTest | Level3)
{
    ASSERT_TRUE(ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_GET_MEID), SLOT_ID_1, GetHandler()));
    return;
}

/**
 * @tc.number Telephony_TelRil_GetVoiceRadioTechnologyTest_0101 to do ...
 * @tc.name Get voice radio technology of the card 1
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_GetVoiceRadioTechnologyTest_0101, Function | MediumTest | Level3)
{
    ASSERT_TRUE(ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_GET_VOICE_RADIO_INFO), SLOT_ID_0, GetHandler()));
    return;
}

/**
 * @tc.number Telephony_TelRil_GetVoiceRadioTechnologyTest_0201 to do ...
 * @tc.name Get voice radio technology of the card 2
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_GetVoiceRadioTechnologyTest_0201, Function | MediumTest | Level3)
{
    ASSERT_TRUE(ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_GET_VOICE_RADIO_INFO), SLOT_ID_1, GetHandler()));
    return;
}

/**
 * @tc.number Telephony_TelRil_GetPhysicalChannelConfigTest_0101 to do ...
 * @tc.name Get physical channel config of the card 1
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_GetPhysicalChannelConfigTest_0101, Function | MediumTest | Level3)
{
    ASSERT_TRUE(
        ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_GET_PHYSICAL_CHANNEL_CONFIG), SLOT_ID_0, GetHandler()));
    return;
}

/**
 * @tc.number Telephony_TelRil_GetPhysicalChannelConfigTest_0201 to do ...
 * @tc.name Get physical channel config of the card 2
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_GetPhysicalChannelConfigTest_0201, Function | MediumTest | Level3)
{
    ASSERT_TRUE(
        ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_GET_PHYSICAL_CHANNEL_CONFIG), SLOT_ID_1, GetHandler()));
    return;
}

/**
 * @tc.number Telephony_TelRil_SetLocateUpdatesTest_0101 to do ...
 * @tc.name Set locate updates of the card 1
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_SetLocateUpdatesTest_0101, Function | MediumTest | Level3)
{
    ASSERT_TRUE(ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_SET_LOCATE_UPDATES), SLOT_ID_0, GetHandler()));
    return;
}

/**
 * @tc.number Telephony_TelRil_SetLocateUpdatesTest_0201 to do ...
 * @tc.name Set locate updates of the card 2
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_SetLocateUpdatesTest_0201, Function | MediumTest | Level3)
{
    ASSERT_TRUE(ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_SET_LOCATE_UPDATES), SLOT_ID_1, GetHandler()));
    return;
}

/**
 * @tc.number Telephony_TelRil_SetNotificationFilterTest_0101 to do ...
 * @tc.name Set notification filter of the card 1
 * @tc.desc Function test
 * @tc.require: issueI5BFY5
 */
HWTEST_F(TelRilTest, Telephony_TelRil_SetNotificationFilterTest_0101, Function | MediumTest | Level3)
{
    ASSERT_TRUE(
        ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_SET_NOTIFICATION_FILTER), SLOT_ID_0, GetHandler()));
    return;
}

/**
 * @tc.number Telephony_TelRil_SetNotificationFilterTest_0201 to do ...
 * @tc.name Set notification filter of the card 2
 * @tc.desc Function test
 * @tc.require: issueI5BFY5
 */
HWTEST_F(TelRilTest, Telephony_TelRil_SetNotificationFilterTest_0201, Function | MediumTest | Level3)
{
    ASSERT_TRUE(
        ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_SET_NOTIFICATION_FILTER), SLOT_ID_1, GetHandler()));
    return;
}

/**
 * @tc.number Telephony_TelRil_SetDeviceStateTest_0101 to do ...
 * @tc.name Set device state of the card 1
 * @tc.desc Function test
 * @tc.require: issueI5BFY5
 */
HWTEST_F(TelRilTest, Telephony_TelRil_SetDeviceStateTest_0101, Function | MediumTest | Level3)
{
    ASSERT_TRUE(ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_SET_DEVICE_STATE), SLOT_ID_0, GetHandler()));
    return;
}

/**
 * @tc.number Telephony_TelRil_SetDeviceStateTest_0201 to do ...
 * @tc.name Set device state of the card 2
 * @tc.desc Function test
 * @tc.require: issueI5BFY5
 */
HWTEST_F(TelRilTest, Telephony_TelRil_SetDeviceStateTest_0201, Function | MediumTest | Level3)
{
    ASSERT_TRUE(ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_SET_DEVICE_STATE), SLOT_ID_1, GetHandler()));
    return;
}
#endif // TEL_TEST_UNSUPPORT
} // namespace Telephony
} // namespace OHOS
