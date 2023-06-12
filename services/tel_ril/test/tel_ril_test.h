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
#ifndef OHOS_TEL_RIL_TEST_H
#define OHOS_TEL_RIL_TEST_H

#include <iostream>

#include "radio_event.h"
#include "securec.h"
#include "tel_ril_manager.h"
#include "telephony_log_wrapper.h"

namespace OHOS {
namespace Telephony {
enum class DiffInterfaceId {
    TEST_GET_SIM_CARD_STATUS = 1,
    TEST_SIM_IO,
    TEST_OPEN_LG_SIMIO,
    TEST_TRANSMIT_APDU_LOGICAL_CHANNEL,
    TEST_TRANSMIT_APDU_BASIC_CHANNEL,
    TEST_CLOSE_LG_SIMIO,
    TEST_SIM_AUTH,
    TEST_GET_IMSI,
    TEST_GET_ICCID,
    TEST_GET_SIM_LOCK_STATUS,
    TEST_SET_SIM_LOCK,
    TEST_GET_CHANGE_SIM_PASSWD,
    TEST_ENTER_SIM_PIN,
    TEST_UNLOCK_SIM_PIN,
    TEST_ENTER_SIM_PIN2,
    TEST_UNLOCK_SIM_PIN2,
    TEST_ENABLE_SIM_CARD,
    TEST_GET_RILCM_VOICE_REGISTRATION_STATE_TEST,
    TEST_GET_RILCM_DATA_REGISTRATION_STATE_TEST,
    TEST_ACKNOWLEDGE_RILCM_LAST_INCOMING_GSM_SMS_TEST,
    TEST_STK_SEND_TERMINAL_RESPONSE,
    TEST_STK_SEND_ENVELOPE,
    TEST_STK_SEND_CALL_SETUP_REQUEST_RESULT,
    /* =========== Cellular Data Start ============= */
    TEST_RILCM_SET_INIT_APN_INFO_TEST,
    TEST_RILCM_SETUP_DATA_CALL_TEST,
    TEST_RILCM_DEACTIVATE_DATA_CALL_TEST,
    TEST_RILCM_GET_DATA_CALL_LIST_TEST,
    TEST_RILCM_GET_LINK_BANDWIDTH_INFO,
    TEST_RILCM_SET_LINK_BANDWIDTH_REPORTING_RULE,
    TEST_RILCM_SET_DATA_PERMITTED_TEST,
    TEST_RILCM_GET_LINK_CAPABILITY,
    /* =========== Cellular Data End ============= */
    TEST_GET_SIGNAL_STRENGTH,
    TEST_CALL_DIAL,
    TEST_HANDUP_CONNECT,
    TEST_ACCEPT_CALL,
    TEST_HOLD_CALL,
    TEST_ACTIVE_CALL,
    TEST_SWAP_CALL,
    TEST_CURRENT_CALLS,
    TEST_REJECT_CALL,
    TEST_JOIN_CALL,
    TEST_SPLIT_CALL,
    TEST_GET_CALL_WAIT,
    TEST_SET_CALL_WAIT,
    TEST_GET_CALL_FORWARD,
    TEST_SET_CALL_FORWARD,
    TEST_GET_CALL_DEAL_CLIP,
    TEST_SET_CALL_CLIP,
    TEST_GET_CALL_DEAL_CLIR,
    TEST_SET_CALL_CLIR,
    TEST_GET_CALL_RESTRICTION,
    TEST_SET_CALL_RESTRICTION,
    TEST_SEND_DTMF,
    TEST_START_DTMF,
    TEST_STOP_DTMF,
    TEST_SEND_SMS,
    TEST_SEND_CDMA_SMS,
    TEST_STORAGE_SMS,
    TEST_DELETE_SMS,
    TEST_UPDATE_SMS,
    TEST_SET_SMS_CENTER_ADDRESS,
    TEST_GET_SMS_CENTER_ADDRESS,
    TEST_SET_CB_CONFIG,
    TEST_SET_CDMA_CB_CONFIG,
    TEST_GET_CB_CONFIG,
    TEST_GET_CDMA_CB_CONFIG,
    TEST_SEND_SMS_EXPECT_MORE,
    TEST_ADD_CDMA_SMS,
    TEST_DEL_CDMA_SMS,
    TEST_UPDATE_CDMA_SMS,

    TEST_SHUT_DOWN,
    TEST_SET_POWER_STATE,
    TEST_GET_POWER_STATE,
    TEST_OPERATOR,
    TEST_GET_NETWORKS_TO_USE,
    TEST_GET_SELECTION_MOD_FOR_NETWORKS,
    TEST_SET_MODE_AUTOMATIC_NETWORKS,
    TEST_GET_CURRENT_CELL_INFO,
    TEST_GET_CELL_INFO_LIST,
    TEST_GET_PREFERRED_NETWORK_TYPE,
    TEST_SET_PREFERRED_NETWORK_TYPE,
    TEST_GET_IMEI,
    TEST_GET_BASEBAND_VERSION,
    TEST_GET_MEID,
    TEST_SET_CALL_PREFERENCE_MODE,
    TEST_GET_CALL_PREFERENCE_MODE,
    TEST_GET_CS_REG_STATUS,
    TEST_GET_PS_REG_STATUS,
    TEST_GET_RADIO_PROTOCOL,
    TEST_SET_RADIO_PROTOCOL,
    TEST_GET_VOICE_RADIO_INFO,
    TEST_GET_PHYSICAL_CHANNEL_CONFIG,
    TEST_SET_LOCATE_UPDATES,
    TEST_SET_NOTIFICATION_FILTER,
    TEST_SET_DEVICE_STATE,
    TEST_SET_USSD,
    TEST_GET_USSD,
    TEST_SET_MUTE,
    TEST_GET_MUTE,
    TEST_GET_XLEMA,
    TEST_GET_CALL_FAIL,
    TEST_SET_VONR_SWITCH,
    TEST_EXIT,
};

enum class CustomMessageID : uint32_t {
    MSG_OPEN_LOGICAL_CHANNEL_DONE = 0x7f000000,
    MSG_TRANSMIT_LOGICAL_CHANNEL_DONE = 0x7f000001,
    MSG_CLOSE_LOGICAL_CHANNEL_DONE = 0x7f000002,
    MSG_TRANSMIT_BASIC_CHANNEL_DONE = 0x7f000003,
    MSG_SIM_AUTHENTICATION_DONE = 0x7f000004
};

const int32_t CID = 1;
const int32_t REASON = 2;
const int32_t TYPE = 7;
const int32_t MAXCONNSTIME = 8;
const int32_t MAXCONNS = 9;
const int32_t TYPESBITMAP = 12;
const int32_t P3 = 15;
const int32_t COMMAND = 192;
const int32_t FILEID = 20272;
const int32_t AUTHTYPE_1 = 0;
const int32_t BANDWIDTH_HYSTERESIS_MS = 3000;
const int32_t BANDWIDTH_HYSTERESIS_KBPS = 50;
const int32_t MAX_DOWNLINK_LINK_BANDWIDTH[11] = { 100, // VoIP
    500, // Web
    1000, // SD
    5000, // HD
    10000, // file
    20000, // 4K
    50000, // LTE
    100000,
    200000, // 5G
    500000, 1000000 };
const int32_t MAX_UPLINK_LINK_BANDWIDTH[9] = { 100, 500, 1000, 5000, 10000, 20000, 50000, 100000, 200000 };

using namespace OHOS;
using namespace OHOS::Telephony;
using namespace std;

class TelRilTest {
public:
    TelRilTest();

    ~TelRilTest();

    std::shared_ptr<ITelRilManager> telRilManager_ = nullptr;

    void OnInitInterface();

    void OnInitCall();

    void OnInitSms();

    void OnInitSim();

    void OnInitNetwork();

    void OnInitForRegister(int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnProcessInput(int32_t slotId, int32_t what, const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestCallGetCurrentCallsStatusTest(
        int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestSimGetSimStatusTest(int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestSimIccIoTest(int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestOpenLGSimIOTest(int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestTransmitApduLogicalChannelTest(int32_t slotId,
        const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestTransmitApduBasicChannelTest(int32_t slotId,
        const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestSimAuthenticationTest(int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestCloseLGSimIOTest(int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestSimGetImsiTest(int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestGetSimLockStatusTest(int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestSetSimLockTest(int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestChangeSimPasswordTest(int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestEnterSimPinTest(int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestUnlockSimPinTest(int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestEnterSimPin2Test(int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestUnlockSimPin2Test(int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestSetActiveSimTest(int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestGetRadioProtocolTest(int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestSetRadioProtocolTest(int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestSendTerminalResponseCmdTest(int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestSendEnvelopeCmdTest(int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestSendCallSetupRequestResultTest(
        int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestNetworkGetRssiTest(int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestRefusedCallTest(int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestGetCallWaitTest(int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestSetCallWaitTest(int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestCallHangupTest(int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestCallJoinTest(int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestSeparateConferenceTest(int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestCallAnswerTest(int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestCallHoldTest(int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestCallDialTest(int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestCallActiveTest(int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestCallSwapTest(int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestGetClipTest(int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestSendDtmfTest(int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestStartDtmfTest(int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestStopDtmfTest(int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestSetClipTest(int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestGetClirTest(int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestSetClirTest(int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestGetCallRestrictionTest(int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestSetCallRestrictionTest(int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestNetworkVoiceRegistrationStateTest(
        int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestNetworkDataRegistrationStateTest(
        int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestGetCallForwardTest(int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestSetCallForwardTest(int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestNetworkOperatorTest(int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestSendRilCmSmsTest(int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestSendRilCmCdmaSmsTest(int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestStorageRilCmSmsTest(int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestDeleteRilCmSmsTest(int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestUpdateRilCmSmsTest(int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestSetRilCmSmsCenterAddressTest(
        int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestGetRilCmSmsCenterAddressTest(
        int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestSetRilCBConfigTest(int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestSetRilCdmaCBConfigTest(int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestGetRilCBConfigTest(int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestGetRilCdmaCBConfigTest(int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestSmsSendSmsExpectMoreTest(int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestAddRilCmCdmaSmsTest(int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestDelRilCmCdmaSmsTest(int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestUpdateRilCmCdmaSmsTest(int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestShutDownTest(int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestSetRadioStateTest(int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestGetRadioStateTest(int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestGetCellInfoListTest(int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestGetCurrentCellInfoTest(int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestSmsAcknowledgeTest(int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestSetInitApnInfoTest(int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    void OnRequestDataSetupDataCallTest(int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    void OnRequestDataDisableDataCallTest(int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    void OnRequestGetDataCallListTest(int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    void OnRequestGetLinkBandwidthInfoTest(int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    void OnRequestSetLinkBandwidthReportingRuleTest(
        int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    void OnRequestSetDataPermittedTest(int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    void OnRequestGetLinkCapabilityTest(int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestGetNetworkSearchInformationTest(
        int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    void OnRequestGetNetworkSelectionModeTest(
        int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    void OnRequestSetNetworkSelectionModeTest(
        int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    void OnRequestSetPreferredNetworkTest(int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    void OnRequestGetPreferredNetworkTest(int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    void OnRequestGetImeiTest(int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    void OnRequestGetBasebandVersionTest(int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    void OnRequestGetMeidTest(int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    void OnRequestGetCsRegStatusTest(int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    void OnRequestGetPsRegStatusTest(int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    void OnRequestGetVoiceRadioTechnology(int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    void OnRequestGetPhysicalChannelConfig(int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    void OnRequestSetLocateUpdatesTest(int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    void OnRequestSetNotificationFilterTest(int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    void OnRequestSetDeviceStateTest(int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestSetCallPreferenceModeTest(int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    void OnRequestGetCallPreferenceModeTest(int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    void OnRequestSetUssdTest(int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    void OnRequestGetUssdTest(int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    void OnRequestSetMuteTest(int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    void OnRequestGetMuteTest(int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    void OnRequestGetEmergencyCallListTest(int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    void OnRequestGetCallFailReasonTest(int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    void OnRequestSetVoNRSwitchTest(int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    class DemoHandler : public AppExecFwk::EventHandler {
    public:
        explicit DemoHandler(int32_t slotId, const std::shared_ptr<AppExecFwk::EventRunner> &runner)
            : AppExecFwk::EventHandler(runner), slotId_(slotId)
        {}

        ~DemoHandler() {}

        void ProcessEvent(const AppExecFwk::InnerEvent::Pointer &event) override;

    private:
        int32_t slotId_;
        void OnRequestGetBasebandVersionTestResponse(const AppExecFwk::InnerEvent::Pointer &event);
        void OnRequestShutDownTestResponse(const AppExecFwk::InnerEvent::Pointer &event);
    };

private:
    using RilManagerAndResponseTestFun = void (TelRilTest::*)(
        int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    std::map<DiffInterfaceId, RilManagerAndResponseTestFun> memberFuncMap_;
};
} // namespace Telephony
} // namespace OHOS
#endif // OHOS_TEL_RIL_TEST_H
