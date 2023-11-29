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

#ifndef OHOS_TEL_RIL_TEST_UTIL_H
#define OHOS_TEL_RIL_TEST_UTIL_H

#include <condition_variable>
#include <gtest/gtest.h>
#include <mutex>

#include "core_service_client.h"
#include "tel_ril_manager.h"
#include "sim_state_handle.h"

namespace OHOS {
namespace Telephony {
enum class DiffInterfaceId {
    TEST_GET_SIM_CARD_STATUS = 1,
    TEST_SIM_IO,
    TEST_GET_IMSI,
    TEST_GET_SIM_LOCK_STATUS,
    TEST_SET_SIM_LOCK,
    TEST_SET_PIN2_LOCK,
    TEST_UNSET_SIM_LOCK,
    TEST_UNSET_PIN2_LOCK,
    TEST_SET_UNPIN2_LOCK,
    TEST_GET_CHANGE_SIM_PASSWD,
    TEST_ENTER_SIM_PIN,
    TEST_RADIO_RESTART,
    TEST_UNLOCK_SIM_PIN,
    TEST_ENTER_ERROR_PIN,
    TEST_ENTER_ERROR_PIN2,
    TEST_ENTER_SIM_PIN2,
    TEST_UNLOCK_SIM_PIN2,
    TEST_ENABLE_SIM_CARD,
    TEST_SET_RILCM_DATA_PROFILE,
    TEST_GET_RILCM_VOICE_REGISTRATION_STATE,
    TEST_GET_RILCM_DATA_REGISTRATION_STATE,
    TEST_STK_SEND_TERMINAL_RESPONSE,
    TEST_STK_SEND_ENVELOPE,
    TEST_STK_SEND_CALL_SETUP_REQUEST_RESULT,
    TEST_SEND_SMS_ACK,
    TEST_RILCM_SET_INIT_APN_INFO,
    TEST_RILCM_SETUP_DATA_CALL,
    TEST_RILCM_DEACTIVATE_DATA_CALL,
    TEST_RILCM_GET_DATA_CALL_LIST,
    TEST_RILCM_GET_LINK_BANDWIDTH_INFO,
    TEST_RILCM_SET_LINK_BANDWIDTH_REPORTING_RULE,
    TEST_RILCM_SET_DATA_PERMITTED_TEST,
    TEST_RILCM_GET_LINK_CAPABILITY_TEST,
    TEST_RILCM_CLEAN_ALL_DATA_CONNECTIONS_TEST,
    TEST_GET_SIGNAL_STRENGTH,
    TEST_CALL_DIAL,
    TEST_HANDUP_CONNECT,
    TEST_ACCEPT_CALL,
    TEST_HOLD_CALL,
    TEST_ACTIVE_CALL,
    TEST_SWAP_CALL,
    TEST_JOIN_CALL,
    TEST_SPLIT_CALL,
    TEST_GET_CALL_WAIT,
    TEST_SET_CALL_WAIT,
    TEST_GET_CALL_FORWARD,
    TEST_SET_CALL_FORWARD,
    TEST_GET_CALL_DEAL_CLIP,
    TEST_SET_CALL_CLIP,
    TEST_GET_CALL_RESTRICTION,
    TEST_SET_CALL_RESTRICTION,
    TEST_SET_BARRING_PWD,
    TEST_SEND_DTMF,
    TEST_START_DTMF,
    TEST_STOP_DTMF,
    TEST_RADIO_LAST_CALL_FAIL_CAUSE,
    TEST_CURRENT_CALLS,
    TEST_REJECT_CALL,
    TEST_SEND_IMS_GSM_SMS,
    TEST_SEND_SMS,

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
    TEST_GET_MEID,
    TEST_GET_RADIO_PROTOCOL,
    TEST_SET_RADIO_PROTOCOL,
    TEST_GET_VOICE_RADIO_INFO,
    TEST_GET_PHYSICAL_CHANNEL_CONFIG,
    TEST_SET_LOCATE_UPDATES,
    TEST_SET_NOTIFICATION_FILTER,
    TEST_SET_DEVICE_STATE,
    TEST_SET_USSD,
    TEST_GET_USSD,
    TEST_SET_CMUT,
    TEST_GET_CMUT,
    TEST_GET_EMERGENCY_CALL_LIST,
    TEST_SET_VONR_STATUS,
    TEST_GET_RRC_CONNECTION_STATE,
    TEST_GET_NR_OPTION_MODE,
    TEST_SET_NR_OPTION_MODE,
    TEST_EXIT,
};

class TelRilTest : public testing::Test {
public:
    TelRilTest();
    ~TelRilTest();
    void SetUp();
    void TearDown();
    static void ReStartTelephony();
    static void SetUpTestCase();
    static void TearDownTestCase();
    static sptr<ICoreService> GetProxy();
    bool ProcessTest(int32_t index, int32_t slotId, std::shared_ptr<AppExecFwk::EventHandler> handler);

public:
    class DemoHandler : public AppExecFwk::EventHandler {
    public:
        explicit DemoHandler(const std::shared_ptr<AppExecFwk::EventRunner> &runner)
            : AppExecFwk::EventHandler(runner)
        {}
        virtual ~DemoHandler() {}

        void NotifyAll();
        void WaitFor(int32_t timeoutSecond);
        void ProcessEvent(const AppExecFwk::InnerEvent::Pointer &event) override;
        void ProcessResponseInfo(const AppExecFwk::InnerEvent::Pointer &event);
        bool GetBoolResult(int32_t eventId);
        void Clean();

    private:
        std::mutex callbackMutex_;
        std::condition_variable cv_;
        int32_t eventId_;
        std::shared_ptr<HRilRadioResponseInfo> resultInfo_;
    };

public:
    std::shared_ptr<TelRilTest::DemoHandler> GetHandler();

private:
    void AddRequestToMap();
    void InitCall();
    void InitData();
    void InitSim();
    void InitSms();
    void InitNetwork();
    void InitModem();

    void CallGetCurrentCallsStatusTest(int32_t slotId, std::shared_ptr<AppExecFwk::EventHandler> handler);
    void SimGetSimStatusTest(int32_t slotId, std::shared_ptr<AppExecFwk::EventHandler> handler);
    void SimIccIoTest(int32_t slotId, std::shared_ptr<AppExecFwk::EventHandler> handler);
    void SimGetImsiTest(int32_t slotId, std::shared_ptr<AppExecFwk::EventHandler> handler);
    void GetSimLockStatusTest(int32_t slotId, std::shared_ptr<AppExecFwk::EventHandler> handler);
    void SetSimLockTest(int32_t slotId, std::shared_ptr<AppExecFwk::EventHandler> handler);
    void UnSetSimLockTest(int32_t slotId, std::shared_ptr<AppExecFwk::EventHandler> handler);
    void ChangeSimPasswordTest(int32_t slotId, std::shared_ptr<AppExecFwk::EventHandler> handler);
    void EnterSimPinTest(int32_t slotId, std::shared_ptr<AppExecFwk::EventHandler> handler);
    void RadioRestartTest(int32_t slotId, std::shared_ptr<AppExecFwk::EventHandler> handler);
    void EnterErrorPinTest(int32_t slotId, std::shared_ptr<AppExecFwk::EventHandler> handler);
    void UnlockSimPinTest(int32_t slotId, std::shared_ptr<AppExecFwk::EventHandler> handler);
    void SetPin2LockTest(int32_t slotId, std::shared_ptr<AppExecFwk::EventHandler> handler);
    void UnSetPin2LockTest(int32_t slotId, std::shared_ptr<AppExecFwk::EventHandler> handler);
    void EnterSimPin2Test(int32_t slotId, std::shared_ptr<AppExecFwk::EventHandler> handler);
    void EnterErrorPin2Test(int32_t slotId, std::shared_ptr<AppExecFwk::EventHandler> handler);
    void UnlockSimPin2Test(int32_t slotId, std::shared_ptr<AppExecFwk::EventHandler> handler);
    void EnableSimCardTest(int32_t slotId, std::shared_ptr<AppExecFwk::EventHandler> handler);
    void SetActiveSimTest(int32_t slotId, std::shared_ptr<AppExecFwk::EventHandler> handler);
    void SendTerminalResponseCmdTest(int32_t slotId, std::shared_ptr<AppExecFwk::EventHandler> handler);
    void SendEnvelopeCmdTest(int32_t slotId, std::shared_ptr<AppExecFwk::EventHandler> handler);
    void SendCallSetupRequestResultTest(int32_t slotId, std::shared_ptr<AppExecFwk::EventHandler> handler);
    void NetworkGetRssiTest(int32_t slotId, std::shared_ptr<AppExecFwk::EventHandler> handler);
    void RefusedCallTest(int32_t slotId, std::shared_ptr<AppExecFwk::EventHandler> handler);
    void GetCallWaitTest(int32_t slotId, std::shared_ptr<AppExecFwk::EventHandler> handler);
    void SetCallWaitTest(int32_t slotId, std::shared_ptr<AppExecFwk::EventHandler> handler);
    void CallHangupTest(int32_t slotId, std::shared_ptr<AppExecFwk::EventHandler> handler);
    void CallJoinTest(int32_t slotId, std::shared_ptr<AppExecFwk::EventHandler> handler);
    void CallSplitTest(int32_t slotId, std::shared_ptr<AppExecFwk::EventHandler> handler);
    void CallAnswerTest(int32_t slotId, std::shared_ptr<AppExecFwk::EventHandler> handler);
    void CallHoldTest(int32_t slotId, std::shared_ptr<AppExecFwk::EventHandler> handler);
    void CallDialTest(int32_t slotId, std::shared_ptr<AppExecFwk::EventHandler> handler);
    void CallActiveTest(int32_t slotId, std::shared_ptr<AppExecFwk::EventHandler> handler);
    void CallSwapTest(int32_t slotId, std::shared_ptr<AppExecFwk::EventHandler> handler);
    void GetClipTest(int32_t slotId, std::shared_ptr<AppExecFwk::EventHandler> handler);
    void SendDtmfTest(int32_t slotId, std::shared_ptr<AppExecFwk::EventHandler> handler);
    void StartDtmfTest(int32_t slotId, std::shared_ptr<AppExecFwk::EventHandler> handler);
    void StopDtmfTest(int32_t slotId, std::shared_ptr<AppExecFwk::EventHandler> handler);
    void SetClipTest(int32_t slotId, std::shared_ptr<AppExecFwk::EventHandler> handler);
    void GetCallRestrictionTest(int32_t slotId, std::shared_ptr<AppExecFwk::EventHandler> handler);
    void SetCallRestrictionTest(int32_t slotId, std::shared_ptr<AppExecFwk::EventHandler> handler);
    void SetBarringPasswordTest(int32_t slotId, std::shared_ptr<AppExecFwk::EventHandler> handler);
    void NetworkVoiceRegistrationStateTest(int32_t slotId, std::shared_ptr<AppExecFwk::EventHandler> handler);
    void NetworkDataRegistrationStateTest(int32_t slotId, std::shared_ptr<AppExecFwk::EventHandler> handler);
    void GetRadioProtocolTest(int32_t slotId, std::shared_ptr<AppExecFwk::EventHandler> handler);
    void SetRadioProtocolTest(int32_t slotId, std::shared_ptr<AppExecFwk::EventHandler> handler);
    void GetCallForwardTest(int32_t slotId, std::shared_ptr<AppExecFwk::EventHandler> handler);
    void SetCallForwardTest(int32_t slotId, std::shared_ptr<AppExecFwk::EventHandler> handler);
    void NetworkOperatorTest(int32_t slotId, std::shared_ptr<AppExecFwk::EventHandler> handler);
    void SendRilCmSmsTest(int32_t slotId, std::shared_ptr<AppExecFwk::EventHandler> handler);
    void StorageRilCmSmsTest(int32_t slotId, std::shared_ptr<AppExecFwk::EventHandler> handler);
    void DeleteRilCmSmsTest(int32_t slotId, std::shared_ptr<AppExecFwk::EventHandler> handler);
    void UpdateRilCmSmsTest(int32_t slotId, std::shared_ptr<AppExecFwk::EventHandler> handler);
    void SetRilCmSmsCenterAddressTest(int32_t slotId, std::shared_ptr<AppExecFwk::EventHandler> handler);
    void GetRilCmSmsCenterAddressTest(int32_t slotId, std::shared_ptr<AppExecFwk::EventHandler> handler);
    void SetRilCmCBConfigTest(int32_t slotId, std::shared_ptr<AppExecFwk::EventHandler> handler);
    void SetRilCmCdmaCBConfigTest(int32_t slotId, std::shared_ptr<AppExecFwk::EventHandler> handler);
    void GetRilCmCBConfigTest(int32_t slotId, std::shared_ptr<AppExecFwk::EventHandler> handler);
    void GetRilCmCdmaCBConfigTest(int32_t slotId, std::shared_ptr<AppExecFwk::EventHandler> handler);
    void SmsSendSmsExpectMoreTest(int32_t slotId, std::shared_ptr<AppExecFwk::EventHandler> handler);
    void SetRadioStateTest(int32_t slotId, std::shared_ptr<AppExecFwk::EventHandler> handler);
    void GetRadioStateTest(int32_t slotId, std::shared_ptr<AppExecFwk::EventHandler> handler);
    void SmsAcknowledgeTest(int32_t slotId, std::shared_ptr<AppExecFwk::EventHandler> handler);
    void AddRilCmCdmaSmsTest(int32_t slotId, std::shared_ptr<AppExecFwk::EventHandler> handler);
    void DelRilCmCdmaSmsTest(int32_t slotId, std::shared_ptr<AppExecFwk::EventHandler> handler);
    void UpdateRilCmCdmaSmsTest(int32_t slotId, std::shared_ptr<AppExecFwk::EventHandler> handler);
    void SetVoNRSwitchTest(int32_t slotId, std::shared_ptr<AppExecFwk::EventHandler> handler);

    /* =========== Cellular Data Start ============= */
    void DataSetInitApnInfoTest(int32_t slotId, std::shared_ptr<AppExecFwk::EventHandler> handler);
    void DataSetupDataCallTest(int32_t slotId, std::shared_ptr<AppExecFwk::EventHandler> handler);
    void DataDisableDataCallTest(int32_t slotId, std::shared_ptr<AppExecFwk::EventHandler> handler);
    void GetLinkBandwidthInfoTest(int32_t slotId, std::shared_ptr<AppExecFwk::EventHandler> handler);
    void OnRequestSetLinkBandwidthReportingRuleTest(int32_t slotId, std::shared_ptr<AppExecFwk::EventHandler> handler);
    void SetDataPermittedTest(int32_t slotId, std::shared_ptr<AppExecFwk::EventHandler> handler);
    void GetLinkCapabilityTest(int32_t slotId, std::shared_ptr<AppExecFwk::EventHandler> handler);
    void CleanAllConnectionsTest(int32_t slotId, std::shared_ptr<AppExecFwk::EventHandler> handler);
    /* =========== Cellular Data End ============= */

    void GetDataCallListTest(int32_t slotId, std::shared_ptr<AppExecFwk::EventHandler> handler);
    void GetNetworkSearchInformationTest(int32_t slotId, std::shared_ptr<AppExecFwk::EventHandler> handler);
    void GetNetworkSelectionModeTest(int32_t slotId, std::shared_ptr<AppExecFwk::EventHandler> handler);
    void SetNetworkSelectionModeTest(int32_t slotId, std::shared_ptr<AppExecFwk::EventHandler> handler);
    void SetPreferredNetworkParaTest(int32_t slotId, std::shared_ptr<AppExecFwk::EventHandler> handler);
    void GetPreferredNetworkParaTest(int32_t slotId, std::shared_ptr<AppExecFwk::EventHandler> handler);
    void GetImeiTest(int32_t slotId, std::shared_ptr<AppExecFwk::EventHandler> handler);
    void GetMeidTest(int32_t slotId, std::shared_ptr<AppExecFwk::EventHandler> handler);
    void GetVoiceRadioTechnologyTest(int32_t slotId, std::shared_ptr<AppExecFwk::EventHandler> handler);
    void GetPhysicalChannelConfigTest(int32_t slotId, std::shared_ptr<AppExecFwk::EventHandler> handler);
    void SetLocateUpdatesTest(int32_t slotId, std::shared_ptr<AppExecFwk::EventHandler> handler);
    void SetNotificationFilterTest(int32_t slotId, std::shared_ptr<AppExecFwk::EventHandler> handler);
    void SetDeviceStateTest(int32_t slotId, std::shared_ptr<AppExecFwk::EventHandler> handler);
    void SetUssdTest(int32_t slotId, std::shared_ptr<AppExecFwk::EventHandler> handler);
    void GetUssdTest(int32_t slotId, std::shared_ptr<AppExecFwk::EventHandler> handler);
    void SetMuteTest(int32_t slotId, std::shared_ptr<AppExecFwk::EventHandler> handler);
    void GetMuteTest(int32_t slotId, std::shared_ptr<AppExecFwk::EventHandler> handler);
    void GetEmergencyCallListTest(int32_t slotId, std::shared_ptr<AppExecFwk::EventHandler> handler);
    void GetRrcConnectionStateTest(int32_t slotId, std::shared_ptr<AppExecFwk::EventHandler> handler);
    void GetNrOptionModeTest(int32_t slotId, std::shared_ptr<AppExecFwk::EventHandler> handler);
    void SetNrOptionModeTest(int32_t slotId, std::shared_ptr<AppExecFwk::EventHandler> handler);

    uint32_t GetRandNum();
    std::string GetRandPhoneNum(const int len);
    bool WaitGetResult(int32_t eventId, std::shared_ptr<AppExecFwk::EventHandler> handler, int32_t timeOut);

private:
    static std::shared_ptr<Telephony::ITelRilManager> telRilManager_;
    using RilManagerAndResponseTestFun = void (TelRilTest::*)(
        int32_t slotId, std::shared_ptr<AppExecFwk::EventHandler> handler);
    std::map<DiffInterfaceId, RilManagerAndResponseTestFun> memberFuncMap_;
};

#ifndef TEL_TEST_UNSUPPORT
inline const int32_t SLOT_ID_0 = 0;
inline const int32_t SLOT_ID_1 = 1;
#endif // TEL_TEST_UNSUPPORT

} // namespace Telephony
} // namespace OHOS
#endif // OHOS_TEL_RIL_TEST_UTIL_H
