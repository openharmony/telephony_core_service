/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#include <condition_variable>
#include <gtest/gtest.h>
#include <mutex>

#include "core_service_client.h"
#include "tel_ril_manager.h"

namespace OHOS {
namespace Telephony {
enum class DiffInterfaceId {
    TEST_GET_SIM_CARD_STATUS = 1,
    TEST_SIM_IO,
    TEST_GET_IMSI,
    TEST_GET_SIM_LOCK_STATUS,
    TEST_SET_SIM_LOCK,
    TEST_GET_CHANGE_SIM_PASSWD,
    TEST_ENTER_SIM_PIN,
    TEST_UNLOCK_SIM_PIN,
    TEST_GET_PIN_INPUT_TIMES,
    TEST_ENTER_SIM_PIN2,
    TEST_UNLOCK_SIM_PIN2,
    TEST_GET_PIN2_INPUT_TIMES,
    TEST_ENABLE_SIM_CARD,
    TEST_SET_RILCM_DATA_PROFILE,
    TEST_GET_RILCM_VOICE_REGISTRATION_STATE,
    TEST_GET_RILCM_DATA_REGISTRATION_STATE,
    TEST_SEND_SMS_ACK,
    TEST_RILCM_SET_INIT_APN_INFO,
    TEST_RILCM_SETUP_DATA_CALL,
    TEST_RILCM_DEACTIVATE_DATA_CALL,
    TEST_RILCM_GET_DATA_CALL_LIST,
    TEST_RILCM_GET_LINK_BANDWIDTH_INFO,
    TEST_RILCM_SET_LINK_BANDWIDTH_REPORTING_RULE,
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
    TEST_GET_IMS_REG_STATUS,
    TEST_GET_PS_ATTACH_STATUS,
    TEST_SET_PS_ATTACH_STATUS,
    TEST_GET_RADIO_CAPABILITY,
    TEST_SET_RADIO_CAPABILITY,
    TEST_GET_VOICE_RADIO_INFO,
    TEST_GET_PHYSICAL_CHANNEL_CONFIG,
    TEST_SET_LOCATE_UPDATES,
    TEST_SET_USSD,
    TEST_GET_USSD,
    TEST_SET_CMUT,
    TEST_GET_CMUT,
    TEST_GET_EMERGENCY_CALL_LIST,
    TEST_EXIT
};

class TelRilTest : public testing::Test {
public:
    TelRilTest();
    ~TelRilTest();
    void SetUp();
    void TearDown();
    static void SetUpTestCase();
    static void TearDownTestCase();
    void ProcessTest(int32_t index, const std::shared_ptr<AppExecFwk::EventHandler> &handler);

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

    void CallGetCurrentCallsStatusTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    void SimGetSimStatusTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    void SimIccIoTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    void SimGetImsiTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    void GetSimLockStatusTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    void SetSimLockTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    void ChangeSimPasswordTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    void EnterSimPinTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    void UnlockSimPinTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    void GetSimPinInputTimesTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    void EnterSimPin2Test(const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    void UnlockSimPin2Test(const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    void GetSimPin2InputTimesTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    void EnableSimCardTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    void SetActiveSimTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    void NetworkGetRssiTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    void RefusedCallTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    void GetCallWaitTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    void SetCallWaitTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    void CallHangupTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    void CallJoinTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    void CallSplitTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    void CallAnswerTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    void CallHoldTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    void CallDialTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    void CallActiveTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    void CallSwapTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    void GetClipTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    void SendDtmfTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    void StartDtmfTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    void StopDtmfTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    void SetClipTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    void GetCallRestrictionTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    void SetCallRestrictionTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    void NetworkVoiceRegistrationStateTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    void NetworkDataRegistrationStateTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    void GetRadioCapabilityTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    void SetRadioCapabilityTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    void GetCallForwardTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    void SetCallForwardTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    void NetworkOperatorTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    void SendRilCmSmsTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    void StorageRilCmSmsTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    void DeleteRilCmSmsTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    void UpdateRilCmSmsTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    void SetRilCmSmsCenterAddressTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    void GetRilCmSmsCenterAddressTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    void SetRilCmCBConfigTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    void SetRilCmCdmaCBConfigTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    void GetRilCmCBConfigTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    void GetRilCmCdmaCBConfigTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    void SmsSendSmsExpectMoreTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    void SetRadioStateTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    void GetRadioStateTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    void SmsAcknowledgeTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    void AddRilCmCdmaSmsTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    void DelRilCmCdmaSmsTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    void UpdateRilCmCdmaSmsTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    /* =========== Cellular Data Start ============= */
    void DataSetInitApnInfoTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    void DataSetupDataCallTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    void DataDisableDataCallTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    void GetLinkBandwidthInfoTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    void OnRequestSetLinkBandwidthReportingRuleTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    /* =========== Cellular Data End ============= */

    void GetDataCallListTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    void GetNetworkSearchInformationTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    void GetNetworkSelectionModeTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    void SetNetworkSelectionModeTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    void SetPreferredNetworkParaTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    void GetPreferredNetworkParaTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    void GetImeiTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    void GetMeidTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    void GetImsRegStatusTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    void GetPsAttachStatusTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    void SetPsAttachStatusTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    void GetVoiceRadioTechnologyTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    void GetPhysicalChannelConfigTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    void SetLocateUpdatesTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    void SetUssdTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    void GetUssdTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    void SetMuteTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    void GetMuteTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    void GetEmergencyCallListTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    int32_t GetRandNum();
    std::string GetRandPhoneNum(const int len);
    bool WaitGetResult(int32_t eventId, const std::shared_ptr<AppExecFwk::EventHandler> &handler, int32_t timeOut);

private:
    int32_t slotId_;
    static std::shared_ptr<Telephony::ITelRilManager> telRilManager_;
    using RilManagerAndResponseTestFun = void (TelRilTest::*)(
        const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    std::map<DiffInterfaceId, RilManagerAndResponseTestFun> memberFuncMap_;
    constexpr static const int32_t WAIT_TIME_SECOND = 10;
    constexpr static const int32_t WAIT_TIME_SECOND_LONG = 60;
};
} // namespace Telephony
} // namespace OHOS
#endif // OHOS_TEL_RIL_TEST_H