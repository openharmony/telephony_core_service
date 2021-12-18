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

#include <iostream>

#include "core_manager.h"
#include "telephony_log_wrapper.h"

namespace OHOS {
namespace Telephony {
enum class DiffInterfaceId {
    TEST_GET_SIM_CARD_STATUS = 1,
    TEST_SIM_IO,
    TEST_GET_IMSI,
    TEST_GET_ICCID,
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
    TEST_SET_RILCM_CELL_INFO_LIST_RATE_TEST,
    TEST_SET_RILCM_INITIAL_ATTACH_APN_TEST,
    TEST_SET_RILCM_DATA_PROFILE_TEST,
    TEST_GET_RILCM_VOICE_REGISTRATION_STATE_TEST,
    TEST_GET_RILCM_DATA_REGISTRATION_STATE_TEST,
    TEST_ACKNOWLEDGE_RILCM_LAST_INCOMING_GSM_SMS_TEST,
    TEST_SETUP_RILCM_DATA_CALL_TEST,
    TEST_DEACTIVATE_RILCM_DATA_CALL_TEST,
    TEST_GET_RILCM_DATA_CALL_LIST_TEST,
    TEST_SET_BASE_DATA_ALLOWED_TEST,
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
    TEST_GET_CALL_RESTRICTION,
    TEST_SET_CALL_RESTRICTION,
    TEST_SEND_DTMF,
    TEST_START_DTMF,
    TEST_STOP_DTMF,
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
    TEST_ACTIVE_CDMA_CB_CONFIG,
    TEST_SEND_SMS_EXPECT_MORE,
    TEST_SET_POWER_STATE,
    TEST_GET_POWER_STATE,
    TEST_OPERATOR,
    TEST_GET_NETWORKS_TO_USE,
    TEST_GET_SELECTION_MOD_FOR_NETWORKS,
    TEST_SET_MODE_AUTOMATIC_NETWORKS,
    TEST_SET_LOCATION_UPDATE_FOR_NETWORKS,
    TEST_GET_CURRENT_CELL_INFO,
    TEST_GET_CELL_INFO_LIST,
    TEST_GET_PREFERRED_NETWORK_TYPE,
    TEST_SET_PREFERRED_NETWORK_TYPE,
    TEST_GET_IMEI,
    TEST_GET_IMS_REG_STATUS,
    TEST_GET_PS_ATTACH_STATUS,
    TEST_SET_PS_ATTACH_STATUS,
    TEST_GET_IMS_CALL_LIST,
    TEST_SET_CALL_PREFERENCE_MODE,
    TEST_GET_CALL_PREFERENCE_MODE,
    TEST_SET_LTE_IMS_SWITCH_STATUS,
    TEST_GET_LTE_IMS_SWITCH_STATUS,
    TEST_GET_CS_REG_STATUS,
    TEST_GET_PS_REG_STATUS,
    TEST_EXIT,
};

using namespace OHOS;
using namespace OHOS::Telephony;
using namespace std;

namespace {
class TelRilTest {
public:
    TelRilTest();

    ~TelRilTest();

    std::shared_ptr<Telephony::ITelRilManager> telRilManager_ = nullptr;

    void OnInitInterface();

    void OnInitCall();

    void OnInitSms();

    void OnInitSim();

    void OnInitNetwork();

    void OnInitForRegister(const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnProcessInput(int32_t what, const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestCallGetCurrentCallsStatusTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestSimGetSimStatusTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestSimIccIoTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestSimGetImsiTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestGetSimLockStatusTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestSetSimLockTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestChangeSimPasswordTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestEnterSimPinTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestUnlockSimPinTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestGetSimPinInputTimesTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestEnterSimPin2Test(const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestUnlockSimPin2Test(const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestGetSimPin2InputTimesTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestSetActiveSimTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestNetworkGetRssiTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestRefusedCallTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestGetCallWaitTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestSetCallWaitTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestCallHangupTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestCallJoinTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestSeparateConferenceTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestCallAnswerTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestCallHoldTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestCallDialTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestCallActiveTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestCallSwapTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestGetClipTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestSendDtmfTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestStartDtmfTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestStopDtmfTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestSetClipTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestGetCallRestrictionTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestSetCallRestrictionTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestNetworkVoiceRegistrationStateTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestNetworkDataRegistrationStateTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestGetCallForwardTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestSetCallForwardTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestNetworkOperatorTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestSendRilCmSmsTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestStorageRilCmSmsTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestDeleteRilCmSmsTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestUpdateRilCmSmsTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestSetRilCmSmsCenterAddressTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestGetRilCmSmsCenterAddressTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestSetRilCBConfigTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestSetRilCdmaCBConfigTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestGetRilCBConfigTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestGetRilCdmaCBConfigTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestActiveRilCmCdmaCBConfigTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestSmsSendSmsExpectMoreTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestSetRadioStateTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestGetRadioStateTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestGetCellInfoListTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestGetCurrentCellInfoTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestSmsAcknowledgeTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestDataSetupDataCallTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestDataDisableDataCallTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    void OnRequestGetDataCallListTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestGetNetworkSearchInformationTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    void OnRequestGetNetworkSelectionModeTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    void OnRequestSetNetworkSelectionModeTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    void OnRequestSetPreferredNetworkTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    void OnRequestGetPreferredNetworkTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    void OnRequestGetImeiTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    void OnRequestGetImsRegStatusTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    void OnRequestGetPsAttachStatusTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    void OnRequestSetPsAttachStatusTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    void OnRequestGetCsRegStatusTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    void OnRequestGetPsRegStatusTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    void OnRequestGetImsCallListTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    void OnRequestSetCallPreferenceModeTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    void OnRequestGetCallPreferenceModeTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    void OnRequestSetLteImsSwitchStatusTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    void OnRequestGetLteImsSwitchStatusTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler);

    const int CID = 1;
    const int REASON = 2;
    const int TYPE = 7;
    const int MAXCONNSTIME = 8;
    const int MAXCONNS = 9;
    const int EVENT_11 = 11;
    const int TYPESBITMAP = 12;
    const int P3 = 15;
    const int COMMAND = 192;
    const int FILEID = 20272;
    const int AUTHTYPE_1 = -1;

    class DemoHandler : public AppExecFwk::EventHandler {
    public:
        explicit DemoHandler(const std::shared_ptr<AppExecFwk::EventRunner> &runner)
            : AppExecFwk::EventHandler(runner)
        {}

        ~DemoHandler() {}

        void ProcessEvent(const AppExecFwk::InnerEvent::Pointer &event) override;
    };

private:
    using RilManagerAndResponseTestFun = void (TelRilTest::*)(
        const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    std::map<DiffInterfaceId, RilManagerAndResponseTestFun> memberFuncMap_;
};

TelRilTest::TelRilTest()
{
    memberFuncMap_[DiffInterfaceId::TEST_CURRENT_CALLS] = &TelRilTest::OnRequestCallGetCurrentCallsStatusTest;
}

TelRilTest::~TelRilTest() {}

void TelRilTest::OnInitInterface()
{
    telRilManager_ = CoreManager::GetInstance().getCore(CoreManager::DEFAULT_SLOT_ID)->GetRilManager();

    /* --------------------------------- MODEL ----------------------------- */
    memberFuncMap_[DiffInterfaceId::TEST_GET_SIGNAL_STRENGTH] = &TelRilTest::OnRequestNetworkGetRssiTest;
    memberFuncMap_[DiffInterfaceId::TEST_SET_POWER_STATE] = &TelRilTest::OnRequestSetRadioStateTest;
    memberFuncMap_[DiffInterfaceId::TEST_GET_POWER_STATE] = &TelRilTest::OnRequestGetRadioStateTest;
    memberFuncMap_[DiffInterfaceId::TEST_GET_CELL_INFO_LIST] = &TelRilTest::OnRequestGetCellInfoListTest;
    memberFuncMap_[DiffInterfaceId::TEST_GET_CURRENT_CELL_INFO] = &TelRilTest::OnRequestGetCurrentCellInfoTest;

    /* --------------------------------- DATA ----------------------------- */
    memberFuncMap_[DiffInterfaceId::TEST_SETUP_RILCM_DATA_CALL_TEST] = &TelRilTest::OnRequestDataSetupDataCallTest;
    memberFuncMap_[DiffInterfaceId::TEST_DEACTIVATE_RILCM_DATA_CALL_TEST] =
        &TelRilTest::OnRequestDataDisableDataCallTest;
    memberFuncMap_[DiffInterfaceId::TEST_GET_RILCM_DATA_CALL_LIST_TEST] = &TelRilTest::OnRequestGetDataCallListTest;

    OnInitCall();

    OnInitSms();

    OnInitSim();

    OnInitNetwork();
}

void TelRilTest::OnInitCall()
{
    /* --------------------------------- CALL ----------------------------- */
    memberFuncMap_[DiffInterfaceId::TEST_CALL_DIAL] = &TelRilTest::OnRequestCallDialTest;
    memberFuncMap_[DiffInterfaceId::TEST_HANDUP_CONNECT] = &TelRilTest::OnRequestCallHangupTest;
    memberFuncMap_[DiffInterfaceId::TEST_ACCEPT_CALL] = &TelRilTest::OnRequestCallAnswerTest;
    memberFuncMap_[DiffInterfaceId::TEST_HOLD_CALL] = &TelRilTest::OnRequestCallHoldTest;
    memberFuncMap_[DiffInterfaceId::TEST_ACTIVE_CALL] = &TelRilTest::OnRequestCallActiveTest;
    memberFuncMap_[DiffInterfaceId::TEST_SWAP_CALL] = &TelRilTest::OnRequestCallSwapTest;
    memberFuncMap_[DiffInterfaceId::TEST_JOIN_CALL] = &TelRilTest::OnRequestCallJoinTest;
    memberFuncMap_[DiffInterfaceId::TEST_SPLIT_CALL] = &TelRilTest::OnRequestSeparateConferenceTest;
    memberFuncMap_[DiffInterfaceId::TEST_REJECT_CALL] = &TelRilTest::OnRequestRefusedCallTest;
    memberFuncMap_[DiffInterfaceId::TEST_GET_CALL_WAIT] = &TelRilTest::OnRequestGetCallWaitTest;
    memberFuncMap_[DiffInterfaceId::TEST_SET_CALL_WAIT] = &TelRilTest::OnRequestSetCallWaitTest;
    memberFuncMap_[DiffInterfaceId::TEST_GET_CALL_FORWARD] = &TelRilTest::OnRequestGetCallForwardTest;
    memberFuncMap_[DiffInterfaceId::TEST_SET_CALL_FORWARD] = &TelRilTest::OnRequestSetCallForwardTest;
    memberFuncMap_[DiffInterfaceId::TEST_GET_CALL_DEAL_CLIP] = &TelRilTest::OnRequestGetClipTest;
    memberFuncMap_[DiffInterfaceId::TEST_SET_CALL_CLIP] = &TelRilTest::OnRequestSetClipTest;
    memberFuncMap_[DiffInterfaceId::TEST_GET_CALL_RESTRICTION] = &TelRilTest::OnRequestGetCallRestrictionTest;
    memberFuncMap_[DiffInterfaceId::TEST_SET_CALL_RESTRICTION] = &TelRilTest::OnRequestSetCallRestrictionTest;
    memberFuncMap_[DiffInterfaceId::TEST_SEND_DTMF] = &TelRilTest::OnRequestSendDtmfTest;
    memberFuncMap_[DiffInterfaceId::TEST_START_DTMF] = &TelRilTest::OnRequestStartDtmfTest;
    memberFuncMap_[DiffInterfaceId::TEST_STOP_DTMF] = &TelRilTest::OnRequestStopDtmfTest;
    memberFuncMap_[DiffInterfaceId::TEST_GET_IMS_CALL_LIST] = &TelRilTest::OnRequestGetImsCallListTest;
    memberFuncMap_[DiffInterfaceId::TEST_SET_CALL_PREFERENCE_MODE] = &TelRilTest::OnRequestSetCallPreferenceModeTest;
    memberFuncMap_[DiffInterfaceId::TEST_GET_CALL_PREFERENCE_MODE] = &TelRilTest::OnRequestGetCallPreferenceModeTest;
    memberFuncMap_[DiffInterfaceId::TEST_SET_LTE_IMS_SWITCH_STATUS] = &TelRilTest::OnRequestSetLteImsSwitchStatusTest;
    memberFuncMap_[DiffInterfaceId::TEST_GET_LTE_IMS_SWITCH_STATUS] = &TelRilTest::OnRequestGetLteImsSwitchStatusTest;
}

void TelRilTest::OnInitSms()
{
    /* --------------------------------- SMS ----------------------------- */
    memberFuncMap_[DiffInterfaceId::TEST_SEND_SMS] = &TelRilTest::OnRequestSendRilCmSmsTest;
    memberFuncMap_[DiffInterfaceId::TEST_STORAGE_SMS] = &TelRilTest::OnRequestStorageRilCmSmsTest;
    memberFuncMap_[DiffInterfaceId::TEST_DELETE_SMS] = &TelRilTest::OnRequestDeleteRilCmSmsTest;
    memberFuncMap_[DiffInterfaceId::TEST_UPDATE_SMS] = &TelRilTest::OnRequestUpdateRilCmSmsTest;
    memberFuncMap_[DiffInterfaceId::TEST_SET_SMS_CENTER_ADDRESS] = &TelRilTest::OnRequestSetRilCmSmsCenterAddressTest;
    memberFuncMap_[DiffInterfaceId::TEST_GET_SMS_CENTER_ADDRESS] = &TelRilTest::OnRequestGetRilCmSmsCenterAddressTest;
    memberFuncMap_[DiffInterfaceId::TEST_SET_CB_CONFIG] = &TelRilTest::OnRequestSetRilCBConfigTest;
    memberFuncMap_[DiffInterfaceId::TEST_SET_CDMA_CB_CONFIG] =
            &TelRilTest::OnRequestSetRilCdmaCBConfigTest;
    memberFuncMap_[DiffInterfaceId::TEST_GET_CB_CONFIG] = &TelRilTest::OnRequestGetRilCBConfigTest;
    memberFuncMap_[DiffInterfaceId::TEST_GET_CDMA_CB_CONFIG] =
            &TelRilTest::OnRequestGetRilCdmaCBConfigTest;
    memberFuncMap_[DiffInterfaceId::TEST_SEND_SMS_EXPECT_MORE] = &TelRilTest::OnRequestSmsSendSmsExpectMoreTest;
    memberFuncMap_[DiffInterfaceId::TEST_ACKNOWLEDGE_RILCM_LAST_INCOMING_GSM_SMS_TEST] =
        &TelRilTest::OnRequestSmsAcknowledgeTest;
}

void TelRilTest::OnInitSim()
{
    /*-----------------------------------SIM----------------------------------*/
    memberFuncMap_[DiffInterfaceId::TEST_GET_SIM_CARD_STATUS] = &TelRilTest::OnRequestSimGetSimStatusTest;
    memberFuncMap_[DiffInterfaceId::TEST_SIM_IO] = &TelRilTest::OnRequestSimIccIoTest;
    memberFuncMap_[DiffInterfaceId::TEST_GET_IMSI] = &TelRilTest::OnRequestSimGetImsiTest;
    memberFuncMap_[DiffInterfaceId::TEST_GET_SIM_LOCK_STATUS] = &TelRilTest::OnRequestGetSimLockStatusTest;
    memberFuncMap_[DiffInterfaceId::TEST_SET_SIM_LOCK] = &TelRilTest::OnRequestSetSimLockTest;
    memberFuncMap_[DiffInterfaceId::TEST_GET_CHANGE_SIM_PASSWD] = &TelRilTest::OnRequestChangeSimPasswordTest;
    memberFuncMap_[DiffInterfaceId::TEST_ENTER_SIM_PIN] = &TelRilTest::OnRequestEnterSimPinTest;
    memberFuncMap_[DiffInterfaceId::TEST_UNLOCK_SIM_PIN] = &TelRilTest::OnRequestUnlockSimPinTest;
    memberFuncMap_[DiffInterfaceId::TEST_GET_PIN_INPUT_TIMES] = &TelRilTest::OnRequestGetSimPinInputTimesTest;
    memberFuncMap_[DiffInterfaceId::TEST_ENTER_SIM_PIN2] = &TelRilTest::OnRequestEnterSimPin2Test;
    memberFuncMap_[DiffInterfaceId::TEST_UNLOCK_SIM_PIN2] = &TelRilTest::OnRequestUnlockSimPin2Test;
    memberFuncMap_[DiffInterfaceId::TEST_GET_PIN2_INPUT_TIMES] = &TelRilTest::OnRequestGetSimPin2InputTimesTest;
    memberFuncMap_[DiffInterfaceId::TEST_ENABLE_SIM_CARD] = &TelRilTest::OnRequestSetActiveSimTest;
}

void TelRilTest::OnInitNetwork()
{
    /* --------------------------------- NETWORK ----------------------------- */
    memberFuncMap_[DiffInterfaceId::TEST_OPERATOR] = &TelRilTest::OnRequestNetworkOperatorTest;
    memberFuncMap_[DiffInterfaceId::TEST_GET_RILCM_VOICE_REGISTRATION_STATE_TEST] =
        &TelRilTest::OnRequestNetworkVoiceRegistrationStateTest;
    memberFuncMap_[DiffInterfaceId::TEST_GET_RILCM_DATA_REGISTRATION_STATE_TEST] =
        &TelRilTest::OnRequestNetworkDataRegistrationStateTest;
    memberFuncMap_[DiffInterfaceId::TEST_GET_NETWORKS_TO_USE] = &TelRilTest::OnRequestGetNetworkSearchInformationTest;
    memberFuncMap_[DiffInterfaceId::TEST_GET_SELECTION_MOD_FOR_NETWORKS] =
        &TelRilTest::OnRequestGetNetworkSelectionModeTest;
    memberFuncMap_[DiffInterfaceId::TEST_SET_MODE_AUTOMATIC_NETWORKS] =
        &TelRilTest::OnRequestSetNetworkSelectionModeTest;
    memberFuncMap_[DiffInterfaceId::TEST_GET_PREFERRED_NETWORK_TYPE] =
        &TelRilTest::OnRequestGetPreferredNetworkTest;
    memberFuncMap_[DiffInterfaceId::TEST_SET_PREFERRED_NETWORK_TYPE] =
        &TelRilTest::OnRequestSetPreferredNetworkTest;
    memberFuncMap_[DiffInterfaceId::TEST_GET_IMS_REG_STATUS] = &TelRilTest::OnRequestGetImsRegStatusTest;
    memberFuncMap_[DiffInterfaceId::TEST_GET_IMEI] = &TelRilTest::OnRequestGetImeiTest;
    memberFuncMap_[DiffInterfaceId::TEST_GET_PS_ATTACH_STATUS] = &TelRilTest::OnRequestGetPsAttachStatusTest;
    memberFuncMap_[DiffInterfaceId::TEST_SET_PS_ATTACH_STATUS] = &TelRilTest::OnRequestSetPsAttachStatusTest;
    memberFuncMap_[DiffInterfaceId::TEST_GET_CS_REG_STATUS] = &TelRilTest::OnRequestGetCsRegStatusTest;
    memberFuncMap_[DiffInterfaceId::TEST_GET_PS_REG_STATUS] = &TelRilTest::OnRequestGetPsRegStatusTest;
}

void TelRilTest::OnInitForRegister(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    TELEPHONY_LOGI("TelRilTest::OnInitForRegister -->");
    // Register all APIs
    telRilManager_->RegisterCoreNotify(handler, ObserverHandler::RADIO_STATE_CHANGED, nullptr);
    telRilManager_->RegisterCoreNotify(handler, ObserverHandler::RADIO_IMS_NETWORK_STATE_CHANGED, nullptr);
    telRilManager_->RegisterCoreNotify(handler, ObserverHandler::RADIO_ON, nullptr);
    telRilManager_->RegisterCoreNotify(handler, ObserverHandler::RADIO_NOT_AVAIL, nullptr);
    telRilManager_->RegisterCoreNotify(handler, ObserverHandler::RADIO_CALL_STATE, nullptr);
    telRilManager_->RegisterCoreNotify(handler, ObserverHandler::RADIO_NETWORK_STATE, nullptr);
    telRilManager_->RegisterCoreNotify(handler, ObserverHandler::RADIO_DATA_CALL_LIST_CHANGED, nullptr);
    telRilManager_->RegisterCoreNotify(handler, ObserverHandler::RADIO_ICC_STATUS_CHANGED, nullptr);
    telRilManager_->RegisterCoreNotify(handler, ObserverHandler::RADIO_GSM_SMS, nullptr);
    telRilManager_->RegisterCoreNotify(handler, ObserverHandler::RADIO_SMS_ON_SIM, nullptr);
    telRilManager_->RegisterCoreNotify(handler, ObserverHandler::RADIO_SMS_STATUS, nullptr);
    telRilManager_->RegisterCoreNotify(handler, ObserverHandler::RADIO_SIGNAL_STRENGTH_UPDATE, nullptr);
    telRilManager_->RegisterCoreNotify(handler, ObserverHandler::RADIO_ICC_REFRESH, nullptr);
    telRilManager_->RegisterCoreNotify(handler, ObserverHandler::RADIO_CONNECTED, nullptr);
    telRilManager_->RegisterCoreNotify(handler, ObserverHandler::RADIO_PCODATA, nullptr);
    telRilManager_->RegisterCoreNotify(handler, ObserverHandler::RADIO_JOIN_CALL, nullptr);
    telRilManager_->RegisterCoreNotify(handler, ObserverHandler::RADIO_SPLIT_CALL, nullptr);
    telRilManager_->RegisterCoreNotify(handler, ObserverHandler::RADIO_GET_CALL_WAIT, nullptr);
    telRilManager_->RegisterCoreNotify(handler, ObserverHandler::RADIO_SET_CALL_WAIT, nullptr);
    telRilManager_->RegisterCoreNotify(handler, ObserverHandler::RADIO_GET_CALL_FORWARD, nullptr);
    telRilManager_->RegisterCoreNotify(handler, ObserverHandler::RADIO_SET_CALL_FORWARD, nullptr);
    telRilManager_->RegisterCoreNotify(handler, ObserverHandler::RADIO_GET_CALL_CLIP, nullptr);
    telRilManager_->RegisterCoreNotify(handler, ObserverHandler::RADIO_SET_CALL_CLIP, nullptr);
    telRilManager_->RegisterCoreNotify(handler, ObserverHandler::RADIO_GET_CALL_RESTRICTION, nullptr);
    telRilManager_->RegisterCoreNotify(handler, ObserverHandler::RADIO_SET_CALL_RESTRICTION, nullptr);
    telRilManager_->RegisterCoreNotify(handler, ObserverHandler::RADIO_SEND_DTMF, nullptr);
    telRilManager_->RegisterCoreNotify(handler, ObserverHandler::RADIO_START_DTMF, nullptr);
    telRilManager_->RegisterCoreNotify(handler, ObserverHandler::RADIO_STOP_DTMF, nullptr);
    telRilManager_->RegisterCoreNotify(handler, ObserverHandler::RADIO_REJECT_CALL, nullptr);
    telRilManager_->RegisterCoreNotify(handler, ObserverHandler::RADIO_GET_IMS_CALL_LIST, nullptr);
    telRilManager_->RegisterCoreNotify(handler, ObserverHandler::RADIO_SET_CALL_PREFERENCE_MODE, nullptr);
    telRilManager_->RegisterCoreNotify(handler, ObserverHandler::RADIO_GET_CALL_PREFERENCE_MODE, nullptr);
    telRilManager_->RegisterCoreNotify(handler, ObserverHandler::RADIO_SET_LTE_IMS_SWITCH_STATUS, nullptr);
    telRilManager_->RegisterCoreNotify(handler, ObserverHandler::RADIO_GET_LTE_IMS_SWITCH_STATUS, nullptr);
}

void TelRilTest::OnProcessInput(int32_t what, const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto itFunc = memberFuncMap_.find((DiffInterfaceId)what);
    if (itFunc != memberFuncMap_.end()) {
        auto memberFunc = itFunc->second;
        if (memberFunc != nullptr) {
            (this->*memberFunc)(handler);
        }
    }
}

void TelRilTest::OnRequestCallGetCurrentCallsStatusTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_CURRENT_CALLS);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::OnRequestCallGetCurrentCallsStatusTest -->");
        telRilManager_->GetCallList(event);
        TELEPHONY_LOGI(
            "TelRilTest::OnRequestCallGetCurrentCallsStatusTest --> "
            "OnRequestCallGetCurrentCallsStatusTest "
            "finished");
    }
}
/************************************** SIM test func *******************************************/
void TelRilTest::OnRequestSimGetSimStatusTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_SIM_GET_STATUS);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::OnRequestSimGetSimStatusTest -->");
        telRilManager_->GetSimStatus(event);
        TELEPHONY_LOGI("TelRilTest::OnRequestSimGetSimStatusTest --> OnRequestSimGetSimStatusTest finished");
    }
}

void TelRilTest::OnRequestSimIccIoTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_SIM_IO);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::OnRequestSimIccIoTest -->");
        SimIoRequestInfo msg;
        msg.command = COMMAND;
        msg.fileId = FILEID;
        msg.p1 = 0;
        msg.p2 = 0;
        msg.p3 = P3;
        msg.data = "";
        msg.path = "3F007F105F3A";
        msg.pin2 = "";
        telRilManager_->GetSimIO(msg, event);
        TELEPHONY_LOGI("TelRilTest::OnRequestSimIccIoTest --> OnRequestSimIccIoTest finished");
    }
}

void TelRilTest::OnRequestSimGetImsiTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_SIM_GET_IMSI);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::OnRequestSimGetImsiTest -->");
        telRilManager_->GetImsi(event);
        TELEPHONY_LOGI("TelRilTest::OnRequestSimGetImsiTest --> OnRequestSimGetImsiTest finished");
    }
}

void TelRilTest::OnRequestGetSimLockStatusTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_SIM_GET_LOCK_STATUS);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        std::string fac;

        std::cout << "please enter the fac:";
        std::cin >> fac;

        TELEPHONY_LOGI("TelRilTest::%{public}s -->", __func__);
        telRilManager_->GetSimLockStatus(fac, event);
        TELEPHONY_LOGI("TelRilTest::%{public}s --> finished", __func__);
    }
}

void TelRilTest::OnRequestSetSimLockTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_SIM_SET_LOCK);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        std::string fac;
        int mode;
        std::string code;

        std::cout << "please enter the fac:";
        std::cin >> fac;
        std::cout << "please enter the mode:";
        std::cin >> mode;
        std::cout << "please enter the pwd:";
        std::cin >> code;

        TELEPHONY_LOGI("TelRilTest::%{public}s -->", __func__);
        telRilManager_->SetSimLock(fac, mode, code, event);
        TELEPHONY_LOGI("TelRilTest::%{public}s --> finished", __func__);
    }
}

void TelRilTest::OnRequestChangeSimPasswordTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_SIM_CHANGE_PASSWD);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        std::string fac;
        std::string oldPassword;
        std::string newPassword;
        int32_t passwordLength = 4;

        std::cout << "please enter the fac:";
        std::cin >> fac;
        std::cout << "please enter the oldPassword:";
        std::cin >> oldPassword;
        std::cout << "please enter the newPassword:";
        std::cin >> newPassword;

        TELEPHONY_LOGI("TelRilTest::%{public}s -->", __func__);
        telRilManager_->ChangeSimPassword(fac, oldPassword, newPassword, passwordLength, event);
        TELEPHONY_LOGI("TelRilTest::%{public}s --> finished", __func__);
    }
}

void TelRilTest::OnRequestEnterSimPinTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_SIM_ENTER_PIN);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);

        std::string pin;
        std::cout << "please enter the SIM PIN:";
        std::cin >> pin;

        TELEPHONY_LOGI("TelRilTest::%{public}s -->", __func__);
        telRilManager_->UnlockPin(pin, event);
        TELEPHONY_LOGI("TelRilTest::%{public}s --> finished", __func__);
    }
}

void TelRilTest::OnRequestUnlockSimPinTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_SIM_UNLOCK_PIN);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        std::string puk;
        std::string pin;

        std::cout << "please enter the SIM PUK:";
        std::cin >> puk;
        std::cout << "please enter the SIM PIN:";
        std::cin >> pin;

        TELEPHONY_LOGI("TelRilTest::%{public}s -->", __func__);
        telRilManager_->UnlockPuk(puk, pin, event);
        TELEPHONY_LOGI("TelRilTest::%{public}s --> finished", __func__);
    }
}

void TelRilTest::OnRequestGetSimPinInputTimesTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_SIM_PIN_INPUT_TIMES);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);

        TELEPHONY_LOGI("TelRilTest::%{public}s -->", __func__);
        telRilManager_->GetSimPinInputTimes(event);
        TELEPHONY_LOGI("TelRilTest::%{public}s --> finished", __func__);
    }
}
void TelRilTest::OnRequestEnterSimPin2Test(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_SIM_ENTER_PIN2);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);

        std::string pin2;
        std::cout << "please enter the SIM PIN2:";
        std::cin >> pin2;

        TELEPHONY_LOGI("TelRilTest::%{public}s -->", __func__);
        telRilManager_->UnlockPin2(pin2, event);
        TELEPHONY_LOGI("TelRilTest::%{public}s --> finished", __func__);
    }
}

void TelRilTest::OnRequestUnlockSimPin2Test(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_SIM_UNLOCK_PIN2);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        std::string puk2;
        std::string pin2;

        std::cout << "please enter the SIM PUK:";
        std::cin >> puk2;
        std::cout << "please enter the SIM PIN:";
        std::cin >> pin2;

        TELEPHONY_LOGI("TelRilTest::%{public}s -->", __func__);
        telRilManager_->UnlockPuk2(puk2, pin2, event);
        TELEPHONY_LOGI("TelRilTest::%{public}s --> finished", __func__);
    }
}

void TelRilTest::OnRequestGetSimPin2InputTimesTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_SIM_PIN2_INPUT_TIMES);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);

        TELEPHONY_LOGI("TelRilTest::%{public}s -->", __func__);
        telRilManager_->GetSimPin2InputTimes(event);
        TELEPHONY_LOGI("TelRilTest::%{public}s --> finished", __func__);
    }
}

void TelRilTest::OnRequestSetActiveSimTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_SIM_CARD_ENABLED);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);

        int index;
        int enable;
        std::cout << "please enter the SIM index:";
        std::cin >> index;

        std::cout << "please enter the SIM enable:";
        std::cin >> enable;

        TELEPHONY_LOGI("TelRilTest::%{public}s -->", __func__);
        telRilManager_->SetActiveSim(index, enable, event);
        TELEPHONY_LOGI("TelRilTest::%{public}s --> finished", __func__);
    }
}

/************************************** SIM test func *******************************************/

void TelRilTest::OnRequestNetworkGetRssiTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_GET_SIGNAL_STRENGTH);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::OnRequestNetworkGetRssiTest -->");
        telRilManager_->GetSignalStrength(event);
        TELEPHONY_LOGI(
            "TelRilTest::OnRequestNetworkGetRssiTest --> "
            "OnRequestNetworkGetRssiTest finished");
    }
}

void TelRilTest::OnRequestCallDialTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_DIAL);
    if (event == nullptr || telRilManager_ == nullptr) {
        TELEPHONY_LOGI("TelRilTest::OnRequestCallDialTest failed!!!!");
        return;
    }

    std::string phoneNum;
    int32_t clirMode; /* Calling Line Identification Restriction . From TS 27.007 V3.4.0 (2000-03) */
    event->SetOwner(handler);
    std::cout << "please enter the phone number:";
    std::cin >> phoneNum;
    clirMode = 0; // use subscription default value
    TELEPHONY_LOGI("TelRilTest::OnRequestCallDialTest -->");
    telRilManager_->Dial(phoneNum, clirMode, event);
    TELEPHONY_LOGI(
        "TelRilTest::OnRequestCallDialTest --> "
        "OnRequestCallDialTest finished");
}

void TelRilTest::OnRequestRefusedCallTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_REJECT_CALL);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::OnRequestRefusedCallTest -->");
        telRilManager_->Reject(event);
        TELEPHONY_LOGI(
            "TelRilTest::OnRequestRefusedCallTest --> "
            "OnRequestRefusedCallTest finished");
    }
}

void TelRilTest::OnRequestGetCallWaitTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_GET_CALL_WAIT);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::OnRequestGetCallWaitTest -->");
        telRilManager_->GetCallWaiting(event);
        TELEPHONY_LOGI(
            "TelRilTest::OnRequestGetCallWaitTest --> "
            "OnRequestGetCallWaitTest finished");
    }
}

void TelRilTest::OnRequestSetCallWaitTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_SET_CALL_WAIT);
    if (event == nullptr || telRilManager_ == nullptr)
        return;

    event->SetOwner(handler);
    int32_t operating;
    TELEPHONY_LOGI("TelRilTest::OnRequestSetCallWaitTest -->");
    std::cout << "Please input set value[0:disable 1:enable]: " << endl;
    std::cin >> operating;

    telRilManager_->SetCallWaiting(operating, event);
    TELEPHONY_LOGI(
        "TelRilTest::OnRequestSetCallWaitTest --> "
        "OnRequestSetCallWaitTest finished");
}

void TelRilTest::OnRequestCallHangupTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_HANGUP_CONNECT);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::OnRequestCallHangupTest -->");
        telRilManager_->Hangup(static_cast<int>(event->GetInnerEventId()), event);
        TELEPHONY_LOGI(
            "TelRilTest::OnRequestCallHangupTest --> OnRequestCallHangupTest "
            "finished");
    }
}

void TelRilTest::OnRequestCallAnswerTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_ACCEPT_CALL);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::OnRequestCallAnswerTest -->");
        telRilManager_->Answer(event);
        TELEPHONY_LOGI(
            "TelRilTest::OnRequestCallAnswerTest --> "
            "OnRequestCallAnswerTest finished");
    }
}

void TelRilTest::OnRequestCallHoldTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_HOLD_CALL);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::OnRequestCallHoldTest -->");
        telRilManager_->HoldCall(event);
        TELEPHONY_LOGI(
            "TelRilTest::OnRequestCallHoldTest --> "
            "OnRequestCallHoldTest finished");
    }
}

void TelRilTest::OnRequestCallActiveTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_ACTIVE_CALL);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::OnRequestCallActiveTest -->");
        telRilManager_->UnHoldCall(event);
        TELEPHONY_LOGI(
            "TelRilTest::OnRequestCallActiveTest --> "
            "OnRequestCallActiveTest finished");
    }
}

void TelRilTest::OnRequestCallSwapTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_SWAP_CALL);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::OnRequestCallSwapTest -->");
        telRilManager_->SwitchCall(event);
        TELEPHONY_LOGI(
            "TelRilTest::OnRequestCallSwapTest --> "
            "OnRequestCallSwapTest finished");
    }
}

void TelRilTest::OnRequestNetworkVoiceRegistrationStateTest(
    const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(TYPE);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::OnRequestNetworkVoiceRegistrationStateTest -->");
        telRilManager_->GetCsRegStatus(event);
        TELEPHONY_LOGI(
            "TelRilTest::OnRequestNetworkVoiceRegistrationStateTest --> "
            "OnRequestNetworkVoiceRegistrationStateTest finished");
    }
}

void TelRilTest::OnRequestNetworkDataRegistrationStateTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(MAXCONNSTIME);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::OnRequestNetworkDataRegistrationStateTest -->");
        telRilManager_->GetPsRegStatus(event);
        TELEPHONY_LOGI(
            "TelRilTest::OnRequestNetworkDataRegistrationStateTest --> "
            "OnRequestNetworkDataRegistrationStateTest finished");
    }
}

void TelRilTest::OnRequestNetworkOperatorTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_OPERATOR);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::OnRequestNetworkOperatorTest -->");
        telRilManager_->GetOperatorInfo(event);
        TELEPHONY_LOGI("TelRilTest::OnRequestNetworkOperatorTest --> OnRequestNetworkOperatorTest finished");
    }
}

void TelRilTest::OnRequestSendRilCmSmsTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_SEND_SMS);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::OnRequestSendRilCmSmsTest -->");
        telRilManager_->SendGsmSms("smscPdu", "pdu", event);
        TELEPHONY_LOGI("TelRilTest::OnRequestSendRilCmSmsTest --> OnRequestSendRilCmSmsTest finished");
    }
}

void TelRilTest::OnRequestStorageRilCmSmsTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_STORAGE_SMS);
    int32_t status;
    std::cout << "Please input status:" << std::endl;
    std::cin >> status;
    std::cout << "Please input smsc:" << std::endl;
    string smsc;
    std::cin >> smsc;
    std::cout << "Please input pdu:" << std::endl;
    string pdu;
    std::cin >> pdu;
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::OnRequestStorageRilCmSmsTest -->");
        telRilManager_->AddSimMessage(status, smsc, pdu, event);
        TELEPHONY_LOGI("TelRilTest::OnRequestStorageRilCmSmsTest --> OnRequestStorageRilCmSmsTest finished");
    }
}

void TelRilTest::OnRequestDeleteRilCmSmsTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_DELETE_SMS);
    int32_t gsmIndex;

    std::cout << "Please input gsmIndex: " << endl;
    std::cin >> gsmIndex;
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::OnRequestDeleteRilCmSmsTest -->");
        telRilManager_->DelSimMessage(gsmIndex, event);
        TELEPHONY_LOGI("TelRilTest::OnRequestDeleteRilCmSmsTest --> OnRequestDeleteRilCmSmsTest finished");
    }
}

void TelRilTest::OnRequestUpdateRilCmSmsTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_UPDATE_SMS);
    int32_t gsmIndex;
    std::string pdu;

    std::cout << "Please input gsmIndex: " << endl;
    std::cin >> gsmIndex;
    std::cout << "Please input pdu: " << endl;
    std::cin >> pdu;
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::OnRequestUpdateRilCmSmsTest -->");
        telRilManager_->UpdateSimMessage(gsmIndex, 0, "00", pdu, event);
        TELEPHONY_LOGI("TelRilTest::OnRequestUpdateRilCmSmsTest --> OnRequestUpdateRilCmSmsTest finished");
    }
}

void TelRilTest::OnRequestSetRilCmSmsCenterAddressTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_SET_SMS_CENTER_ADDRESS);
    int32_t tosca;
    std::string address;

    std::cout << "Please input tosca: " << endl;
    std::cin >> tosca;
    std::cout << "Please input address: " << endl;
    std::cin >> address;
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::OnRequestSetRilCmSmsCenterAddressTest -->");
        telRilManager_->SetSmscAddr(tosca, address, event);
        TELEPHONY_LOGI(
            "TelRilTest::OnRequestSetRilCmSmsCenterAddressTest --> OnRequestSetRilCmSmsCenterAddressTest "
            "finished");
    }
}

void TelRilTest::OnRequestGetRilCmSmsCenterAddressTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_GET_SMS_CENTER_ADDRESS);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::OnRequestGetRilCmSmsCenterAddressTest -->");
        telRilManager_->GetSmscAddr(event);
        TELEPHONY_LOGI(
            "TelRilTest::OnRequestGetRilCmSmsCenterAddressTest --> OnRequestGetRilCmSmsCenterAddressTest "
            "finished");
    }
}

void TelRilTest::OnRequestSetRilCBConfigTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_SET_CELL_BROADCAST);
    int32_t mode;
    std::string idList;
    std::string dcsList;

    std::cout << "Please input mode: " << endl;
    std::cin >> mode;
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::SetRilCBConfig -->");
        telRilManager_->SetCBConfig(mode, "0,1,5,320-478,922", "0-3,5", event);
        TELEPHONY_LOGI("TelRilTest::SetRilCBConfig --> SetRilCBConfig finished");
    }
}

void TelRilTest::OnRequestSetRilCdmaCBConfigTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_SET_CDMA_CELL_BROADCAST);
    CdmaCBConfigInfoList cdmaCBConfigInfoList = {};
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::OnRequestSetRilCdmaCBConfigTest -->");
        telRilManager_->SetCdmaCBConfig(cdmaCBConfigInfoList, event);
        TELEPHONY_LOGI("TelRilTest::OnRequestSetRilCdmaCBConfigTest --> SetRilCdmaCBConfigTest finished");
    }
}

void TelRilTest::OnRequestGetRilCBConfigTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_GET_CELL_BROADCAST);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::OnRequestGetRilCBConfig -->");
        telRilManager_->GetCBConfig(event);
        TELEPHONY_LOGI("TelRilTest::OnRequestGetRilCBConfig--> GetRilCmCBConfigTest finished");
    }
}

void TelRilTest::OnRequestGetRilCdmaCBConfigTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_GET_CDMA_CELL_BROADCAST);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::OnRequestGetRilCdmaCBConfig -->");
        telRilManager_->GetCdmaCBConfig(event);
        TELEPHONY_LOGI("TelRilTest::OnRequestGetRilCdmaCBConfig--> OnRequestGetRilCdmaCBConfig finished");
    }
}

void TelRilTest::OnRequestSmsSendSmsExpectMoreTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_SEND_SMS_EXPECT_MORE);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::OnRequestSmsSendSmsExpectMoreTest -->");
        telRilManager_->SendSmsMoreMode("smscPdu", "pdu", event);
        TELEPHONY_LOGI(
            "TelRilTest::OnRequestSmsSendSmsExpectMoreTest --> OnRequestSmsSendSmsExpectMoreTest "
            "finished");
    }
}

void TelRilTest::OnRequestSetRadioStateTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_SET_STATUS);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::OnRequestSetRadioStateTest -->");
        int radioState = -1;

        std::cout << "please enter the new radioState:";
        std::cin >> radioState;

        telRilManager_->SetRadioState(radioState, 0, event);
        TELEPHONY_LOGI("TelRilTest::OnRequestSetRadioStateTest --> OnRequestSetRadioStateTest finished");
    }
}

void TelRilTest::OnRequestGetRadioStateTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_GET_STATUS);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::OnRequestOnGetRadioStateTest -->");
        telRilManager_->GetRadioState(event);
        TELEPHONY_LOGI("TelRilTest::OnRequestOnGetRadioStateTest --> OnRequestOnGetRadioStateTest finished");
    }
}

void TelRilTest::OnRequestGetCellInfoListTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_POWER);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::OnRequestGetCellInfoListTest -->");
        telRilManager_->GetCellInfoList(event);
        TELEPHONY_LOGI("TelRilTest::OnRequestGetCellInfoListTest --> OnRequestGetCellInfoListTest finished");
    }
}

void TelRilTest::OnRequestGetCurrentCellInfoTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_POWER);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::OnRequestGetCurrentCellInfoTest -->");
        telRilManager_->GetCurrentCellInfo(event);
        TELEPHONY_LOGI("TelRilTest::OnRequestGetCurrentCellInfoTest --> OnRequestGetCurrentCellInfoTest finished");
    }
}

void TelRilTest::OnRequestSmsAcknowledgeTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(MAXCONNS);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::OnRequestSmsAcknowledgeTest -->");
        telRilManager_->SendSmsAck(true, REASON, event);
        TELEPHONY_LOGI(
            "TelRilTest::OnRequestSmsAcknowledgeTest -->"
            " OnRequestSmsAcknowledgeTest finished");
    }
}

void TelRilTest::OnRequestDataSetupDataCallTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(EVENT_11);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::OnRequestCallSetupDataCallTest -->");
        ITelRilManager::CellularDataProfile dataProfile(0, "cmnet", "IPV4V6", AUTHTYPE_1, "", "", "IPV4V6");
        telRilManager_->ActivatePdpContext(REASON, dataProfile, false, true, event);
        TELEPHONY_LOGI(
            "TelRilTest::OnRequestDataSetupDataCallTest -->"
            "OnRequestDataSetupDataCallTest finished");
    }
}

void TelRilTest::OnRequestDataDisableDataCallTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(TYPESBITMAP);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::OnRequestCallDeactivateDataCallTest -->");
        telRilManager_->DeactivatePdpContext(CID, REASON, event);
        TELEPHONY_LOGI(
            "TelRilTest::OnRequestDataDisableDataCallTest --> "
            "OnRequestDataDisableDataCallTest finished");
    }
}

void TelRilTest::OnRequestGetDataCallListTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(TYPESBITMAP);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::OnRequestGetDataCallListTest -->");
        telRilManager_->GetPdpContextList(event);
        TELEPHONY_LOGI("OnRequestGetDataCallListTest finished");
    }
}

void TelRilTest::OnRequestGetNetworkSearchInformationTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(TYPESBITMAP);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::OnRequestGetAvailableNetworkTest -->");
        telRilManager_->GetNetworkSearchInformation(event);
        TELEPHONY_LOGI("TelRilTest::OnRequestGetAvailableNetworkTest -->finished");
    }
}

void TelRilTest::OnRequestGetNetworkSelectionModeTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(TYPESBITMAP);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::OnRequestGetNetworkSelectionModeTest -->");
        telRilManager_->GetNetworkSelectionMode(event);
        TELEPHONY_LOGI(
            "TelRilTest::OnRequestGetNetworkSelectionModeTest --> "
            "OnRequestGetNetworkSelectionModeTest finished");
    }
}

void TelRilTest::OnRequestSetNetworkSelectionModeTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(TYPESBITMAP);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::OnRequestSetNetworkSelectionModeTest -->");
        telRilManager_->SetNetworkSelectionMode(1, "46001", event);
        TELEPHONY_LOGI(
            "TelRilTest::OnRequestSetNetworkSelectionModeTest --> "
            "OnRequestSetNetworkSelectionModeTest finished");
    }
}

void TelRilTest::OnRequestSetPreferredNetworkTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(TYPESBITMAP);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        int32_t netType = 0;
        std::cout << "Please input netType: " << endl;
        std::cin >> netType;
        TELEPHONY_LOGI("TelRilTest::OnRequestSetPreferredNetworkParaTest -->");
        telRilManager_->SetPreferredNetwork(netType, event);
        TELEPHONY_LOGI(
            "TelRilTest::OnRequestSetPreferredNetworkParaTest --> "
            "OnRequestSetPreferredNetworkParaTest finished");
    }
}

void TelRilTest::OnRequestGetPreferredNetworkTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(TYPESBITMAP);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::OnRequestGetPreferredNetworkParaTest -->");
        telRilManager_->GetPreferredNetwork(event);
        TELEPHONY_LOGI(
            "TelRilTest::OnRequestGetPreferredNetworkParaTest --> "
            "OnRequestGetPreferredNetworkParaTest finished");
    }
}

void TelRilTest::OnRequestGetImeiTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(TYPESBITMAP);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::OnRequestGetImeiTest -->");
        telRilManager_->GetImei(event);
        TELEPHONY_LOGI(
            "TelRilTest::OnRequestGetImeiTest --> "
            "OnRequestGetImeiTest finished");
    }
}

void TelRilTest::OnRequestGetImsRegStatusTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(TYPESBITMAP);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::OnRequestGetImsRegStatusTest -->");
        telRilManager_->GetImsRegStatus(event);
        TELEPHONY_LOGI(
            "TelRilTest::OnRequestGetImsRegStatusTest --> "
            "OnRequestGetImsRegStatusTest finished");
    }
}

void TelRilTest::OnRequestGetPsAttachStatusTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(TYPESBITMAP);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::OnRequestGetPsAttachStatusTest -->");
        telRilManager_->GetPsAttachStatus(event);
        TELEPHONY_LOGI(
            "TelRilTest::OnRequestGetPsAttachStatusTest --> "
            "OnRequestGetPsAttachStatusTest finished");
    }
}

void TelRilTest::OnRequestGetCsRegStatusTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(TYPESBITMAP);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::OnRequestGetCsRegStatusTest -->");
        telRilManager_->GetCsRegStatus(event);
        TELEPHONY_LOGI("TelRilTest::OnRequestGetCsRegStatusTest -->finished");
    }
}

void TelRilTest::OnRequestGetPsRegStatusTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(TYPESBITMAP);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::OnRequestGetPsRegStatusTest -->");
        telRilManager_->GetPsRegStatus(event);
        TELEPHONY_LOGI("TelRilTest::OnRequestGetPsRegStatusTest -->finished");
    }
}

void TelRilTest::OnRequestSetPsAttachStatusTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(TYPESBITMAP);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        int32_t psAttachStatus = 0;
        std::cout << "Please input psAttachStatus(1 / 0): " << endl;
        std::cin >> psAttachStatus;
        if (psAttachStatus != 0) {
            psAttachStatus = 1;
        }
        TELEPHONY_LOGI("TelRilTest::OnRequestSetPsAttachStatusTest -->psAttachStatus:%{public}d", psAttachStatus);
        telRilManager_->SetPsAttachStatus(psAttachStatus, event);
        TELEPHONY_LOGI(
            "TelRilTest::OnRequestSetPsAttachStatusTest --> "
            "OnRequestSetPsAttachStatusTest finished");
    }
}

void TelRilTest::OnRequestCallJoinTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    int32_t callType = 0; /* call type
                       * 0: Voice call
                       * 1: Video call: send one-way video, two-way voice
                       * 2: Video call: one-way receiving video, two-way voice
                       * 3: Video call: two-way video, two-way voice
                       */

    TELEPHONY_LOGI("RilUnitTest::OnRequestCallJoinTest -->");
    std::cout << "please enter the call type:";
    std::cin >> callType;

    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_JOIN_CALL);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::OnRequestCallJoinTest -->");
        telRilManager_->CombineConference(callType, event);
        TELEPHONY_LOGI(
            "TelRilTest::OnRequestCallJoinTest --> "
            "OnRequestCallJoinTest finished");
    }
}

void TelRilTest::OnRequestSeparateConferenceTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    int32_t callIndex = 0;
    int32_t callType = 0; /* call type
                       * 0: Voice call
                       * 1: Video call: send one-way video, two-way voice
                       * 2: Video call: one-way receiving video, two-way voice
                       * 3: Video call: two-way video, two-way voice
                       */

    TELEPHONY_LOGI("RilUnitTest::OnRequestSeparateConferenceTest -->");

    std::cout << "please enter the call split number:";
    std::cin >> callIndex;

    std::cout << "please enter the call type:";
    std::cin >> callType;

    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_SPLIT_CALL);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::OnRequestSeparateConferenceTest -->");
        telRilManager_->SeparateConference(callIndex, callType, event);
        TELEPHONY_LOGI(
            "TelRilTest::OnRequestSeparateConferenceTest --> "
            "OnRequestSeparateConferenceTest finished");
    }
}

void TelRilTest::OnRequestGetCallForwardTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    int32_t reason = 0;
    TELEPHONY_LOGI("RilUnitTest::OnRequestGetCallForwardTest -->");
    std::cout << "please enter Get Call Forward reason<0-5>:";
    std::cin >> reason;

    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_GET_CALL_FORWARD);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::OnRequestGetCallForwardTest -->");
        telRilManager_->GetCallTransferInfo(reason, event);
        TELEPHONY_LOGI("OnRequestGetCallForwardTest --> "
            "OnRequestGetCallForwardTest ");
    }
}

void DiffParamType(int32_t loopFlag, int32_t reasonType)
{
    const int32_t MIN_TYPE = 0;
    const int32_t MAX_TYPE = 4;

    while (loopFlag) {
        cout << "0: unconditional" << endl;
        cout << "1: mobile busy" << endl;
        cout << "2: no reply" << endl;
        cout << "3: not reachable" << endl;
        cout << "4: all call forwarding" << endl;
        cout << "5: all conditional call forwarding" << endl;
        std::cout << "please select call forward reason type: ";
        std::cin >> reasonType;
        if (reasonType < MIN_TYPE || reasonType > MAX_TYPE) {
            std::cout << "select error, please retry!" << endl;
            continue;
        }
        break;
    }
}

void DiffParamMode(int32_t loopFlag, int32_t mode)
{
    const int32_t MIN_MODE = 0;
    const int32_t MAX_MODE = 4;
    const int32_t QUERY_STATUS = 2;

    while (loopFlag) {
        cout << "0: disable" << endl;
        cout << "1: enable" << endl; //  "2: query status"
        cout << "3: registration" << endl;
        cout << "4: erasure" << endl;
        std::cout << "please select call forward mode type: ";
        std::cin >> mode;
        if (mode < MIN_MODE || mode > MAX_MODE) {
            std::cout << "select error, please retry!" << endl;
            continue;
        }
        if (mode == QUERY_STATUS) {
            std::cout << "select error, mode 2 is query status please retry!" << endl;
            continue;
        }
        break;
    }
}

void DiffParamClassx(int32_t loopFlag, int32_t classx)
{
    const int32_t MIN_CLASSX = 1;
    const int32_t MAX_CLASSX = 16;

    while (loopFlag) {
        cout << "1: voice" << endl;
        cout << "2: data" << endl;
        cout << "4: fax" << endl;
        cout << "8: short message service" << endl;
        cout << "16: data circuit sync" << endl;
        std::cout << "please select call forward class type: ";
        std::cin >> classx;
        if (classx < MIN_CLASSX || classx > MAX_CLASSX) {
            std::cout << "select error, please retry!" << endl;
            continue;
        }
        break;
    }
}

void TelRilTest::OnRequestSetCallForwardTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    int32_t mode = 0;
    int32_t reasonType = 0;
    int32_t classx = 0; /* call type
                         * 0: Voice call
                         * 1: Video call: send one-way video, two-way voice
                         * 2: Video call: one-way receiving video, two-way voice
                         * 3: Video call: two-way video, two-way voice
                         */
    std::string phoneNum;
    int32_t loopFlag = true;

    TELEPHONY_LOGI("RilUnitTest::OnRequestSetCallForwardTest -->");
    DiffParamType(loopFlag, reasonType);

    DiffParamMode(loopFlag, mode);

    std::cout << "please enter the phone number:";
    std::cin >> phoneNum;

    DiffParamClassx(loopFlag, classx);

    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_SPLIT_CALL);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::OnRequestSetCallForwardTest -->");
        telRilManager_->SetCallTransferInfo(reasonType, mode, phoneNum, classx, event);
        TELEPHONY_LOGI(
            "TelRilTest::OnRequestSetCallForwardTest --> "
            "OnRequestSetCallForwardTest finished");
    }
}

void TelRilTest::OnRequestGetClipTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_GET_CALL_CLIP);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::OnRequestGetClipTest -->");
        telRilManager_->GetClip(event);
        TELEPHONY_LOGI(
            "TelRilTest::OnRequestGetClipTest --> "
            "OnRequestGetClipTest finished");
    }
}

void TelRilTest::OnRequestSetClipTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_SET_CALL_CLIP);
    if (event != nullptr && telRilManager_ != nullptr) {
        int32_t action;
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::OnRequestSetClipTest -->");
        std::cout << "please input call set clip action: ";
        std::cin >> action;
        telRilManager_->SetClip(action, event);
        TELEPHONY_LOGI(
            "TelRilTest::OnRequestSetClipTest --> "
            "OnRequestSetClipTest finished");
    }
}

void TelRilTest::OnRequestGetCallRestrictionTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_GET_CALL_RESTRICTION);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::OnRequestGetCallRestrictionTest -->");
        telRilManager_->GetCallRestriction("AI", event);
        TELEPHONY_LOGI(
            "TelRilTest::OnRequestGetCallRestrictionTest --> "
            "OnRequestGetCallRestrictionTest finished");
    }
}

void TelRilTest::OnRequestSetCallRestrictionTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_SET_CALL_RESTRICTION);
    if (event != nullptr && telRilManager_ != nullptr) {
        int32_t action = 0;
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::OnRequestSetCallRestrictionTest -->");
        std::cout << "please input call set clir action: ";
        std::cin >> action;
        telRilManager_->SetClip(action, event);
        TELEPHONY_LOGI(
            "TelRilTest::OnRequestSetCallRestrictionTest --> "
            "OnRequestSetCallRestrictionTest finished");
    }
}

void TelRilTest::OnRequestSendDtmfTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_SEND_DTMF);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::OnRequestSendDtmfTest -->");
        TELEPHONY_LOGI(
            "TelRilTest::OnRequestSendDtmfTest --> "
            "OnRequestSendDtmfTest finished");
    }
}

void TelRilTest::OnRequestStartDtmfTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_START_DTMF);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::OnRequestStartDtmfTest -->");
        TELEPHONY_LOGI(
            "TelRilTest::OnRequestStartDtmfTest --> "
            "OnRequestStartDtmfTest finished");
    }
}

void TelRilTest::OnRequestStopDtmfTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_STOP_DTMF);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::OnRequestStopDtmfTest -->");
        TELEPHONY_LOGI(
            "TelRilTest::OnRequestStopDtmfTest --> "
            "OnRequestStopDtmfTest finished");
    }
}

void TelRilTest::DemoHandler::ProcessEvent(const AppExecFwk::InnerEvent::Pointer &event)
{
    auto eventId = event->GetInnerEventId();
    if (event != nullptr) {
        TELEPHONY_LOGI("TelRilTest::DemoHandler::ProcessEvent --> eventId:%{public}d", eventId);
    }
}

void TelRilTest::OnRequestGetImsCallListTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_GET_IMS_CALL_LIST);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::OnRequestGetImsCallListTest -->");
        telRilManager_->GetImsCallList(event);
        TELEPHONY_LOGI(
            "TelRilTest::OnRequestGetImsCallListTest --> "
            "OnRequestGetImsCallListTest finished");
    }
}

void TelRilTest::OnRequestSetCallPreferenceModeTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_SET_CALL_PREFERENCE_MODE);
    if (event != nullptr && telRilManager_ != nullptr) {
        int32_t mode = 0;
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::OnRequestSetCallPreferenceModeTest -->");
        std::cout << "Please enter to set the voice call mode operation,[1-4]: ";
        std::cin >> mode;
        TELEPHONY_LOGI("TelRilTest::OnRequestSetCallPreferenceModeTest --> mode = [%{public}d]", mode);
        telRilManager_->SetCallPreferenceMode(mode, event);
        TELEPHONY_LOGI(
            "TelRilTest::OnRequestSetCallPreferenceModeTest --> "
            "OnRequestSetCallPreferenceModeTest finished");
    }
}

void TelRilTest::OnRequestGetCallPreferenceModeTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_GET_CALL_PREFERENCE_MODE);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::OnRequestGetCallPreferenceModeTest -->");
        telRilManager_->GetCallPreferenceMode(event);
        TELEPHONY_LOGI(
            "TelRilTest::OnRequestGetCallPreferenceModeTest --> "
            "OnRequestGetCallPreferenceModeTest finished");
    }
}

void TelRilTest::OnRequestSetLteImsSwitchStatusTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_SET_LTE_IMS_SWITCH_STATUS);
    if (event != nullptr && telRilManager_ != nullptr) {
        int32_t active = 0;
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::OnRequestSetLteImsSwitchStatusTest -->");
        std::cout << "Please enter to set the Let IMS switch state operation,[0/1]: ";
        std::cin >> active;
        TELEPHONY_LOGI("TelRilTest::OnRequestSetLteImsSwitchStatusTest --> active = [%{public}d]", active);
        telRilManager_->SetLteImsSwitchStatus(active, event);
        TELEPHONY_LOGI(
            "TelRilTest::OnRequestSetLteImsSwitchStatusTest --> "
            "OnRequestSetLteImsSwitchStatusTest finished");
    }
}

void TelRilTest::OnRequestGetLteImsSwitchStatusTest(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_GET_LTE_IMS_SWITCH_STATUS);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::OnRequestGetLteImsSwitchStatusTest -->");
        telRilManager_->GetLteImsSwitchStatus(event);
        TELEPHONY_LOGI(
            "TelRilTest::OnRequestGetLteImsSwitchStatusTest --> "
            "OnRequestGetLteImsSwitchStatusTest finished");
    }
}

void Promote()
{
    cout << "########################### TEL RIL TEST ######################" << endl;
    cout << "usage:" << endl;

    cout << (int32_t)DiffInterfaceId::TEST_SET_POWER_STATE << " --> OnRequestSetRadioStateTest" << endl;
    cout << (int32_t)DiffInterfaceId::TEST_GET_POWER_STATE << " --> OnRequestGetRadioStateTest" << endl;
    cout << (int32_t)DiffInterfaceId::TEST_EXIT << "--> Exit" << endl << endl; // exit
}

void SimTest()
{
    /*-----------------------------------------------SIM-------------------------------------*/
    cout << "please input a cmd num: " << endl;
    cout << (int32_t)DiffInterfaceId::TEST_GET_SIM_CARD_STATUS << "--> OnRequestSimGetSimStatusTest" << endl; // pass
    cout << (int32_t)DiffInterfaceId::TEST_SIM_IO << "--> OnRequestSimIccIoTest" << endl;
    cout << (int32_t)DiffInterfaceId::TEST_GET_IMSI << "--> OnRequestSimGetImsiTest" << endl; // pass
    cout << (int32_t)DiffInterfaceId::TEST_GET_ICCID << "--> OnRequestSimGetIccIDTest" << endl; // pass
    cout << (int32_t)DiffInterfaceId::TEST_GET_SIM_LOCK_STATUS << "--> OnRequestGetSimLockStatusTest"
        << endl; // pass
    cout << (int32_t)DiffInterfaceId::TEST_SET_SIM_LOCK << "--> OnRequestSetSimLockTest" << endl; // pass
    cout << (int32_t)DiffInterfaceId::TEST_GET_CHANGE_SIM_PASSWD << "--> OnRequestChangeSimPasswordTest"
        << endl; // pass
    cout << (int32_t)DiffInterfaceId::TEST_ENTER_SIM_PIN << "--> OnRequestEnterSimPinTest" << endl; // pass
    cout << (int32_t)DiffInterfaceId::TEST_UNLOCK_SIM_PIN << "--> OnRequestUnlockSimPinTest" << endl; // pass
    cout << (int32_t)DiffInterfaceId::TEST_GET_PIN_INPUT_TIMES << "--> OnRequestGetSimPinInputTimesTest"
        << endl; // pass
    cout << (int32_t)DiffInterfaceId::TEST_ENTER_SIM_PIN2 << "--> OnRequestEnterSimPin2Test" << endl; // pass
    cout << (int32_t)DiffInterfaceId::TEST_UNLOCK_SIM_PIN2 << "--> OnRequestUnlockSimPin2Test" << endl; // pass
    cout << (int32_t)DiffInterfaceId::TEST_GET_PIN2_INPUT_TIMES << "--> OnRequestGetSimPin2InputTimesTest"
        << endl; // pass
    cout << (int32_t)DiffInterfaceId::TEST_ENABLE_SIM_CARD << "--> OnRequestSetActiveSimTest" << endl; // pass

    cout << (int32_t)DiffInterfaceId::TEST_SETUP_RILCM_DATA_CALL_TEST << "--> OnRequestDataSetupDataCallTest" << endl;
    cout << (int32_t)DiffInterfaceId::TEST_DEACTIVATE_RILCM_DATA_CALL_TEST << "--> OnRequestDataDisableDataCallTest"
        << endl; // pass
    cout << (int32_t)DiffInterfaceId::TEST_GET_RILCM_DATA_CALL_LIST_TEST << "--> OnRequestGetDataCallListTest"
        << endl; // pass
    cout << (int32_t)DiffInterfaceId::TEST_ACKNOWLEDGE_RILCM_LAST_INCOMING_GSM_SMS_TEST
        << "--> OnRequestSmsAcknowledgeTest" << endl;
}

void CallTest()
{
    /* --------------------------------- CALL -------------------------- */
    cout << (int32_t)DiffInterfaceId::TEST_CALL_DIAL << " --> OnRequestCallDialTest" << endl;
    cout << (int32_t)DiffInterfaceId::TEST_HANDUP_CONNECT << " --> OnRequestCallHangupTest" << endl;
    cout << (int32_t)DiffInterfaceId::TEST_ACCEPT_CALL << "--> OnRequestCallAnswerTest" << endl;
    cout << (int32_t)DiffInterfaceId::TEST_CURRENT_CALLS << "--> OnRequestCallGetCurrentCallsStatusTest" << endl;
    cout << (int32_t)DiffInterfaceId::TEST_REJECT_CALL << "--> OnRequestRefusedCallTest" << endl;
    cout << (int32_t)DiffInterfaceId::TEST_JOIN_CALL << "--> OnRequestCallJoinTest" << endl;
    cout << (int32_t)DiffInterfaceId::TEST_SPLIT_CALL << "--> OnRequestSeparateConferenceTest" << endl;
    cout << (int32_t)DiffInterfaceId::TEST_GET_CALL_WAIT << " --> OnRequestGetCallWaitTest" << endl;
    cout << (int32_t)DiffInterfaceId::TEST_SET_CALL_WAIT << " --> OnRequestSetCallWaitTest" << endl;
    cout << (int32_t)DiffInterfaceId::TEST_GET_CALL_FORWARD << " --> OnRequestGetCallForwardTest" << endl;
    cout << (int32_t)DiffInterfaceId::TEST_SET_CALL_FORWARD << " --> OnRequestSetCallForwardTest" << endl;
    cout << (int32_t)DiffInterfaceId::TEST_GET_CALL_DEAL_CLIP << " --> OnRequestGetClipTest" << endl;
    cout << (int32_t)DiffInterfaceId::TEST_SET_CALL_CLIP << " --> OnRequestSetClipTest" << endl;
    cout << (int32_t)DiffInterfaceId::TEST_GET_CALL_RESTRICTION << " --> OnRequestGetCallRestrictionTest" << endl;
    cout << (int32_t)DiffInterfaceId::TEST_SET_CALL_RESTRICTION << " --> OnRequestSetCallRestrictionTest" << endl;
    cout << (int32_t)DiffInterfaceId::TEST_SEND_DTMF << " --> OnRequestSendDtmfTest" << endl;
    cout << (int32_t)DiffInterfaceId::TEST_START_DTMF << " --> OnRequestStartDtmfTest" << endl;
    cout << (int32_t)DiffInterfaceId::TEST_STOP_DTMF << " --> OnRequestStopDtmfTest" << endl;
    cout << (int32_t)DiffInterfaceId::TEST_GET_IMS_CALL_LIST << " --> OnRequestGetImsCallListTest" << endl;
    cout << (int32_t)DiffInterfaceId::TEST_SET_CALL_PREFERENCE_MODE << "--> OnRequestSetCallPreferenceModeTest"
    << endl;
    cout << (int32_t)DiffInterfaceId::TEST_GET_CALL_PREFERENCE_MODE << "--> OnRequestGetCallPreferenceModeTest"
    << endl;
    cout << (int32_t)DiffInterfaceId::TEST_SET_LTE_IMS_SWITCH_STATUS << " --> OnRequestSetLteImsSwitchStatusTest"
    << endl;
    cout << (int32_t)DiffInterfaceId::TEST_GET_LTE_IMS_SWITCH_STATUS << " --> OnRequestGetLteImsSwitchStatusTest"
    << endl;
}

void SmsTest()
{
    /* --------------------------------- SMS -------------------------- */
    cout << (int32_t)DiffInterfaceId::TEST_SEND_SMS << "--> OnRequestSendRilCmSmsTest"
         << endl; // failed, Sim not inserted, radioResponseInfo->error : 2
    cout << (int32_t)DiffInterfaceId::TEST_STORAGE_SMS << "--> OnRequestStorageRilCmSmsTest" << endl;
    cout << (int32_t)DiffInterfaceId::TEST_DELETE_SMS << "--> OnRequestDeleteRilCmSmsTest" << endl;
    cout << (int32_t)DiffInterfaceId::TEST_UPDATE_SMS << "--> OnRequestUpdateRilCmSmsTest" << endl;
    cout << (int32_t)DiffInterfaceId::TEST_SET_SMS_CENTER_ADDRESS << "--> OnRequestSetRilCmSmsCenterAddressTest"
        << endl;
    cout << (int32_t)DiffInterfaceId::TEST_GET_SMS_CENTER_ADDRESS << "--> OnRequestGetRilCmSmsCenterAddressTest"
        << endl;
    cout << (int32_t)DiffInterfaceId::TEST_SET_CB_CONFIG << "--> OnRequestSetRilCBConfigTest" << endl;
    cout << (int32_t)DiffInterfaceId::TEST_GET_CB_CONFIG << "--> OnRequestGetRilCBConfigTest" << endl;
    cout << (int32_t)DiffInterfaceId::TEST_GET_CDMA_CB_CONFIG << "--> OnRequestGetRilCdmaCBConfigTest"<<endl;
    cout << (int32_t)DiffInterfaceId::TEST_ACTIVE_CDMA_CB_CONFIG << "--> OnRequestGetRilCmCdmaCBConfigTest"
        << endl;
    cout << (int32_t)DiffInterfaceId::TEST_SEND_SMS_EXPECT_MORE << " --> OnRequestSmsSendSmsExpectMoreTest"
        << endl; // failed, Sim not inserted, radioResponseInfo->error : 2
    cout << (int32_t)DiffInterfaceId::TEST_GET_RILCM_VOICE_REGISTRATION_STATE_TEST
        << "--> OnRequestNetworkVoiceRegistrationStateTest" << endl; // pass
    cout << (int32_t)DiffInterfaceId::TEST_GET_RILCM_DATA_REGISTRATION_STATE_TEST
        << "--> OnRequestNetworkDataRegistrationStateTest" << endl; // pass
}

void NetworkTest()
{
    /* --------------------------------- Network -------------------------- */
    cout << (int32_t)DiffInterfaceId::TEST_SET_PREFERRED_NETWORK_TYPE << "--> OnRequestSetPreferredNetworkTest"
        << endl;
    cout << (int32_t)DiffInterfaceId::TEST_GET_PREFERRED_NETWORK_TYPE << "--> OnRequestGetPreferredNetworkTest"
        << endl;
    cout << (int32_t)DiffInterfaceId::TEST_GET_IMEI << "--> OnRequestGetImeiTest" << endl;
    cout << (int32_t)DiffInterfaceId::TEST_GET_IMS_REG_STATUS << "--> OnRequestGetImsRegStatusTest" << endl;
    cout << (int32_t)DiffInterfaceId::TEST_GET_PS_ATTACH_STATUS << "--> OnRequestGetPsAttachStatusTest"
        << endl;
    cout << (int32_t)DiffInterfaceId::TEST_SET_PS_ATTACH_STATUS << "--> OnRequestSetPsAttachStatusTest"
        << endl;
    cout << (int32_t)DiffInterfaceId::TEST_GET_CURRENT_CELL_INFO << " --> OnRequestGetCurrentCellInfoTest" << endl;
    cout << (int32_t)DiffInterfaceId::TEST_GET_CELL_INFO_LIST << " --> OnRequestGetCellInfoListTest" << endl;
    cout << (int32_t)DiffInterfaceId::TEST_OPERATOR << " --> OnRequestNetworkOperatorTest"
        << endl; // failed, Invalid response: nullptr, radioResponseInfo->error : 2
    cout << (int32_t)DiffInterfaceId::TEST_GET_NETWORKS_TO_USE << "--> OnRequestGetNetworkSearchInformationTest"
        << endl; // failed, Invalid response: nullptr, radioResponseInfo->error : 2
    cout << (int32_t)DiffInterfaceId::TEST_GET_SELECTION_MOD_FOR_NETWORKS << "--> OnRequestGetNetworkSelectionModeTest"
        << endl; // failed, Invalid response: nullptr, radioResponseInfo->error : 2
    cout << (int32_t)DiffInterfaceId::TEST_SET_MODE_AUTOMATIC_NETWORKS << "--> OnRequestSetNetworkSelectionModeTest"
        << endl; // failed, Invalid response: nullptr, radioResponseInfo->error : 2
    cout << (int32_t)DiffInterfaceId::TEST_GET_SIGNAL_STRENGTH << "--> OnRequestNetworkGetRssiTest" << endl;
    cout << (int32_t)DiffInterfaceId::TEST_GET_CS_REG_STATUS << "--> OnRequestGetCsRegStatusTest" << endl;
    cout << (int32_t)DiffInterfaceId::TEST_GET_PS_REG_STATUS << "--> OnRequestGetPsRegStatusTest" << endl;
}
} // namespace
} // namespace Telephony
} // namespace OHOS

using namespace OHOS;
using namespace OHOS::Telephony;
int main()
{
    std::unique_ptr<TelRilTest> rilManagerAndResponseTest;
    std::shared_ptr<AppExecFwk::EventRunner> eventRunner;
    std::shared_ptr<TelRilTest::DemoHandler> demohandler;
    TELEPHONY_LOGI("TelRilTest::main function entry -->");
    rilManagerAndResponseTest = std::make_unique<TelRilTest>();
    if (rilManagerAndResponseTest != nullptr) {
        rilManagerAndResponseTest->OnInitInterface();
    }
    if (rilManagerAndResponseTest->telRilManager_ == nullptr) {
        TELEPHONY_LOGE("ERROR : make_shared<ITelRilManager>(telRilManager) --> nullptr !!!");
        return -1;
    }
    TELEPHONY_LOGI("make_shared<ITelRilManager>(telRilManager) --> success");
    eventRunner = AppExecFwk::EventRunner::Create("DemoHandler");
    if (eventRunner == nullptr) {
        TELEPHONY_LOGE("ERROR : AppExecFwk::EventRunner::Create(\"DemoHandler\") --> nullptr !!!");
        return -1;
    }
    TELEPHONY_LOGI("AppExecFwk::EventRunner::Create(\"DemoHandler\") --> success");
    demohandler = make_shared<TelRilTest::DemoHandler>(eventRunner);
    if (demohandler == nullptr) {
        TELEPHONY_LOGE("ERROR : make_shared<TelRilTest::DemoHandler>(runner) --> nullptr !!!");
        return -1;
    }
    TELEPHONY_LOGI("make_shared<TelRilTest::DemoHandler>(runner) --> success");
    rilManagerAndResponseTest->OnInitForRegister(demohandler);
    TELEPHONY_LOGI("OnInitForRegister(g_handler) finished -->");
    eventRunner->Run();
    int32_t what = 1;
    while (what) {
        Promote();
        SimTest();
        CallTest();
        SmsTest();
        NetworkTest();
        cin >> what;
        cout << "" << endl;
        if (what == static_cast<int32_t>(DiffInterfaceId::TEST_EXIT)) {
            break;
        }
        if ((what >= static_cast<int32_t>(DiffInterfaceId::TEST_GET_SIM_CARD_STATUS)) &&
            (what < static_cast<int32_t>(DiffInterfaceId::TEST_EXIT))) {
            rilManagerAndResponseTest->OnProcessInput(what, demohandler);
        }
    }
    return 0;
}
