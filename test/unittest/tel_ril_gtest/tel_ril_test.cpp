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

#include "tel_ril_test.h"

#include <fcntl.h>
#include <iostream>

#include "iservice_registry.h"
#include "radio_event.h"
#include "system_ability_definition.h"

using namespace testing::ext;

namespace OHOS {
namespace Telephony {
const std::string GTEST_STRING = "1234";
const std::string GTEST_STRING_PIN1 = "1234";
const std::string GTEST_STRING_PIN2 = "80785121";
const std::string GTEST_STRING_PUK1 = "19467362";
const std::string GTEST_STRING_PUK2 = "19467362";
const int32_t PW_LEN = 4;
const int32_t DECIMAL = 10;
const int32_t PHONE_NUM_LEN = 11;
const int32_t CID = 1;
const int32_t REASON = 2;
const int32_t P3 = 15;
const int32_t COMMAND = 192;
const int32_t FILEID = 20272;
const int32_t AUTHTYPE_1 = 0;
constexpr static const int32_t WAIT_TIME_SECOND = 20;
constexpr static const int32_t WAIT_TIME_SECOND_LONG = 30;
const int BANDWIDTH_HYSTERESIS_MS = 3000;
const int BANDWIDTH_HYSTERESIS_KBPS = 50;
const int MAX_DOWNLINK_LINK_BANDWIDTH[] = { 100, // VoIP
    500, // Web
    1000, // SD
    5000, // HD
    10000, // file
    20000, // 4K
    50000, // LTE
    100000,
    200000, // 5G
    500000, 1000000 };
const int MAX_UPLINK_LINK_BANDWIDTH[] = { 100, 500, 1000, 5000, 10000, 20000, 50000, 100000, 200000 };
#ifndef TEL_TEST_UNSUPPORT
const int32_t SLOT_ID_0 = 0;
const int32_t SLOT_ID_1 = 1;
#endif // TEL_TEST_UNSUPPORT

// send "test"
const std::string TEST_PDU = "A10305810180F6000004F4F29C0E";
// leave blank, smsc will be acquired automatically
const std::string TEST_SMSC_PDU = "";
// smsc addr
std::string g_smscAddr = "";
int32_t tosca = 0;
std::shared_ptr<Telephony::ITelRilManager> TelRilTest::telRilManager_ = nullptr;
sptr<ICoreService> TelRilTest::telephonyService_ = nullptr;

void TelRilTest::SetUp() {}

void TelRilTest::TearDown() {}

void TelRilTest::SetUpTestCase()
{
    TELEPHONY_LOGI("----------TelRilTest gtest start ------------");
    telRilManager_ = std::make_shared<TelRilManager>();
    auto ret = telRilManager_->OnInit();
    if (telephonyService_ == nullptr) {
        telephonyService_ = GetProxy();
    }
    TELEPHONY_LOGI("----------TelRilTest setup finished ret: %{public}d ------------", ret);
}

void TelRilTest::TearDownTestCase()
{
    TELEPHONY_LOGI("----------TelRilTest gtest end ------------");
}

TelRilTest::TelRilTest()
{
    AddRequestToMap();
}

TelRilTest::~TelRilTest()
{
    memberFuncMap_.clear();
}

sptr<ICoreService> TelRilTest::GetProxy()
{
    TELEPHONY_LOGI("TelRilTest::GetProxy");
    sptr<ISystemAbilityManager> systemAbilityMgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (systemAbilityMgr == nullptr) {
        TELEPHONY_LOGI("TelRilTest::GetProxy systemAbilityMgr is nullptr");
        return nullptr;
    }
    sptr<IRemoteObject> remote = systemAbilityMgr->CheckSystemAbility(TELEPHONY_CORE_SERVICE_SYS_ABILITY_ID);
    if (remote) {
        sptr<ICoreService> telephonyService = iface_cast<ICoreService>(remote);
        return telephonyService;
    } else {
        TELEPHONY_LOGE("TelRilTest::GetProxy Get TELEPHONY_CORE_SERVICE_SYS_ABILITY_ID fail");
        return nullptr;
    }
}

void TelRilTest::ProcessTest(int32_t index, int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    if (telephonyService_ == nullptr) {
        TELEPHONY_LOGE("TelRilTest::ProcessTest telephonyService_ is nullptr");
        telephonyService_ = GetProxy();
        return;
    }
    bool hasSimCard = false;
    telephonyService_->HasSimCard(slotId, hasSimCard);
    if (!hasSimCard) {
        TELEPHONY_LOGE("TelRilTest::ProcessTest no sim card %{public}d", slotId);
        return;
    }

    for (auto itFunc : memberFuncMap_) {
        int32_t val = static_cast<int32_t>(itFunc.first);
        if (val == index) {
            auto memberFunc = itFunc.second;
            (this->*memberFunc)(slotId, handler);
        }
    }
}

void TelRilTest::AddRequestToMap()
{
    InitCall();
    InitData();
    InitSim();
    InitSms();
    InitNetwork();
    InitModem();
}

void TelRilTest::InitCall()
{
    /* --------------------------------- CALL ----------------------------- */
    memberFuncMap_[DiffInterfaceId::TEST_CURRENT_CALLS] = &TelRilTest::CallGetCurrentCallsStatusTest;
    memberFuncMap_[DiffInterfaceId::TEST_CALL_DIAL] = &TelRilTest::CallDialTest;
    memberFuncMap_[DiffInterfaceId::TEST_HANDUP_CONNECT] = &TelRilTest::CallHangupTest;
    memberFuncMap_[DiffInterfaceId::TEST_ACCEPT_CALL] = &TelRilTest::CallAnswerTest;
    memberFuncMap_[DiffInterfaceId::TEST_HOLD_CALL] = &TelRilTest::CallHoldTest;
    memberFuncMap_[DiffInterfaceId::TEST_ACTIVE_CALL] = &TelRilTest::CallActiveTest;
    memberFuncMap_[DiffInterfaceId::TEST_SWAP_CALL] = &TelRilTest::CallSwapTest;
    memberFuncMap_[DiffInterfaceId::TEST_JOIN_CALL] = &TelRilTest::CallJoinTest;
    memberFuncMap_[DiffInterfaceId::TEST_SPLIT_CALL] = &TelRilTest::CallSplitTest;
    memberFuncMap_[DiffInterfaceId::TEST_REJECT_CALL] = &TelRilTest::RefusedCallTest;
    memberFuncMap_[DiffInterfaceId::TEST_GET_CALL_WAIT] = &TelRilTest::GetCallWaitTest;
    memberFuncMap_[DiffInterfaceId::TEST_SET_CALL_WAIT] = &TelRilTest::SetCallWaitTest;
    memberFuncMap_[DiffInterfaceId::TEST_GET_CALL_FORWARD] = &TelRilTest::GetCallForwardTest;
    memberFuncMap_[DiffInterfaceId::TEST_SET_CALL_FORWARD] = &TelRilTest::SetCallForwardTest;
    memberFuncMap_[DiffInterfaceId::TEST_GET_CALL_DEAL_CLIP] = &TelRilTest::GetClipTest;
    memberFuncMap_[DiffInterfaceId::TEST_SET_CALL_CLIP] = &TelRilTest::SetClipTest;
    memberFuncMap_[DiffInterfaceId::TEST_GET_CALL_RESTRICTION] = &TelRilTest::GetCallRestrictionTest;
    memberFuncMap_[DiffInterfaceId::TEST_SET_CALL_RESTRICTION] = &TelRilTest::SetCallRestrictionTest;
    memberFuncMap_[DiffInterfaceId::TEST_SEND_DTMF] = &TelRilTest::SendDtmfTest;
    memberFuncMap_[DiffInterfaceId::TEST_START_DTMF] = &TelRilTest::StartDtmfTest;
    memberFuncMap_[DiffInterfaceId::TEST_STOP_DTMF] = &TelRilTest::StopDtmfTest;
    memberFuncMap_[DiffInterfaceId::TEST_SET_USSD] = &TelRilTest::SetUssdTest;
    memberFuncMap_[DiffInterfaceId::TEST_GET_USSD] = &TelRilTest::GetUssdTest;
    memberFuncMap_[DiffInterfaceId::TEST_SET_CMUT] = &TelRilTest::SetMuteTest;
    memberFuncMap_[DiffInterfaceId::TEST_GET_CMUT] = &TelRilTest::GetMuteTest;
    memberFuncMap_[DiffInterfaceId::TEST_GET_EMERGENCY_CALL_LIST] = &TelRilTest::GetEmergencyCallListTest;
}

void TelRilTest::InitData()
{
    /* --------------------------------- DATA ----------------------------- */
    memberFuncMap_[DiffInterfaceId::TEST_RILCM_SET_INIT_APN_INFO] = &TelRilTest::DataSetInitApnInfoTest;
    memberFuncMap_[DiffInterfaceId::TEST_RILCM_SETUP_DATA_CALL] = &TelRilTest::DataSetupDataCallTest;
    memberFuncMap_[DiffInterfaceId::TEST_RILCM_DEACTIVATE_DATA_CALL] = &TelRilTest::DataDisableDataCallTest;
    memberFuncMap_[DiffInterfaceId::TEST_RILCM_GET_DATA_CALL_LIST] = &TelRilTest::GetDataCallListTest;
    memberFuncMap_[DiffInterfaceId::TEST_RILCM_GET_LINK_BANDWIDTH_INFO] = &TelRilTest::GetLinkBandwidthInfoTest;
    memberFuncMap_[DiffInterfaceId::TEST_RILCM_SET_LINK_BANDWIDTH_REPORTING_RULE] =
        &TelRilTest::OnRequestSetLinkBandwidthReportingRuleTest;
    memberFuncMap_[DiffInterfaceId::TEST_RILCM_SET_DATA_PERMITTED_TEST] = &TelRilTest::SetDataPermittedTest;
}

void TelRilTest::InitSim()
{
    /*-----------------------------------SIM----------------------------------*/
    memberFuncMap_[DiffInterfaceId::TEST_GET_SIM_CARD_STATUS] = &TelRilTest::SimGetSimStatusTest;
    memberFuncMap_[DiffInterfaceId::TEST_SIM_IO] = &TelRilTest::SimIccIoTest;
    memberFuncMap_[DiffInterfaceId::TEST_GET_IMSI] = &TelRilTest::SimGetImsiTest;
    memberFuncMap_[DiffInterfaceId::TEST_GET_SIM_LOCK_STATUS] = &TelRilTest::GetSimLockStatusTest;
    memberFuncMap_[DiffInterfaceId::TEST_SET_SIM_LOCK] = &TelRilTest::SetSimLockTest;
    memberFuncMap_[DiffInterfaceId::TEST_UNSET_SIM_LOCK] = &TelRilTest::UnSetSimLockTest;
    memberFuncMap_[DiffInterfaceId::TEST_GET_CHANGE_SIM_PASSWD] = &TelRilTest::ChangeSimPasswordTest;
    memberFuncMap_[DiffInterfaceId::TEST_ENTER_SIM_PIN] = &TelRilTest::EnterSimPinTest;
    memberFuncMap_[DiffInterfaceId::TEST_RADIO_RESTART] = &TelRilTest::RadioRestartTest;
    memberFuncMap_[DiffInterfaceId::TEST_ENTER_ERROR_PIN] = &TelRilTest::EnterErrorPinTest;
    memberFuncMap_[DiffInterfaceId::TEST_UNLOCK_SIM_PIN] = &TelRilTest::UnlockSimPinTest;
    memberFuncMap_[DiffInterfaceId::TEST_SET_PIN2_LOCK] = &TelRilTest::SetPin2LockTest;
    memberFuncMap_[DiffInterfaceId::TEST_ENTER_SIM_PIN2] = &TelRilTest::EnterSimPin2Test;
    memberFuncMap_[DiffInterfaceId::TEST_ENTER_ERROR_PIN2] = &TelRilTest::EnterErrorPin2Test;
    memberFuncMap_[DiffInterfaceId::TEST_UNLOCK_SIM_PIN2] = &TelRilTest::UnlockSimPin2Test;
    memberFuncMap_[DiffInterfaceId::TEST_UNSET_PIN2_LOCK] = &TelRilTest::UnSetPin2LockTest;
    memberFuncMap_[DiffInterfaceId::TEST_ENABLE_SIM_CARD] = &TelRilTest::EnableSimCardTest;
    memberFuncMap_[DiffInterfaceId::TEST_STK_SEND_TERMINAL_RESPONSE] = &TelRilTest::SendTerminalResponseCmdTest;
    memberFuncMap_[DiffInterfaceId::TEST_STK_SEND_ENVELOPE] = &TelRilTest::SendEnvelopeCmdTest;
    memberFuncMap_[DiffInterfaceId::TEST_STK_SEND_CALL_SETUP_REQUEST_RESULT] =
        &TelRilTest::SendCallSetupRequestResultTest;
    memberFuncMap_[DiffInterfaceId::TEST_GET_RADIO_PROTOCOL] = &TelRilTest::GetRadioProtocolTest;
    memberFuncMap_[DiffInterfaceId::TEST_SET_RADIO_PROTOCOL] = &TelRilTest::SetRadioProtocolTest;
}

void TelRilTest::InitSms()
{
    /* --------------------------------- SMS ----------------------------- */
    memberFuncMap_[DiffInterfaceId::TEST_SEND_SMS] = &TelRilTest::SendRilCmSmsTest;
    memberFuncMap_[DiffInterfaceId::TEST_STORAGE_SMS] = &TelRilTest::StorageRilCmSmsTest;
    memberFuncMap_[DiffInterfaceId::TEST_DELETE_SMS] = &TelRilTest::DeleteRilCmSmsTest;
    memberFuncMap_[DiffInterfaceId::TEST_UPDATE_SMS] = &TelRilTest::UpdateRilCmSmsTest;
    memberFuncMap_[DiffInterfaceId::TEST_SET_SMS_CENTER_ADDRESS] = &TelRilTest::SetRilCmSmsCenterAddressTest;
    memberFuncMap_[DiffInterfaceId::TEST_GET_SMS_CENTER_ADDRESS] = &TelRilTest::GetRilCmSmsCenterAddressTest;
    memberFuncMap_[DiffInterfaceId::TEST_SET_CB_CONFIG] = &TelRilTest::SetRilCmCBConfigTest;
    memberFuncMap_[DiffInterfaceId::TEST_SET_CDMA_CB_CONFIG] = &TelRilTest::SetRilCmCdmaCBConfigTest;
    memberFuncMap_[DiffInterfaceId::TEST_GET_CB_CONFIG] = &TelRilTest::GetRilCmCBConfigTest;
    memberFuncMap_[DiffInterfaceId::TEST_GET_CDMA_CB_CONFIG] = &TelRilTest::GetRilCmCdmaCBConfigTest;
    memberFuncMap_[DiffInterfaceId::TEST_SEND_SMS_EXPECT_MORE] = &TelRilTest::SmsSendSmsExpectMoreTest;
    memberFuncMap_[DiffInterfaceId::TEST_SEND_SMS_ACK] = &TelRilTest::SmsAcknowledgeTest;
    memberFuncMap_[DiffInterfaceId::TEST_ADD_CDMA_SMS] = &TelRilTest::AddRilCmCdmaSmsTest;
    memberFuncMap_[DiffInterfaceId::TEST_DEL_CDMA_SMS] = &TelRilTest::DelRilCmCdmaSmsTest;
    memberFuncMap_[DiffInterfaceId::TEST_UPDATE_CDMA_SMS] = &TelRilTest::UpdateRilCmCdmaSmsTest;
}

void TelRilTest::InitNetwork()
{
    /* --------------------------------- NETWORK ----------------------------- */
    memberFuncMap_[DiffInterfaceId::TEST_OPERATOR] = &TelRilTest::NetworkOperatorTest;
    memberFuncMap_[DiffInterfaceId::TEST_GET_RILCM_VOICE_REGISTRATION_STATE] =
        &TelRilTest::NetworkVoiceRegistrationStateTest;
    memberFuncMap_[DiffInterfaceId::TEST_GET_RILCM_DATA_REGISTRATION_STATE] =
        &TelRilTest::NetworkDataRegistrationStateTest;
    memberFuncMap_[DiffInterfaceId::TEST_GET_NETWORKS_TO_USE] = &TelRilTest::GetNetworkSearchInformationTest;
    memberFuncMap_[DiffInterfaceId::TEST_GET_SELECTION_MOD_FOR_NETWORKS] = &TelRilTest::GetNetworkSelectionModeTest;
    memberFuncMap_[DiffInterfaceId::TEST_SET_MODE_AUTOMATIC_NETWORKS] = &TelRilTest::SetNetworkSelectionModeTest;
    memberFuncMap_[DiffInterfaceId::TEST_GET_PREFERRED_NETWORK_TYPE] = &TelRilTest::GetPreferredNetworkParaTest;
    memberFuncMap_[DiffInterfaceId::TEST_SET_PREFERRED_NETWORK_TYPE] = &TelRilTest::SetPreferredNetworkParaTest;
    memberFuncMap_[DiffInterfaceId::TEST_GET_IMEI] = &TelRilTest::GetImeiTest;
    memberFuncMap_[DiffInterfaceId::TEST_GET_MEID] = &TelRilTest::GetMeidTest;
    memberFuncMap_[DiffInterfaceId::TEST_GET_VOICE_RADIO_INFO] = &TelRilTest::GetVoiceRadioTechnologyTest;
    memberFuncMap_[DiffInterfaceId::TEST_GET_PHYSICAL_CHANNEL_CONFIG] = &TelRilTest::GetPhysicalChannelConfigTest;
    memberFuncMap_[DiffInterfaceId::TEST_SET_LOCATE_UPDATES] = &TelRilTest::SetLocateUpdatesTest;
    memberFuncMap_[DiffInterfaceId::TEST_SET_NOTIFICATION_FILTER] = &TelRilTest::SetNotificationFilterTest;
    memberFuncMap_[DiffInterfaceId::TEST_SET_DEVICE_STATE] = &TelRilTest::SetDeviceStateTest;
}

void TelRilTest::InitModem()
{
    /* --------------------------------- MODEM -------------------------- */
    memberFuncMap_[DiffInterfaceId::TEST_GET_SIGNAL_STRENGTH] = &TelRilTest::NetworkGetRssiTest;
    memberFuncMap_[DiffInterfaceId::TEST_SET_POWER_STATE] = &TelRilTest::SetRadioStateTest;
    memberFuncMap_[DiffInterfaceId::TEST_GET_POWER_STATE] = &TelRilTest::GetRadioStateTest;
}

/**
 * @brief Get current calls status
 *
 * @param handler
 */
void TelRilTest::CallGetCurrentCallsStatusTest(int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    int32_t eventId = static_cast<int32_t>(RadioEvent::RADIO_CURRENT_CALLS);
    auto event = AppExecFwk::InnerEvent::Get(eventId);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::CallGetCurrentCallsStatusTest -->");
        telRilManager_->GetCallList(slotId, event);
        TELEPHONY_LOGI("TelRilTest::CallGetCurrentCallsStatusTest --> finished");
        bool syncResult = WaitGetResult(eventId, handler, WAIT_TIME_SECOND);
        ASSERT_TRUE(syncResult);
    }
}

/************************************** SIM test func *******************************************/
/**
 * @brief Get SIM card status
 *
 * @param handler
 */
void TelRilTest::SimGetSimStatusTest(int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    int32_t eventId = static_cast<int32_t>(RadioEvent::RADIO_SIM_GET_STATUS);
    auto event = AppExecFwk::InnerEvent::Get(eventId);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::SimGetSimStatusTest -->");
        telRilManager_->GetSimStatus(slotId, event);
        TELEPHONY_LOGI("TelRilTest::SimGetSimStatusTest --> finished");
        bool syncResult = WaitGetResult(eventId, handler, WAIT_TIME_SECOND);
        ASSERT_TRUE(syncResult);
    }
}

/**
 * @brief Get SIM card IO
 *
 * @param handler
 */
void TelRilTest::SimIccIoTest(int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    int32_t eventId = static_cast<int32_t>(RadioEvent::RADIO_SIM_IO);
    auto event = AppExecFwk::InnerEvent::Get(eventId);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::SimIccIoTest -->");
        SimIoRequestInfo msg;
        msg.command = COMMAND;
        msg.fileId = FILEID;
        msg.p1 = 0;
        msg.p2 = 0;
        msg.p3 = P3;
        msg.data = "";
        msg.path = "3F007F105F3A";
        msg.pin2 = "";
        telRilManager_->GetSimIO(slotId, msg, event);
        TELEPHONY_LOGI("TelRilTest::SimIccIoTest --> finished");
        bool syncResult = WaitGetResult(eventId, handler, WAIT_TIME_SECOND);
        ASSERT_TRUE(syncResult);
    }
}

/**
 * @brief Get International Mobile Subscriber Identity
 *
 * @param handler
 */
void TelRilTest::SimGetImsiTest(int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    int32_t eventId = static_cast<int32_t>(RadioEvent::RADIO_SIM_GET_IMSI);
    auto event = AppExecFwk::InnerEvent::Get(eventId);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::SimGetImsiTest -->");
        telRilManager_->GetImsi(slotId, event);
        TELEPHONY_LOGI("TelRilTest::SimGetImsiTest --> finished");
        bool syncResult = WaitGetResult(eventId, handler, WAIT_TIME_SECOND);
        ASSERT_TRUE(syncResult);
    }
}

/**
 * @brief Get SIM card lock status
 *
 * @param handler
 */
void TelRilTest::GetSimLockStatusTest(int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    int32_t eventId = static_cast<int32_t>(RadioEvent::RADIO_SIM_GET_LOCK_STATUS);
    auto event = AppExecFwk::InnerEvent::Get(eventId);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        std::string fac = FAC_PIN_LOCK;
        TELEPHONY_LOGI("TelRilTest::GetSimLockStatusTest -->");
        telRilManager_->GetSimLockStatus(slotId, fac, event);
        TELEPHONY_LOGI("TelRilTest::GetSimLockStatusTest --> finished");
        bool syncResult = WaitGetResult(eventId, handler, WAIT_TIME_SECOND);
        ASSERT_TRUE(syncResult);
    }
}

/**
 * @brief Set SIM card lock status
 *
 * @param handler
 */
void TelRilTest::SetSimLockTest(int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    int32_t eventId = static_cast<int32_t>(RadioEvent::RADIO_SIM_SET_LOCK);
    auto event = AppExecFwk::InnerEvent::Get(eventId);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        SimLockParam simLockParam;
        simLockParam.fac = FAC_PIN_LOCK;
        simLockParam.mode = static_cast<int32_t>(LockState::LOCK_ON);
        simLockParam.passwd = GTEST_STRING_PIN1;
        TELEPHONY_LOGI("TelRilTest::SetSimLockTest -->");
        telRilManager_->SetSimLock(slotId, simLockParam, event);
        TELEPHONY_LOGI("TelRilTest::SetSimLockTest --> finished");
        bool syncResult = WaitGetResult(eventId, handler, WAIT_TIME_SECOND);
        ASSERT_TRUE(syncResult);
    }
}

/**
 * @brief UnSet SIM card lock status
 *
 * @param handler
 */
void TelRilTest::UnSetSimLockTest(int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    int32_t eventId = static_cast<int32_t>(RadioEvent::RADIO_SIM_SET_LOCK);
    auto event = AppExecFwk::InnerEvent::Get(eventId);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        SimLockParam simLockParam;
        simLockParam.fac = FAC_PIN_LOCK;
        simLockParam.mode = static_cast<int32_t>(LockState::LOCK_OFF);
        simLockParam.passwd = GTEST_STRING_PIN1;
        TELEPHONY_LOGI("TelRilTest::UnSetSimLockTest -->");
        telRilManager_->SetSimLock(slotId, simLockParam, event);
        TELEPHONY_LOGI("TelRilTest::UnSetSimLockTest --> finished");
        bool syncResult = WaitGetResult(eventId, handler, WAIT_TIME_SECOND);
        ASSERT_TRUE(syncResult);
    }
}

/**
 * @brief Change SIM card Password
 *
 * @param handler
 */
void TelRilTest::ChangeSimPasswordTest(int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    int32_t eventId = static_cast<int32_t>(RadioEvent::RADIO_SIM_CHANGE_PASSWD);
    auto event = AppExecFwk::InnerEvent::Get(eventId);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        SimPasswordParam simPassword;
        simPassword.passwordLength = PW_LEN;
        simPassword.fac = FAC_PIN_LOCK;
        simPassword.oldPassword = GTEST_STRING_PIN1;
        simPassword.newPassword = GTEST_STRING_PIN1;
        TELEPHONY_LOGI("TelRilTest::ChangeSimPasswordTest -->");
        telRilManager_->ChangeSimPassword(slotId, simPassword, event);
        TELEPHONY_LOGI("TelRilTest::ChangeSimPasswordTest --> finished");
        bool syncResult = WaitGetResult(eventId, handler, WAIT_TIME_SECOND);
        ASSERT_TRUE(syncResult);
    }
}

/**
 * @brief Restart Radio
 *
 * @param handler
 */
void TelRilTest::RadioRestartTest(int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    int32_t eventId = static_cast<int32_t>(RadioEvent::RADIO_SET_STATUS);
    auto event = AppExecFwk::InnerEvent::Get(eventId);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        uint8_t funOffline = 4;
        uint8_t rstOffline = 1;
        telRilManager_->SetRadioState(slotId, funOffline, rstOffline, event);
        TELEPHONY_LOGI("TelRilTest::RadioRestartTest1 -->");
        bool syncResult = WaitGetResult(eventId, handler, WAIT_TIME_SECOND_LONG);
        ASSERT_TRUE(syncResult);

        uint8_t funReboot = 6;
        uint8_t rstReboot = 1;
        telRilManager_->SetRadioState(slotId, funReboot, rstReboot, event);
        TELEPHONY_LOGI("TelRilTest::RadioRestartTest2 -->");
        bool syncResult2 = WaitGetResult(eventId, handler, WAIT_TIME_SECOND_LONG);
        ASSERT_TRUE(syncResult2);
    }
}

/**
 * @brief Enter SIM card pin code
 *
 * @param handler
 */
void TelRilTest::EnterSimPinTest(int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    int32_t eventId = static_cast<int32_t>(RadioEvent::RADIO_SIM_ENTER_PIN);
    auto event = AppExecFwk::InnerEvent::Get(eventId);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        std::string pin = GTEST_STRING_PIN1;
        TELEPHONY_LOGI("TelRilTest::EnterSimPinTest -->");
        telRilManager_->UnlockPin(slotId, pin, event);
        TELEPHONY_LOGI("TelRilTest::EnterSimPinTest --> finished");
        bool syncResult = WaitGetResult(eventId, handler, WAIT_TIME_SECOND);
        ASSERT_TRUE(syncResult);
    }
}

/**
 * @brief Enter error pin code
 *
 * @param handler
 */
void TelRilTest::EnterErrorPinTest(int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
        int32_t eventId = static_cast<int32_t>(RadioEvent::RADIO_SIM_ENTER_PIN);
        auto event = AppExecFwk::InnerEvent::Get(eventId);
        if (event != nullptr && telRilManager_ != nullptr) {
            event->SetOwner(handler);
            std::string pin = "1111";
            TELEPHONY_LOGI("TelRilTest::EnterErrorPinTest -->");
            telRilManager_->UnlockPin(slotId, pin, event);
            TELEPHONY_LOGI("TelRilTest::EnterErrorPinTest --> finished");
            bool syncResult = WaitGetResult(eventId, handler, WAIT_TIME_SECOND);
            ASSERT_TRUE(syncResult);
    }
}

/**
 * @brief Unlock SIM card pin code
 *
 * @param handler
 */
void TelRilTest::UnlockSimPinTest(int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    int32_t eventId = static_cast<int32_t>(RadioEvent::RADIO_SIM_UNLOCK_PIN);
    auto event = AppExecFwk::InnerEvent::Get(eventId);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        std::string puk = GTEST_STRING_PUK1;
        std::string pin = GTEST_STRING_PIN1;
        TELEPHONY_LOGI("TelRilTest::UnlockSimPinTest -->");
        telRilManager_->UnlockPuk(slotId, puk, pin, event);
        TELEPHONY_LOGI("TelRilTest::UnlockSimPinTest --> finished");
        bool syncResult = WaitGetResult(eventId, handler, WAIT_TIME_SECOND);
        ASSERT_TRUE(syncResult);
    }
}

/**
 * @brief Set SIM card PIN2 lock status
 *
 * @param handler
 */
void TelRilTest::SetPin2LockTest(int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    int32_t eventId = static_cast<int32_t>(RadioEvent::RADIO_SIM_SET_LOCK);
    auto event = AppExecFwk::InnerEvent::Get(eventId);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        SimLockParam simLockParam;
        simLockParam.fac = FDN_PIN2_LOCK;
        simLockParam.mode = static_cast<int32_t>(LockState::LOCK_ON);
        simLockParam.passwd = GTEST_STRING_PIN2;
        TELEPHONY_LOGI("TelRilTest::SetPIN2LockTest -->");
        telRilManager_->SetSimLock(slotId, simLockParam, event);
        TELEPHONY_LOGI("TelRilTest::SetPin2LockTest --> finished");
        bool syncResult = WaitGetResult(eventId, handler, WAIT_TIME_SECOND);
        ASSERT_TRUE(syncResult);
    }
}

/**
 * @brief Set SIM card PIN2 lock status
 *
 * @param handler
 */
void TelRilTest::UnSetPin2LockTest(int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    int32_t eventId = static_cast<int32_t>(RadioEvent::RADIO_SIM_SET_LOCK);
    auto event = AppExecFwk::InnerEvent::Get(eventId);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        SimLockParam simLockParam;
        simLockParam.fac = FDN_PIN2_LOCK;
        simLockParam.mode = static_cast<int32_t>(LockState::LOCK_OFF);
        simLockParam.passwd = GTEST_STRING_PIN2;
        TELEPHONY_LOGI("TelRilTest::UnSetPin2LockTest -->");
        telRilManager_->SetSimLock(slotId, simLockParam, event);
        TELEPHONY_LOGI("TelRilTest::UnSetPin2LockTest --> finished");
        bool syncResult = WaitGetResult(eventId, handler, WAIT_TIME_SECOND);
        ASSERT_TRUE(syncResult);
    }
}

/**
 * @brief Enter SIM card pin2 code
 *
 * @param handler
 */
void TelRilTest::EnterSimPin2Test(int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    int32_t eventId = static_cast<int32_t>(RadioEvent::RADIO_SIM_ENTER_PIN2);
    auto event = AppExecFwk::InnerEvent::Get(eventId);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        std::string pin2 = GTEST_STRING_PIN2;
        TELEPHONY_LOGI("TelRilTest::EnterSimPin2Test -->");
        telRilManager_->UnlockPin2(slotId, pin2, event);
        TELEPHONY_LOGI("TelRilTest::EnterSimPin2Test --> finished");
        bool syncResult = WaitGetResult(eventId, handler, WAIT_TIME_SECOND);
        ASSERT_TRUE(syncResult);
    }
}

/**
 * @brief Enter Error pin2 code
 *
 * @param handler
 */
void TelRilTest::EnterErrorPin2Test(int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    int32_t eventId = static_cast<int32_t>(RadioEvent::RADIO_SIM_ENTER_PIN2);
    auto event = AppExecFwk::InnerEvent::Get(eventId);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        std::string pin2 = "2222";
        TELEPHONY_LOGI("TelRilTest::EnterErrorPin2Test -->");
        telRilManager_->UnlockPin2(slotId, pin2, event);
        TELEPHONY_LOGI("TelRilTest::EnterErrorPin2Test --> finished");
        bool syncResult = WaitGetResult(eventId, handler, WAIT_TIME_SECOND);
        ASSERT_TRUE(syncResult);
    }
}

/**
 * @brief Unlock SIM card pin2 code
 *
 * @param handler
 */
void TelRilTest::UnlockSimPin2Test(int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    int32_t eventId = static_cast<int32_t>(RadioEvent::RADIO_SIM_UNLOCK_PIN2);
    auto event = AppExecFwk::InnerEvent::Get(eventId);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        std::string puk2 = GTEST_STRING_PUK2;
        std::string pin2 = GTEST_STRING_PIN2;
        TELEPHONY_LOGI("TelRilTest::UnlockSimPin2Test -->");
        telRilManager_->UnlockPuk2(slotId, puk2, pin2, event);
        TELEPHONY_LOGI("TelRilTest::UnlockSimPin2Test --> finished");
        bool syncResult = WaitGetResult(eventId, handler, WAIT_TIME_SECOND);
        ASSERT_TRUE(syncResult);
    }
}

/**
 * @brief Enable SIM card
 *
 * @param handler
 */
void TelRilTest::EnableSimCardTest(int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    int32_t eventId = static_cast<int32_t>(RadioEvent::RADIO_SIM_CARD_ENABLED);
    auto event = AppExecFwk::InnerEvent::Get(eventId);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        int index = 0;
        int enable = 0;
        TELEPHONY_LOGI("TelRilTest::EnableSimCardTest -->");
        telRilManager_->SetActiveSim(slotId, index, enable, event);
        TELEPHONY_LOGI("TelRilTest::EnableSimCardTest --> finished");
        bool syncResult = WaitGetResult(eventId, handler, WAIT_TIME_SECOND);
        ASSERT_TRUE(syncResult);
    }
}

/**
 * @brief Get radio protocol
 *
 * @param handler
 */
void TelRilTest::GetRadioProtocolTest(int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    int32_t eventId = static_cast<int32_t>(DiffInterfaceId::TEST_SET_RADIO_PROTOCOL);
    auto event = AppExecFwk::InnerEvent::Get(eventId);
    if (event == nullptr || telRilManager_ == nullptr) {
        TELEPHONY_LOGE("TelRilTest::GetRadioProtocolTest telRilManager_ or event is nullptr");
        return;
    }
    event->SetOwner(handler);
    TELEPHONY_LOGI("TelRilTest::GetRadioProtocolTest -->");
    telRilManager_->GetRadioProtocol(slotId, event);
    TELEPHONY_LOGI("TelRilTest::GetRadioProtocolTest --> finished");
    bool syncResult = WaitGetResult(eventId, handler, WAIT_TIME_SECOND);
    ASSERT_TRUE(syncResult);
}

/**
 * @brief Set radio protocol
 *
 * @param handler
 */
void TelRilTest::SetRadioProtocolTest(int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    int32_t eventId = static_cast<int32_t>(DiffInterfaceId::TEST_GET_RADIO_PROTOCOL);
    auto event = AppExecFwk::InnerEvent::Get(eventId);
    if (event == nullptr || telRilManager_ == nullptr) {
        TELEPHONY_LOGE("TelRilTest::SetRadioProtocolTest telRilManager_ or event is nullptr");
        return;
    }
    event->SetOwner(handler);
    TELEPHONY_LOGI("TelRilTest::SetRadioProtocolTest -->");
    RadioProtocol protocol;
    protocol.sessionId = 1;
    protocol.phase = RadioProtocolPhase::RADIO_PROTOCOL_PHASE_CHECK;
    protocol.technology = (int32_t)RadioProtocolTech::RADIO_PROTOCOL_TECH_LTE;
    protocol.modemId = 0;
    protocol.status = RadioProtocolStatus::RADIO_PROTOCOL_STATUS_NONE;
    telRilManager_->SetRadioProtocol(slotId, protocol, event);
    TELEPHONY_LOGI("TelRilTest::SetRadioProtocolTest --> finished");
    bool syncResult = WaitGetResult(eventId, handler, WAIT_TIME_SECOND);
    ASSERT_TRUE(syncResult);
}

/**
 * @brief Send terminal response command
 *
 * @param handler
 */
void TelRilTest::SendTerminalResponseCmdTest(int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    int32_t eventId = static_cast<int32_t>(RadioEvent::RADIO_STK_SEND_TERMINAL_RESPONSE);
    auto event = AppExecFwk::InnerEvent::Get(eventId);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::SendTerminalResponseCmdTest -->");
        telRilManager_->SendTerminalResponseCmd(slotId, "", event);
        TELEPHONY_LOGI("TelRilTest::SendTerminalResponseCmdTest --> finished");
        bool syncResult = WaitGetResult(eventId, handler, WAIT_TIME_SECOND);
        ASSERT_TRUE(syncResult);
    }
}

/**
 * @brief Send envelope command
 *
 * @param handler
 */
void TelRilTest::SendEnvelopeCmdTest(int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    int32_t eventId = static_cast<int32_t>(RadioEvent::RADIO_STK_SEND_ENVELOPE);
    auto event = AppExecFwk::InnerEvent::Get(eventId);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::SendEnvelopeCmdTest -->");
        telRilManager_->SendEnvelopeCmd(slotId, "", event);
        TELEPHONY_LOGI("TelRilTest::SendEnvelopeCmdTest --> finished");
        bool syncResult = WaitGetResult(eventId, handler, WAIT_TIME_SECOND);
        ASSERT_TRUE(syncResult);
    }
}

/**
 * @brief Send Call Setup Request Result command
 *
 * @param handler
 */
void TelRilTest::SendCallSetupRequestResultTest(
    int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    int32_t eventId = static_cast<int32_t>(RadioEvent::RADIO_STK_SEND_CALL_SETUP_REQUEST_RESULT);
    auto event = AppExecFwk::InnerEvent::Get(eventId);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::SendCallSetupRequestResultTest -->");
        telRilManager_->SendCallSetupRequestResult(slotId, true, event);
        TELEPHONY_LOGI("TelRilTest::SendCallSetupRequestResultTest --> finished");
        bool syncResult = WaitGetResult(eventId, handler, WAIT_TIME_SECOND);
        ASSERT_TRUE(syncResult);
    }
}

/************************************** SIM test func *******************************************/
/**
 * @brief Get Received Signal Strength Indication
 *
 * @param handler
 */
void TelRilTest::NetworkGetRssiTest(int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    int32_t eventId = static_cast<int32_t>(RadioEvent::RADIO_GET_SIGNAL_STRENGTH);
    auto event = AppExecFwk::InnerEvent::Get(eventId);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::NetworkGetRssiTest -->");
        telRilManager_->GetSignalStrength(slotId, event);
        TELEPHONY_LOGI("TelRilTest::NetworkGetRssiTest --> finished");
        bool syncResult = WaitGetResult(eventId, handler, WAIT_TIME_SECOND);
        ASSERT_TRUE(syncResult);
    }
}

/**
 * @brief Call dial
 *
 * @param handler
 */
void TelRilTest::CallDialTest(int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    int32_t eventId = static_cast<int32_t>(RadioEvent::RADIO_DIAL);
    auto event = AppExecFwk::InnerEvent::Get(eventId);
    if (event == nullptr || telRilManager_ == nullptr) {
        TELEPHONY_LOGI("TelRilTest::CallDialTest failed!!!!");
        return;
    }

    std::string phoneNum = GetRandPhoneNum(PHONE_NUM_LEN);
    int32_t clirMode; /* Calling Line Identification Restriction . From TS 27.007 V3.4.0 (2000-03) */
    event->SetOwner(handler);
    clirMode = 0; // use subscription default value
    TELEPHONY_LOGI("TelRilTest::CallDialTest -->");
    telRilManager_->Dial(slotId, phoneNum, clirMode, event);
    TELEPHONY_LOGI("TelRilTest::CallDialTest --> finished");
    bool syncResult = WaitGetResult(eventId, handler, WAIT_TIME_SECOND);
    ASSERT_TRUE(syncResult);
}

/**
 * @brief Reject call
 *
 * @param handler
 */
void TelRilTest::RefusedCallTest(int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    int32_t eventId = static_cast<int32_t>(RadioEvent::RADIO_REJECT_CALL);
    auto event = AppExecFwk::InnerEvent::Get(eventId);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::RefusedCallTest -->");
        telRilManager_->Reject(slotId, event);
        TELEPHONY_LOGI("TelRilTest::RefusedCallTest --> finished");
        bool syncResult = WaitGetResult(eventId, handler, WAIT_TIME_SECOND);
        ASSERT_TRUE(syncResult);
    }
}

/**
 * @brief Get call waiting
 *
 * @param handler
 */
void TelRilTest::GetCallWaitTest(int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    int32_t eventId = static_cast<int32_t>(RadioEvent::RADIO_GET_CALL_WAIT);
    auto event = AppExecFwk::InnerEvent::Get(eventId);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::GetCallWaitTest -->");
        telRilManager_->GetCallWaiting(slotId, event);
        TELEPHONY_LOGI("TelRilTest::GetCallWaitTest --> finished");
        bool syncResult = WaitGetResult(eventId, handler, WAIT_TIME_SECOND);
        ASSERT_TRUE(syncResult);
    }
}

/**
 * @brief Set call waiting
 *
 * @param handler
 */
void TelRilTest::SetCallWaitTest(int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    int32_t eventId = static_cast<int32_t>(RadioEvent::RADIO_SET_CALL_WAIT);
    auto event = AppExecFwk::InnerEvent::Get(eventId);
    if (event == nullptr || telRilManager_ == nullptr) {
        return;
    }
    event->SetOwner(handler);
    int32_t operating = 0;
    TELEPHONY_LOGI("TelRilTest::SetCallWaitTest -->");
    telRilManager_->SetCallWaiting(slotId, operating, event);
    TELEPHONY_LOGI("TelRilTest::SetCallWaitTest --> finished");
    bool syncResult = WaitGetResult(eventId, handler, WAIT_TIME_SECOND);
    ASSERT_TRUE(syncResult);
}

/**
 * @brief Call hangup
 *
 * @param handler
 */
void TelRilTest::CallHangupTest(int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    int32_t eventId = static_cast<int32_t>(RadioEvent::RADIO_HANGUP_CONNECT);
    auto event = AppExecFwk::InnerEvent::Get(eventId);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::CallHangupTest -->");
        telRilManager_->Hangup(slotId, static_cast<int>(event->GetInnerEventId()), event);
        TELEPHONY_LOGI("TelRilTest::CallHangupTest --> finished");
        bool syncResult = WaitGetResult(eventId, handler, WAIT_TIME_SECOND);
        ASSERT_TRUE(syncResult);
    }
}

/**
 * @brief Answer the call
 *
 * @param handler
 */
void TelRilTest::CallAnswerTest(int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    int32_t eventId = static_cast<int32_t>(RadioEvent::RADIO_ACCEPT_CALL);
    auto event = AppExecFwk::InnerEvent::Get(eventId);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::CallAnswerTest -->");
        telRilManager_->Answer(slotId, event);
        TELEPHONY_LOGI("TelRilTest::CallAnswerTest --> finished");
        bool syncResult = WaitGetResult(eventId, handler, WAIT_TIME_SECOND);
        ASSERT_TRUE(syncResult);
    }
}

/**
 * @brief Call on hold
 *
 * @param handler
 */
void TelRilTest::CallHoldTest(int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    int32_t eventId = static_cast<int32_t>(RadioEvent::RADIO_HOLD_CALL);
    auto event = AppExecFwk::InnerEvent::Get(eventId);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::CallHoldTest -->");
        telRilManager_->HoldCall(slotId, event);
        TELEPHONY_LOGI("TelRilTest::CallHoldTest --> finished");
        bool syncResult = WaitGetResult(eventId, handler, WAIT_TIME_SECOND);
        ASSERT_TRUE(syncResult);
    }
}

/**
 * @brief Call activation
 *
 * @param handler
 */
void TelRilTest::CallActiveTest(int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    int32_t eventId = static_cast<int32_t>(RadioEvent::RADIO_ACTIVE_CALL);
    auto event = AppExecFwk::InnerEvent::Get(eventId);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::CallActiveTest -->");
        telRilManager_->UnHoldCall(slotId, event);
        TELEPHONY_LOGI("TelRilTest::CallActiveTest --> finished");
        bool syncResult = WaitGetResult(eventId, handler, WAIT_TIME_SECOND);
        ASSERT_TRUE(syncResult);
    }
}

/**
 * @brief Call switch
 *
 * @param handler
 */
void TelRilTest::CallSwapTest(int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    int32_t eventId = static_cast<int32_t>(RadioEvent::RADIO_SWAP_CALL);
    auto event = AppExecFwk::InnerEvent::Get(eventId);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::CallSwapTest -->");
        telRilManager_->SwitchCall(slotId, event);
        TELEPHONY_LOGI("TelRilTest::CallSwapTest --> finished");
        bool syncResult = WaitGetResult(eventId, handler, WAIT_TIME_SECOND);
        ASSERT_TRUE(syncResult);
    }
}

/**
 * @brief Get Voice Registration State
 *
 * @param handler
 */
void TelRilTest::NetworkVoiceRegistrationStateTest(
    int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    int32_t eventId = static_cast<int32_t>(RadioEvent::RADIO_VOICE_REG_STATE);
    auto event = AppExecFwk::InnerEvent::Get(eventId);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::NetworkVoiceRegistrationStateTest -->");
        telRilManager_->GetCsRegStatus(slotId, event);
        TELEPHONY_LOGI("TelRilTest::NetworkVoiceRegistrationStateTest --> finished");
        bool syncResult = WaitGetResult(eventId, handler, WAIT_TIME_SECOND);
        ASSERT_TRUE(syncResult);
    }
}

/**
 * @brief Get Data Registration State
 *
 * @param handler
 */
void TelRilTest::NetworkDataRegistrationStateTest(
    int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    int32_t eventId = static_cast<int32_t>(RadioEvent::RADIO_DATA_REG_STATE);
    auto event = AppExecFwk::InnerEvent::Get(eventId);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::NetworkDataRegistrationStateTest -->");
        telRilManager_->GetPsRegStatus(slotId, event);
        TELEPHONY_LOGI("TelRilTest::NetworkDataRegistrationStateTest --> finished");
        bool syncResult = WaitGetResult(eventId, handler, WAIT_TIME_SECOND);
        ASSERT_TRUE(syncResult);
    }
}

/**
 * @brief Get operator information
 *
 * @param handler
 */
void TelRilTest::NetworkOperatorTest(int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    int32_t eventId = static_cast<int32_t>(RadioEvent::RADIO_OPERATOR);
    auto event = AppExecFwk::InnerEvent::Get(eventId);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::NetworkOperatorTest -->");
        telRilManager_->GetOperatorInfo(slotId, event);
        TELEPHONY_LOGI("TelRilTest::NetworkOperatorTest --> finished");
        bool syncResult = WaitGetResult(eventId, handler, WAIT_TIME_SECOND);
        ASSERT_TRUE(syncResult);
    }
}

/**
 * @brief Send SMS
 *
 * @param handler
 */
void TelRilTest::SendRilCmSmsTest(int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    int32_t eventId = static_cast<int32_t>(RadioEvent::RADIO_SEND_SMS);
    auto event = AppExecFwk::InnerEvent::Get(eventId);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::SendRilCmSmsTest -->");
        telRilManager_->SendGsmSms(slotId, TEST_SMSC_PDU, TEST_PDU, event);
        TELEPHONY_LOGI("TelRilTest::SendRilCmSmsTest --> finished");
        bool syncResult = WaitGetResult(eventId, handler, WAIT_TIME_SECOND);
        ASSERT_TRUE(syncResult);
    }
}

/**
 * @brief Storage SMS
 *
 * @param handler
 */
void TelRilTest::StorageRilCmSmsTest(int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    int32_t eventId = static_cast<int32_t>(RadioEvent::RADIO_STORAGE_SMS);
    auto event = AppExecFwk::InnerEvent::Get(eventId);
    SimMessageParam simMessage;
    simMessage.status = 0;
    simMessage.gsmIndex = 0;
    simMessage.pdu = GTEST_STRING;
    simMessage.smscPdu = GTEST_STRING;
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::StorageRilCmSmsTest -->");
        telRilManager_->AddSimMessage(slotId, simMessage, event);
        TELEPHONY_LOGI("TelRilTest::StorageRilCmSmsTest --> finished");
        bool syncResult = WaitGetResult(eventId, handler, WAIT_TIME_SECOND);
        ASSERT_TRUE(syncResult);
    }
}

/**
 * @brief Delete SMS
 *
 * @param handler
 */
void TelRilTest::DeleteRilCmSmsTest(int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    int32_t eventId = static_cast<int32_t>(RadioEvent::RADIO_DELETE_SMS);
    auto event = AppExecFwk::InnerEvent::Get(eventId);
    int32_t gsmIndex = 0;
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::DeleteRilCmSmsTest -->");
        telRilManager_->DelSimMessage(slotId, gsmIndex, event);
        TELEPHONY_LOGI("TelRilTest::DeleteRilCmSmsTest --> finished");
        bool syncResult = WaitGetResult(eventId, handler, WAIT_TIME_SECOND);
        ASSERT_TRUE(syncResult);
    }
}

/**
 * @brief Update SMS
 *
 * @param handler
 */
void TelRilTest::UpdateRilCmSmsTest(int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    int32_t eventId = static_cast<int32_t>(RadioEvent::RADIO_UPDATE_SMS);
    auto event = AppExecFwk::InnerEvent::Get(eventId);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        SimMessageParam simMessage;
        simMessage.gsmIndex = 0;
        simMessage.status = 0;
        simMessage.pdu = GTEST_STRING;
        simMessage.smscPdu = GTEST_STRING;
        TELEPHONY_LOGI("TelRilTest::UpdateRilCmSmsTest -->");
        telRilManager_->UpdateSimMessage(slotId, simMessage, event);
        TELEPHONY_LOGI("TelRilTest::UpdateRilCmSmsTest --> finished");
        bool syncResult = WaitGetResult(eventId, handler, WAIT_TIME_SECOND);
        ASSERT_TRUE(syncResult);
    }
}

/**
 * @brief Set SMS center address
 *
 * @param handler
 */
void TelRilTest::SetRilCmSmsCenterAddressTest(int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    int32_t eventIdGetSmsc = static_cast<int32_t>(RadioEvent::RADIO_GET_SMS_CENTER_ADDRESS);
    int32_t eventIdSetSmsc = static_cast<int32_t>(RadioEvent::RADIO_SET_SMS_CENTER_ADDRESS);
    auto eventGetSmsc = AppExecFwk::InnerEvent::Get(eventIdGetSmsc);
    auto eventSetSmsc = AppExecFwk::InnerEvent::Get(eventIdSetSmsc);
    if (eventGetSmsc != nullptr && eventSetSmsc != nullptr && telRilManager_ != nullptr) {
        // get smsc first
        eventGetSmsc->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::GetRilCmSmsCenterAddressTest -->");
        telRilManager_->GetSmscAddr(slotId, eventGetSmsc);
        TELEPHONY_LOGI("TelRilTest::GetRilCmSmsCenterAddressTest --> finished");
        bool syncResult = WaitGetResult(eventIdGetSmsc, handler, WAIT_TIME_SECOND);
        ASSERT_TRUE(syncResult);
        // then set smsc
        eventSetSmsc->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::SetRilCmSmsCenterAddressTest -->");
        telRilManager_->SetSmscAddr(slotId, tosca, g_smscAddr, eventSetSmsc);
        TELEPHONY_LOGI("TelRilTest::SetRilCmSmsCenterAddressTest --> finished");
        syncResult = WaitGetResult(eventIdSetSmsc, handler, WAIT_TIME_SECOND);
        ASSERT_TRUE(syncResult);
    }
}

/**
 * @brief Get SMS center address
 *
 * @param handler
 */
void TelRilTest::GetRilCmSmsCenterAddressTest(int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    int32_t eventId = static_cast<int32_t>(RadioEvent::RADIO_GET_SMS_CENTER_ADDRESS);
    auto event = AppExecFwk::InnerEvent::Get(eventId);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::GetRilCmSmsCenterAddressTest -->");
        telRilManager_->GetSmscAddr(slotId, event);
        TELEPHONY_LOGI("TelRilTest::GetRilCmSmsCenterAddressTest --> finished");
        bool syncResult = WaitGetResult(eventId, handler, WAIT_TIME_SECOND);
        ASSERT_TRUE(syncResult);
    }
}

/**
 * @brief Set SMS cell broadcast
 *
 * @param handler
 */
void TelRilTest::SetRilCmCBConfigTest(int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    int32_t eventId = static_cast<int32_t>(RadioEvent::RADIO_SET_CELL_BROADCAST);
    auto event = AppExecFwk::InnerEvent::Get(eventId);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        CBConfigParam cbConfig;
        cbConfig.mode = 0;
        cbConfig.idList = "0,1,5,320-478,922";
        cbConfig.dcsList = "0-3,5";
        TELEPHONY_LOGI("TelRilTest::SetRilCmCBConfigTest -->");
        telRilManager_->SetCBConfig(slotId, cbConfig, event);
        TELEPHONY_LOGI("TelRilTest::SetRilCmCBConfigTest --> finished");
        bool syncResult = WaitGetResult(eventId, handler, WAIT_TIME_SECOND);
        ASSERT_TRUE(syncResult);
    }
}

/**
 * @brief Set CDMA SMS cell broadcast
 *
 * @param handler
 */
void TelRilTest::SetRilCmCdmaCBConfigTest(int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    int32_t eventId = static_cast<int32_t>(RadioEvent::RADIO_SET_CDMA_CELL_BROADCAST);
    auto event = AppExecFwk::InnerEvent::Get(eventId);
    CdmaCBConfigInfoList broadcastInfoList = {};
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::SetRilCmCdmaCBConfigTest -->");
        telRilManager_->SetCdmaCBConfig(slotId, broadcastInfoList, event);
        TELEPHONY_LOGI("TelRilTest::SetRilCmCdmaCBConfigTest --> finished");
        bool syncResult = WaitGetResult(eventId, handler, WAIT_TIME_SECOND);
        ASSERT_TRUE(syncResult);
    }
}

/**
 * @brief Get SMS cell broadcast
 *
 * @param handler
 */
void TelRilTest::GetRilCmCBConfigTest(int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    int32_t eventId = static_cast<int32_t>(RadioEvent::RADIO_GET_CELL_BROADCAST);
    auto event = AppExecFwk::InnerEvent::Get(eventId);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::GetRilCmCBConfigTest -->");
        telRilManager_->GetCBConfig(slotId, event);
        TELEPHONY_LOGI("TelRilTest::GetRilCmCBConfigTest --> finished");
        bool syncResult = WaitGetResult(eventId, handler, WAIT_TIME_SECOND);
        ASSERT_TRUE(syncResult);
    }
}

/**
 * @brief Get CDMA SMS cell broadcast
 *
 * @param handler
 */
void TelRilTest::GetRilCmCdmaCBConfigTest(int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    int32_t eventId = static_cast<int32_t>(RadioEvent::RADIO_GET_CDMA_CELL_BROADCAST);
    auto event = AppExecFwk::InnerEvent::Get(eventId);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::GetRilCmCdmaCBConfigTest -->");
        telRilManager_->GetCdmaCBConfig(slotId, event);
        TELEPHONY_LOGI("TelRilTest::GetRilCmCdmaCBConfigTest --> finished");
        bool syncResult = WaitGetResult(eventId, handler, WAIT_TIME_SECOND);
        ASSERT_TRUE(syncResult);
    }
}

/**
 * @brief Send multiple SMS
 *
 * @param handler
 */
void TelRilTest::SmsSendSmsExpectMoreTest(int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    int32_t eventId = static_cast<int32_t>(RadioEvent::RADIO_SEND_SMS_EXPECT_MORE);
    auto event = AppExecFwk::InnerEvent::Get(eventId);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::SmsSendSmsExpectMoreTest -->");
        telRilManager_->SendSmsMoreMode(slotId, TEST_SMSC_PDU, TEST_PDU, event);
        TELEPHONY_LOGI("TelRilTest::SmsSendSmsExpectMoreTest --> finished");
        bool syncResult = WaitGetResult(eventId, handler, WAIT_TIME_SECOND);
        ASSERT_TRUE(syncResult);
    }
}

/**
 * @brief Set radio state
 *
 * @param handler
 */
void TelRilTest::SetRadioStateTest(int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    int32_t eventId = static_cast<int32_t>(RadioEvent::RADIO_SET_STATUS);
    auto event = AppExecFwk::InnerEvent::Get(eventId);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::SetRadioStateTest -->");
        // set radio state off
        telRilManager_->SetRadioState(slotId, 0, 0, event);
        bool syncResult = WaitGetResult(eventId, handler, WAIT_TIME_SECOND);
        ASSERT_TRUE(syncResult);
        // set radio state on
        telRilManager_->SetRadioState(slotId, 1, 0, event);
        syncResult = WaitGetResult(eventId, handler, WAIT_TIME_SECOND);
        ASSERT_TRUE(syncResult);
        TELEPHONY_LOGI("TelRilTest::SetRadioStateTest --> finished");
    }
}

/**
 * @brief Get radio state
 *
 * @param handler
 */
void TelRilTest::GetRadioStateTest(int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    int32_t eventId = static_cast<int32_t>(RadioEvent::RADIO_GET_STATUS);
    auto event = AppExecFwk::InnerEvent::Get(eventId);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::GetRadioStateTest -->");
        telRilManager_->GetRadioState(slotId, event);
        TELEPHONY_LOGI("TelRilTest::GetRadioStateTest --> finished");
        bool syncResult = WaitGetResult(eventId, handler, WAIT_TIME_SECOND);
        ASSERT_TRUE(syncResult);
    }
}

/**
 * @brief SMS Acknowledge
 *
 * @param handler
 */
void TelRilTest::SmsAcknowledgeTest(int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    int32_t eventId = static_cast<int32_t>(DiffInterfaceId::TEST_SEND_SMS_ACK);
    auto event = AppExecFwk::InnerEvent::Get(eventId);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::SmsAcknowledgeTest -->");
        telRilManager_->SendSmsAck(slotId, true, REASON, event);
        TELEPHONY_LOGI("TelRilTest::SmsAcknowledgeTest --> finished");
        bool syncResult = WaitGetResult(eventId, handler, WAIT_TIME_SECOND);
        ASSERT_TRUE(syncResult);
    }
}

/**
 * @brief Add CDMA SMS
 *
 * @param handler
 */
void TelRilTest::AddRilCmCdmaSmsTest(int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    int32_t eventId = static_cast<int32_t>(RadioEvent::RADIO_ADD_CDMA_SMS);
    auto event = AppExecFwk::InnerEvent::Get(eventId);
    int32_t status = 0;
    std::string pdu = GTEST_STRING;
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::AddRilCmCdmaSmsTest -->");
        telRilManager_->AddCdmaSimMessage(slotId, status, pdu, event);
        TELEPHONY_LOGI("TelRilTest::AddRilCmCdmaSmsTest --> finished");
        bool syncResult = WaitGetResult(eventId, handler, WAIT_TIME_SECOND);
        ASSERT_TRUE(syncResult);
    }
}

/**
 * @brief Delete CDMA SMS
 *
 * @param handler
 */
void TelRilTest::DelRilCmCdmaSmsTest(int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    int32_t eventId = static_cast<int32_t>(RadioEvent::RADIO_DEL_CDMA_SMS);
    auto event = AppExecFwk::InnerEvent::Get(eventId);
    int32_t gsmIndex = 0;
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::DelRilCmCdmaSmsTest -->");
        telRilManager_->DelCdmaSimMessage(slotId, gsmIndex, event);
        TELEPHONY_LOGI("TelRilTest::DelRilCmCdmaSmsTest --> finished");
        bool syncResult = WaitGetResult(eventId, handler, WAIT_TIME_SECOND);
        ASSERT_TRUE(syncResult);
    }
}

/**
 * @brief Update CDMA SMS
 *
 * @param handler
 */
void TelRilTest::UpdateRilCmCdmaSmsTest(int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    int32_t eventId = static_cast<int32_t>(RadioEvent::RADIO_UPDATE_CDMA_SMS);
    auto event = AppExecFwk::InnerEvent::Get(eventId);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        CdmaSimMessageParam cdmaSimMsg;
        cdmaSimMsg.cdmaIndex = 0;
        cdmaSimMsg.status = 0;
        cdmaSimMsg.pdu = GTEST_STRING;
        TELEPHONY_LOGI("TelRilTest::UpdateRilCmCdmaSmsTest -->");
        telRilManager_->UpdateCdmaSimMessage(slotId, cdmaSimMsg, event);
        TELEPHONY_LOGI("TelRilTest::UpdateRilCmCdmaSmsTest --> finished");
        bool syncResult = WaitGetResult(eventId, handler, WAIT_TIME_SECOND);
        ASSERT_TRUE(syncResult);
    }
}

/**
 * @brief Set apn initialization information
 *
 * @param handler
 */
void TelRilTest::DataSetInitApnInfoTest(int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    int32_t eventId = static_cast<int32_t>(DiffInterfaceId::TEST_RILCM_SET_INIT_APN_INFO);
    auto event = AppExecFwk::InnerEvent::Get(eventId);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::DataSetInitApnInfoTest -->");
        DataProfile dataProfile;
        dataProfile.profileId = 0;
        dataProfile.apn = "cmnet";
        dataProfile.protocol = "IPV4V6";
        dataProfile.verType = AUTHTYPE_1;
        dataProfile.userName = "";
        dataProfile.password = "";
        dataProfile.roamingProtocol = "IPV4V6";
        telRilManager_->SetInitApnInfo(slotId, dataProfile, event);
        TELEPHONY_LOGI("TelRilTest::DataSetInitApnInfoTest --> finished");
        bool syncResult = WaitGetResult(eventId, handler, WAIT_TIME_SECOND);
        ASSERT_TRUE(syncResult);
    }
}

/**
 * @brief Set data call
 *
 * @param handler
 */
void TelRilTest::DataSetupDataCallTest(int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    int32_t eventId = static_cast<int32_t>(DiffInterfaceId::TEST_RILCM_SETUP_DATA_CALL);
    auto event = AppExecFwk::InnerEvent::Get(eventId);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        ActivateDataParam activateData;
        activateData.param = 0;
        activateData.radioTechnology = 0;
        activateData.isRoaming = false;
        activateData.allowRoaming = true;
        activateData.dataProfile.profileId = 0;
        activateData.dataProfile.apn = "cmnet";
        activateData.dataProfile.protocol = "IPV4V6";
        activateData.dataProfile.verType = AUTHTYPE_1;
        activateData.dataProfile.userName = "";
        activateData.dataProfile.password = "";
        activateData.dataProfile.roamingProtocol = "IPV4V6";
        TELEPHONY_LOGI("TelRilTest::DataSetupDataCallTest -->");
        telRilManager_->ActivatePdpContext(slotId, activateData, event);
        TELEPHONY_LOGI("TelRilTest::DataSetupDataCallTest --> finished");
        bool syncResult = WaitGetResult(eventId, handler, WAIT_TIME_SECOND);
        ASSERT_TRUE(syncResult);
    }
}

/**
 * @brief Disable data call
 *
 * @param handler
 */
void TelRilTest::DataDisableDataCallTest(int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    int32_t eventId = static_cast<int32_t>(DiffInterfaceId::TEST_RILCM_DEACTIVATE_DATA_CALL);
    auto event = AppExecFwk::InnerEvent::Get(eventId);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::DataDisableDataCallTest -->");
        telRilManager_->DeactivatePdpContext(slotId, CID, REASON, event);
        TELEPHONY_LOGI("TelRilTest::DataDisableDataCallTest --> finished");
        bool syncResult = WaitGetResult(eventId, handler, WAIT_TIME_SECOND);
        ASSERT_TRUE(syncResult);
    }
}

/**
 * @brief Get data call list
 *
 * @param handler
 */
void TelRilTest::GetDataCallListTest(int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    int32_t eventId = static_cast<int32_t>(DiffInterfaceId::TEST_RILCM_GET_DATA_CALL_LIST);
    auto event = AppExecFwk::InnerEvent::Get(eventId);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::GetDataCallListTest -->");
        sleep(WAIT_TIME_SECOND);
        telRilManager_->GetPdpContextList(slotId, event);
        TELEPHONY_LOGI("TelRilTest::GetDataCallListTest --> finished");
        bool syncResult = WaitGetResult(eventId, handler, WAIT_TIME_SECOND);
        ASSERT_TRUE(syncResult);
    }
}

void TelRilTest::SetDataPermittedTest(int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    int32_t eventId = static_cast<int32_t>(DiffInterfaceId::TEST_RILCM_SET_DATA_PERMITTED_TEST);
    auto event = AppExecFwk::InnerEvent::Get(eventId);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::SetDataPermittedTest -->");
        telRilManager_->SetDataPermitted(slotId, true, event);
        TELEPHONY_LOGI("TelRilTest::SetDataPermittedTest --> finished");
        bool syncResult = WaitGetResult(eventId, handler, WAIT_TIME_SECOND);
        ASSERT_TRUE(syncResult);
    }
}

/**
 * @brief Search for carrier information
 *
 * @param handler
 */
void TelRilTest::GetNetworkSearchInformationTest(
    int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    int32_t eventId = static_cast<int32_t>(DiffInterfaceId::TEST_GET_NETWORKS_TO_USE);
    auto event = AppExecFwk::InnerEvent::Get(eventId);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::GetNetworkSearchInformationTest -->");
        telRilManager_->GetNetworkSearchInformation(slotId, event);
        TELEPHONY_LOGI("TelRilTest::GetNetworkSearchInformationTest --> finished");
        bool syncResult = WaitGetResult(eventId, handler, WAIT_TIME_SECOND);
        ASSERT_TRUE(syncResult);
    }
}

/**
 * @brief Get selection mode
 *
 * @param handler
 */
void TelRilTest::GetNetworkSelectionModeTest(int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    int32_t eventId = static_cast<int32_t>(DiffInterfaceId::TEST_GET_SELECTION_MOD_FOR_NETWORKS);
    auto event = AppExecFwk::InnerEvent::Get(eventId);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::GetNetworkSelectionModeTest -->");
        telRilManager_->GetNetworkSelectionMode(slotId, event);
        TELEPHONY_LOGI("TelRilTest::GetNetworkSelectionModeTest --> finished");
        bool syncResult = WaitGetResult(eventId, handler, WAIT_TIME_SECOND);
        ASSERT_TRUE(syncResult);
    }
}

/**
 * @brief Set selection mode
 *
 * @param handler
 */
void TelRilTest::SetNetworkSelectionModeTest(int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    int32_t eventId = static_cast<int32_t>(DiffInterfaceId::TEST_SET_MODE_AUTOMATIC_NETWORKS);
    auto event = AppExecFwk::InnerEvent::Get(eventId);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::SetNetworkSelectionModeTest -->");
        telRilManager_->SetNetworkSelectionMode(slotId, 0, "46001", event);
        TELEPHONY_LOGI("TelRilTest::SetNetworkSelectionModeTest --> finished");
        bool syncResult = WaitGetResult(eventId, handler, WAIT_TIME_SECOND);
        ASSERT_TRUE(syncResult);
    }
}

/**
 * @brief Set preferred network parameters
 *
 * @param handler
 */
void TelRilTest::SetPreferredNetworkParaTest(int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    int32_t eventId = static_cast<int32_t>(DiffInterfaceId::TEST_SET_PREFERRED_NETWORK_TYPE);
    auto event = AppExecFwk::InnerEvent::Get(eventId);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        int32_t netType = 0;
        TELEPHONY_LOGI("TelRilTest::SetPreferredNetworkParaTest -->");
        telRilManager_->SetPreferredNetwork(slotId, netType, event);
        TELEPHONY_LOGI("TelRilTest::SetPreferredNetworkParaTest --> finished");
        bool syncResult = WaitGetResult(eventId, handler, WAIT_TIME_SECOND);
        ASSERT_TRUE(syncResult);
    }
}

/**
 * @brief Get preferred network parameters
 *
 * @param handler
 */
void TelRilTest::GetPreferredNetworkParaTest(int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    int32_t eventId = static_cast<int32_t>(DiffInterfaceId::TEST_GET_PREFERRED_NETWORK_TYPE);
    auto event = AppExecFwk::InnerEvent::Get(eventId);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::GetPreferredNetworkParaTest -->");
        telRilManager_->GetPreferredNetwork(slotId, event);
        TELEPHONY_LOGI("TelRilTest::GetPreferredNetworkParaTest --> finished");
        bool syncResult = WaitGetResult(eventId, handler, WAIT_TIME_SECOND);
        ASSERT_TRUE(syncResult);
    }
}

/**
 * @brief Get IMEI
 *
 * @param handler
 */
void TelRilTest::GetImeiTest(int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    int32_t eventId = static_cast<int32_t>(DiffInterfaceId::TEST_GET_IMEI);
    auto event = AppExecFwk::InnerEvent::Get(eventId);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::GetImeiTest -->");
        telRilManager_->GetImei(slotId, event);
        TELEPHONY_LOGI("TelRilTest::GetImeiTest --> finished");
        bool syncResult = WaitGetResult(eventId, handler, WAIT_TIME_SECOND);
        ASSERT_TRUE(syncResult);
    }
}

/**
 * @brief Get MEID
 *
 * @param handler
 */
void TelRilTest::GetMeidTest(int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    int32_t eventId = static_cast<int32_t>(DiffInterfaceId::TEST_GET_MEID);
    auto event = AppExecFwk::InnerEvent::Get(eventId);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::GetMeidTest -->");
        telRilManager_->GetMeid(slotId, event);
        TELEPHONY_LOGI("TelRilTest::GetMeidTest --> finished");
        bool syncResult = WaitGetResult(eventId, handler, WAIT_TIME_SECOND);
        ASSERT_TRUE(syncResult);
    }
}

/**
 * @brief Get voice radio technology
 *
 * @param handler
 */
void TelRilTest::GetVoiceRadioTechnologyTest(int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    int32_t eventId = static_cast<int32_t>(DiffInterfaceId::TEST_GET_VOICE_RADIO_INFO);
    auto event = AppExecFwk::InnerEvent::Get(eventId);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::GetVoiceRadioTechnologyTest -->");
        telRilManager_->GetVoiceRadioTechnology(slotId, event);
        TELEPHONY_LOGI("TelRilTest::GetVoiceRadioTechnologyTest --> finished");
        bool syncResult = WaitGetResult(eventId, handler, WAIT_TIME_SECOND);
        ASSERT_TRUE(syncResult);
    }
}

/**
 * @brief Get physical channel config
 *
 * @param handler
 */
void TelRilTest::GetPhysicalChannelConfigTest(int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    int32_t eventId = static_cast<int32_t>(DiffInterfaceId::TEST_GET_PHYSICAL_CHANNEL_CONFIG);
    auto event = AppExecFwk::InnerEvent::Get(eventId);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::GetPhysicalChannelConfigTest -->");
        telRilManager_->GetPhysicalChannelConfig(slotId, event);
        TELEPHONY_LOGI("TelRilTest::GetPhysicalChannelConfigTest --> finished");
        bool syncResult = WaitGetResult(eventId, handler, WAIT_TIME_SECOND);
        ASSERT_TRUE(syncResult);
    }
}

/**
 * @brief Set location updates
 *
 * @param handler
 */
void TelRilTest::SetLocateUpdatesTest(int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    int32_t eventId = static_cast<int32_t>(DiffInterfaceId::TEST_SET_LOCATE_UPDATES);
    auto event = AppExecFwk::InnerEvent::Get(eventId);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::SetLocateUpdatesTest -->");
        HRilRegNotifyMode mode = REG_NOTIFY_STAT_LAC_CELLID;
        telRilManager_->SetLocateUpdates(slotId, mode, event);
        TELEPHONY_LOGI("TelRilTest::SetLocateUpdatesTest --> finished");
        bool syncResult = WaitGetResult(eventId, handler, WAIT_TIME_SECOND);
        ASSERT_TRUE(syncResult);
    }
}

/**
 * @brief Set notification fiter
 *
 * @param handler
 */
void TelRilTest::SetNotificationFilterTest(int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    int32_t eventId = static_cast<int32_t>(DiffInterfaceId::TEST_SET_NOTIFICATION_FILTER);
    auto event = AppExecFwk::InnerEvent::Get(eventId);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        int32_t filter = 1;
        TELEPHONY_LOGI("TelRilTest::SetNotificationFilterTest -->");
        telRilManager_->SetNotificationFilter(slotId, filter, event);
        TELEPHONY_LOGI("TelRilTest::SetNotificationFilterTest --> finished");
        bool syncResult = WaitGetResult(eventId, handler, WAIT_TIME_SECOND);
        ASSERT_TRUE(syncResult);
    }
}

/**
 * @brief Set device state
 *
 * @param handler
 */
void TelRilTest::SetDeviceStateTest(int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    int32_t eventId = static_cast<int32_t>(DiffInterfaceId::TEST_SET_DEVICE_STATE);
    auto event = AppExecFwk::InnerEvent::Get(eventId);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        int32_t deviceStateType = 0;
        bool deviceStateOn = true;
        TELEPHONY_LOGI("TelRilTest::SetDeviceStateTest -->");
        telRilManager_->SetDeviceState(slotId, deviceStateType, deviceStateOn, event);
        TELEPHONY_LOGI("TelRilTest::SetDeviceStateTest --> finished");
        bool syncResult = WaitGetResult(eventId, handler, WAIT_TIME_SECOND);
        ASSERT_TRUE(syncResult);
    }
}

/**
 * @brief Call merge
 *
 * @param handler
 */
void TelRilTest::CallJoinTest(int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    int32_t callType = 0; /* call type
                           * 0: Voice call
                           * 1: Video call: send one-way video
                           * 2: Video call: two-way voice
                           * 3: Video call: two-way video, two-way voice
                           */
    int32_t eventId = static_cast<int32_t>(RadioEvent::RADIO_JOIN_CALL);
    auto event = AppExecFwk::InnerEvent::Get(eventId);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::CallJoinTest -->");
        telRilManager_->CombineConference(slotId, callType, event);
        TELEPHONY_LOGI("TelRilTest::CallJoinTest --> finished");
        bool syncResult = WaitGetResult(eventId, handler, WAIT_TIME_SECOND);
        ASSERT_TRUE(syncResult);
    }
}

/**
 * @brief Call separation
 *
 * @param handler
 */
void TelRilTest::CallSplitTest(int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    int32_t callIndex = 1;
    int32_t callType = 0; /* call type
                           * 0: Voice call
                           * 1: Video call: send one-way video
                           * 2: Video call:two-way voice
                           * 3: Video call: two-way video, two-way voice
                           */
    int32_t eventId = static_cast<int32_t>(RadioEvent::RADIO_SPLIT_CALL);
    auto event = AppExecFwk::InnerEvent::Get(eventId);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::CallSplitTest -->");
        telRilManager_->SeparateConference(slotId, callIndex, callType, event);
        TELEPHONY_LOGI("TelRilTest::CallSplitTest --> finished");
        bool syncResult = WaitGetResult(eventId, handler, WAIT_TIME_SECOND);
        ASSERT_TRUE(syncResult);
    }
}

/**
 * @brief Get call forwarding
 *
 * @param handler
 */
void TelRilTest::GetCallForwardTest(int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    int32_t reason = 0;
    int32_t eventId = static_cast<int32_t>(RadioEvent::RADIO_GET_CALL_FORWARD);
    auto event = AppExecFwk::InnerEvent::Get(eventId);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::GetCallForwardTest -->");
        telRilManager_->GetCallTransferInfo(slotId, reason, event);
        TELEPHONY_LOGI("TelRilTest::GetCallForwardTest --> finished");
        bool syncResult = WaitGetResult(eventId, handler, WAIT_TIME_SECOND);
        ASSERT_TRUE(syncResult);
    }
}

/**
 * @brief Set call forwarding
 *
 * @param handler
 */
void TelRilTest::SetCallForwardTest(int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    int32_t eventId = static_cast<int32_t>(RadioEvent::RADIO_SPLIT_CALL);
    auto event = AppExecFwk::InnerEvent::Get(eventId);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        CallTransferParam callTransfer;
        callTransfer.mode = 0;
        callTransfer.reason = 0;
        callTransfer.classx = 0;
        callTransfer.number = GTEST_STRING;
        TELEPHONY_LOGI("TelRilTest::SetCallForwardTest -->");
        telRilManager_->SetCallTransferInfo(slotId, callTransfer, event);
        TELEPHONY_LOGI("TelRilTest::SetCallForwardTest --> finished");
        bool syncResult = WaitGetResult(eventId, handler, WAIT_TIME_SECOND);
        ASSERT_TRUE(syncResult);
    }
}

/**
 * @brief Get Calling line Identification Presentation Supplementary Service
 *
 * @param handler
 */
void TelRilTest::GetClipTest(int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    int32_t eventId = static_cast<int32_t>(RadioEvent::RADIO_GET_CALL_CLIP);
    auto event = AppExecFwk::InnerEvent::Get(eventId);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::GetClipTest -->");
        telRilManager_->GetClip(slotId, event);
        TELEPHONY_LOGI("TelRilTest::GetClipTest --> finished");
        bool syncResult = WaitGetResult(eventId, handler, WAIT_TIME_SECOND);
        ASSERT_TRUE(syncResult);
    }
}

/**
 * @brief Set Calling line Identification Presentation Supplementary Service
 *
 * @param handler
 */
void TelRilTest::SetClipTest(int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    int32_t eventId = static_cast<int32_t>(RadioEvent::RADIO_SET_CALL_CLIP);
    auto event = AppExecFwk::InnerEvent::Get(eventId);
    if (event != nullptr && telRilManager_ != nullptr) {
        int32_t action = 0;
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::SetClipTest -->");
        telRilManager_->SetClip(slotId, action, event);
        TELEPHONY_LOGI("TelRilTest::SetClipTest --> finished");
        bool syncResult = WaitGetResult(eventId, handler, WAIT_TIME_SECOND);
        ASSERT_TRUE(syncResult);
    }
}

/**
 * @brief Get call barring
 *
 * @param handler
 */
void TelRilTest::GetCallRestrictionTest(int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    int32_t eventId = static_cast<int32_t>(RadioEvent::RADIO_GET_CALL_RESTRICTION);
    auto event = AppExecFwk::InnerEvent::Get(eventId);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::GetCallRestrictionTest -->");
        telRilManager_->GetCallRestriction(slotId, "AI", event);
        TELEPHONY_LOGI("TelRilTest::GetCallRestrictionTest --> finished");
        bool syncResult = WaitGetResult(eventId, handler, WAIT_TIME_SECOND);
        ASSERT_TRUE(syncResult);
    }
}

/**
 * @brief Set call barring
 *
 * @param handler
 */
void TelRilTest::SetCallRestrictionTest(int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    int32_t eventId = static_cast<int32_t>(RadioEvent::RADIO_SET_CALL_RESTRICTION);
    auto event = AppExecFwk::InnerEvent::Get(eventId);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        CallRestrictionParam callRestriction;
        callRestriction.mode = 0;
        callRestriction.fac = GTEST_STRING;
        callRestriction.password = GTEST_STRING;
        TELEPHONY_LOGI("TelRilTest::SetCallRestrictionTest -->");
        telRilManager_->SetCallRestriction(slotId, callRestriction, event);
        TELEPHONY_LOGI("TelRilTest::SetCallRestrictionTest --> finished");
        bool syncResult = WaitGetResult(eventId, handler, WAIT_TIME_SECOND);
        ASSERT_TRUE(syncResult);
    }
}

/**
 * @brief Send DTMF
 *
 * @param handler
 */
void TelRilTest::SendDtmfTest(int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    int32_t eventId = static_cast<int32_t>(RadioEvent::RADIO_SEND_DTMF);
    auto event = AppExecFwk::InnerEvent::Get(eventId);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::SendDtmfTest -->");
        TELEPHONY_LOGI("TelRilTest::SendDtmfTest --> finished");
    }
}

/**
 * @brief Start DTMF
 *
 * @param handler
 */
void TelRilTest::StartDtmfTest(int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    int32_t eventId = static_cast<int32_t>(RadioEvent::RADIO_START_DTMF);
    auto event = AppExecFwk::InnerEvent::Get(eventId);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::StartDtmfTest -->");
        TELEPHONY_LOGI("TelRilTest::StartDtmfTest --> finished");
    }
}

/**
 * @brief Stop DTMF
 *
 * @param handler
 */
void TelRilTest::StopDtmfTest(int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    int32_t eventId = static_cast<int32_t>(RadioEvent::RADIO_STOP_DTMF);
    auto event = AppExecFwk::InnerEvent::Get(eventId);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::StopDtmfTest -->");
        TELEPHONY_LOGI("TelRilTest::StopDtmfTest --> finished");
    }
}

/**
 * @brief Set USSD
 *
 * @param handler
 */
void TelRilTest::SetUssdTest(int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    int32_t eventId = static_cast<int32_t>(RadioEvent::RADIO_SET_USSD);
    auto event = AppExecFwk::InnerEvent::Get(eventId);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::SetUssdTest -->");
        telRilManager_->SetUssd(slotId, "12345678", event);
        TELEPHONY_LOGI("TelRilTest::SetUssdTest --> finished");
        bool syncResult = WaitGetResult(eventId, handler, WAIT_TIME_SECOND);
        ASSERT_TRUE(syncResult);
    }
}

/**
 * @brief Get USSD
 *
 * @param handler
 */
void TelRilTest::GetUssdTest(int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    int32_t eventId = static_cast<int32_t>(RadioEvent::RADIO_GET_USSD);
    auto event = AppExecFwk::InnerEvent::Get(eventId);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::GetUssdTest -->");
        telRilManager_->GetUssd(slotId, event);
        TELEPHONY_LOGI("TelRilTest::GetUssdTest --> finished");
        bool syncResult = WaitGetResult(eventId, handler, WAIT_TIME_SECOND);
        ASSERT_TRUE(syncResult);
    }
}

/**
 * @brief Set call mute
 *
 * @param handler
 */
void TelRilTest::SetMuteTest(int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    int32_t eventId = static_cast<int32_t>(RadioEvent::RADIO_SET_CMUT);
    auto event = AppExecFwk::InnerEvent::Get(eventId);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::SetMuteTest -->");
        telRilManager_->SetMute(slotId, 1, event);
        TELEPHONY_LOGI("TelRilTest::SetMuteTest --> finished");
        bool syncResult = WaitGetResult(eventId, handler, WAIT_TIME_SECOND);
        ASSERT_TRUE(syncResult);
    }
}

/**
 * @brief Get call mute
 *
 * @param handler
 */
void TelRilTest::GetMuteTest(int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    int32_t eventId = static_cast<int32_t>(RadioEvent::RADIO_GET_CMUT);
    auto event = AppExecFwk::InnerEvent::Get(eventId);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::GetMuteTest -->");
        telRilManager_->GetMute(slotId, event);
        TELEPHONY_LOGI("TelRilTest::GetMuteTest --> finished");
        bool syncResult = WaitGetResult(eventId, handler, WAIT_TIME_SECOND);
        ASSERT_TRUE(syncResult);
    }
}

/**
 * @brief Get emergency call list
 *
 * @param handler
 */
void TelRilTest::GetEmergencyCallListTest(int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    int32_t eventId = static_cast<int32_t>(RadioEvent::RADIO_GET_EMERGENCY_CALL_LIST);
    auto event = AppExecFwk::InnerEvent::Get(eventId);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::GetEmergencyCallListTest -->");
        telRilManager_->GetEmergencyCallList(slotId, event);
        TELEPHONY_LOGI("TelRilTest::GetEmergencyCallListTest --> finished");
        bool syncResult = WaitGetResult(eventId, handler, WAIT_TIME_SECOND_LONG);
        ASSERT_TRUE(syncResult);
    }
}

/**
 * @brief Setting link bandwidth reporting rules
 *
 * @param handler
 */
void TelRilTest::OnRequestSetLinkBandwidthReportingRuleTest(
    int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    int32_t eventId = static_cast<int32_t>(DiffInterfaceId::TEST_RILCM_SET_LINK_BANDWIDTH_REPORTING_RULE);
    auto event = AppExecFwk::InnerEvent::Get(eventId);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        TELEPHONY_LOGI("TelRilTest::OnRequestSetLinkBandwidthReportingRuleTest -->");
        LinkBandwidthRule rule;
        rule.delayMs = BANDWIDTH_HYSTERESIS_MS;
        rule.rat = NETWORK_TYPE_LTE;
        rule.delayUplinkKbps = BANDWIDTH_HYSTERESIS_KBPS;
        rule.delayDownlinkKbps = BANDWIDTH_HYSTERESIS_KBPS;
        for (uint32_t i = 0; i < sizeof(MAX_UPLINK_LINK_BANDWIDTH) / sizeof(int); i++) {
            rule.maximumUplinkKbps.push_back(MAX_UPLINK_LINK_BANDWIDTH[i]);
        }
        for (uint32_t i = 0; i < sizeof(MAX_DOWNLINK_LINK_BANDWIDTH) / sizeof(int); i++) {
            rule.maximumDownlinkKbps.push_back(MAX_DOWNLINK_LINK_BANDWIDTH[i]);
        }
        telRilManager_->SetLinkBandwidthReportingRule(slotId, rule, event);
        TELEPHONY_LOGI("TelRilTest::OnRequestSetLinkBandwidthReportingRuleTest --> finished");
        bool syncResult = WaitGetResult(eventId, handler, WAIT_TIME_SECOND);
        ASSERT_TRUE(syncResult);
    }
}

/**
 * @brief Get link bandwidth information
 *
 * @param handler
 */
void TelRilTest::GetLinkBandwidthInfoTest(int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    int32_t eventId = static_cast<int32_t>(DiffInterfaceId::TEST_RILCM_GET_LINK_BANDWIDTH_INFO);
    auto event = AppExecFwk::InnerEvent::Get(eventId);
    if (event != nullptr && telRilManager_ != nullptr) {
        event->SetOwner(handler);
        int32_t cid = CID;
        TELEPHONY_LOGI("TelRilTest::GetLinkBandwidthInfoTest -->");
        telRilManager_->GetLinkBandwidthInfo(slotId, cid, event);
        TELEPHONY_LOGI("TelRilTest::GetLinkBandwidthInfoTest --> finished");
        bool syncResult = WaitGetResult(eventId, handler, WAIT_TIME_SECOND);
        ASSERT_TRUE(syncResult);
    }
}

/**
 * @brief Waiting the result
 * @param eventId
 * @param handler
 * @param timeOut
 */
bool TelRilTest::WaitGetResult(
    int32_t eventId, const std::shared_ptr<AppExecFwk::EventHandler> &handler, int32_t timeOut)
{
    TelRilTest::DemoHandler *demoHandler = static_cast<TelRilTest::DemoHandler *>(handler.get());
    if (demoHandler == nullptr) {
        return false;
    }
    demoHandler->WaitFor(timeOut);
    bool syncResult = demoHandler->GetBoolResult(eventId);
    return syncResult;
}

void TelRilTest::DemoHandler::NotifyAll()
{
    std::unique_lock<std::mutex> callbackLock(callbackMutex_);
    cv_.notify_all();
}

void TelRilTest::DemoHandler::WaitFor(int32_t timeoutSecond)
{
    std::unique_lock<std::mutex> callbackLock(callbackMutex_);
    cv_.wait_for(callbackLock, std::chrono::seconds(timeoutSecond));
}

void TelRilTest::DemoHandler::Clean()
{
    eventId_ = 0;
    resultInfo_ = nullptr;
}

bool TelRilTest::DemoHandler::GetBoolResult(int32_t eventId)
{
    bool ret = false;
    if (eventId_ == 0) {
        TELEPHONY_LOGI("Ril interface response timeout, not implemented."
            "eventId: %{public}d, current eventId: %{public}d", eventId, eventId_);
        ret = true;
        Clean();
        return ret;
    }
    if (eventId_ != eventId) {
        ret = false;
        TELEPHONY_LOGI("GetBoolResult eventId does not match. eventId: %{public}d, current eventId: %{public}d",
            eventId, eventId_);
        Clean();
        return ret;
    }
    if ((resultInfo_ != nullptr) &&
        ((resultInfo_->error == HRilErrType::NONE) ||
         (resultInfo_->error == HRilErrType::HRIL_ERR_GENERIC_FAILURE) ||
         (resultInfo_->error == HRilErrType::HRIL_ERR_INVALID_RESPONSE) ||
         (resultInfo_->error == HRilErrType::HRIL_ERR_INVALID_MODEM_PARAMETER))) {
        ret = true;
    }
    if (resultInfo_ == nullptr) {
        ret = true;
        TELEPHONY_LOGI("GetBoolResult eventId: %{public}d", eventId_);
    } else {
        TELEPHONY_LOGI("GetBoolResult eventId: %{public}d, error: %{public}d", eventId_, (int32_t)(resultInfo_->error));
    }
    Clean();
    return ret;
}

void TelRilTest::DemoHandler::ProcessResponseInfo(const AppExecFwk::InnerEvent::Pointer &event)
{
    if (event != nullptr) {
        eventId_ = event->GetInnerEventId();
        TELEPHONY_LOGI("TelRilTest::DemoHandler::ProcessResponseInfo --> eventId:%{public}d", eventId_);
        // for some SIM interfaces, response data need to be get before HRilRadioResponseInfo
        switch (eventId_) {
            case static_cast<int32_t>(RadioEvent::RADIO_SIM_GET_IMSI): {
                TELEPHONY_LOGI("TelRilTest::DemoHandler::ProcessResponseInfo --> RADIO_SIM_GET_IMSI");
                std::shared_ptr<std::string> imsi = event->GetSharedObject<std::string>();
                if (imsi != nullptr) {
                    TELEPHONY_LOGI("TelRilTest::DemoHandler::ProcessResponseInfo --> imsi=%{public}s", imsi->c_str());
                } else {
                    TELEPHONY_LOGI("TelRilTest::DemoHandler::ProcessResponseInfo --> get resultInfo_");
                    resultInfo_ = event->GetSharedObject<HRilRadioResponseInfo>();
                }
                break;
            }
            case static_cast<int32_t>(RadioEvent::RADIO_GET_SMS_CENTER_ADDRESS): {
                TELEPHONY_LOGI("TelRilTest::DemoHandler::ProcessResponseInfo --> RADIO_GET_SMS_CENTER_ADDRESS");
                std::shared_ptr<ServiceCenterAddress> addr = event->GetSharedObject<ServiceCenterAddress>();
                if (addr != nullptr) {
                    g_smscAddr = addr->address;
                    tosca = addr->tosca;
                    TELEPHONY_LOGI("TelRilTest::DemoHandler::ProcessResponseInfo --> g_smscAddr=%{public}s,"
                                   "tosca=%{public}d",
                        g_smscAddr.c_str(), tosca);
                } else {
                    TELEPHONY_LOGI("TelRilTest::DemoHandler::ProcessResponseInfo --> get resultInfo_");
                    resultInfo_ = event->GetSharedObject<HRilRadioResponseInfo>();
                }
                break;
            }
            default: {
                TELEPHONY_LOGI("TelRilTest::DemoHandler::ProcessResponseInfo --> case default");
                resultInfo_ = event->GetSharedObject<HRilRadioResponseInfo>();
            }
        }
    }
    NotifyAll();
}

/**
 * @brief Process event
 *
 * @param event
 */
void TelRilTest::DemoHandler::ProcessEvent(const AppExecFwk::InnerEvent::Pointer &event)
{
    ProcessResponseInfo(event);
}

uint32_t TelRilTest::GetRandNum()
{
    int32_t r = 0;
    int fd = open("/dev/random", O_RDONLY);
    if (fd > 0) {
        read(fd, &r, sizeof(int32_t));
    }
    close(fd);
    return r;
}

/**
 * @brief Get random phone number
 *
 * @param length
 */
std::string TelRilTest::GetRandPhoneNum(const int len)
{
    char c;
    int32_t idx;
    uint32_t rtv = 0;
    std::string str;

    for (idx = 0; idx < len; idx++) {
        rtv = GetRandNum() % DECIMAL;
        c = static_cast<char>(rtv + '0');
        str.push_back(c);
    }

    return str;
}

std::shared_ptr<TelRilTest::DemoHandler> TelRilTest::GetHandler(void)
{
    std::shared_ptr<AppExecFwk::EventRunner> eventRunner;
    std::shared_ptr<TelRilTest::DemoHandler> demohandler;
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("ERROR : make_shared<ITelRilManager>(telRilManager) --> nullptr !!!");
        return NULL;
    }
    eventRunner = AppExecFwk::EventRunner::Create("DemoHandler");
    if (eventRunner == nullptr) {
        TELEPHONY_LOGE("ERROR : AppExecFwk::EventRunner::Create(\"DemoHandler\") --> nullptr !!!");
        return NULL;
    }
    demohandler = std::make_shared<TelRilTest::DemoHandler>(eventRunner);
    if (demohandler == nullptr) {
        TELEPHONY_LOGE("ERROR : make_shared<TelRilTest::DemoHandler>(runner) --> nullptr !!!");
        return NULL;
    }
    eventRunner->Run();

    return demohandler;
}

#ifndef TEL_TEST_UNSUPPORT
/**
 * @tc.number Telephony_TelRil_NetworkGetRssiTest_0101 to do ...
 * @tc.name Get Rssi information of the card 1
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_NetworkGetRssiTest_0101, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_GET_SIGNAL_STRENGTH), SLOT_ID_0, GetHandler());
    return;
}

/**
 * @tc.number Telephony_TelRil_NetworkGetRssiTest_0201 to do ...
 * @tc.name Get Rssi information of the card 2
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_NetworkGetRssiTest_0201, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_GET_SIGNAL_STRENGTH), SLOT_ID_1, GetHandler());
    return;
}

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
 * @tc.number Telephony_TelRil_SendRilCmSmsTest_0101 to do ...
 * @tc.name Send SMS of the card 1
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_SendRilCmSmsTest_0101, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_SEND_SMS), SLOT_ID_0, GetHandler());
    return;
}

/**
 * @tc.number Telephony_TelRil_SendRilCmSmsTest_0201 to do ...
 * @tc.name Send SMS of the card 2
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_SendRilCmSmsTest_0201, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_SEND_SMS), SLOT_ID_1, GetHandler());
    return;
}

/**
 * @tc.number Telephony_TelRil_StorageRilCmSmsTest_0101 to do ...
 * @tc.name Storage SMS of the card 1
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_StorageRilCmSmsTest_0101, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_STORAGE_SMS), SLOT_ID_0, GetHandler());
    return;
}

/**
 * @tc.number Telephony_TelRil_StorageRilCmSmsTest_0201 to do ...
 * @tc.name Storage SMS of the card 2
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_StorageRilCmSmsTest_0201, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_STORAGE_SMS), SLOT_ID_1, GetHandler());
    return;
}

/**
 * @tc.number Telephony_TelRil_DeleteRilCmSmsTest_0101 to do ...
 * @tc.name Delete SMS of the card 1
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_DeleteRilCmSmsTest_0101, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_DELETE_SMS), SLOT_ID_0, GetHandler());
    return;
}

/**
 * @tc.number Telephony_TelRil_DeleteRilCmSmsTest_0201 to do ...
 * @tc.name Delete SMS of the card 2
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_DeleteRilCmSmsTest_0201, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_DELETE_SMS), SLOT_ID_1, GetHandler());
    return;
}

/**
 * @tc.number Telephony_TelRil_UpdateRilCmSmsTest_0101 to do ...
 * @tc.name Update SMS of the card 1
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_UpdateRilCmSmsTest_0101, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_UPDATE_SMS), SLOT_ID_0, GetHandler());
    return;
}

/**
 * @tc.number Telephony_TelRil_UpdateRilCmSmsTest_0201 to do ...
 * @tc.name Update SMS of the card 2
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_UpdateRilCmSmsTest_0201, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_UPDATE_SMS), SLOT_ID_1, GetHandler());
    return;
}

/**
 * @tc.number Telephony_TelRil_SetRilCmSmsCenterAddressTest_0101 to do ...
 * @tc.name Set SMS center address of the card 1
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_SetRilCmSmsCenterAddressTest_0101, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_SET_SMS_CENTER_ADDRESS), SLOT_ID_0, GetHandler());
    return;
}

/**
 * @tc.number Telephony_TelRil_SetRilCmSmsCenterAddressTest_0201 to do ...
 * @tc.name Set SMS center address of the card 2
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_SetRilCmSmsCenterAddressTest_0201, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_SET_SMS_CENTER_ADDRESS), SLOT_ID_1, GetHandler());
    return;
}

/**
 * @tc.number Telephony_TelRil_GetRilCmSmsCenterAddressTest_0101 to do ...
 * @tc.name Get SMS center address of the card 1
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_GetRilCmSmsCenterAddressTest_0101, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_GET_SMS_CENTER_ADDRESS), SLOT_ID_0, GetHandler());
    return;
}

/**
 * @tc.number Telephony_TelRil_GetRilCmSmsCenterAddressTest_0201 to do ...
 * @tc.name Get SMS center address of the card 2
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_GetRilCmSmsCenterAddressTest_0201, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_GET_SMS_CENTER_ADDRESS), SLOT_ID_1, GetHandler());
    return;
}

/**
 * @tc.number Telephony_TelRil_SetRilCmCBConfigTest_0101 to do ...
 * @tc.name Set SMS cell broadcast of the card 1
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_SetRilCmCBConfigTest_0101, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_SET_CB_CONFIG), SLOT_ID_0, GetHandler());
    return;
}

/**
 * @tc.number Telephony_TelRil_SetRilCmCBConfigTest_0201 to do ...
 * @tc.name Set SMS cell broadcast of the card 2
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_SetRilCmCBConfigTest_0201, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_SET_CB_CONFIG), SLOT_ID_1, GetHandler());
    return;
}

/**
 * @tc.number Telephony_TelRil_GetRilCmCBConfigTest_0101 to do ...
 * @tc.name Get SMS cell broadcast of the card 1
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_GetRilCmCBConfigTest_0101, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_GET_CB_CONFIG), SLOT_ID_0, GetHandler());
    return;
}

/**
 * @tc.number Telephony_TelRil_GetRilCmCBConfigTest_0201 to do ...
 * @tc.name Get SMS cell broadcast of the card 2
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_GetRilCmCBConfigTest_0201, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_GET_CB_CONFIG), SLOT_ID_1, GetHandler());
    return;
}

/**
 * @tc.number Telephony_TelRil_GetRilCmCdmaCBConfigTest_0101 to do ...
 * @tc.name Get CDMA SMS cell broadcast of the card 1
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_GetRilCmCdmaCBConfigTest_0101, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_GET_CDMA_CB_CONFIG), SLOT_ID_0, GetHandler());
    return;
}

/**
 * @tc.number Telephony_TelRil_GetRilCmCdmaCBConfigTest_0201 to do ...
 * @tc.name Get CDMA SMS cell broadcast of the card 2
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_GetRilCmCdmaCBConfigTest_0201, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_GET_CDMA_CB_CONFIG), SLOT_ID_1, GetHandler());
    return;
}

/**
 * @tc.number Telephony_TelRil_SmsSendSmsExpectMoreTest_0101 to do ...
 * @tc.name Send multiple SMS of the card 1
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_SmsSendSmsExpectMoreTest_0101, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_SEND_SMS_EXPECT_MORE), SLOT_ID_0, GetHandler());
    return;
}

/**
 * @tc.number Telephony_TelRil_SmsSendSmsExpectMoreTest_0201 to do ...
 * @tc.name Send multiple SMS of the card 2
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_SmsSendSmsExpectMoreTest_0201, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_SEND_SMS_EXPECT_MORE), SLOT_ID_1, GetHandler());
    return;
}

/**
 * @tc.number Telephony_TelRil_SmsAcknowledgeTest_0101 to do ...
 * @tc.name SMS Acknowledge of the card 1
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_SmsAcknowledgeTest_0101, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_SEND_SMS_ACK), SLOT_ID_0, GetHandler());
    return;
}

/**
 * @tc.number Telephony_TelRil_SmsAcknowledgeTest_0201 to do ...
 * @tc.name SMS Acknowledge of the card 2
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_SmsAcknowledgeTest_0201, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_SEND_SMS_ACK), SLOT_ID_1, GetHandler());
    return;
}

/**
 * @tc.number Telephony_TelRil_AddRilCmCdmaSmsTest_0101 to do ...
 * @tc.name Add CDMA SMS of the card 1
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_AddRilCmCdmaSmsTest_0101, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_ADD_CDMA_SMS), SLOT_ID_0, GetHandler());
    return;
}

/**
 * @tc.number Telephony_TelRil_AddRilCmCdmaSmsTest_0201 to do ...
 * @tc.name Add CDMA SMS of the card 2
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_AddRilCmCdmaSmsTest_0201, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_ADD_CDMA_SMS), SLOT_ID_1, GetHandler());
    return;
}

/**
 * @tc.number Telephony_TelRil_DelRilCmCdmaSmsTest_0101 to do ...
 * @tc.name Delete CDMA SMS of the card 1
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_DelRilCmCdmaSmsTest_0101, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_DEL_CDMA_SMS), SLOT_ID_0, GetHandler());
    return;
}

/**
 * @tc.number Telephony_TelRil_DelRilCmCdmaSmsTest_0201 to do ...
 * @tc.name Delete CDMA SMS of the card 2
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_DelRilCmCdmaSmsTest_0201, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_DEL_CDMA_SMS), SLOT_ID_1, GetHandler());
    return;
}

/**
 * @tc.number Telephony_TelRil_UpdateRilCmCdmaSmsTest_0101 to do ...
 * @tc.name Update CDMA SMS of the card 1
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_UpdateRilCmCdmaSmsTest_0101, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_UPDATE_CDMA_SMS), SLOT_ID_0, GetHandler());
    return;
}

/**
 * @tc.number Telephony_TelRil_UpdateRilCmCdmaSmsTest_0201 to do ...
 * @tc.name Update CDMA SMS of the card 2
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_UpdateRilCmCdmaSmsTest_0201, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_UPDATE_CDMA_SMS), SLOT_ID_1, GetHandler());
    return;
}

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
    ProcessTest(
        static_cast<int32_t>(DiffInterfaceId::TEST_STK_SEND_CALL_SETUP_REQUEST_RESULT), SLOT_ID_0, GetHandler());
    return;
}

/**
 * @tc.number Telephony_TelRil_SendCallSetupRequestResultTest_0201 to do ...
 * @tc.name Send Call Setup Request Result command of the card 2
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_SendCallSetupRequestResultTest_0201, Function | MediumTest | Level3)
{
    ProcessTest(
        static_cast<int32_t>(DiffInterfaceId::TEST_STK_SEND_CALL_SETUP_REQUEST_RESULT), SLOT_ID_1, GetHandler());
    return;
}

/**
 * @tc.number Telephony_TelRil_NetworkOperatorTest_0101 to do ...
 * @tc.name Get operator information of the card 1
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_NetworkOperatorTest_0101, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_OPERATOR), SLOT_ID_0, GetHandler());
    return;
}

/**
 * @tc.number Telephony_TelRil_NetworkOperatorTest_0201 to do ...
 * @tc.name Get operator information of the card 2
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_NetworkOperatorTest_0201, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_OPERATOR), SLOT_ID_1, GetHandler());
    return;
}

/**
 * @tc.number Telephony_TelRil_NetworkVoiceRegistrationStateTest_0101 to do ...
 * @tc.name Voice registration state of the card 1
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_NetworkVoiceRegistrationStateTest_0101, Function | MediumTest | Level3)
{
    ProcessTest(
        static_cast<int32_t>(DiffInterfaceId::TEST_GET_RILCM_VOICE_REGISTRATION_STATE), SLOT_ID_0, GetHandler());
    return;
}

/**
 * @tc.number Telephony_TelRil_NetworkVoiceRegistrationStateTest_0201 to do ...
 * @tc.name Voice registration state of the card 2
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_NetworkVoiceRegistrationStateTest_0201, Function | MediumTest | Level3)
{
    ProcessTest(
        static_cast<int32_t>(DiffInterfaceId::TEST_GET_RILCM_VOICE_REGISTRATION_STATE), SLOT_ID_1, GetHandler());
    return;
}

/**
 * @tc.number Telephony_TelRil_NetworkDataRegistrationStateTest_0101 to do ...
 * @tc.name Data registration state of the card 1
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_NetworkDataRegistrationStateTest_0101, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_GET_RILCM_DATA_REGISTRATION_STATE), SLOT_ID_0, GetHandler());
    return;
}

/**
 * @tc.number Telephony_TelRil_NetworkDataRegistrationStateTest_0201 to do ...
 * @tc.name Data registration state of the card 2
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_NetworkDataRegistrationStateTest_0201, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_GET_RILCM_DATA_REGISTRATION_STATE), SLOT_ID_1, GetHandler());
    return;
}

/**
 * @tc.number Telephony_TelRil_GetNetworkSearchInformationTest_0101 to do ...
 * @tc.name Search for carrier information of the card 1
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_GetNetworkSearchInformationTest_0101, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_GET_NETWORKS_TO_USE), SLOT_ID_0, GetHandler());
    return;
}

/**
 * @tc.number Telephony_TelRil_GetNetworkSearchInformationTest_0201 to do ...
 * @tc.name Search for carrier information of the card 2
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_GetNetworkSearchInformationTest_0201, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_GET_NETWORKS_TO_USE), SLOT_ID_1, GetHandler());
    return;
}

/**
 * @tc.number Telephony_TelRil_GetNetworkSelectionModeTest_0101 to do ...
 * @tc.name Get network selection mode of the card 1
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_GetNetworkSelectionModeTest_0101, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_GET_SELECTION_MOD_FOR_NETWORKS), SLOT_ID_0, GetHandler());
    return;
}

/**
 * @tc.number Telephony_TelRil_GetNetworkSelectionModeTest_0201 to do ...
 * @tc.name Get network selection mode of the card 2
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_GetNetworkSelectionModeTest_0201, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_GET_SELECTION_MOD_FOR_NETWORKS), SLOT_ID_1, GetHandler());
    return;
}

/**
 * @tc.number Telephony_TelRil_SetNetworkSelectionModeTest_0101 to do ...
 * @tc.name Set network selection mode of the card 1
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_SetNetworkSelectionModeTest_0101, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_SET_MODE_AUTOMATIC_NETWORKS), SLOT_ID_0, GetHandler());
    return;
}

/**
 * @tc.number Telephony_TelRil_SetNetworkSelectionModeTest_0201 to do ...
 * @tc.name Set network selection mode of the card 2
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_SetNetworkSelectionModeTest_0201, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_SET_MODE_AUTOMATIC_NETWORKS), SLOT_ID_1, GetHandler());
    return;
}

/**
 * @tc.number Telephony_TelRil_GetPreferredNetworkParaTest_0101 to do ...
 * @tc.name Get preferred network parameters of the card 1
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_GetPreferredNetworkParaTest_0101, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_GET_PREFERRED_NETWORK_TYPE), SLOT_ID_0, GetHandler());
    return;
}

/**
 * @tc.number Telephony_TelRil_GetPreferredNetworkParaTest_0201 to do ...
 * @tc.name Get preferred network parameters of the card 2
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_GetPreferredNetworkParaTest_0201, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_GET_PREFERRED_NETWORK_TYPE), SLOT_ID_1, GetHandler());
    return;
}

/**
 * @tc.number Telephony_TelRil_SetPreferredNetworkParaTest_0101 to do ...
 * @tc.name Set preferred network parameters of the card 1
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_SetPreferredNetworkParaTest_0101, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_SET_PREFERRED_NETWORK_TYPE), SLOT_ID_0, GetHandler());
    return;
}

/**
 * @tc.number Telephony_TelRil_SetPreferredNetworkParaTest_0201 to do ...
 * @tc.name Set preferred network parameters of the card 2
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_SetPreferredNetworkParaTest_0201, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_SET_PREFERRED_NETWORK_TYPE), SLOT_ID_1, GetHandler());
    return;
}

/**
 * @tc.number Telephony_TelRil_GetImeiTest_0101 to do ...
 * @tc.name Get Imei information of the card 1
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_GetImeiTest_0101, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_GET_IMEI), SLOT_ID_0, GetHandler());
    return;
}

/**
 * @tc.number Telephony_TelRil_GetImeiTest_0201 to do ...
 * @tc.name Get Imei information of the card 2
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_GetImeiTest_0201, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_GET_IMEI), SLOT_ID_1, GetHandler());
    return;
}

/**
 * @tc.number Telephony_TelRil_GetMeidTest_0101 to do ...
 * @tc.name Get Meid information of the card 1
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_GetMeidTest_0101, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_GET_MEID), SLOT_ID_0, GetHandler());
    return;
}

/**
 * @tc.number Telephony_TelRil_GetMeidTest_0201 to do ...
 * @tc.name Get Meid information of the card 2
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_GetMeidTest_0201, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_GET_MEID), SLOT_ID_1, GetHandler());
    return;
}

/**
 * @tc.number Telephony_TelRil_GetVoiceRadioTechnologyTest_0101 to do ...
 * @tc.name Get voice radio technology of the card 1
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_GetVoiceRadioTechnologyTest_0101, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_GET_VOICE_RADIO_INFO), SLOT_ID_0, GetHandler());
    return;
}

/**
 * @tc.number Telephony_TelRil_GetVoiceRadioTechnologyTest_0201 to do ...
 * @tc.name Get voice radio technology of the card 2
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_GetVoiceRadioTechnologyTest_0201, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_GET_VOICE_RADIO_INFO), SLOT_ID_1, GetHandler());
    return;
}

/**
 * @tc.number Telephony_TelRil_GetPhysicalChannelConfigTest_0101 to do ...
 * @tc.name Get physical channel config of the card 1
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_GetPhysicalChannelConfigTest_0101, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_GET_PHYSICAL_CHANNEL_CONFIG), SLOT_ID_0, GetHandler());
    return;
}

/**
 * @tc.number Telephony_TelRil_GetPhysicalChannelConfigTest_0201 to do ...
 * @tc.name Get physical channel config of the card 2
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_GetPhysicalChannelConfigTest_0201, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_GET_PHYSICAL_CHANNEL_CONFIG), SLOT_ID_1, GetHandler());
    return;
}

/**
 * @tc.number Telephony_TelRil_SetLocateUpdatesTest_0101 to do ...
 * @tc.name Set locate updates of the card 1
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_SetLocateUpdatesTest_0101, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_SET_LOCATE_UPDATES), SLOT_ID_0, GetHandler());
    return;
}

/**
 * @tc.number Telephony_TelRil_SetLocateUpdatesTest_0201 to do ...
 * @tc.name Set locate updates of the card 2
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_SetLocateUpdatesTest_0201, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_SET_LOCATE_UPDATES), SLOT_ID_1, GetHandler());
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
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_SET_NOTIFICATION_FILTER), SLOT_ID_0, GetHandler());
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
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_SET_NOTIFICATION_FILTER), SLOT_ID_1, GetHandler());
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
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_SET_DEVICE_STATE), SLOT_ID_0, GetHandler());
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
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_SET_DEVICE_STATE), SLOT_ID_1, GetHandler());
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
 * @tc.number Telephony_TelRil_SetRadioStateTest_0101 to do ...
 * @tc.name Set radio state of the card 1
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_SetRadioStateTest_0101, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_SET_POWER_STATE), SLOT_ID_0, GetHandler());
    return;
}

/**
 * @tc.number Telephony_TelRil_SetRadioStateTest_0201 to do ...
 * @tc.name Set radio state of the card 2
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_SetRadioStateTest_0201, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_SET_POWER_STATE), SLOT_ID_1, GetHandler());
    return;
}

/**
 * @tc.number Telephony_TelRil_GetRadioStateTest_0101 to do ...
 * @tc.name Get radio state of the card 1
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_GetRadioStateTest_0101, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_GET_POWER_STATE), SLOT_ID_0, GetHandler());
    return;
}

/**
 * @tc.number Telephony_TelRil_GetRadioStateTest_0201 to do ...
 * @tc.name Get radio state of the card 2
 * @tc.desc Function test
 */
HWTEST_F(TelRilTest, Telephony_TelRil_GetRadioStateTest_0201, Function | MediumTest | Level3)
{
    ProcessTest(static_cast<int32_t>(DiffInterfaceId::TEST_GET_POWER_STATE), SLOT_ID_1, GetHandler());
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
