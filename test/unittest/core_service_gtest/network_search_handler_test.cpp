/*
 * Copyright (C) 2025-2025 Huawei Device Co., Ltd.
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
#define private public
#define protected public
 
#include "gtest/gtest.h"
#include <gmock/gmock.h>
 
#include "cell_info.h"
#include "cell_location.h"
#include "common_event_manager.h"
#include "common_event_support.h"
#include "core_manager_inner.h"
#include "core_service_client.h"
#include "tel_ril_base_parcel.h"
#include "network_register.h"
#include "network_search_manager.h"
#include "network_search_state.h"
#include "operator_matching_rule.h"
#include "operator_name.h"
#include "radio_protocol_controller.h"
#include "sim_manager.h"
#include "tel_ril_manager.h"
#include "telephony_errors.h"
#include "telephony_log_wrapper.h"
#include "telephony_data_helper.h"
#include "nativetoken_kit.h"
#include "telephony_ext_wrapper.h"
#include "network_utils.h"
#include "mock_sim_manager.h"
#include "app_mgr_interface.h"
#include "i_network_search_callback_stub.h"
#include "setting_utils.h"
#include "device_state_observer.h"
#include "ims_reg_info_callback_gtest.h"
 
namespace OHOS {
namespace Telephony {
using namespace testing::ext;
 
namespace {
constexpr int32_t INVALID_SLOTID = -1;
constexpr int32_t SLOT_ID_0 = 0;
constexpr int32_t MAX_SIZE = 100;
} // namespace
 
class NetworkSearchHandlerTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};
 
void NetworkSearchHandlerTest::TearDownTestCase() {}
 
void NetworkSearchHandlerTest::SetUp() {}
 
void NetworkSearchHandlerTest::TearDown() {}
 
void NetworkSearchHandlerTest::SetUpTestCase() {}
 
HWTEST_F(NetworkSearchHandlerTest, Telephony_NetworkSearchManager_PostDeinitAndNullPtr, Function | MediumTest | Level1)
{
    std::u16string imeiSv = u"";
    std::shared_ptr<SimManager> simManager = nullptr;
    sptr<INetworkSearchCallback> networkSearchCallback = nullptr;
    std::shared_ptr<ITelRilManager> telRilManager = std::make_shared<TelRilManager>();
    auto networkSearchManager = std::make_shared<NetworkSearchManager>(telRilManager, simManager);
    auto networkSearchState = std::make_shared<NetworkSearchState>(networkSearchManager, SLOT_ID_0);
 
    networkSearchManager->ClearManagerInner();
    networkSearchManager->DeInit();
    networkSearchManager->eventSender_ = nullptr;
    EXPECT_EQ(networkSearchManager->InitModuleBySlotId(SLOT_ID_0), TELEPHONY_ERROR);
    EXPECT_EQ(networkSearchManager->GetImeiSv(SLOT_ID_0, imeiSv), TELEPHONY_ERR_LOCAL_PTR_NULL);
}
 
HWTEST_F(NetworkSearchHandlerTest, Telephony_NetworkSearchManager_ResidentNetworkNumericSet,
    Function | MediumTest | Level1)
{
    std::u16string str;
    std::string residentNetworkNumeric = "abc";
    sptr<NetworkState> networkState = nullptr;
    std::shared_ptr<SimManager> simManager = nullptr;
    sptr<INetworkSearchCallback> networkSearchCallback = nullptr;
    std::shared_ptr<ITelRilManager> telRilManager = std::make_shared<TelRilManager>();
    auto networkSearchManager = std::make_shared<NetworkSearchManager>(telRilManager, simManager);
    auto networkSearchState = std::make_shared<NetworkSearchState>(networkSearchManager, SLOT_ID_0);
 
    auto inner = std::make_shared<NetworkSearchManagerInner>();
    networkSearchState->networkState_ = nullptr;
    inner->networkSearchState_ = networkSearchState;
    networkSearchManager->AddManagerInner(SLOT_ID_0, inner);
    EXPECT_EQ(networkSearchManager->GetOperatorNumeric(SLOT_ID_0), str);
    EXPECT_EQ(networkSearchManager->GetOperatorName(SLOT_ID_0, str), TELEPHONY_ERR_SLOTID_INVALID);
 
    TELEPHONY_EXT_WRAPPER.getNetworkStatusExt_ = nullptr;
    EXPECT_EQ(networkSearchManager->GetNetworkStatus(INVALID_SLOTID, networkState), TELEPHONY_ERR_SLOTID_INVALID);
    networkSearchManager->SetResidentNetworkNumeric(SLOT_ID_0, residentNetworkNumeric);
    auto mapManagerInner = networkSearchManager->FindManagerInner(SLOT_ID_0);
    EXPECT_EQ(mapManagerInner->residentNetworkNumeric_, residentNetworkNumeric);
}
 
HWTEST_F(NetworkSearchHandlerTest, Telephony_NetworkSearchManager_GetNetworkStatusError,
    Function | MediumTest | Level1) {
    std::u16string str;
    std::string residentNetworkNumeric = "abc";
    sptr<NetworkState> networkState = nullptr;
    std::shared_ptr<SimManager> simManager = nullptr;
    sptr<INetworkSearchCallback> networkSearchCallback = nullptr;
    std::shared_ptr<ITelRilManager> telRilManager = std::make_shared<TelRilManager>();
    auto networkSearchManager = std::make_shared<NetworkSearchManager>(telRilManager, simManager);
    auto networkSearchState = std::make_shared<NetworkSearchState>(networkSearchManager, SLOT_ID_0);
 
    auto inner = std::make_shared<NetworkSearchManagerInner>();
    networkSearchState->networkState_ = nullptr;
    inner->networkSearchState_ = nullptr;
    networkSearchManager->AddManagerInner(INVALID_SLOTID, inner);
    EXPECT_EQ(networkSearchManager->GetOperatorNumeric(INVALID_SLOTID), str);
    EXPECT_EQ(networkSearchManager->GetOperatorName(INVALID_SLOTID, str), TELEPHONY_ERR_SLOTID_INVALID);
    EXPECT_EQ(networkSearchManager->GetNetworkStatus(INVALID_SLOTID, networkState), TELEPHONY_ERR_SLOTID_INVALID);
}
 
HWTEST_F(NetworkSearchHandlerTest, Telephony_NetworkSearchManager_GetNeighboringCellInfoError,
Function | MediumTest | Level1)
{
    sptr<NetworkState> networkState = nullptr;
    std::vector<sptr<CellInformation>> cellInfo;
    RadioTech csRadioTech = RadioTech::RADIO_TECHNOLOGY_GSM;
    RadioTech psRadioTech = RadioTech::RADIO_TECHNOLOGY_GSM;
    SelectionMode selection = SelectionMode::MODE_TYPE_AUTO;
    ModemPowerState radioState = ModemPowerState::CORE_SERVICE_POWER_ON;
    std::shared_ptr<SimManager> simManager = nullptr;
    std::shared_ptr<ITelRilManager> telRilManager = std::make_shared<TelRilManager>();
    auto networkSearchManager = std::make_shared<NetworkSearchManager>(telRilManager, simManager);
 
    std::shared_ptr<NetworkSearchManagerInner> inner = nullptr;
    networkSearchManager->AddManagerInner(SLOT_ID_0, inner);
    
    networkSearchManager->SetFrequencyType(SLOT_ID_0, FrequencyType::FREQ_TYPE_MMWAVE);
    networkSearchManager->SetRadioStateValue(SLOT_ID_0, radioState);
    networkSearchManager->SetNetworkSelectionValue(SLOT_ID_0, selection);
    networkSearchManager->UpdatePhone(SLOT_ID_0, csRadioTech, psRadioTech);
    EXPECT_EQ(networkSearchManager->GetNetworkSearchInformationValue(SLOT_ID_0), nullptr);
    EXPECT_EQ(networkSearchManager->GetNetworkStatus(SLOT_ID_0, networkState), TELEPHONY_ERR_SLOTID_INVALID);
    EXPECT_EQ(networkSearchManager->GetNeighboringCellInfoList(SLOT_ID_0, cellInfo), TELEPHONY_ERR_LOCAL_PTR_NULL);
}
 
HWTEST_F(NetworkSearchHandlerTest, Telephony_NetworkSearchManager_ProcessNotifyStateChangeEventNotNull,
    Function | MediumTest | Level1)
{
    int32_t status = 0;
    std::u16string deviceId = u"";
    NrMode mode = NrMode::NR_MODE_NSA_ONLY;
    std::shared_ptr<ITelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<SimManager> simManager = nullptr;
    auto networkSearchManager = std::make_shared<NetworkSearchManager>(telRilManager, simManager);
    networkSearchManager->eventSender_ = std::make_unique<EventSender>(telRilManager, networkSearchManager);
    auto networkSearchHandler =
        std::make_shared<NetworkSearchHandler>(networkSearchManager, telRilManager, simManager, SLOT_ID_0);
 
    auto inner = std::make_shared<NetworkSearchManagerInner>();
    networkSearchHandler->radioInfo_ = std::make_unique<RadioInfo>(networkSearchManager, SLOT_ID_0);
    networkSearchHandler->radioInfo_->phoneType_ = PhoneType::PHONE_TYPE_IS_GSM;
    inner->imei_ = deviceId;
    inner->networkSearchHandler_ = networkSearchHandler;
    networkSearchManager->AddManagerInner(SLOT_ID_0, inner);
 
    EXPECT_EQ(networkSearchManager->GetNrOptionMode(SLOT_ID_0, mode), TELEPHONY_ERR_SUCCESS);
    EXPECT_EQ(networkSearchManager->UpdateNrOptionMode(SLOT_ID_0, mode), TELEPHONY_ERR_SUCCESS);
    EXPECT_EQ(networkSearchManager->GetRrcConnectionState(SLOT_ID_0, status), TELEPHONY_ERR_SUCCESS);
    EXPECT_NE(networkSearchManager->GetUniqueDeviceId(SLOT_ID_0, deviceId), TELEPHONY_ERR_SUCCESS);
 
    EXPECT_NE(networkSearchManager->ProcessNotifyStateChangeEvent(SLOT_ID_0), TELEPHONY_ERR_LOCAL_PTR_NULL);
}
 
HWTEST_F(NetworkSearchHandlerTest, Telephony_NetworkSearchManager_InvalidSlotIdErrorHandling,
    Function | MediumTest | Level1) {
    std::u16string deviceId = u"";
    std::shared_ptr<ITelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<SimManager> simManager = nullptr;
    auto networkSearchManager = std::make_shared<NetworkSearchManager>(telRilManager, simManager);
    networkSearchManager->eventSender_ = std::make_unique<EventSender>(telRilManager, networkSearchManager);
    auto networkSearchHandler =
        std::make_shared<NetworkSearchHandler>(networkSearchManager, telRilManager, simManager, SLOT_ID_0);
 
    auto inner = std::make_shared<NetworkSearchManagerInner>();
    networkSearchHandler->radioInfo_ = std::make_unique<RadioInfo>(networkSearchManager, SLOT_ID_0);
    networkSearchHandler->radioInfo_->phoneType_ = PhoneType::PHONE_TYPE_IS_GSM;
    inner->imei_ = deviceId;
    inner->networkSearchHandler_ = networkSearchHandler;
    networkSearchManager->AddManagerInner(SLOT_ID_0, inner);
    inner->networkSearchHandler_ = nullptr;
    networkSearchManager->AddManagerInner(INVALID_SLOTID, inner);
    networkSearchManager->SetLocateUpdate(INVALID_SLOTID);
    EXPECT_EQ(networkSearchManager->ProcessNotifyStateChangeEvent(INVALID_SLOTID), TELEPHONY_ERR_LOCAL_PTR_NULL);
}
 
HWTEST_F(NetworkSearchHandlerTest, Telephony_NetworkSearchManager_NetworkSearchAndOperatorUpdate,
    Function | MediumTest | Level1)
{
    ImsRegInfo info;
    int32_t listSize = 0;
    std::u16string imei = u"";
    std::vector<NetworkInformation> operatorInfo;
    RadioTech psRadioTech = RadioTech::RADIO_TECHNOLOGY_GSM;
    std::shared_ptr<ITelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<SimManager> simManager = nullptr;
    auto networkSearchManager = std::make_shared<NetworkSearchManager>(telRilManager, simManager);
    networkSearchManager->eventSender_ = std::make_unique<EventSender>(telRilManager, networkSearchManager);
 
    auto inner = std::make_shared<NetworkSearchManagerInner>();
    inner->imei_ = imei;
    inner->networkSearchState_ = nullptr;
    inner->networkSearchResult_ = std::make_unique<NetworkSearchResult>();
    inner->networkSearchHandler_ =
        std::make_shared<NetworkSearchHandler>(networkSearchManager, telRilManager, simManager, SLOT_ID_0);
    networkSearchManager->AddManagerInner(SLOT_ID_0, inner);
 
    networkSearchManager->SetNetworkSearchResultValue(SLOT_ID_0, listSize, operatorInfo);
    EXPECT_NE(networkSearchManager->GetNetworkSearchInformationValue(SLOT_ID_0), nullptr);
 
    networkSearchManager->UpdatePhone(SLOT_ID_0, psRadioTech, psRadioTech);
    networkSearchManager->SetLocateUpdate(SLOT_ID_0);
    EXPECT_EQ(networkSearchManager->UpdateOperatorName(SLOT_ID_0), TELEPHONY_ERR_SUCCESS);
    EXPECT_EQ(networkSearchManager->GetImsRegStatus(SLOT_ID_0, ImsServiceType::TYPE_VOICE, info),
        TELEPHONY_ERR_LOCAL_PTR_NULL);
    EXPECT_NE(networkSearchManager->GetImei(SLOT_ID_0, imei), TELEPHONY_ERR_SUCCESS);
 
    INetworkSearch::NSCALLBACK callback = nullptr;
    EXPECT_NE(networkSearchManager->GetRadioState(SLOT_ID_0, callback), TELEPHONY_ERR_LOCAL_PTR_NULL);
}
 
HWTEST_F(NetworkSearchHandlerTest, Telephony_NetworkSearchManager_StateFetchAndInvalidSlotHandling,
    Function | MediumTest | Level1)
{
    std::u16string imeiSv = u"";
    std::string version = "a";
    int32_t psRadioTech = SLOT_ID_0;
    std::shared_ptr<ITelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<SimManager> simManager = nullptr;
    auto networkSearchManager = std::make_shared<NetworkSearchManager>(telRilManager, simManager);
    networkSearchManager->eventSender_ = std::make_unique<EventSender>(telRilManager, networkSearchManager);
    auto networkSearchState = std::make_shared<NetworkSearchState>(networkSearchManager, SLOT_ID_0);
 
    auto inner = std::make_shared<NetworkSearchManagerInner>();
    inner->imeiSv_ = imeiSv;
    inner->networkSearchState_ = networkSearchState;
    inner->networkSearchState_->networkState_ = std::make_unique<NetworkState>();
    networkSearchManager->AddManagerInner(SLOT_ID_0, inner);
 
    TELEPHONY_EXT_WRAPPER.getRadioTechExt_ = nullptr;
    EXPECT_NE(networkSearchManager->GetCsRegState(SLOT_ID_0), TELEPHONY_ERROR);
    EXPECT_NE(networkSearchManager->GetPsRoamingState(SLOT_ID_0), TELEPHONY_ERROR);
    EXPECT_EQ(networkSearchManager->GetPsRadioTech(SLOT_ID_0, psRadioTech), TELEPHONY_ERR_SUCCESS);
    EXPECT_EQ(networkSearchManager->GetCsRadioTech(SLOT_ID_0, psRadioTech), TELEPHONY_ERR_SUCCESS);
 
    EXPECT_NE(networkSearchManager->GetMeid(SLOT_ID_0, imeiSv), TELEPHONY_ERR_SUCCESS);
    EXPECT_NE(networkSearchManager->GetImeiSv(SLOT_ID_0, imeiSv), TELEPHONY_ERR_SUCCESS);
    EXPECT_NE(networkSearchManager->GetBasebandVersion(SLOT_ID_0, version), TELEPHONY_ERR_SUCCESS);
    EXPECT_EQ(networkSearchManager->GetMeid(INVALID_SLOTID, imeiSv), TELEPHONY_ERR_LOCAL_PTR_NULL);
    EXPECT_EQ(networkSearchManager->GetImeiSv(INVALID_SLOTID, imeiSv), TELEPHONY_ERR_LOCAL_PTR_NULL);
    EXPECT_EQ(networkSearchManager->GetBasebandVersion(INVALID_SLOTID, version), TELEPHONY_ERR_LOCAL_PTR_NULL);
}
 
HWTEST_F(NetworkSearchHandlerTest, Telephony_NetworkSearchManager_SignalAndCellInfo, Function | MediumTest | Level1)
{
    std::vector<sptr<CellInformation>> cellInfo;
    auto telRilManager = std::make_shared<TelRilManager>();
    auto simManager = std::make_shared<SimManager>(telRilManager);
    auto networkSearchManager = std::make_shared<NetworkSearchManager>(telRilManager, simManager);
    auto networkSearchState = std::make_shared<NetworkSearchState>(networkSearchManager, SLOT_ID_0);
    auto networkSearchHandler =
        std::make_shared<NetworkSearchHandler>(networkSearchManager, telRilManager, simManager, SLOT_ID_0);
 
    auto inner = std::make_shared<NetworkSearchManagerInner>();
    inner->networkSearchState_ = networkSearchState;
    inner->networkSearchHandler_ = networkSearchHandler;
    inner->networkSearchState_->networkState_ = std::make_unique<NetworkState>();
    networkSearchManager->AddManagerInner(SLOT_ID_0, inner);
 
    TELEPHONY_EXT_WRAPPER.getSignalInfoListExt_ = nullptr;
    TELEPHONY_EXT_WRAPPER.sortSignalInfoListExt_ = nullptr;
    sptr<SignalInformation> signalInfo = new WcdmaSignalInformation;
    std::vector<sptr<SignalInformation>> signals;
    signals.emplace_back(signalInfo);
    EXPECT_EQ(networkSearchManager->GetSignalInfoList(SLOT_ID_0, signals), TELEPHONY_ERR_SUCCESS);
 
    networkSearchManager->delayTime_ = SLOT_ID_0;
    EXPECT_EQ(networkSearchManager->IsNeedDelayNotify(SLOT_ID_0), false);
 
    TELEPHONY_EXT_WRAPPER.getCellInfoList_ = nullptr;
    EXPECT_EQ(networkSearchManager->GetCellInfoList(SLOT_ID_0, cellInfo), TELEPHONY_ERR_SUCCESS);
    EXPECT_EQ(networkSearchManager->GetNeighboringCellInfoList(SLOT_ID_0, cellInfo), TELEPHONY_ERR_SUCCESS);
}
 
HWTEST_F(NetworkSearchHandlerTest, Telephony_NetworkSearchManager_SignalAndCellInfoFetch,
    Function | MediumTest | Level1) {
    std::vector<sptr<CellInformation>> cellInfo;
    auto telRilManager = std::make_shared<TelRilManager>();
    auto simManager = std::make_shared<SimManager>(telRilManager);
    auto networkSearchManager = std::make_shared<NetworkSearchManager>(telRilManager, simManager);
    auto networkSearchState = std::make_shared<NetworkSearchState>(networkSearchManager, SLOT_ID_0);
    auto networkSearchHandler =
        std::make_shared<NetworkSearchHandler>(networkSearchManager, telRilManager, simManager, SLOT_ID_0);
 
    auto inner = std::make_shared<NetworkSearchManagerInner>();
    inner->networkSearchState_ = networkSearchState;
    inner->networkSearchHandler_ = networkSearchHandler;
    inner->networkSearchState_->networkState_ = std::make_unique<NetworkState>();
    networkSearchManager->AddManagerInner(SLOT_ID_0, inner);
 
    TELEPHONY_EXT_WRAPPER.getSignalInfoListExt_ = nullptr;
    TELEPHONY_EXT_WRAPPER.sortSignalInfoListExt_ = nullptr;
    sptr<SignalInformation> signalInfo = new WcdmaSignalInformation;
    std::vector<sptr<SignalInformation>> signals;
    signals.emplace_back(signalInfo);
    inner->networkSearchHandler_ = nullptr;
    networkSearchManager->AddManagerInner(INVALID_SLOTID, inner);
    EXPECT_NE(networkSearchManager->GetCellInfoList(INVALID_SLOTID, cellInfo), TELEPHONY_ERR_SUCCESS);
    EXPECT_NE(networkSearchManager->GetNeighboringCellInfoList(INVALID_SLOTID, cellInfo), TELEPHONY_ERR_SUCCESS);
}
 
 
HWTEST_F(NetworkSearchHandlerTest, Telephony_NetworkSearchManager_NullPointerHandling, Function | MediumTest | Level1)
{
    Rssi signalIntensity;
    std::shared_ptr<ITelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<SimManager> simManager = nullptr;
    auto networkSearchManager = std::make_shared<NetworkSearchManager>(telRilManager, simManager);
    networkSearchManager->eventSender_ = std::make_unique<EventSender>(telRilManager, networkSearchManager);
 
    std::shared_ptr<NrSsbInformation> nrSsbInformation = nullptr;
    auto inner = std::make_shared<NetworkSearchManagerInner>();
    inner->networkSearchHandler_ = nullptr;
    networkSearchManager->AddManagerInner(SLOT_ID_0, inner);
    EXPECT_EQ(networkSearchManager->GetNrSsbId(SLOT_ID_0, nrSsbInformation), TELEPHONY_ERR_LOCAL_PTR_NULL);
    EXPECT_EQ(networkSearchManager->ProcessSignalIntensity(SLOT_ID_0, signalIntensity), TELEPHONY_ERR_LOCAL_PTR_NULL);
}
 
HWTEST_F(NetworkSearchHandlerTest, Telephony_NetworkSearchManager_IMSCallbackRegistration,
    Function | MediumTest | Level1)
{
    std::shared_ptr<ITelRilManager> telRilManager = std::make_shared<TelRilManager>();
    std::shared_ptr<SimManager> simManager = nullptr;
    auto networkSearchManager = std::make_shared<NetworkSearchManager>(telRilManager, simManager);
 
    ImsRegInfo info;
    NetworkSearchManager::ImsRegInfoCallbackRecord record;
    record.slotId = SLOT_ID_0;
    record.tokenId = SLOT_ID_0;
    record.imsCallback = nullptr;
    record.imsSrvType = ImsServiceType::TYPE_VOICE;
    sptr<ImsRegInfoCallback> imsRegInfoCallback = new ImsRegInfoCallbackGtest();
    networkSearchManager->listImsRegInfoCallbackRecord_.emplace_back(record);
 
    networkSearchManager->NotifyImsRegInfoChanged(INVALID_SLOTID, ImsServiceType::TYPE_VOICE, info);
    networkSearchManager->NotifyImsRegInfoChanged(SLOT_ID_0, ImsServiceType::TYPE_VIDEO, info);
 
    EXPECT_EQ(networkSearchManager->RegisterImsRegInfoCallback(INVALID_SLOTID, ImsServiceType::TYPE_VOICE, SLOT_ID_0,
        imsRegInfoCallback), TELEPHONY_SUCCESS);
    EXPECT_EQ(networkSearchManager->RegisterImsRegInfoCallback(SLOT_ID_0, ImsServiceType::TYPE_VIDEO, INVALID_SLOTID,
        imsRegInfoCallback), TELEPHONY_SUCCESS);
    EXPECT_EQ(networkSearchManager->RegisterImsRegInfoCallback(SLOT_ID_0, ImsServiceType::TYPE_VOICE, INVALID_SLOTID,
        imsRegInfoCallback), TELEPHONY_SUCCESS);
    EXPECT_EQ(networkSearchManager->RegisterImsRegInfoCallback(SLOT_ID_0, ImsServiceType::TYPE_VOICE, SLOT_ID_0,
        imsRegInfoCallback), TELEPHONY_SUCCESS);
}
 
HWTEST_F(NetworkSearchHandlerTest, Telephony_NetworkSearchHandler_StateChanges, Function | MediumTest | Level1)
{
    std::shared_ptr<ITelRilManager> telRilManager = std::make_shared<TelRilManager>();
    auto simManager = std::make_shared<SimManager>(telRilManager);
    auto networkSearchManager = std::make_shared<NetworkSearchManager>(telRilManager, simManager);
    auto networkSearchHandler =
        std::make_shared<NetworkSearchHandler>(networkSearchManager, telRilManager, simManager, SLOT_ID_0);
 
    auto parcel = std::make_shared<Int32Parcel>();
    auto inner = std::make_shared<NetworkSearchManagerInner>();
    inner->deviceStateHandler_ = std::make_shared<DeviceStateHandler>(networkSearchManager, telRilManager, SLOT_ID_0);
    networkSearchManager->AddManagerInner(SLOT_ID_0, inner);
    networkSearchHandler->networkSearchManager_ = networkSearchManager;
    parcel->data = ModemPowerState::CORE_SERVICE_POWER_ON;
    AppExecFwk::InnerEvent::Pointer event = AppExecFwk::InnerEvent::Get(RadioEvent::RADIO_SIM_STATE_CHANGE, parcel);
 
    networkSearchHandler->RadioStateChange(event);
    networkSearchHandler->GetNetworkStateInfo(event);
    networkSearchHandler->UpdateImsServiceStatus(event);
 
    networkSearchHandler->GetDeviceId();
    networkSearchHandler->SetRadioOffWhenAirplaneIsOn();
 
    networkSearchHandler->signalInfo_ = nullptr;
    networkSearchHandler->networkRegister_ = nullptr;
    networkSearchHandler->UpdateNetworkState();
    networkSearchHandler->RadioSignalStrength(event);
 
    networkSearchHandler->networkSearchManager_.reset();
    networkSearchHandler->RadioRilOperator(event);
    networkSearchHandler->GetNetworkStateInfo(event);
    networkSearchHandler->RadioRilDataRegState(event);
    networkSearchHandler->RadioRilVoiceRegState(event);
    EXPECT_FALSE(networkSearchHandler->InitOperatorName());
}
 
HWTEST_F(NetworkSearchHandlerTest, Telephony_NetworkSearchHandler_RadioStateAndNetworkInfoHandling,
    Function | MediumTest | Level1)
{
    RadioTech csRadioTech = RadioTech::RADIO_TECHNOLOGY_GSM;
    std::shared_ptr<NrSsbInformation> nrCellSsbIdsInfo = nullptr;
    std::shared_ptr<ITelRilManager> telRilManager = std::make_shared<TelRilManager>();
    auto simManager = std::make_shared<SimManager>(telRilManager);
    auto networkSearchManager = std::make_shared<NetworkSearchManager>(telRilManager, simManager);
    auto networkSearchHandler =
        std::make_shared<NetworkSearchHandler>(networkSearchManager, telRilManager, simManager, SLOT_ID_0);
 
    AppExecFwk::InnerEvent::Pointer event = AppExecFwk::InnerEvent::Get(0, 1);
 
    networkSearchHandler->radioInfo_ = nullptr;
    networkSearchHandler->UpdatePhone(csRadioTech, csRadioTech);
 
    networkSearchHandler->radioInfo_ = std::make_unique<RadioInfo>(networkSearchManager, SLOT_ID_0);
    networkSearchHandler->GetRadioStateResponse(event);
    networkSearchHandler->SetRadioStateResponse(event);
    
    networkSearchHandler->nrSsbInfo_ = std::make_unique<NrSsbInfo>(networkSearchManager, SLOT_ID_0);
    networkSearchHandler->GetNrSsbIdResponse(event);
    EXPECT_EQ(networkSearchHandler->GetNrSsbId(nrCellSsbIdsInfo), TELEPHONY_ERR_LOCAL_PTR_NULL);
 
    networkSearchHandler->nrSsbInfo_ = nullptr;
    EXPECT_EQ(networkSearchHandler->GetNrSsbId(nrCellSsbIdsInfo), TELEPHONY_ERR_LOCAL_PTR_NULL);
}
 
HWTEST_F(NetworkSearchHandlerTest, Telephony_NetworkSearchHandler_NetworkSelectionAndNrSsbId,
    Function | MediumTest | Level1)
{
    std::shared_ptr<ITelRilManager> telRilManager = std::make_shared<TelRilManager>();
    auto simManager = std::make_shared<SimManager>(telRilManager);
    auto networkSearchManager = std::make_shared<NetworkSearchManager>(telRilManager, simManager);
    auto networkSearchHandler =
        std::make_shared<NetworkSearchHandler>(networkSearchManager, telRilManager, simManager, SLOT_ID_0);
    auto networkSearchState = std::make_shared<NetworkSearchState>(networkSearchManager, SLOT_ID_0);
    auto operatorName = std::make_shared<OperatorName>(networkSearchState, simManager, networkSearchManager, SLOT_ID_0);
 
    networkSearchManager->ClearManagerInner();
    networkSearchHandler->networkSearchManager_ = networkSearchManager;
    auto stringPtr = std::make_shared<std::string>("abc");
    AppExecFwk::InnerEvent::Pointer event = AppExecFwk::InnerEvent::Get(RadioEvent::RADIO_SIM_STATE_CHANGE, stringPtr);
 
    TELEPHONY_EXT_WRAPPER.updatePlmnExt_ = nullptr;
    networkSearchHandler->RadioResidentNetworkChange(event);
 
    networkSearchHandler->networkSelection_ = std::make_unique<NetworkSelection>(networkSearchManager, SLOT_ID_0);
    networkSearchHandler->GetNetworkSelectionModeResponse(event);
    networkSearchHandler->SetNetworkSelectionModeResponse(event);
 
    std::shared_ptr<NrSsbInformation> nrCellSsbIdsInfo = std::make_shared<NrSsbInformation>();
    EXPECT_TRUE(networkSearchHandler->GetNrSsbId(nrCellSsbIdsInfo));
}
 
HWTEST_F(NetworkSearchHandlerTest, Telephony_NetworkSearchHandler_NetworkStateUpdateAndImsHandling,
    Function | MediumTest | Level1)
{
    auto telRilManager = std::make_shared<TelRilManager>();
    auto simManager = std::make_shared<SimManager>(telRilManager);
    auto networkSearchManager = std::make_shared<NetworkSearchManager>(telRilManager, simManager);
    auto networkSearchHandler =
        std::make_shared<NetworkSearchHandler>(networkSearchManager, telRilManager, simManager, SLOT_ID_0);
    auto networkSearchState = std::make_shared<NetworkSearchState>(networkSearchManager, SLOT_ID_0);
    auto networkRegister = std::make_shared<NetworkRegister>(networkSearchState, networkSearchManager, SLOT_ID_0);
    auto operatorName = std::make_shared<OperatorName>(networkSearchState, simManager, networkSearchManager, SLOT_ID_0);
 
    networkSearchHandler->networkRegister_ = std::make_unique<NetworkRegister>(
    networkSearchManager->GetNetworkSearchState(SLOT_ID_0), networkSearchManager, SLOT_ID_0);
    networkSearchHandler->UpdateNetworkState();
 
    networkSearchHandler->networkRegister_ = nullptr;
    networkSearchHandler->operatorName_ = operatorName;
    networkSearchHandler->UpdateNetworkState();
 
    networkSearchHandler->networkSearchManager_.reset();
    networkSearchHandler->UpdateNetworkState();
 
    AppExecFwk::InnerEvent::Pointer event = AppExecFwk::InnerEvent::Get(0, 1);
    networkSearchHandler->GetNetworkStateInfo(event);
    networkSearchHandler->InitGetNetworkSelectionMode();
    networkSearchHandler->UpdateImsServiceStatus(event);
 
    auto imsServiceStatus = std::make_shared<ImsServiceStatus>();
    event = AppExecFwk::InnerEvent::Get(RadioEvent::RADIO_SIM_STATE_CHANGE, imsServiceStatus);
    networkSearchHandler->UpdateImsServiceStatus(event);
 
    auto registerInfo = std::make_shared<int32_t>();
    event = AppExecFwk::InnerEvent::Get(RadioEvent::RADIO_SIM_STATE_CHANGE, registerInfo);
    networkSearchHandler->UpdateImsRegisterState(event);
 
    std::vector<sptr<CellInformation>> cells;
    networkSearchHandler->cellInfo_ = std::make_unique<CellInfo>(networkSearchManager, SLOT_ID_0);
    EXPECT_EQ(networkSearchHandler->GetNeighboringCellInfoList(cells), TELEPHONY_ERR_SUCCESS);
}
 
HWTEST_F(NetworkSearchHandlerTest, Telephony_NetworkSearchHandler_SimStateRadioControl, Function | MediumTest | Level1)
{
    auto telRilManager = std::make_shared<TelRilManager>();
    auto simManager = std::make_shared<SimManager>(telRilManager);
    auto networkSearchManager = std::make_shared<NetworkSearchManager>(telRilManager, simManager);
    auto networkSearchHandler =
        std::make_shared<NetworkSearchHandler>(networkSearchManager, telRilManager, simManager, SLOT_ID_0);
 
    networkSearchHandler->signalInfo_ = std::make_unique<SignalInfo>();
    networkSearchHandler->ClearSignalAndCellInfoList();
    
    networkSearchManager->simManager_ = nullptr;
    networkSearchHandler->networkSearchManager_ = networkSearchManager;
    networkSearchHandler->SetRadioOffWhenSimDeactive();
    networkSearchHandler->RadioOnWhenHasSim(networkSearchManager, SLOT_ID_0);
    EXPECT_EQ(networkSearchHandler->IsPowerOnPrimaryRadioWhenNoSim(), false);
}
 
HWTEST_F(NetworkSearchHandlerTest, Telephony_OperatorName_GetReturnsNullAndFalse, Function | MediumTest | Level1)
{
    int32_t state = 0;
    bool isForce = true;
    std::string netPlmn = "";
    auto telRilManager = std::make_shared<TelRilManager>();
    auto simManager = std::make_shared<SimManager>(telRilManager);
    auto networkSearchManager = std::make_shared<NetworkSearchManager>(telRilManager, simManager);
    auto networkSearchState = std::make_shared<NetworkSearchState>(networkSearchManager, SLOT_ID_0);
    auto operatorName = std::make_shared<OperatorName>(networkSearchState, simManager, networkSearchManager, SLOT_ID_0);
 
    auto inner = std::make_shared<NetworkSearchManagerInner>();
    networkSearchManager->AddManagerInner(SLOT_ID_0, inner);
 
    operatorName->slotId_ = SLOT_ID_0;
    networkSearchState->networkState_ = std::make_unique<NetworkState>();
    networkSearchState->networkState_->psRegStatus_ = RegServiceState::REG_STATE_IN_SERVICE;
    operatorName->networkSearchState_ = networkSearchState;
    operatorName->networkSearchManager_ = networkSearchManager;
    
    operatorName->OnOperatorConfigChanged(INVALID_SLOTID, state);
    operatorName->networkSearchManager_.reset();
    operatorName->OnLocaleChanged();
    operatorName->NotifySpnChanged(isForce);
    EXPECT_EQ(operatorName->networkSearchManager_.lock(), nullptr);
 
    operatorName->simManager_ = nullptr;
    EXPECT_EQ(operatorName->GetRoamStateBySimFile(netPlmn), false);
}
 
HWTEST_F(NetworkSearchHandlerTest, Telephony_OperatorName_GetCurrentLacReturnsZero, Function | MediumTest | Level1)
{
    int32_t state = 0;
    std::string numeri = "";
    std::string operatorLongName = "";
    auto telRilManager = std::make_shared<TelRilManager>();
    auto simManager = std::make_shared<SimManager>(telRilManager);
    auto networkSearchManager = std::make_shared<NetworkSearchManager>(telRilManager, simManager);
    auto networkSearchState = std::make_shared<NetworkSearchState>(networkSearchManager, SLOT_ID_0);
    auto operatorName = std::make_shared<OperatorName>(networkSearchState, simManager, networkSearchManager, SLOT_ID_0);
 
    operatorName->networkSearchState_ = networkSearchState;
    operatorName->networkSearchManager_ = networkSearchManager;
    auto inner = std::make_shared<NetworkSearchManagerInner>();
    networkSearchManager->AddManagerInner(SLOT_ID_0, inner);
    operatorName->slotId_ = SLOT_ID_0;
    operatorName->OnLocaleChanged();
    operatorName->OnOperatorConfigChanged(SLOT_ID_0, state);
    
    EXPECT_NE(operatorName->networkSearchManager_.lock(), nullptr);
 
    operatorName->TrySetLongOperatorNameWithTranslation();
    operatorName->UpdateOperatorLongName(operatorLongName, numeri);
 
    auto networkSearchHandler =
        std::make_shared<NetworkSearchHandler>(networkSearchManager, telRilManager, simManager, SLOT_ID_0);
    networkSearchHandler->cellInfo_ = std::make_unique<CellInfo>(networkSearchManager, SLOT_ID_0);
    inner->networkSearchHandler_ = networkSearchHandler;
    networkSearchManager->AddManagerInner(SLOT_ID_0, inner);
    EXPECT_EQ(operatorName->GetCurrentLac(), 0);
}
 
HWTEST_F(NetworkSearchHandlerTest, Telephony_OperatorName_GetNetworkStatusReturnsNull, Function | MediumTest | Level1)
{
    OperatorNameParams params;
    sptr<NetworkState> networkState = nullptr;
    auto regStatus = RegServiceState::REG_STATE_IN_SERVICE;
    auto telRilManager = std::make_shared<TelRilManager>();
    auto simManager = std::make_shared<SimManager>(telRilManager);
    auto networkSearchManager = std::make_shared<NetworkSearchManager>(telRilManager, simManager);
    auto networkSearchState = std::make_shared<NetworkSearchState>(networkSearchManager, SLOT_ID_0);
    auto operatorName = std::make_shared<OperatorName>(networkSearchState, simManager, networkSearchManager, SLOT_ID_0);
 
    operatorName->spnCust_ = "";
    operatorName->enableCust_ = false;
    operatorName->UpdateSpn(regStatus, networkState, params);
 
    std::string operatorLongName = "";
    TELEPHONY_EXT_WRAPPER.processOperatorName_ = nullptr;
    operatorName->networkSearchState_ = networkSearchState;
    operatorName->networkSearchState_->networkState_ = nullptr;
    operatorName->TrySetLongOperatorNameWithTranslation();
    operatorName->UpdateOperatorLongName(operatorLongName, operatorLongName);
    EXPECT_EQ(operatorName->GetNetworkStatus(), nullptr);
}
 
HWTEST_F(NetworkSearchHandlerTest, Telephony_OperatorName_ShowSpnFalse, Function | MediumTest | Level1) {
    OperatorNameParams params;
    sptr<NetworkState> networkState = nullptr;
    auto regStatus = RegServiceState::REG_STATE_IN_SERVICE;
    auto telRilManager = std::make_shared<TelRilManager>();
    auto simManager = std::make_shared<SimManager>(telRilManager);
    auto networkSearchManager = std::make_shared<NetworkSearchManager>(telRilManager, simManager);
    auto networkSearchState = std::make_shared<NetworkSearchState>(networkSearchManager, SLOT_ID_0);
    auto operatorName = std::make_shared<OperatorName>(networkSearchState, simManager, networkSearchManager, SLOT_ID_0);
    std::string operatorLongName = "";
    regStatus = RegServiceState::REG_STATE_NO_SERVICE;
    operatorName->UpdateSpn(regStatus, networkState, params);
    operatorName->UpdateOperatorLongName(operatorLongName, operatorLongName);
    EXPECT_EQ(params.showSpn, false);
}
 
 
HWTEST_F(NetworkSearchHandlerTest, Telephony_OperatorName_GetNetworkStatusReturnsNotNull,
    Function | MediumTest | Level1) {
    OperatorNameParams params;
    sptr<NetworkState> networkState = nullptr;
    auto regStatus = RegServiceState::REG_STATE_IN_SERVICE;
    auto telRilManager = std::make_shared<TelRilManager>();
    auto simManager = std::make_shared<SimManager>(telRilManager);
    auto networkSearchManager = std::make_shared<NetworkSearchManager>(telRilManager, simManager);
    auto networkSearchState = std::make_shared<NetworkSearchState>(networkSearchManager, SLOT_ID_0);
    auto operatorName = std::make_shared<OperatorName>(networkSearchState, simManager, networkSearchManager, SLOT_ID_0);
 
    operatorName->spnCust_ = "";
    operatorName->enableCust_ = false;
    operatorName->UpdateSpn(regStatus, networkState, params);
    std::string operatorLongName = "";
    TELEPHONY_EXT_WRAPPER.processOperatorName_ = nullptr;
    operatorName->networkSearchState_ = networkSearchState;
 
    operatorName->networkSearchState_->networkState_ = std::make_unique<NetworkState>();
    operatorName->TrySetLongOperatorNameWithTranslation();
    operatorName->UpdateOperatorLongName(operatorLongName, operatorLongName);
    EXPECT_NE(operatorName->GetNetworkStatus(), nullptr);
}
 
 
HWTEST_F(NetworkSearchHandlerTest, Telephony_NetworkSearchState_SetImsServiceStatusValid,
    Function | MediumTest | Level1)
{
    bool imsRegStatus = true;
    auto telRilManager = std::make_shared<TelRilManager>();
    auto simManager = std::make_shared<SimManager>(telRilManager);
    auto networkSearchManager = std::make_shared<NetworkSearchManager>(telRilManager, simManager);
    auto networkSearchState = std::make_shared<NetworkSearchState>(networkSearchManager, SLOT_ID_0);
 
    networkSearchState->imsRegStatus_ = imsRegStatus;
    networkSearchState->imsServiceStatus_ = std::make_unique<ImsServiceStatus>();
    networkSearchState->imsServiceStatus_->supportImsVoice = true;
    networkSearchState->imsServiceStatus_->supportImsVideo = true;
    networkSearchState->imsServiceStatus_->supportImsUt = false;
    networkSearchState->imsServiceStatus_->supportImsSms = true;
    networkSearchState->imsServiceStatus_->imsRegTech = ImsRegTech::IMS_REG_TECH_NONE;
    networkSearchState->SetImsStatus(imsRegStatus);
 
    ImsServiceStatus imsServiceStatus;
    imsServiceStatus.supportImsVoice = false;
    imsServiceStatus.supportImsVideo = false;
    imsServiceStatus.supportImsUt = false;
    imsServiceStatus.supportImsSms = false;
    imsServiceStatus.imsRegTech = ImsRegTech::IMS_REG_TECH_NONE;
 
    networkSearchState->imsServiceStatus_->supportImsUt = true;
    networkSearchState->SetImsServiceStatus(imsServiceStatus);
    EXPECT_EQ(networkSearchState->imsServiceStatus_->supportImsVoice, imsServiceStatus.supportImsVoice);
 
    imsServiceStatus.supportImsVoice = true;
    imsServiceStatus.supportImsVideo = true;
    imsServiceStatus.supportImsUt = true;
    imsServiceStatus.supportImsSms = true;
    imsServiceStatus.imsRegTech = ImsRegTech::IMS_REG_TECH_NONE;
    networkSearchState->SetImsServiceStatus(imsServiceStatus);
    EXPECT_EQ(networkSearchState->imsServiceStatus_->supportImsUt, imsServiceStatus.supportImsUt);
 
    imsServiceStatus.imsRegTech = ImsRegTech::IMS_REG_TECH_NR;
    networkSearchState->SetImsServiceStatus(imsServiceStatus);
    EXPECT_NE(networkSearchState->imsServiceStatus_, nullptr);
    EXPECT_EQ(networkSearchState->imsServiceStatus_->imsRegTech, imsServiceStatus.imsRegTech);
}
 
HWTEST_F(NetworkSearchHandlerTest, Telephony_NetworkSearchState_ImsRegStatusTrue, Function | MediumTest | Level1)
{
    bool imsRegStatus = true;
    auto telRilManager = std::make_shared<TelRilManager>();
    auto simManager = std::make_shared<SimManager>(telRilManager);
    auto networkSearchManager = std::make_shared<NetworkSearchManager>(telRilManager, simManager);
    auto networkSearchState = std::make_shared<NetworkSearchState>(networkSearchManager, SLOT_ID_0);
 
    networkSearchState->imsRegStatus_ = imsRegStatus;
    networkSearchState->imsServiceStatus_ = std::make_unique<ImsServiceStatus>();
 
    ImsServiceStatus imsServiceStatus;
    imsServiceStatus.supportImsVoice = true;
    imsServiceStatus.supportImsVideo = true;
    imsServiceStatus.supportImsUt = true;
    imsServiceStatus.supportImsSms = true;
    imsServiceStatus.imsRegTech = ImsRegTech::IMS_REG_TECH_NR;
 
    networkSearchState->imsServiceStatus_->supportImsVoice = false;
    networkSearchState->imsServiceStatus_->supportImsVideo = false;
    networkSearchState->imsServiceStatus_->supportImsUt = false;
    networkSearchState->imsServiceStatus_->supportImsSms = false;
    networkSearchState->imsServiceStatus_->imsRegTech = ImsRegTech::IMS_REG_TECH_NONE;
    networkSearchState->SetImsServiceStatus(imsServiceStatus);
    EXPECT_EQ(networkSearchState->imsServiceStatus_->imsRegTech, imsServiceStatus.imsRegTech);
    
    imsServiceStatus.imsRegTech = ImsRegTech::IMS_REG_TECH_NR;
    networkSearchState->SetImsServiceStatus(imsServiceStatus);
    EXPECT_EQ(networkSearchState->imsServiceStatus_->supportImsVoice, imsServiceStatus.supportImsVoice);
 
    imsServiceStatus.imsRegTech = ImsRegTech::IMS_REG_TECH_NONE;
    networkSearchState->SetImsServiceStatus(imsServiceStatus);
    EXPECT_NE(networkSearchState->imsServiceStatus_, nullptr);
    EXPECT_EQ(networkSearchState->imsServiceStatus_->imsRegTech, imsServiceStatus.imsRegTech);
}
 
HWTEST_F(NetworkSearchHandlerTest, Telephony_NetworkRegister_ChannelConfigAndNrStateUpdate,
    Function | MediumTest | Level1)
{
    auto telRilManager = std::make_shared<TelRilManager>();
    auto simManager = std::make_shared<SimManager>(telRilManager);
    auto networkSearchManager = std::make_shared<NetworkSearchManager>(telRilManager, simManager);
    auto networkSearchState = std::make_shared<NetworkSearchState>(networkSearchManager, SLOT_ID_0);
    auto networkRegister = std::make_shared<NetworkRegister>(networkSearchState, networkSearchManager, SLOT_ID_0);
 
    networkSearchState->networkState_ = std::make_unique<NetworkState>();
    networkRegister->networkSearchState_ = networkSearchState;
    networkRegister->UpdateCfgTech();
 
    auto channelConfigInfoList = std::make_shared<ChannelConfigInfoList>();
    channelConfigInfoList->itemNum = MAX_SIZE;
    auto event = AppExecFwk::InnerEvent::Get(RadioEvent::RADIO_SIM_STATE_CHANGE, channelConfigInfoList);
    networkRegister->ProcessChannelConfigInfo(event);
 
    channelConfigInfoList->itemNum = SLOT_ID_0;
    event = AppExecFwk::InnerEvent::Get(RadioEvent::RADIO_SIM_STATE_CHANGE, channelConfigInfoList);
    networkRegister->ProcessChannelConfigInfo(event);
 
    PhysicalChannelConfig config;
    channelConfigInfoList->itemNum = 1;
    config.ratType = TelRilRadioTech::RADIO_TECHNOLOGY_NR;
    config.cellConnStatus = CellConnectionStatus::SERVING_CELL_SECONDARY;
    networkRegister->isNrSecondaryCell_ = true;
    channelConfigInfoList->channelConfigInfos.push_back(config);
    networkRegister->networkSearchManager_ = networkSearchManager;
    event = AppExecFwk::InnerEvent::Get(RadioEvent::RADIO_SIM_STATE_CHANGE, channelConfigInfoList);
    networkRegister->ProcessChannelConfigInfo(event);
 
    networkRegister->networkSearchState_->networkState_->psRadioTech_ = RadioTech::RADIO_TECHNOLOGY_NR;
    networkRegister->UpdateNrState();
    EXPECT_EQ(networkRegister->nrState_, NrState::NR_NSA_STATE_SA_ATTACHED);
}
 
HWTEST_F(NetworkSearchHandlerTest, Telephony_RadioInfo_RadioStateHandlingAndAirplaneMode,
    Function | MediumTest | Level1)
{
    RadioTech csRadioTech = RadioTech::RADIO_TECHNOLOGY_GSM;
    ModemPowerState radioState = ModemPowerState::CORE_SERVICE_POWER_ON;
    auto telRilManager = std::make_shared<TelRilManager>();
    auto simManager = std::make_shared<SimManager>(telRilManager);
    auto networkSearchManager = std::make_shared<NetworkSearchManager>(telRilManager, simManager);
    auto radioInfo = std::make_shared<RadioInfo>(networkSearchManager, INVALID_SLOTID);
    AppExecFwk::InnerEvent::Pointer event = AppExecFwk::InnerEvent::Get(RadioEvent::RADIO_SIM_STATE_CHANGE, 1);
 
    auto radioResponseInfo = std::make_shared<RadioResponseInfo>();
    radioResponseInfo->error = ErrType::ERR_REPEAT_STATUS;
    event = AppExecFwk::InnerEvent::Get(RadioEvent::RADIO_SIM_STATE_CHANGE, radioResponseInfo);
    radioInfo->ProcessGetRadioState(event);
    radioInfo->ProcessSetRadioState(event);
 
    auto radioStateInfo = std::make_unique<RadioStateInfo>();
    event = AppExecFwk::InnerEvent::Get(RadioEvent::RADIO_SIM_STATE_CHANGE, radioStateInfo);
 
    radioInfo->networkSearchManager_ = networkSearchManager;
    radioInfo->ProcessGetRadioState(event);
 
    radioInfo->networkSearchManager_.reset();
    radioInfo->AirplaneModeChange();
    radioInfo->ProcessGetRadioState(event);
    radioInfo->ProcessSetRadioState(event);
    radioInfo->UpdatePhone(csRadioTech, csRadioTech);
    radioInfo->RadioFirstPowerOn(networkSearchManager, radioState);
    EXPECT_EQ(radioInfo->ProcessSetNrOptionMode(event), TELEPHONY_ERR_LOCAL_PTR_NULL);
}
 
HWTEST_F(NetworkSearchHandlerTest, Telephony_RadioInfo_RadioFirstPowerOnAndVoiceTechHandling,
    Function | MediumTest | Level1)
{
    auto telRilManager = std::make_shared<TelRilManager>();
    auto simManager = std::make_shared<SimManager>(telRilManager);
    auto networkSearchManager = std::make_shared<NetworkSearchManager>(telRilManager, simManager);
    auto radioInfo = std::make_shared<RadioInfo>(networkSearchManager, SLOT_ID_0);
    AppExecFwk::InnerEvent::Pointer event = AppExecFwk::InnerEvent::Get(RadioEvent::RADIO_SIM_STATE_CHANGE, 1);
 
    auto inner = std::make_shared<NetworkSearchManagerInner>();
    inner->isRadioFirstPowerOn_ = true;
    networkSearchManager->AddManagerInner(SLOT_ID_0, inner);
    radioInfo->slotId_ = INVALID_SLOTID;
    radioInfo->RadioFirstPowerOn(networkSearchManager,  ModemPowerState::CORE_SERVICE_POWER_ON);
 
    radioInfo->slotId_ = SLOT_ID_0;
    radioInfo->RadioFirstPowerOn(networkSearchManager,  ModemPowerState::CORE_SERVICE_POWER_ON);
 
    auto radioTech = std::make_shared<VoiceRadioTechnology>();
    event = AppExecFwk::InnerEvent::Get(RadioEvent::RADIO_SIM_STATE_CHANGE, radioTech);
    radioInfo->networkSearchManager_.reset();
    radioInfo->ProcessVoiceTechChange(event);
 
    radioInfo->networkSearchManager_ = networkSearchManager;
    radioInfo->ProcessVoiceTechChange(event);
 
    auto strParcel = std::make_shared<StringParcel>("abc");
    event = AppExecFwk::InnerEvent::Get(RadioEvent::RADIO_SIM_STATE_CHANGE, strParcel);
    radioInfo->ProcessGetImei(event);
    radioInfo->ProcessGetImeiSv(event);
    EXPECT_EQ(radioInfo->ProcessGetBasebandVersion(event), TELEPHONY_ERR_SUCCESS);
}
 
HWTEST_F(NetworkSearchHandlerTest, Telephony_RadioInfo_RadioStateUpdateAndNrOptionHandling,
    Function | MediumTest | Level1)
{
    int64_t index = 0;
    bool state = true;
    MessageParcel data;
    data.WriteBool(state);
    data.WriteInt32(TELEPHONY_SUCCESS);
    auto object = std::make_unique<RadioStateInfo>();
    ModemPowerState radioState = ModemPowerState::CORE_SERVICE_POWER_ON;
    sptr<INetworkSearchCallback> callback = new INetworkSearchCallbackStub();
    auto networkUtils = std::make_shared<NetworkUtils>();
    auto telRilManager = std::make_shared<TelRilManager>();
    auto simManager = std::make_shared<SimManager>(telRilManager);
    auto networkSearchManager = std::make_shared<NetworkSearchManager>(telRilManager, simManager);
    auto radioInfo = std::make_shared<RadioInfo>(networkSearchManager, SLOT_ID_0);
    AppExecFwk::InnerEvent::Pointer event = AppExecFwk::InnerEvent::Get(RadioEvent::RADIO_SIM_STATE_CHANGE, 1);
 
    radioInfo->networkSearchManager_ = networkSearchManager;
 
    auto callbackInfo = std::make_shared<NetworkSearchCallbackInfo>(SLOT_ID_0, callback);
    callbackInfo->networkSearchItem_ = callback;
    networkUtils->AddNetworkSearchCallBack(index, callbackInfo);
    radioInfo->UpdateInfoOfSetRadioState(radioState, true, data, index);
    radioInfo->UpdateInfoOfSetRadioState(radioState, false, data, index);
 
    object->flag = 0;
    EXPECT_TRUE(radioInfo->WriteRadioStateObject(index, data, state, object));
 
    auto radioResponseInfo = std::make_shared<RadioResponseInfo>();
    radioResponseInfo->error = ErrType::ERR_REPEAT_STATUS;
    event = AppExecFwk::InnerEvent::Get(RadioEvent::RADIO_SIM_STATE_CHANGE, radioResponseInfo);
    EXPECT_EQ(radioInfo->ProcessSetNrOptionMode(event), TELEPHONY_ERR_LOCAL_PTR_NULL);
}
 
HWTEST_F(NetworkSearchHandlerTest, Telephony_RadioInfo_RrcConnectionStateAndNrOptionHandling,
    Function | MediumTest | Level1)
{
    int64_t index = 0;
    auto object  = std::make_shared<Int32Parcel>();
    auto inner = std::make_shared<NetworkSearchManagerInner>();
    auto networkUtils = std::make_shared<NetworkUtils>();
    auto telRilManager = std::make_shared<TelRilManager>();
    auto simManager = std::make_shared<SimManager>(telRilManager);
    auto networkSearchManager = std::make_shared<NetworkSearchManager>(telRilManager, simManager);
    auto radioInfo = std::make_shared<RadioInfo>(networkSearchManager, SLOT_ID_0);
 
    object->data = SLOT_ID_0;
    inner->rrcConnectionStatus_ = SLOT_ID_0;
    networkSearchManager->AddManagerInner(SLOT_ID_0, inner);
    radioInfo->networkSearchManager_ = networkSearchManager;
    auto event = AppExecFwk::InnerEvent::Get(RadioEvent::RADIO_SIM_STATE_CHANGE, object);
    EXPECT_EQ(radioInfo->ProcessGetRrcConnectionState(event),TELEPHONY_ERR_FAIL);
 
    auto nrModeInfo = std::make_shared<NrModeInfo>();
    auto responseInfo = std::make_shared<RadioResponseInfo>();
    event = AppExecFwk::InnerEvent::Get(RadioEvent::RADIO_SIM_STATE_CHANGE, nrModeInfo);
    event = AppExecFwk::InnerEvent::Get(RadioEvent::RADIO_SIM_STATE_CHANGE, responseInfo);
    sptr<INetworkSearchCallback> callback = new INetworkSearchCallbackStub();
    auto callbackInfo = std::make_shared<NetworkSearchCallbackInfo>(SLOT_ID_0, callback);
 
    responseInfo->flag = index;
    callbackInfo->networkSearchItem_ = callback;
    networkUtils->AddNetworkSearchCallBack(index, callbackInfo);
    EXPECT_EQ(radioInfo->ProcessGetNrOptionMode(event), TELEPHONY_ERR_SUCCESS);
}
 
HWTEST_F(NetworkSearchHandlerTest, Telephony_NetworkUtils_StringSplitAndCallbackAdd_Boundary,
    Function | MediumTest | Level1)
{
    int64_t index = 0;
    std::string inputString = "";
    std::vector<std::string> result;
    sptr<INetworkSearchCallback> callback = nullptr;
    auto networkUtils = std::make_shared<NetworkUtils>();
 
    EXPECT_EQ(networkUtils->SplitString(inputString, inputString), result);
 
    std::shared_ptr<NetworkSearchCallbackInfo> networkSearchCallback = nullptr;
    EXPECT_EQ(networkUtils->AddNetworkSearchCallBack(index, networkSearchCallback), false);
}
 
HWTEST_F(NetworkSearchHandlerTest, Telephony_NetworkType_PreferredNetworkAndSearchHandling,
    Function | MediumTest | Level1)
{
    int64_t index = -1;
    auto networkUtils = std::make_shared<NetworkUtils>();
    auto telRilManager = std::make_shared<TelRilManager>();
    auto simManager = std::make_shared<SimManager>(telRilManager);
    auto networkSearchManager = std::make_shared<NetworkSearchManager>(telRilManager, simManager);
    auto radioInfo = std::make_shared<RadioInfo>(networkSearchManager, SLOT_ID_0);
    auto networkType = std::make_unique<NetworkType>(networkSearchManager, INVALID_SLOTID);
    auto networkSelection = std::make_unique<NetworkSelection>(networkSearchManager, SLOT_ID_0);
 
    auto responseInfo = std::make_shared<RadioResponseInfo>();
    responseInfo->flag = index;
    responseInfo->error = ErrType::NONE;
    auto event = AppExecFwk::InnerEvent::Get(RadioEvent::RADIO_SIM_STATE_CHANGE, responseInfo);
 
    networkType->networkSearchManager_.reset();
    networkType->ProcessGetPreferredNetwork(event);
 
    networkType->networkSearchManager_ = networkSearchManager;
    networkType->ProcessGetPreferredNetwork(event);
 
    sptr<INetworkSearchCallback> callback = new INetworkSearchCallbackStub();
    auto callbackInfo = std::make_shared<NetworkSearchCallbackInfo>(SLOT_ID_0, callback);
 
    callbackInfo->networkSearchItem_ = callback;
    networkUtils->AddNetworkSearchCallBack(index, callbackInfo);
    networkType->ProcessGetPreferredNetwork(event);
    networkType->ProcessSetPreferredNetwork(event);
    networkSelection->ProcessNetworkSearchResult(event);
    networkSelection->ProcessGetNetworkSelectionMode(event);
    networkSelection->ProcessSetNetworkSelectionMode(event);
    EXPECT_NE(radioInfo->ProcessSetNrOptionMode(event), TELEPHONY_ERR_SUCCESS);
}
 
HWTEST_F(NetworkSearchHandlerTest, Telephony_NitzUpdate_NitzProcessingAndTimeZoneSave, Function | MediumTest | Level1)
{
    Uri uri(SimRdbInfo::SIM_RDB_SELECTION);
    std::string timeZone = "";
    auto settingUtils = SettingUtils::GetInstance();
    auto telRilManager = std::make_shared<TelRilManager>();
    auto simManager = std::make_shared<SimManager>(telRilManager);
    auto networkSearchManager = std::make_shared<NetworkSearchManager>(telRilManager, simManager);
    auto nitzUpdate = std::make_unique<NitzUpdate>(networkSearchManager, SLOT_ID_0);
 
    auto str = std::make_shared<std::string>(timeZone);
    auto event = AppExecFwk::InnerEvent::Get(RadioEvent::RADIO_SIM_STATE_CHANGE, str);
    nitzUpdate->ProcessNitzUpdate(event);
 
    timeZone = "abc";
    str = std::make_shared<std::string>("timeZone");
    event = AppExecFwk::InnerEvent::Get(RadioEvent::RADIO_SIM_STATE_CHANGE, str);
    nitzUpdate->ProcessNitzUpdate(event);
    nitzUpdate->SaveTimeZone(timeZone);
 
    settingUtils->Insert(uri, timeZone, timeZone);
    EXPECT_NE(nitzUpdate->IsAutoTimeZone(), true);
}
 
HWTEST_F(NetworkSearchHandlerTest, Telephony_NetworkSelection_NetworkSearchResultAndResponseHandling,
    Function | MediumTest | Level1)
{
    int64_t index = 0;
    auto telRilManager = std::make_shared<TelRilManager>();
    auto simManager = std::make_shared<SimManager>(telRilManager);
    auto networkSearchManager = std::make_shared<NetworkSearchManager>(telRilManager, simManager);
    auto networkSelection = std::make_unique<NetworkSelection>(networkSearchManager, SLOT_ID_0);
 
    auto availNetworkResult = std::make_shared<AvailableNetworkList>();
    auto event = AppExecFwk::InnerEvent::Get(RadioEvent::RADIO_SIM_STATE_CHANGE, availNetworkResult);
    networkSelection->networkSearchManager_.reset();
    networkSelection->ProcessNetworkSearchResult(event);
 
    MessageParcel data;
    data.WriteInt32(TELEPHONY_SUCCESS);
    networkSelection->networkSearchManager_ = networkSearchManager;
    networkSelection->ProcessNetworkSearchResult(event);
    EXPECT_EQ(networkSelection->AvailNetworkResult(availNetworkResult, data, index), true);
 
    auto responseInfo = std::make_shared<RadioResponseInfo>();
    responseInfo->error = ErrType::NONE;
    EXPECT_TRUE(networkSelection->ResponseInfoOfGet(responseInfo, data, index));
    EXPECT_TRUE(networkSelection->ResponseInfoOfResult(responseInfo, data, index));
 
    std::shared_ptr<SetNetworkModeInfo> selectModeResult = nullptr;
    EXPECT_FALSE(networkSelection->SelectModeResult(selectModeResult, data, index));
}
} // namespace Telephony
} // namespace OHOS