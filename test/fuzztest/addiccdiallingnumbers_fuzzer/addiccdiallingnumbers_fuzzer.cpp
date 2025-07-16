/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "addiccdiallingnumbers_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <thread>

#define private public
#include "addcoreservicetoken_fuzzer.h"
#include "core_service.h"
#include "napi_util.h"
#include "system_ability_definition.h"
#include "tel_event_handler.h"
#include "unistd.h"
#include "tel_ril_manager.h"
#include "sim_state_type.h"
#include "sim_manager.h"
#include "operator_config_cache.h"
#include "voice_mail_constants.h"

using namespace OHOS::Telephony;
namespace OHOS {
static bool g_isInited = false;
constexpr int32_t SLOT_NUM = 2;
constexpr int32_t SIM_TYPE_NUM = 2;
constexpr int32_t SIZE_LIMIT = 4;
constexpr uint32_t FUCTION_SIZE = 100;
constexpr int32_t SIM_STATUS_NUM = 5;
constexpr int32_t ICC_STATUS_NUM = 12;
constexpr const char *DEFAULT_SLOT_COUNT = "1";

bool IsServiceInited()
{
    if (!g_isInited) {
        DelayedSingleton<CoreService>::GetInstance()->OnStart();
        if (DelayedSingleton<CoreService>::GetInstance()->GetServiceRunningState() ==
            static_cast<int32_t>(ServiceRunningState::STATE_RUNNING)) {
            g_isInited = true;
        }
    }
    return g_isInited;
}

void OnRemoteRequest(const uint8_t *data, size_t size)
{
    if (!IsServiceInited()) {
        return;
    }

    if (size < SIZE_LIMIT) {
        return;
    }

    MessageParcel dataMessageParcel;
    if (!dataMessageParcel.WriteInterfaceToken(CoreServiceStub::GetDescriptor())) {
        return;
    }
    dataMessageParcel.WriteBuffer(data, size);
    dataMessageParcel.RewindRead(0);

    uint32_t code = (static_cast<uint32_t>(data[0]) << 24) | (static_cast<uint32_t>(data[1]) << 16) |
                    (static_cast<uint32_t>(data[2]) << 8) | (static_cast<uint32_t>(data[3])) % FUCTION_SIZE;

    MessageParcel reply;
    MessageOption option;
    DelayedSingleton<CoreService>::GetInstance()->OnRemoteRequest(code, dataMessageParcel, reply, option);
}

void GetSimGid1(const uint8_t *data, size_t size)
{
    if (!IsServiceInited()) {
        return;
    }

    int32_t slotId = static_cast<int32_t>(*data % SLOT_NUM);
    MessageParcel dataMessageParcel;
    dataMessageParcel.WriteInt32(slotId);
    dataMessageParcel.WriteBuffer(data, size);
    dataMessageParcel.RewindRead(0);
    MessageParcel reply;
    DelayedSingleton<CoreService>::GetInstance()->OnGetSimGid1(dataMessageParcel, reply);
}

void GetSimGid2(const uint8_t *data, size_t size)
{
    if (!IsServiceInited()) {
        return;
    }

    int32_t slotId = static_cast<int32_t>(*data % SLOT_NUM);
    MessageParcel dataMessageParcel;
    dataMessageParcel.WriteInt32(slotId);
    dataMessageParcel.WriteBuffer(data, size);
    dataMessageParcel.RewindRead(0);
    MessageParcel reply;
    DelayedSingleton<CoreService>::GetInstance()->OnGetSimGid2(dataMessageParcel, reply);
}

void GetSimAccountInfo(const uint8_t *data, size_t size)
{
    if (!IsServiceInited()) {
        return;
    }

    int32_t slotId = static_cast<int32_t>(*data % SLOT_NUM);
    MessageParcel dataMessageParcel;
    dataMessageParcel.WriteInt32(slotId);
    dataMessageParcel.WriteBuffer(data, size);
    dataMessageParcel.RewindRead(0);
    MessageParcel reply;
    DelayedSingleton<CoreService>::GetInstance()->OnGetSimSubscriptionInfo(dataMessageParcel, reply);
}

void GetCardType(const uint8_t *data, size_t size)
{
    if (!IsServiceInited()) {
        return;
    }

    int32_t slotId = static_cast<int32_t>(*data % SLOT_NUM);
    MessageParcel dataMessageParcel;
    dataMessageParcel.WriteInt32(slotId);
    dataMessageParcel.WriteBuffer(data, size);
    dataMessageParcel.RewindRead(0);
    MessageParcel reply;
    DelayedSingleton<CoreService>::GetInstance()->OnGetCardType(dataMessageParcel, reply);
}

void GetSimState(const uint8_t *data, size_t size)
{
    if (!IsServiceInited()) {
        return;
    }

    int32_t slotId = static_cast<int32_t>(*data % SLOT_NUM);
    MessageParcel dataMessageParcel;
    dataMessageParcel.WriteInt32(slotId);
    dataMessageParcel.WriteBuffer(data, size);
    dataMessageParcel.RewindRead(0);
    MessageParcel reply;
    DelayedSingleton<CoreService>::GetInstance()->OnGetSimState(dataMessageParcel, reply);
}

void GetDsdsMode(const uint8_t *data, size_t size)
{
    if (!IsServiceInited()) {
        return;
    }

    int32_t dsdsMode = static_cast<int32_t>(*data);
    MessageParcel dataMessageParcel;
    dataMessageParcel.WriteInt32(dsdsMode);
    dataMessageParcel.WriteBuffer(data, size);
    dataMessageParcel.RewindRead(0);
    MessageParcel reply;
    DelayedSingleton<CoreService>::GetInstance()->OnGetDsdsMode(dataMessageParcel, reply);
}

void HasSimCard(const uint8_t *data, size_t size)
{
    if (!IsServiceInited()) {
        return;
    }

    int32_t slotId = static_cast<int32_t>(*data % SLOT_NUM);
    MessageParcel dataMessageParcel;
    dataMessageParcel.WriteInt32(slotId);
    dataMessageParcel.WriteBuffer(data, size);
    dataMessageParcel.RewindRead(0);
    MessageParcel reply;
    DelayedSingleton<CoreService>::GetInstance()->OnHasSimCard(dataMessageParcel, reply);
}

void AddIccDiallingNumbers(const uint8_t *data, size_t size)
{
    if (!IsServiceInited()) {
        return;
    }

    int32_t slotId = static_cast<int32_t>(*data % SLOT_NUM);
    int32_t type = *data % SIM_TYPE_NUM + 1; // SIM_ADN 1  SIM_FDN 2
    MessageParcel dataMessageParcel;
    dataMessageParcel.WriteInt32(slotId);
    dataMessageParcel.WriteInt32(type);
    dataMessageParcel.WriteBuffer(data, size);
    dataMessageParcel.RewindRead(0);
    MessageParcel reply;
    DelayedSingleton<CoreService>::GetInstance()->OnAddIccDiallingNumbers(dataMessageParcel, reply);
}

void IsCTSimCard(const uint8_t *data, size_t size)
{
    if (!IsServiceInited()) {
        return;
    }

    int32_t slotId = static_cast<int32_t>(*data % SLOT_NUM);
    MessageParcel dataMessageParcel;
    dataMessageParcel.WriteInt32(slotId);
    dataMessageParcel.WriteBuffer(data, size);
    dataMessageParcel.RewindRead(0);
    MessageParcel reply;
    DelayedSingleton<CoreService>::GetInstance()->OnIsCTSimCard(dataMessageParcel, reply);
}

static int32_t GetInt(const uint8_t *data, size_t size, int index = 0)
{
    size_t typeSize = sizeof(int32_t);
    uintptr_t align = reinterpret_cast<uintptr_t>(data) % typeSize;
    const uint8_t *base = data + (align > 0 ? typeSize - align : 0);
    if (size - align < typeSize * index + (typeSize - align)) {
        return 0;
    }
    return *reinterpret_cast<const int32_t*>(base + index * typeSize);
}
 
void SimManagerFunc(const uint8_t *data, size_t size)
{
    int index = 0;
    auto telRilManager = std::make_shared<TelRilManager>();
    auto simManager = std::make_shared<SimManager>(telRilManager);
    std::vector<std::shared_ptr<Telephony::SimStateManager>> simStateManager = { nullptr, nullptr };
    std::vector<std::shared_ptr<Telephony::SimFileManager>> simFileManager = { nullptr, nullptr };
    simManager->multiSimController_ =std::make_shared<MultiSimController>(
        telRilManager, simStateManager, simFileManager);
    int32_t slotId = static_cast<int32_t>(*data % SLOT_NUM);
    int32_t slotCount = GetInt(data, size, index++);
    int32_t voiceMailCount = GetInt(data, size, index++);
    bool hasOperatorPrivileges = true;
    simManager->OnInit(slotCount);
    simManager->InitTelExtraModule(slotId);
    simManager->SetDefaultVoiceSlotId(slotId);
    simManager->SetDefaultSmsSlotId(slotId);
    simManager->SetDefaultCellularDataSlotId(slotId);
    simManager->SetPrimarySlotId(slotId, true);
    simManager->GetDefaultVoiceSimId(slotId);
    simManager->GetDefaultSmsSlotId();
    simManager->GetDefaultSmsSimId(slotId);
    simManager->GetDefaultCellularDataSlotId();
    simManager->GetDefaultCellularDataSimId(slotId);
    simManager->UpdateOperatorConfigs(slotId);
    simManager->HasOperatorPrivileges(slotId, hasOperatorPrivileges);
    simManager->ResetSimLoadAccount(slotId);
    simManager->InsertEsimData(std::string(reinterpret_cast<const char *>(data), size), voiceMailCount,
        std::string(reinterpret_cast<const char *>(data), size));
    simManager->SetSimLabelIndex(std::string(reinterpret_cast<const char *>(data), size), voiceMailCount);
    simManager->SaveImsSwitch(slotId, voiceMailCount);
    simManager->QueryImsSwitch(slotId, voiceMailCount);
    simManager->IsSetPrimarySlotIdInProgress();
    simManager->SavePrimarySlotId(slotId);
    simManager->IsDataShareError();
    simManager->ResetDataShareError();
    simManager->GetPrimarySlotId(slotId);
}

void SimManagerFuncTwo(const uint8_t *data, size_t size)
{
    int index = 0;
    auto telRilManager = std::make_shared<TelRilManager>();
    auto simManager = std::make_shared<SimManager>(telRilManager);
    int32_t slotId = static_cast<int32_t>(*data % SLOT_NUM);
    int32_t voiceMailCount = GetInt(data, size, index++);
    simManager->multiSimController_ = nullptr;
    simManager->SetDefaultVoiceSlotId(slotId);
    simManager->SetDefaultSmsSlotId(slotId);
    simManager->SetDefaultCellularDataSlotId(slotId);
    simManager->SetPrimarySlotId(slotId, true);
    simManager->GetDefaultVoiceSimId(slotId);
    simManager->GetDefaultSmsSlotId();
    simManager->GetDefaultSmsSimId(slotId);
    simManager->GetDefaultCellularDataSlotId();
    simManager->GetDefaultCellularDataSimId(slotId);
    simManager->GetPrimarySlotId(slotId);
    simManager->InsertEsimData(std::string(reinterpret_cast<const char *>(data), size), voiceMailCount,
        std::string(reinterpret_cast<const char *>(data), size));
    simManager->SetSimLabelIndex(std::string(reinterpret_cast<const char *>(data), size), voiceMailCount);
    simManager->slotCount_ = std::atoi(DEFAULT_SLOT_COUNT);
    simManager->GetDefaultSmsSlotId();
    simManager->GetDefaultCellularDataSlotId();
    simManager->GetPrimarySlotId(slotId);
}

void SimManagerFuncThree(const uint8_t *data, size_t size)
{
    int index = 0;
    auto telRilManager = std::make_shared<TelRilManager>();
    auto simManager = std::make_shared<SimManager>(telRilManager);
    int32_t slotId = static_cast<int32_t>(*data % SLOT_NUM);
    int32_t slotCount = GetInt(data, size, index++);
    int32_t voiceMailCount = GetInt(data, size, index++);
    int32_t simState = *data % SIM_STATUS_NUM + 1;
    int32_t iccStatus = *data % ICC_STATUS_NUM + 1;
    SimState simEnum = static_cast<SimState>(simState);
    IccSimStatus iccEnum = static_cast<IccSimStatus>(iccStatus);
    bool hasOperatorPrivileges = true;
    simManager->GetSimState(slotId, simEnum);
    simManager->GetSimIccStatus(slotId, iccEnum);
    simManager->SetModemInit(slotId, true);
    simManager->RefreshSimState(slotId);
    simManager->SendSimMatchedOperatorInfo(slotId, simState, std::string(reinterpret_cast<const char *>(data), size),
        std::string(reinterpret_cast<const char *>(data), size));
    simManager->SetVoiceMailCount(slotId, voiceMailCount);
    simManager->GetVoiceMailCount(slotId, voiceMailCount);
    simManager->ObtainSpnCondition(
        slotId, hasOperatorPrivileges, std::string(reinterpret_cast<const char *>(data), size));
    std::string pdu(reinterpret_cast<const char*>(data), size);
    std::string smsc(reinterpret_cast<const char*>(data), size);
    simManager->AddSmsToIcc(slotId, static_cast<int32_t>(simState), pdu, smsc);
    simManager->IsCTSimCard(slotId, hasOperatorPrivileges);
    simManager->IsValidSlotIdForDefault(slotId);
    simManager->GetSimIst(slotId);
    simManager->NotifySimSlotsMapping(slotId);
}
 
void OperatorConfigCacheFunc(const uint8_t *data, size_t size)
{
    int index = 0;
    auto telRilManager = std::make_shared<TelRilManager>();
    auto simStateManager = std::make_shared<SimStateManager>(telRilManager);
    EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent(CommonEventSupport::COMMON_EVENT_OPERATOR_CONFIG_CHANGED);
    EventFwk::CommonEventSubscribeInfo subcribeInfo(matchingSkills);
    auto simFileManager = std::make_shared<SimFileManager>(subcribeInfo, telRilManager, simStateManager);
    auto operatorConfigCache = std::make_shared<OperatorConfigCache>(simFileManager, simStateManager, 0);
    int32_t slotId = static_cast<int32_t>(*data % SLOT_NUM);
    int32_t simState = *data % SIM_STATUS_NUM + 1;
    SimState simEnum = static_cast<SimState>(simState);
    operatorConfigCache->UpdateIccidCache(simState);
    operatorConfigCache->GetSimState(slotId, simEnum);
    operatorConfigCache->IsNeedOperatorLoad(slotId);
    operatorConfigCache->AnnounceOperatorConfigChanged(slotId, simState);
    operatorConfigCache->notifyInitApnConfigs(slotId);
    operatorConfigCache->SendSimMatchedOperatorInfo(slotId, simState);
    operatorConfigCache->UnRegisterForIccChange();
    operatorConfigCache->UpdateOperatorConfigs(slotId);
    operatorConfigCache->ClearOperatorValue(slotId);
    operatorConfigCache->ClearMemoryAndOpkey(slotId);
    operatorConfigCache->ClearAllCache(slotId);
    operatorConfigCache->simStateManager_ = nullptr;
    operatorConfigCache->GetSimState(slotId, simEnum);
    slotId = GetInt(data, size, index++);
    operatorConfigCache->GetSimState(slotId, simEnum);
}

void VoiceMailConstantseFunc(const uint8_t *data, size_t size)
{
    int index = 0;
    int32_t slotId = static_cast<int32_t>(*data % SLOT_NUM);
    auto voiceMailConstants = std::make_shared<VoiceMailConstants>(slotId);
    int32_t simState = *data % SIM_STATUS_NUM + 1;
    std::string key(reinterpret_cast<const char *>(data), size);
    voiceMailConstants->GetStringValueFromCust(slotId, key);
    voiceMailConstants->ResetVoiceMailLoadedFlag();
    voiceMailConstants->GetVoiceMailFixed(key);
    voiceMailConstants->GetVoiceMailNumber(key);
    voiceMailConstants->GetVoiceMailTag(key);
    voiceMailConstants->LoadVoiceMailConfigFromCard(key, key);
    voiceMailConstants->ContainsCarrier(key);
}
 
void SimManagerFuncFour(const uint8_t *data, size_t size)
{
    int index = 0;
    auto telRilManager = std::make_shared<TelRilManager>();
    auto simManager = std::make_shared<SimManager>(telRilManager);
    std::vector<std::shared_ptr<Telephony::SimStateManager>> simStateManager = { nullptr, nullptr };
    std::vector<std::shared_ptr<Telephony::SimFileManager>> simFileManager = { nullptr, nullptr };
    simManager->multiSimController_ =std::make_shared<MultiSimController>(
        telRilManager, simStateManager, simFileManager);
    int32_t slotId = static_cast<int32_t>(*data % SLOT_NUM);
    int32_t enable = GetInt(data, size, index++);
    std::string pin(reinterpret_cast<const char *>(data), size);
    std::string puk(reinterpret_cast<const char *>(data), size);
    std::u16string number(reinterpret_cast<const char16_t *>(data), size);
    LockStatusResponse lockResponse;
    int32_t lockType = *data % LOCK_TYPE_NUM + 1;
    LockType lockEnum = static_cast<LockType>(lockType);
    int32_t lockState = *data % LOCK_STATE_NUM + 1;
    LockState lockStateEnum = static_cast<LockState>(lockState);
    PersoLockInfo lockInfo;
    SimAuthenticationResponse simResponse;
    simManager->UnlockPin(slotId, pin, lockResponse);
    simManager->UnlockPuk(slotId, pin, puk, lockResponse);
    simManager->AlterPin(slotId, pin, puk, lockResponse);
    simManager->UnlockPin2(slotId, pin, lockResponse);
    simManager->UnlockPuk2(slotId, pin, puk, lockResponse);
    simManager->AlterPin2(slotId, pin, puk, lockResponse);
    simManager->GetLockState(slotId, lockEnum, lockStateEnum);
    simManager->UnlockSimLock(slotId, lockInfo, lockResponse);
    simManager->SetActiveSim(slotId, enable);
    simManager->SetActiveSimSatellite(slotId, enable);
    simManager->SetShowNumber(slotId, number);
    simManager->SetShowName(slotId, number);
    simManager->GetShowNumber(slotId, number);
    simManager->GetShowName(slotId, number);
    simManager->GetDsdsMode(enable);
    simManager->SetDsdsMode(enable);
    simManager->SendEnvelopeCmd(slotId, pin);
    simManager->SendTerminalResponseCmd(slotId, pin);
    simManager->SendCallSetupRequestResult(slotId, true);
    simManager->GetSimIccId(slotId, number);
}

void SimManagerFuncFive(const uint8_t *data, size_t size)
{
    int index = 0;
    auto telRilManager = std::make_shared<TelRilManager>();
    auto simManager = std::make_shared<SimManager>(telRilManager);
    std::vector<std::shared_ptr<Telephony::SimStateManager>> simStateManager = { nullptr, nullptr };
    std::vector<std::shared_ptr<Telephony::SimFileManager>> simFileManager = { nullptr, nullptr };
    simManager->multiSimController_ =std::make_shared<MultiSimController>(
        telRilManager, simStateManager, simFileManager);
    int32_t slotId = static_cast<int32_t>(*data % SLOT_NUM);
    int32_t enable = GetInt(data, size, index++);
    int32_t simState = *data % SIM_STATUS_NUM + 1;
    std::string pin(reinterpret_cast<const char *>(data), size);
    std::u16string number(reinterpret_cast<const char16_t *>(data), size);
    simManager->GetIMSI(slotId, number);
    simManager->GetLocaleFromDefaultSim(slotId);
    simManager->GetSimGid1(slotId, number);
    simManager->GetSimGid1(slotId, number);
    simManager->GetSimTelephoneNumber(slotId, number);
    simManager->GetSimTeleNumberIdentifier(slotId);
    simManager->GetVoiceMailIdentifier(slotId, number);
    simManager->GetVoiceMailNumber(slotId, number);
    simManager->SetVoiceCallForwarding(slotId, true, pin);
    simManager->SetVoiceMailInfo(slotId, number, number);
    simManager->UpdateSmsIcc(slotId, static_cast<int>(enable), static_cast<int>(simState), pin, pin);
    simManager->DelSmsIcc(slotId, static_cast<int>(enable));
    simManager->ObtainAllSmsOfIcc(slotId);
    simManager->GetDefaultMainSlotByIccId();
    simManager->multiSimController_ = nullptr;
    simManager->SetActiveSim(slotId, enable);
    simManager->SetActiveSimSatellite(slotId, enable);
    simManager->SetShowNumber(slotId, number);
    simManager->SetShowName(slotId, number);
    simManager->GetShowNumber(slotId, number);
    simManager->GetShowName(slotId, number);
    simManager->GetSimTelephoneNumber(slotId, number);
    simManager->GetDefaultMainSlotByIccId();
    simManager->IsDataShareError();
    simManager->ResetDataShareError();
    simManager->slotCount_ = std::atoi(DEFAULT_SLOT_COUNT);
    simManager->GetDsdsMode(enable);
}

void DoSomethingInterestingWithMyAPI(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }

    OnRemoteRequest(data, size);
    GetSimGid1(data, size);
    GetSimGid2(data, size);
    GetSimAccountInfo(data, size);
    GetCardType(data, size);
    GetSimState(data, size);
    GetDsdsMode(data, size);
    HasSimCard(data, size);
    AddIccDiallingNumbers(data, size);
    IsCTSimCard(data, size);
    SimManagerFunc(data, size);
    SimManagerFuncTwo(data, size);
    SimManagerFuncThree(data, size);
    OperatorConfigCacheFunc(data, size);
    VoiceMailConstantseFunc(data, size);
    SimManagerFuncFour(data, size);
    SimManagerFuncFive(data, size);
    auto telRilManager = std::static_pointer_cast<TelRilManager>(
        DelayedSingleton<CoreService>::GetInstance()->telRilManager_);
    if (telRilManager == nullptr || telRilManager->handler_ == nullptr) {
        return;
    }
    telRilManager->handler_->ClearFfrt(false);
    telRilManager->handler_->queue_ = nullptr;
    return;
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    OHOS::AddCoreServiceTokenFuzzer token;
    return 0;
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::DoSomethingInterestingWithMyAPI(data, size);
    OHOS::DelayedSingleton<CoreService>::DestroyInstance();
    return 0;
}
