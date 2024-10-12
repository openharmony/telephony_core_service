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

#include "sim_file_manager.h"

#include <openssl/sha.h>
#include "core_manager_inner.h"
#include "network_state.h"
#include "parameters.h"
#include "radio_event.h"
#include "system_ability_definition.h"
#include "telephony_ext_wrapper.h"

namespace OHOS {
namespace Telephony {
static constexpr int32_t VM_NUMBER_LEN = 256;
constexpr const char *VM_NUMBER_SIM_IMSI_KEY = "persist.telephony.voicemail.simimsi";
const std::vector<std::string> CT_CPLMNS = { "46003", "46005", "46011", "46012", "47008", "45502", "45507", "46050",
    "46051", "46059" };
const std::vector<std::string> CT_ICCID_ARRAY = { "898603", "898606", "898611", "8985302", "8985307" };
constexpr int32_t ICCID_LEN_MINIMUM = 7;
constexpr int32_t ICCID_LEN_SIX = 6;
constexpr int32_t PREFIX_LOCAL_ICCID_LEN = 4;
constexpr const char *GC_ICCID = "8985231";
constexpr const char *PREFIX_LOCAL_ICCID = "8986";
constexpr const char *ROAMING_CPLMN = "20404";

SimFileManager::SimFileManager(
    const EventFwk::CommonEventSubscribeInfo &sp, std::weak_ptr<ITelRilManager> telRilManager,
    std::weak_ptr<Telephony::SimStateManager> state)
    : TelEventHandler("SimFileManager"), CommonEventSubscriber(sp), telRilManager_(telRilManager),
    simStateManager_(state)
{
    if (simStateManager_.lock() == nullptr) {
        TELEPHONY_LOGE("SimFileManager set NULL simStateManager.");
        return;
    }
    TELEPHONY_LOGI("SIM manager SimFileManager::SimFileManager started ");
}

SimFileManager::~SimFileManager()
{
    if (simFile_ != nullptr) {
        simFile_->UnInit();
    }
}

void SimFileManager::OnReceiveEvent(const EventFwk::CommonEventData &data)
{
    const AAFwk::Want &want = data.GetWant();
    std::string action = want.GetAction();
    int32_t slotId = want.GetIntParam("slotId", 0);
    TELEPHONY_LOGI("[slot%{public}d] action=%{public}s code=%{public}d", slotId, action.c_str(), data.GetCode());
    if (EventFwk::CommonEventSupport::COMMON_EVENT_OPERATOR_CONFIG_CHANGED == action) {
        if (slotId_ != slotId || simFile_ == nullptr) {
            return;
        }
        TELEPHONY_LOGI("SimFileManager::OnReceiveEvent");
        simFile_->LoadVoiceMail();
    }
}

void SimFileManager::Init(int slotId)
{
    TELEPHONY_LOGI("SimFileManager::Init() started slot %{public}d", slotId);
    slotId_ = slotId;
    if (stateRecord_ == HandleRunningState::STATE_RUNNING) {
        TELEPHONY_LOGI("SimFileManager::Init stateRecord_ started.");
        return;
    }
    if (stateHandler_ == HandleRunningState::STATE_RUNNING) {
        TELEPHONY_LOGI("SimFileManager::Init stateHandler_ started.");
        return;
    }
    auto telRilManager = telRilManager_.lock();
    if (telRilManager == nullptr) {
        TELEPHONY_LOGE("SimFileManager get NULL ITelRilManager.");
        return;
    }
    auto simStateManager = simStateManager_.lock();
    if (simStateManager == nullptr) {
        TELEPHONY_LOGE("SimFileManager get NULL simStateManager.");
        return;
    }
    CardType cardType = simStateManager->GetCardType();
    TELEPHONY_LOGI("SimFileManager current card type is %{public}d", cardType);
    if ((cardType == static_cast<CardType>(0)) || (cardType == CardType::UNKNOWN_CARD)) {
        cardType = CardType::SINGLE_MODE_USIM_CARD; // default card
    }
    iccType_ = GetIccTypeByCardType(cardType);
    TELEPHONY_LOGI("SimFileManager current icc type is %{public}d", iccType_);
    if (!InitIccFileController(iccType_)) {
        TELEPHONY_LOGE("SimFileManager::InitIccFileController fail");
        return;
    }
    if (!InitDiallingNumberHandler()) {
        TELEPHONY_LOGE("SimFileManager::InitDiallingNumberHandler fail");
        return;
    }
    if (!InitSimFile(iccType_)) {
        TELEPHONY_LOGE("SimFileManager::InitSimFile fail");
        return;
    }
    stateRecord_ = HandleRunningState::STATE_RUNNING;
    stateHandler_ = HandleRunningState::STATE_RUNNING;

    simStateManager->RegisterCoreNotify(shared_from_this(), RadioEvent::RADIO_CARD_TYPE_CHANGE);
    simStateManager->RegisterCoreNotify(shared_from_this(), RadioEvent::RADIO_SIM_ICCID_LOADED);
    telRilManager->RegisterCoreNotify(slotId, shared_from_this(), RadioEvent::RADIO_VOICE_TECH_CHANGED, nullptr);
    telRilManager->RegisterCoreNotify(slotId, shared_from_this(), RadioEvent::RADIO_ICC_REFRESH, nullptr);
    TELEPHONY_LOGI("SimFileManager::Init() end");
}

bool SimFileManager::InitSimFile(SimFileManager::IccType type)
{
    if (fileController_ == nullptr || diallingNumberHandler_ == nullptr) {
        TELEPHONY_LOGE("InitSimFile need more helper");
        return false;
    }
    auto iccFileIt = iccFileCache_.find(type);
    if (iccFileIt == iccFileCache_.end()) {
        if (type == SimFileManager::IccType::ICC_TYPE_CDMA) {
            simFile_ = std::make_shared<RuimFile>(simStateManager_.lock());
            iccFileCache_.insert(std::make_pair(SimFileManager::IccType::ICC_TYPE_CDMA, simFile_));
        } else if (type == SimFileManager::IccType::ICC_TYPE_IMS) {
            simFile_ = std::make_shared<IsimFile>(simStateManager_.lock());
            iccFileCache_.insert(std::make_pair(SimFileManager::IccType::ICC_TYPE_IMS, simFile_));
        } else {
            simFile_ = std::make_shared<SimFile>(simStateManager_.lock());
            iccFileCache_.insert(std::make_pair(SimFileManager::IccType::ICC_TYPE_USIM, simFile_));
            iccFileCache_.insert(std::make_pair(SimFileManager::IccType::ICC_TYPE_GSM, simFile_));
        }
        if (simFile_ != nullptr) {
#ifdef CORE_SERVICE_SUPPORT_ESIM
            eSimFile_ = std::make_shared<EsimFile>(simStateManager_.lock());
#endif
            simFile_->RegisterCoreNotify(shared_from_this(), RadioEvent::RADIO_SIM_RECORDS_LOADED);
        }
    } else {
        simFile_ = iccFileIt->second;
    }

    if (simFile_ == nullptr) {
        TELEPHONY_LOGE("SimFileManager::Init simFile create nullptr.");
        return false;
    }

#ifdef CORE_SERVICE_SUPPORT_ESIM
    eSimFile_->SetRilAndFileController(telRilManager_.lock(), fileController_, diallingNumberHandler_);
#endif
    simFile_->SetRilAndFileController(telRilManager_.lock(), fileController_, diallingNumberHandler_);
    simFile_->SetId(slotId_);
    simFile_->Init();
    if (TELEPHONY_EXT_WRAPPER.createIccFileExt_ != nullptr) {
        TELEPHONY_EXT_WRAPPER.createIccFileExt_(slotId_, simFile_);
    }
    return true;
}

bool SimFileManager::InitIccFileController(SimFileManager::IccType type)
{
    auto iccFileConIt = iccFileControllerCache_.find(type);
    if (iccFileConIt == iccFileControllerCache_.end()) {
        if (type == SimFileManager::IccType::ICC_TYPE_CDMA) { // ruim 30 usim 20 isim 60
            fileController_ = std::make_shared<RuimFileController>(slotId_);
        } else if (type == SimFileManager::IccType::ICC_TYPE_IMS) {
            fileController_ = std::make_shared<IsimFileController>(slotId_);
        } else if (type == SimFileManager::IccType::ICC_TYPE_GSM) {
            fileController_ = std::make_shared<SimFileController>(slotId_);
        } else {
            fileController_ = std::make_shared<UsimFileController>(slotId_);
        }
        iccFileControllerCache_.insert(std::make_pair(type, fileController_));
    } else {
        fileController_ = iccFileConIt->second;
    }
    if (fileController_ == nullptr) {
        TELEPHONY_LOGE("SimFileManager::Init fileController create nullptr.");
        return false;
    }
    fileController_->SetRilManager(telRilManager_.lock());
    return true;
}

std::u16string SimFileManager::GetSimOperatorNumeric()
{
    if (simFile_ == nullptr) {
        TELEPHONY_LOGE("SimFileManager::GetSimOperatorNumeric simFile nullptr");
        return Str8ToStr16("");
    }

    std::string result = simFile_->ObtainSimOperator();
    TELEPHONY_LOGD("SimFileManager::GetOperator result:%{public}s ", (result.empty() ? "false" : "true"));
    return Str8ToStr16(result);
}

std::u16string SimFileManager::GetMCC()
{
    if (simFile_ == nullptr) {
        TELEPHONY_LOGE("SimFileManager::GetMCC simFile nullptr");
        return Str8ToStr16("");
    }

    std::string result = simFile_->ObtainMCC();
    TELEPHONY_LOGD("SimFileManager::GetMCC result:%{public}s ", (result.empty() ? "false" : "true"));
    return Str8ToStr16(result);
}

std::u16string SimFileManager::GetMNC()
{
    if (simFile_ == nullptr) {
        TELEPHONY_LOGE("SimFileManager::GetMNC simFile nullptr");
        return Str8ToStr16("");
    }

    std::string result = simFile_->ObtainMNC();
    TELEPHONY_LOGD("SimFileManager::GetMNC result:%{public}s ", (result.empty() ? "false" : "true"));
    return Str8ToStr16(result);
}

std::u16string SimFileManager::GetISOCountryCodeForSim()
{
    if (simFile_ == nullptr) {
        TELEPHONY_LOGE("SimFileManager::GetISOCountryCodeForSim simFile nullptr");
        return Str8ToStr16("");
    }

    std::string result = simFile_->ObtainIsoCountryCode();
    TELEPHONY_LOGD("SimFileManager::ObtainIsoCountryCode result:%{public}s ", (result.empty() ? "false" : "true"));
    return Str8ToStr16(result);
}

std::u16string SimFileManager::GetSimSpn()
{
    if (simFile_ == nullptr) {
        TELEPHONY_LOGE("SimFileManager::GetSimSpn simFile nullptr");
        return Str8ToStr16("");
    }

    std::string result = simFile_->ObtainSPN();
    TELEPHONY_LOGD("SimFileManager::GetSimSpn result:%{public}s ", (result.empty() ? "false" : "true"));
    return Str8ToStr16(result);
}

std::u16string SimFileManager::GetSimEons(const std::string &plmn, int32_t lac, bool longNameRequired)
{
    if (simFile_ == nullptr) {
        TELEPHONY_LOGE("SimFileManager::GetEons simFile nullptr");
        return Str8ToStr16("");
    }

    std::string result = simFile_->ObtainEons(plmn, lac, longNameRequired);
    TELEPHONY_LOGD("SimFileManager::GetEons result:%{public}s ", (result.empty() ? "false" : "true"));
    return Str8ToStr16(result);
}

std::u16string SimFileManager::GetSimIccId()
{
    auto simStateManager = simStateManager_.lock();
    if (simStateManager == nullptr) {
        TELEPHONY_LOGE("simStateManager nullptr");
        return Str8ToStr16("");
    }
    std::string result = simStateManager->GetIccid();
    if (!result.empty()) {
        return Str8ToStr16(result);
    }
    if (simFile_ == nullptr) {
        TELEPHONY_LOGE("SimFileManager::GetSimIccId simFile nullptr");
        return Str8ToStr16("");
    }
    result = simFile_->ObtainIccId();
    TELEPHONY_LOGD("SimFileManager::GetSimIccId result:%{public}s ", (result.empty() ? "false" : "true"));
    return Str8ToStr16(result);
}

std::u16string SimFileManager::GetSimDecIccId()
{
    if (simFile_ == nullptr) {
        TELEPHONY_LOGE("simFile is nullptr!");
        return Str8ToStr16("");
    }

    std::string result = simFile_->ObtainDecIccId();
    TELEPHONY_LOGD("obtain dec iccId result:%{public}s ", (result.empty() ? "false" : "true"));
    return Str8ToStr16(result);
}

std::u16string SimFileManager::GetIMSI()
{
    if (simFile_ == nullptr) {
        TELEPHONY_LOGE("SimFileManager::GetIMSI simFile nullptr");
        return Str8ToStr16("");
    }

    std::string result = simFile_->ObtainIMSI();
    TELEPHONY_LOGD("SimFileManager::ObtainIMSI result:%{public}s ", (result.empty() ? "false" : "true"));
    return Str8ToStr16(result);
}

std::u16string SimFileManager::GetLocaleFromDefaultSim()
{
    if (simFile_ == nullptr) {
        TELEPHONY_LOGE("SimFileManager::GetLocaleFromDefaultSim simFile nullptr");
        return Str8ToStr16("");
    }

    std::string result = simFile_->ObtainIccLanguage();
    TELEPHONY_LOGD("SimFileManager::GetLocaleFromDefaultSim result:%{public}s ", (result.empty() ? "false" : "true"));
    return Str8ToStr16(result);
}

std::u16string SimFileManager::GetSimGid1()
{
    if (simFile_ == nullptr) {
        TELEPHONY_LOGE("SimFileManager::GetSimGid1 simFile nullptr");
        return Str8ToStr16("");
    }

    std::string result = simFile_->ObtainGid1();
    TELEPHONY_LOGI("SimFileManager::GetSimGid1 result:%{public}s ", (result.empty() ? "false" : "true"));
    return Str8ToStr16(result);
}

std::u16string SimFileManager::GetSimGid2()
{
    if (simFile_ == nullptr) {
        TELEPHONY_LOGE("SimFileManager::GetSimGid2 simFile nullptr");
        return Str8ToStr16("");
    }

    std::string result = simFile_->ObtainGid2();
    TELEPHONY_LOGI("SimFileManager::GetSimGid2 result:%{public}s ", (result.empty() ? "false" : "true"));
    return Str8ToStr16(result);
}

std::u16string SimFileManager::GetSimTelephoneNumber()
{
    std::string result = "";
    if (simFile_ != nullptr) {
        result = simFile_->ObtainMsisdnNumber();
    }
    TELEPHONY_LOGD("result is empty:%{public}s", (result.empty() ? "true" : "false"));
    return Str8ToStr16(result);
}

bool SimFileManager::SetSimTelephoneNumber(const std::u16string &alphaTag, const std::u16string &phoneNumber)
{
    if (simFile_ == nullptr) {
        TELEPHONY_LOGE("SimFileManager::SetSimTelephoneNumber simFile nullptr");
        return false;
    }
    std::string tag = Str16ToStr8(alphaTag);
    std::string number = Str16ToStr8(phoneNumber);
    return simFile_->UpdateMsisdnNumber(tag, number);
}

std::u16string SimFileManager::GetSimTeleNumberIdentifier()
{
    if (simFile_ == nullptr) {
        TELEPHONY_LOGE("SimFileManager::GetSimTeleNumberIdentifier simFile nullptr");
        return Str8ToStr16("");
    }

    std::string result = simFile_->ObtainMsisdnAlphaStatus();
    TELEPHONY_LOGI(
        "SimFileManager::GetSimTeleNumberIdentifier result:%{public}s ", (result.empty() ? "false" : "true"));
    return Str8ToStr16(result);
}

std::u16string SimFileManager::GetVoiceMailIdentifier()
{
    if (simFile_ == nullptr) {
        TELEPHONY_LOGE("SimFileManager::GetVoiceMailIdentifier simFile nullptr");
        return Str8ToStr16("");
    }

    std::string result = simFile_->ObtainVoiceMailInfo();
    TELEPHONY_LOGI(
        "SimFileManager::GetVoiceMailIdentifier result:%{public}s ", (result.empty() ? "false" : "true"));
    return Str8ToStr16(result);
}

bool SimFileManager::IsPhoneTypeGsm(int32_t slotId)
{
    PhoneType phoneType = CoreManagerInner::GetInstance().GetPhoneType(slotId);
    return phoneType == PhoneType::PHONE_TYPE_IS_GSM;
}

std::string SimFileManager::GetVoiceMailNumberCdmaKey()
{
    std::string key = "";
    char spNumber[VM_NUMBER_LEN] = {0};
    std::string spName = VM_NUMBER_CDMA_KEY;
    GetParameter(key.append(spName).append(std::to_string(slotId_)).c_str(), "", spNumber, VM_NUMBER_LEN);
    return spNumber;
}

std::string SimFileManager::GetVoiceMailNumberKey()
{
    std::string number = simFile_->GetVoiceMailNumber();
    if (!number.empty()) {
        return number;
    }
    if (TELEPHONY_EXT_WRAPPER.getVoiceMailIccidParameter_ != nullptr) {
        std::string iccid = simFile_->ObtainIccId();
        TELEPHONY_EXT_WRAPPER.getVoiceMailIccidParameter_(slotId_, iccid.c_str(), number);
        if (!number.empty()) {
            return number;
        }
    }
    std::string key = "";
    char spNumber[VM_NUMBER_LEN] = {0};
    std::string spName = VM_NUMBER_KEY;
    GetParameter(key.append(spName).append(std::to_string(slotId_)).c_str(), "", spNumber, VM_NUMBER_LEN);
    return spNumber;
}

std::string SimFileManager::GetVoiceMailNumberFromParam()
{
    std::string number = "";
    if (IsPhoneTypeGsm(slotId_)) {
        number = GetVoiceMailNumberKey();
    } else {
        number = GetVoiceMailNumberCdmaKey();
    }
    return number;
}

std::u16string SimFileManager::GetVoiceMailNumber()
{
    if (simFile_ == nullptr) {
        TELEPHONY_LOGE("SimFileManager::GetVoiceMailNumber simFile nullptr");
        return Str8ToStr16("");
    }

    std::string result = GetVoiceMailNumberFromParam();
    TELEPHONY_LOGI("SimFileManager::GetVoiceMailNumber result:%{public}s ", (result.empty() ? "false" : "true"));
    return Str8ToStr16(result);
}

int32_t SimFileManager::GetVoiceMailCount()
{
    if (simFile_ == nullptr) {
        TELEPHONY_LOGE("SimFileManager::GetVoiceMailCount simFile nullptr");
        return UNKNOWN_VOICE_MAIL_COUNT;
    }

    return simFile_->ObtainVoiceMailCount();
}

bool SimFileManager::SetVoiceMailCount(int32_t voiceMailCount)
{
    if (simFile_ == nullptr) {
        TELEPHONY_LOGE("SimFileManager::SetVoiceMailCount simFile nullptr");
        return false;
    }

    return simFile_->SetVoiceMailCount(voiceMailCount);
}

bool SimFileManager::SetVoiceCallForwarding(bool enable, const std::string &number)
{
    if (simFile_ == nullptr) {
        TELEPHONY_LOGE("SimFileManager::SetVoiceCallForwarding simFile nullptr");
        return false;
    }

    return simFile_->SetVoiceCallForwarding(enable, number);
}

std::u16string SimFileManager::GetOpName()
{
    return Str8ToStr16(opName_);
}

std::u16string SimFileManager::GetOpKey()
{
    return Str8ToStr16(opKey_);
}

std::u16string SimFileManager::GetOpKeyExt()
{
    return Str8ToStr16(opKeyExt_);
}

void SimFileManager::SetOpName(const std::string &opName)
{
    opName_ = opName;
}

void SimFileManager::SetOpKey(const std::string &opKey)
{
    opKey_ = opKey;
}

void SimFileManager::SetOpKeyExt(const std::string &opKeyExt)
{
    opKeyExt_ = opKeyExt;
}

int SimFileManager::ObtainSpnCondition(bool roaming, const std::string &operatorNum)
{
    if (simFile_ == nullptr) {
        TELEPHONY_LOGE("SimFileManager::ObtainSpnCondition simFile nullptr");
        return 0;
    }

    int result = simFile_->ObtainSpnCondition(roaming, operatorNum);
    TELEPHONY_LOGD("SimFileManager::ObtainSpnCondition:%{public}d", result);
    return result;
}

std::shared_ptr<IccFile> SimFileManager::GetIccFile()
{
    return simFile_;
}

std::shared_ptr<IccFileController> SimFileManager::GetIccFileController()
{
    return fileController_;
}

void SimFileManager::RegisterCoreNotify(const std::shared_ptr<AppExecFwk::EventHandler> &handler, int what)
{
    auto simStateManager = simStateManager_.lock();
    if (what == RadioEvent::RADIO_SIM_STATE_CHANGE && simStateManager != nullptr) {
        simStateManager->RegisterCoreNotify(handler, what);
        return;
    }
    if (simFile_ == nullptr) {
        TELEPHONY_LOGE("SimFileManager::RegisterCoreNotify simFile nullptr");
        return;
    }
    simFile_->RegisterCoreNotify(handler, what);
}

void SimFileManager::UnRegisterCoreNotify(const std::shared_ptr<AppExecFwk::EventHandler> &handler, int what)
{
    auto simStateManager = simStateManager_.lock();
    if (what == RadioEvent::RADIO_SIM_STATE_CHANGE && simStateManager != nullptr) {
        simStateManager->UnRegisterCoreNotify(handler, what);
        return;
    }
    if (simFile_ == nullptr) {
        TELEPHONY_LOGE("SimFileManager::UnRegisterCoreNotify simFile nullptr");
        return;
    }
    simFile_->UnRegisterCoreNotify(handler, what);
}

void SimFileManager::SetImsi(std::string imsi)
{
    if (simFile_ == nullptr) {
        TELEPHONY_LOGE("SimFileManager::SetImsi simFile nullptr");
        return;
    }
    simFile_->UpdateImsi(imsi);
}

void SimFileManager::SetVoiceMailParamGsm(const std::u16string mailNumber, bool isSavedIccRecords)
{
    TELEPHONY_LOGI("SimFileManager::SetVoiceMailParamGsm, set gsm voice mail number");
    std::string vmNumKey = "";
    SetParameter(vmNumKey.append(VM_NUMBER_KEY).append(std::to_string(slotId_)).c_str(),
        Str16ToStr8(mailNumber).c_str());
    if (isSavedIccRecords) {
        simFile_->SetVoiceMailNumber(Str16ToStr8(mailNumber));
    }
    if (TELEPHONY_EXT_WRAPPER.setVoiceMailIccidParameter_ != nullptr) {
        std::string iccid = simFile_->ObtainIccId();
        TELEPHONY_EXT_WRAPPER.setVoiceMailIccidParameter_(slotId_, iccid.c_str(), Str16ToStr8(mailNumber).c_str());
    }
}

void SimFileManager::SetVoiceMailParamCdma(const std::u16string mailNumber)
{
    TELEPHONY_LOGI("SimFileManager::SetVoiceMailParamGsm, set cdma voice mail number");
    std::string vmNumKey = "";
    SetParameter(vmNumKey.append(VM_NUMBER_CDMA_KEY).append(std::to_string(slotId_)).c_str(),
        Str16ToStr8(mailNumber).c_str());
}

std::string SimFileManager::EncryptImsi(const std::string imsi)
{
    if (imsi.empty()) {
        return "";
    }
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, imsi.c_str(), imsi.size());
    SHA256_Final(hash, &sha256);
    std::string encryptImsi = SIMUtils::BytesConvertToHexString(hash, SHA256_DIGEST_LENGTH);
    return encryptImsi;
}

std::string SimFileManager::GetVoiceMailSimImsiFromParam()
{
    std::string key = "";
    char spNumber[VM_NUMBER_LEN] = {0};
    GetParameter(key.append(VM_NUMBER_SIM_IMSI_KEY).append(std::to_string(slotId_)).c_str(), "",
        spNumber, VM_NUMBER_LEN);
    return spNumber;
}

void SimFileManager::SetVoiceMailSimImsiParam(std::string imsi)
{
    std::string encryptImsi = EncryptImsi(imsi);
    std::string key = "";
    SetParameter(key.append(VM_NUMBER_SIM_IMSI_KEY).append(std::to_string(slotId_)).c_str(), encryptImsi.c_str());
}

void SimFileManager::StoreVoiceMailNumber(const std::u16string mailNumber, bool isSavedIccRecords)
{
    std::string imsi = simFile_->ObtainIMSI();
    SetVoiceMailSimImsiParam(imsi);
    if (IsPhoneTypeGsm(slotId_)) {
        SetVoiceMailParamGsm(mailNumber, isSavedIccRecords);
    } else {
        SetVoiceMailParamCdma(mailNumber);
    }
}

bool SimFileManager::SetVoiceMailInfo(const std::u16string &mailName, const std::u16string &mailNumber)
{
    if (simFile_ == nullptr || !HasSimCard()) {
        TELEPHONY_LOGE("SimFileManager::SetVoiceMail simFile nullptr");
        return false;
    }
    bool isVoiceMailFixed = simFile_->GetIsVoiceMailFixed();
    if (isVoiceMailFixed) {
        TELEPHONY_LOGE("SimFileManager::SetVoiceMailInfo, voice mail is fixed by cust, set fail");
        return false;
    }
    StoreVoiceMailNumber(mailNumber, true);
    std::string name = Str16ToStr8(mailName);
    std::string number = Str16ToStr8(mailNumber);
    bool result = simFile_->UpdateVoiceMail(name, number);
    TELEPHONY_LOGI("SimFileManager::SetVoiceMail result:%{public}s ", (!result ? "false" : "true"));
    return true;
}

bool SimFileManager::HasSimCard()
{
    auto simStateManager = simStateManager_.lock();
    if (simStateManager == nullptr) {
        TELEPHONY_LOGE("simStateManager nullptr");
        return false;
    }
    bool result = simStateManager->HasSimCard();
    TELEPHONY_LOGI("result:%{public}s ", (result ? "true" : "false"));
    return result;
}

bool SimFileManager::InitDiallingNumberHandler()
{
    if (fileController_ == nullptr) {
        TELEPHONY_LOGE("InitDiallingNumberHandler null fileController");
        return false;
    }
    if (diallingNumberHandler_ != nullptr) {
        TELEPHONY_LOGI("InitDiallingNumberHandler update fileController");
        diallingNumberHandler_->UpdateFileController(fileController_);
        return true;
    }
    diallingNumberHandler_ = std::make_shared<IccDiallingNumbersHandler>(fileController_);
    if (diallingNumberHandler_ == nullptr) {
        TELEPHONY_LOGE("SimFileManager failed to create IccDiallingNumbersHandler.");
        return false;
    }
    return true;
}

void SimFileManager::DeleteOperatorCache()
{
    if (simFile_ != nullptr) {
        simFile_->DeleteOperatorCache();
    }
}

void SimFileManager::UpdateOpkeyConfig()
{
    if (simFile_ != nullptr) {
        simFile_->UpdateOpkeyConfig();
    }
}

bool SimFileManager::IsCTSimCard()
{
    auto simStateManager = simStateManager_.lock();
    if (simStateManager == nullptr) {
        TELEPHONY_LOGE("simStateManager nullptr");
        return false;
    }
    if (simFile_ == nullptr) {
        TELEPHONY_LOGE("simFile nullptr");
        return false;
    }
    CardType cardType = simStateManager->GetCardType();
    bool isCTCardType = IsCTCardType(cardType);
    std::string iccId = simFile_->ObtainIccId();
    if (!iccId.empty() && iccId.length() >= ICCID_LEN_MINIMUM) {
        iccId.resize(ICCID_LEN_MINIMUM);
    }
    if (isCTCardType && IsCTIccId(iccId)) {
        TELEPHONY_LOGI("[slot%{public}d] result = 1", slotId_);
        return true;
    }
    TELEPHONY_LOGD("[slot%{public}d] goto check plmn", slotId_);
    bool result = false;
    std::string plmn = simFile_->ObtainSimOperator();
    if (!plmn.empty()) {
        auto plmnRet = find(CT_CPLMNS.begin(), CT_CPLMNS.end(), plmn);
        result = plmnRet != CT_CPLMNS.end();
        TELEPHONY_LOGD("[slot%{public}d] plmn check result = %{public}d", slotId_, result);
    }
    if (!iccId.empty()) {
        if (result) {
            if (!iccId.compare(GC_ICCID)) {
                result = false;
            }
        } else {
            if (!plmn.compare(ROAMING_CPLMN) && IsCTIccId(iccId)) {
                result = true;
            }
        }
    }
    TELEPHONY_LOGI("[slot%{public}d] result = %{public}d", slotId_, result);
    return result;
}

bool SimFileManager::IsCTCardType(CardType type)
{
    bool isCTCardType = false;
    switch (type) {
        case CardType::SINGLE_MODE_RUIM_CARD:
        case CardType::CT_NATIONAL_ROAMING_CARD:
        case CardType::DUAL_MODE_TELECOM_LTE_CARD:
            isCTCardType = true;
            break;
        default:
            isCTCardType = false;
            break;
    }
    return isCTCardType;
}

bool SimFileManager::IsCTIccId(std::string iccId)
{
    bool isCTIccId = false;
    if (!iccId.empty() && iccId.length() >= ICCID_LEN_MINIMUM) {
        if (iccId.compare(0, PREFIX_LOCAL_ICCID_LEN, PREFIX_LOCAL_ICCID) == 0) {
            iccId.resize(ICCID_LEN_SIX);
        }
        auto iccIdRet = find(CT_ICCID_ARRAY.begin(), CT_ICCID_ARRAY.end(), iccId);
        isCTIccId = iccIdRet != CT_ICCID_ARRAY.end();
    }
    return isCTIccId;
}

std::shared_ptr<IccDiallingNumbersHandler> SimFileManager::ObtainDiallingNumberHandler()
{
    return diallingNumberHandler_;
}

void SimFileManager::HandleSimRecordsLoaded()
{
    if (simFile_ == nullptr) {
        TELEPHONY_LOGE("simFile_ is null");
        return;
    }

    std::string imsiFromSim = simFile_->ObtainIMSI();
    std::string encryptImsiFromSim = EncryptImsi(imsiFromSim);
    std::string imsiFromParam = GetVoiceMailSimImsiFromParam();
    if ((!IsPhoneTypeGsm(slotId_) || !imsiFromParam.empty()) &&
        !encryptImsiFromSim.empty() && imsiFromParam != encryptImsiFromSim) {
        std::string nullStr = "";
        StoreVoiceMailNumber(Str8ToStr16(nullStr), false);
        SetVoiceMailSimImsiParam(nullStr);
    }
}

void SimFileManager::HandleSimIccidLoaded(std::string iccid)
{
    if (simFile_ == nullptr) {
        TELEPHONY_LOGE("simFile_ is null");
        return;
    }
    simFile_->UpdateIccId(iccid);
}

void SimFileManager::ProcessEvent(const AppExecFwk::InnerEvent::Pointer &event)
{
    if (event == nullptr) {
        TELEPHONY_LOGE("event is nullptr!");
        return;
    }
    uint32_t id = event->GetInnerEventId();
    TELEPHONY_LOGD("SimFileManager::ProcessEvent id %{public}d", id);
    auto simStateManager = simStateManager_.lock();
    if (simStateManager == nullptr) {
        TELEPHONY_LOGE("simStateManager is nullptr");
        return;
    }
    switch (id) {
        case RadioEvent::RADIO_VOICE_TECH_CHANGED: {
            TELEPHONY_LOGD("SimFileManager receive RADIO_VOICE_TECH_CHANGED");
            std::shared_ptr<VoiceRadioTechnology> tech = event->GetSharedObject<VoiceRadioTechnology>();
            SimFileManager::IccType iccType = GetIccTypeByTech(tech);
            if (iccType == SimFileManager::IccType::ICC_TYPE_CDMA &&
                simStateManager->GetCardType() == CardType::SINGLE_MODE_USIM_CARD) {
                iccType = SimFileManager::IccType::ICC_TYPE_USIM;
                TELEPHONY_LOGI("change iccType to USIM, slotId: %{public}d", slotId_);
            }
            ChangeSimFileByCardType(iccType);
            break;
        }
        case RadioEvent::RADIO_CARD_TYPE_CHANGE: {
            CardType cardType = simStateManager->GetCardType();
            TELEPHONY_LOGI("getCardType is %{public}d, slotId: %{public}d", cardType, slotId_);
            SimFileManager::IccType iccType = GetIccTypeByCardType(cardType);
            ChangeSimFileByCardType(iccType);
            break;
        }
        case RadioEvent::RADIO_SIM_RECORDS_LOADED: {
            TELEPHONY_LOGI("handle sim records loaded event, slotId: %{public}d", slotId_);
            HandleSimRecordsLoaded();
            break;
        }
        case RadioEvent::RADIO_ICC_REFRESH: {
            TELEPHONY_LOGI("handle sim refresh event, slotId: %{public}d", slotId_);
            if (simFile_ == nullptr) {
                TELEPHONY_LOGE("simFile_ is null");
                return;
            }
            simFile_->ProcessIccRefresh(MSG_ID_DEFAULT);
            break;
        }
        case RadioEvent::RADIO_SIM_ICCID_LOADED: {
            TELEPHONY_LOGI("handle sim iccid load event, slotId: %{public}d", slotId_);
            std::string iccid = simStateManager->GetIccid();
            HandleSimIccidLoaded(iccid);
            break;
        }
        default:
            break;
    }
}

std::shared_ptr<SimFileManager> SimFileManager::CreateInstance(
    std::weak_ptr<ITelRilManager> ril, std::weak_ptr<SimStateManager> simState)
{
    if (ril.lock() == nullptr) {
        TELEPHONY_LOGE("rilmanager null pointer");
        return nullptr;
    }
    if (simState.lock() == nullptr) {
        TELEPHONY_LOGE("simState null pointer");
        return nullptr;
    }

    EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_OPERATOR_CONFIG_CHANGED);
    EventFwk::CommonEventSubscribeInfo subscribeInfo(matchingSkills);
    subscribeInfo.SetThreadMode(EventFwk::CommonEventSubscribeInfo::COMMON);

    std::shared_ptr<SimFileManager> manager = std::make_shared<SimFileManager>(subscribeInfo, ril, simState);
    if (manager == nullptr) {
        TELEPHONY_LOGE("manager create nullptr.");
        return nullptr;
    }
    bool subRet = EventFwk::CommonEventManager::SubscribeCommonEvent(manager);
    TELEPHONY_LOGI("SimFileManager::CreateInstance, subscribe user switched subRet is %{public}d", subRet);
    return manager;
}

void SimFileManager::ChangeSimFileByCardType(SimFileManager::IccType type)
{
    TELEPHONY_LOGI("SimFileManager new icc type:%{public}d, old icc type: %{public}d", type, iccType_);
    if (!IsValidType(type)) {
        TELEPHONY_LOGI("SimFileManager handle new icc invalid type received %{public}d", type);
        return;
    }
    if (type == iccType_) {
        TELEPHONY_LOGI("SimFileManager same type as ready");
        return;
    }
    if (type != iccType_) {
        TELEPHONY_LOGI("SimFileManager handle new icc type received %{public}d", type);
        iccType_ = type;
        if (simFile_ != nullptr) {
            simFile_->UnInit();
        }
        InitIccFileController(type);
        InitDiallingNumberHandler();
        InitSimFile(type);
    }
}

SimFileManager::IccType SimFileManager::GetIccTypeByCardType(CardType type)
{
    switch (type) {
        case CardType::SINGLE_MODE_RUIM_CARD:
            return SimFileManager::IccType::ICC_TYPE_CDMA;
        case CardType::SINGLE_MODE_ISIM_CARD:
            return SimFileManager::IccType::ICC_TYPE_IMS;
        case CardType::SINGLE_MODE_SIM_CARD:
        case CardType::DUAL_MODE_CG_CARD:
        case CardType::CT_NATIONAL_ROAMING_CARD:
        case CardType::CU_DUAL_MODE_CARD:
        case CardType::DUAL_MODE_TELECOM_LTE_CARD:
        case CardType::DUAL_MODE_UG_CARD:
            return SimFileManager::IccType::ICC_TYPE_GSM;
        default:
            break;
    }
    return SimFileManager::IccType::ICC_TYPE_USIM;
}

SimFileManager::IccType SimFileManager::GetIccTypeByTech(const std::shared_ptr<VoiceRadioTechnology> &tech)
{
    if (tech == nullptr) {
        TELEPHONY_LOGE("GetCardTypeByTech param tech is nullptr then ICC_TYPE_UNKNOW");
        return SimFileManager::IccType::ICC_TYPE_USIM;
    }
    switch (tech->actType) {
        case int32_t(RadioTech::RADIO_TECHNOLOGY_EHRPD):
        case int32_t(RadioTech::RADIO_TECHNOLOGY_1XRTT):
            return SimFileManager::IccType::ICC_TYPE_CDMA;
        case int32_t(RadioTech::RADIO_TECHNOLOGY_LTE_CA):
        case int32_t(RadioTech::RADIO_TECHNOLOGY_LTE):
        case int32_t(RadioTech::RADIO_TECHNOLOGY_GSM):
        case int32_t(RadioTech::RADIO_TECHNOLOGY_TD_SCDMA):
        case int32_t(RadioTech::RADIO_TECHNOLOGY_HSPA):
        case int32_t(RadioTech::RADIO_TECHNOLOGY_HSPAP):
        default:
            break;
    }
    return SimFileManager::IccType::ICC_TYPE_USIM;
}

bool SimFileManager::IsValidType(SimFileManager::IccType type)
{
    switch (type) {
        case SimFileManager::IccType::ICC_TYPE_CDMA:
        case SimFileManager::IccType::ICC_TYPE_GSM:
        case SimFileManager::IccType::ICC_TYPE_IMS:
        case SimFileManager::IccType::ICC_TYPE_USIM:
            return true;
        default:
            break;
    }
    return false;
}

std::u16string SimFileManager::GetSimIst()
{
    if (simFile_ == nullptr) {
        TELEPHONY_LOGE("SimFileManager::GetSimIst simFile nullptr");
        return Str8ToStr16("");
    }
    std::string result = static_cast<IsimFile *>(simFile_.get())->ObtainIsimIst();
    TELEPHONY_LOGI("SimFileManager::GetSimIst result:%{public}s ", (result.empty() ? "false" : "true"));
    return Str8ToStr16(result);
}

void SimFileManager::ClearData()
{
    opName_ = "";
    opKey_ = "";
    opKeyExt_ = "";
    if (simFile_ == nullptr) {
        TELEPHONY_LOGE("SimFileManager::ClearData simFile nullptr");
        return;
    }
    simFile_->ClearData();
}

#ifdef CORE_SERVICE_SUPPORT_ESIM
std::shared_ptr<EsimFile> SimFileManager::GetEsimfile()
{
    return eSimFile_;
}

std::u16string SimFileManager::GetEid()
{
    if (eSimFile_ == nullptr) {
        TELEPHONY_LOGE("esimFile is nullptr");
        return Str8ToStr16("");
    }
    std::string result = eSimFile_->ObtainEid();
    return Str8ToStr16(result);
}

GetEuiccProfileInfoListResult SimFileManager::GetEuiccProfileInfoList()
{
    if (eSimFile_ == nullptr) {
        TELEPHONY_LOGE("esimFile is nullptr");
        return GetEuiccProfileInfoListResult();
    }
    return eSimFile_->GetEuiccProfileInfoList();
}

EuiccInfo SimFileManager::GetEuiccInfo()
{
    if (eSimFile_ == nullptr) {
        TELEPHONY_LOGE("simFile is nullptr");
        return EuiccInfo();
    }
    return eSimFile_->GetEuiccInfo();
}

ResultState SimFileManager::DisableProfile(int32_t portIndex, const std::u16string &iccId)
{
    if (eSimFile_ == nullptr) {
        TELEPHONY_LOGE("esimFile is nullptr");
        return ResultState::RESULT_UNDEFINED_ERROR;
    }
    ResultState enumResult = eSimFile_->DisableProfile(portIndex, iccId);
    return enumResult;
}

std::u16string SimFileManager::GetSmdsAddress(int32_t portIndex)
{
    if (eSimFile_ == nullptr) {
        TELEPHONY_LOGE("esimFile is nullptr");
        return Str8ToStr16("");
    }
    std::string result = eSimFile_->ObtainSmdsAddress(portIndex);
    return Str8ToStr16(result);
}

EuiccRulesAuthTable SimFileManager::GetRulesAuthTable(int32_t portIndex)
{
    if (eSimFile_ == nullptr) {
        TELEPHONY_LOGE("esimFile is nullptr");
        return EuiccRulesAuthTable();
    }
    EuiccRulesAuthTable result = eSimFile_->ObtainRulesAuthTable(portIndex);
    return result;
}

ResponseEsimResult SimFileManager::GetEuiccChallenge(int32_t portIndex)
{
    if (eSimFile_ == nullptr) {
        TELEPHONY_LOGE("esimFile is nullptr");
        return ResponseEsimResult();
    }
    ResponseEsimResult result = eSimFile_->ObtainEuiccChallenge(portIndex);
    return result;
}
#endif
} // namespace Telephony
} // namespace OHOS
