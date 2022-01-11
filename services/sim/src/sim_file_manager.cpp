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

namespace OHOS {
namespace Telephony {
SimFileManager::SimFileManager(const std::shared_ptr<AppExecFwk::EventRunner> &runner,
    std::shared_ptr<ITelRilManager> telRilManager, std::shared_ptr<Telephony::ISimStateManager> state)
    : AppExecFwk::EventHandler(runner), telRilManager_(telRilManager), simStateManager_(state)
{
    if (simStateManager_ == nullptr) {
        TELEPHONY_LOGE("SimFileManager set NULL simStateManager.");
        return;
    }
    TELEPHONY_LOGI("SIM manager SimFileManager::SimFileManager started ");
}

SimFileManager::~SimFileManager() {}

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
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("SimFileManager get NULL ITelRilManager.");
        return;
    }
    CardType cardType = simStateManager_->GetCardType(slotId_);
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

    simStateManager_->RegisterCoreNotify(shared_from_this(), ObserverHandler::RADIO_CARD_TYPE_CHANGE);
    telRilManager_->RegisterCoreNotify(shared_from_this(), ObserverHandler::RADIO_VOICE_TECH_CHANGED, nullptr);
    TELEPHONY_LOGI("SimFileManager::Init() end");
}

bool SimFileManager::InitSimFile(SimFileManager::IccType type)
{
    if (fileController_ == nullptr || diallingNumberHandler_ == nullptr) {
        TELEPHONY_LOGE("InitSimFile need more helper");
        return false;
    }
    if (eventLoopRecord_ == nullptr) {
        eventLoopRecord_ = AppExecFwk::EventRunner::Create("IccFile");
        if (eventLoopRecord_.get() == nullptr) {
            TELEPHONY_LOGE("IccFile  failed to create EventRunner");
            return false;
        }
    } else {
        eventLoopRecord_->Stop();
    }
    auto iccFileIt = iccFileCache_.find(type);
    if (iccFileIt == iccFileCache_.end()) {
        if (type == SimFileManager::IccType::ICC_TYPE_CDMA) {
            simFile_ = std::make_shared<RuimFile>(eventLoopRecord_, simStateManager_);
        } else if (type == SimFileManager::IccType::ICC_TYPE_IMS) {
            simFile_ = std::make_shared<IsimFile>(eventLoopRecord_, simStateManager_);
        } else {
            simFile_ = std::make_shared<SimFile>(eventLoopRecord_, simStateManager_);
        }
        iccFileCache_.insert(std::make_pair(type, simFile_));
    } else {
        simFile_ = iccFileIt->second;
    }

    if (simFile_ == nullptr) {
        TELEPHONY_LOGE("SimFileManager::Init simFile create nullptr.");
        return false;
    }
    simFile_->SetRilAndFileController(telRilManager_, fileController_, diallingNumberHandler_);
    eventLoopRecord_->Run();
    simFile_->SetId(slotId_);
    simFile_->Init();
    return true;
}

bool SimFileManager::InitIccFileController(SimFileManager::IccType type)
{
    if (eventLoopFileController_ == nullptr) {
        eventLoopFileController_ = AppExecFwk::EventRunner::Create("SIMController");
        if (eventLoopFileController_.get() == nullptr) {
            TELEPHONY_LOGE("SIMHandler failed to create EventRunner");
            return false;
        }
    } else {
        eventLoopFileController_->Stop();
    }
    auto iccFileConIt = iccFileControllerCache_.find(type);
    if (iccFileConIt == iccFileControllerCache_.end()) {
        if (type == SimFileManager::IccType::ICC_TYPE_CDMA) { // ruim 30 usim 20 isim 60
            fileController_ = std::make_shared<RuimFileController>(eventLoopFileController_);
        } else if (type == SimFileManager::IccType::ICC_TYPE_IMS) {
            fileController_ = std::make_shared<IsimFileController>(eventLoopFileController_);
        } else if (type == SimFileManager::IccType::ICC_TYPE_USIM) {
            fileController_ = std::make_shared<UsimFileController>(eventLoopFileController_);
        } else if (type == SimFileManager::IccType::ICC_TYPE_GSM) {
            fileController_ = std::make_shared<SimFileController>(eventLoopFileController_);
        } else {
            fileController_ = std::make_shared<UsimFileController>(eventLoopFileController_);
        }
        iccFileControllerCache_.insert(std::make_pair(type, fileController_));
    } else {
        fileController_ = iccFileConIt->second;
    }
    if (fileController_ == nullptr) {
        TELEPHONY_LOGE("SimFileManager::Init fileController create nullptr.");
        return false;
    }
    fileController_->SetRilManager(telRilManager_);
    eventLoopFileController_->Run();
    return true;
}

std::u16string SimFileManager::GetSimOperatorNumeric(int32_t slotId)
{
    if (simFile_ == nullptr) {
        TELEPHONY_LOGE("SimFileManager::GetSimOperatorNumeric simFile nullptr");
        return Str8ToStr16("");
    }

    std::string result = simFile_->ObtainSimOperator();
    TELEPHONY_LOGI("SimFileManager::GetOperator result:%{public}s ", (result.empty() ? "false" : "true"));
    return Str8ToStr16(result);
}

std::u16string SimFileManager::GetISOCountryCodeForSim(int32_t slotId)
{
    if (simFile_ == nullptr) {
        TELEPHONY_LOGE("SimFileManager::GetISOCountryCodeForSim simFile nullptr");
        return Str8ToStr16("");
    }

    std::string result = simFile_->ObtainIsoCountryCode();
    TELEPHONY_LOGI("SimFileManager::ObtainIsoCountryCode result:%{public}s ", (result.empty() ? "false" : "true"));
    return Str8ToStr16(result);
}

std::u16string SimFileManager::GetSimSpn(int32_t slotId)
{
    if (simFile_ == nullptr) {
        TELEPHONY_LOGE("SimFileManager::GetSimSpn simFile nullptr");
        return Str8ToStr16("");
    }

    std::string result = simFile_->ObtainSPN();
    TELEPHONY_LOGI("SimFileManager::GetSimSpn result:%{public}s ", (result.empty() ? "false" : "true"));
    return Str8ToStr16(result);
}

std::u16string SimFileManager::GetSimIccId(int32_t slotId)
{
    if (simFile_ == nullptr) {
        TELEPHONY_LOGE("SimFileManager::GetSimIccId simFile nullptr");
        return Str8ToStr16("");
    }

    std::string result = simFile_->ObtainIccId();
    TELEPHONY_LOGI("SimFileManager::GetSimIccId result:%{public}s ", (result.empty() ? "false" : "true"));
    return Str8ToStr16(result);
}

std::u16string SimFileManager::GetIMSI(int32_t slotId)
{
    if (simFile_ == nullptr) {
        TELEPHONY_LOGE("SimFileManager::GetIMSI simFile nullptr");
        return Str8ToStr16("");
    }

    std::string result = simFile_->ObtainIMSI();
    TELEPHONY_LOGI("SimFileManager::ObtainIMSI result:%{public}s ", (result.empty() ? "false" : "true"));
    return Str8ToStr16(result);
}

std::u16string SimFileManager::GetLocaleFromDefaultSim()
{
    if (simFile_ == nullptr) {
        TELEPHONY_LOGE("SimFileManager::GetLocaleFromDefaultSim simFile nullptr");
        return Str8ToStr16("");
    }

    std::string result = simFile_->ObtainIccLanguage();
    TELEPHONY_LOGI(
        "SimFileManager::GetLocaleFromDefaultSim result:%{public}s ", (result.empty() ? "false" : "true"));
    return Str8ToStr16(result);
}

std::u16string SimFileManager::GetSimGid1(int32_t slotId)
{
    if (simFile_ == nullptr) {
        TELEPHONY_LOGE("SimFileManager::GetSimGid1 simFile nullptr");
        return Str8ToStr16("");
    }

    std::string result = simFile_->ObtainGid1();
    TELEPHONY_LOGI("SimFileManager::GetSimGid1 result:%{public}s ", (result.empty() ? "false" : "true"));
    return Str8ToStr16(result);
}

std::u16string SimFileManager::GetSimTelephoneNumber(int32_t slotId)
{
    if (simFile_ == nullptr) {
        TELEPHONY_LOGE("SimFileManager::GetSimTelephoneNumber simFile nullptr");
        return Str8ToStr16("");
    }

    std::string result = simFile_->ObtainMsisdnNumber();
    TELEPHONY_LOGI("SimFileManager::GetSimTelephoneNumber result:%{public}s ", (result.empty() ? "false" : "true"));
    return Str8ToStr16(result);
}

std::u16string SimFileManager::GetSimTeleNumberIdentifier(const int32_t slotId)
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

std::u16string SimFileManager::GetVoiceMailIdentifier(int32_t slotId)
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

std::u16string SimFileManager::GetVoiceMailNumber(int32_t slotId)
{
    if (simFile_ == nullptr) {
        TELEPHONY_LOGE("SimFileManager::GetVoiceMailNumber simFile nullptr");
        return Str8ToStr16("");
    }

    std::string result = simFile_->ObtainVoiceMailNumber();
    TELEPHONY_LOGI("SimFileManager::GetVoiceMailNumber result:%{public}s ", (result.empty() ? "false" : "true"));
    return Str8ToStr16(result);
}

int SimFileManager::ObtainSpnCondition(bool roaming, std::string operatorNum)
{
    if (simFile_ == nullptr) {
        TELEPHONY_LOGE("SimFileManager::ObtainSpnCondition simFile nullptr");
        return 0;
    }

    int result = simFile_->ObtainSpnCondition(roaming, operatorNum);
    TELEPHONY_LOGI("SimFileManager::ObtainSpnCondition:%{public}d", result);
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
    if (simFile_ == nullptr) {
        TELEPHONY_LOGE("SimFileManager::RegisterCoreNotify simFile nullptr");
        return;
    }
    simFile_->RegisterCoreNotify(handler, what);
}

void SimFileManager::UnRegisterCoreNotify(const std::shared_ptr<AppExecFwk::EventHandler> &handler, int what)
{
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

bool SimFileManager::SetVoiceMailInfo(
    int32_t slotId, const std::u16string &mailName, const std::u16string &mailNumber)
{
    if (simFile_ == nullptr || !simFile_->HasSimCard(slotId)) {
        TELEPHONY_LOGE("SimFileManager::SetVoiceMail simFile nullptr");
        return false;
    }
    std::string name = Str16ToStr8(mailName);
    std::string number = Str16ToStr8(mailNumber);
    bool result = simFile_->UpdateVoiceMail(name, number);
    TELEPHONY_LOGI("SimFileManager::SetVoiceMail result:%{public}s ", (!result ? "false" : "true"));
    return result;
}

bool SimFileManager::InitDiallingNumberHandler()
{
    if (fileController_ == nullptr) {
        return false;
    }
    std::shared_ptr<AppExecFwk::EventRunner> loaderLoop = AppExecFwk::EventRunner::Create("msisdnLoader");
    if (loaderLoop.get() == nullptr) {
        TELEPHONY_LOGE("SimFileManager failed to create diallingNumberloader loop");
        return false;
    }
    diallingNumberHandler_ = std::make_shared<IccDiallingNumbersHandler>(loaderLoop, fileController_);
    if (diallingNumberHandler_ == nullptr) {
        TELEPHONY_LOGE("SimFileManager failed to create IccDiallingNumbersHandler.");
        return false;
    }
    loaderLoop->Run();
    return true;
}

std::shared_ptr<IccDiallingNumbersHandler> SimFileManager::ObtainDiallingNumberHandler()
{
    return diallingNumberHandler_;
}

void SimFileManager::ProcessEvent(const AppExecFwk::InnerEvent::Pointer &event)
{
    int id = event->GetInnerEventId();
    TELEPHONY_LOGI("SimFileManager::ProcessEvent id %{public}d", id);
    switch (id) {
        case ObserverHandler::RADIO_VOICE_TECH_CHANGED: {
            TELEPHONY_LOGI("SimFileManager receive RADIO_VOICE_TECH_CHANGED");
            std::shared_ptr<VoiceRadioTechnology> tech = event->GetSharedObject<VoiceRadioTechnology>();
            SimFileManager::IccType iccType = GetIccTypeByTech(tech);
            ChangeSimFileByCardType(iccType);
            break;
        }
        case ObserverHandler::RADIO_CARD_TYPE_CHANGE: {
            CardType cardType = simStateManager_->GetCardType(slotId_);
            TELEPHONY_LOGI("SimFileManager GetCardType is %{public}d", cardType);
            SimFileManager::IccType iccType = GetIccTypeByCardType(cardType);
            ChangeSimFileByCardType(iccType);
            break;
        }
        default:
            break;
    }
}

std::shared_ptr<ISimFileManager> SimFileManager::CreateInstance(
    const std::shared_ptr<ITelRilManager> &ril, const std::shared_ptr<ISimStateManager> &simState)
{
    std::shared_ptr<AppExecFwk::EventRunner> eventLoop = AppExecFwk::EventRunner::Create("simFileMgrLoop");
    if (eventLoop.get() == nullptr) {
        TELEPHONY_LOGE("SimFileManager failed to create EventRunner");
        return nullptr;
    }
    if (ril == nullptr) {
        TELEPHONY_LOGE("SimFileManager::Init rilmanager null pointer");
        return nullptr;
    }
    std::shared_ptr<SimFileManager> manager = std::make_shared<SimFileManager>(eventLoop, ril, simState);
    if (manager == nullptr) {
        TELEPHONY_LOGE("SimFileManager::Init manager create nullptr.");
        return nullptr;
    }
    eventLoop->Run();
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
        case CardType::SINGLE_MODE_USIM_CARD:
            return SimFileManager::IccType::ICC_TYPE_USIM;
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
        default:
            break;
    }
    return SimFileManager::IccType::ICC_TYPE_GSM;
}

SimFileManager::IccType SimFileManager::GetIccTypeByTech(const std::shared_ptr<VoiceRadioTechnology> &tech)
{
    if (tech == nullptr) {
        TELEPHONY_LOGI("GetCardTypeByTech param tech is nullptr then ICC_TYPE_UNKNOW");
        return SimFileManager::IccType::ICC_TYPE_GSM;
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
    return SimFileManager::IccType::ICC_TYPE_GSM;
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
} // namespace Telephony
} // namespace OHOS
