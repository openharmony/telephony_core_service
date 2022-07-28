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

#include "icc_file.h"
#include "if_system_ability_manager.h"
#include "inner_event.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"
#include "telephony_state_registry_client.h"
#include "radio_event.h"

using namespace std;
using namespace OHOS::AppExecFwk;
using namespace OHOS::EventFwk;

namespace OHOS {
namespace Telephony {
std::unique_ptr<ObserverHandler> IccFile::filesFetchedObser_ = nullptr;
IccFile::IccFile(
    const std::shared_ptr<AppExecFwk::EventRunner> &runner, std::shared_ptr<SimStateManager> simStateManager)
    : AppExecFwk::EventHandler(runner), stateManager_(simStateManager)
{
    if (stateManager_ == nullptr) {
        TELEPHONY_LOGE("IccFile::IccFile set NULL SIMStateManager!!");
    }
    if (filesFetchedObser_ == nullptr) {
        filesFetchedObser_ = std::make_unique<ObserverHandler>();
    }
    if (filesFetchedObser_ == nullptr) {
        TELEPHONY_LOGE("IccFile::IccFile filesFetchedObser_ create nullptr.");
        return;
    }

    lockedFilesFetchedObser_ = std::make_unique<ObserverHandler>();
    if (lockedFilesFetchedObser_ == nullptr) {
        TELEPHONY_LOGE("IccFile::IccFile lockedFilesFetchedObser_ create nullptr.");
        return;
    }
    networkLockedFilesFetchedObser_ = std::make_unique<ObserverHandler>();
    if (networkLockedFilesFetchedObser_ == nullptr) {
        TELEPHONY_LOGE("IccFile::IccFile networkLockedFilesFetchedObser_ create nullptr.");
        return;
    }
    imsiReadyObser_ = std::make_unique<ObserverHandler>();
    if (imsiReadyObser_ == nullptr) {
        TELEPHONY_LOGE("IccFile::IccFile imsiReadyObser_ create nullptr.");
        return;
    }
    recordsEventsObser_ = std::make_unique<ObserverHandler>();
    if (recordsEventsObser_ == nullptr) {
        TELEPHONY_LOGE("IccFile::IccFile recordsEventsObser_ create nullptr.");
        return;
    }
    networkSelectionModeAutomaticObser_ = std::make_unique<ObserverHandler>();
    if (networkSelectionModeAutomaticObser_ == nullptr) {
        TELEPHONY_LOGE("IccFile::IccFile networkSelectionModeAutomaticObser_ create nullptr.");
        return;
    }
    spnUpdatedObser_ = std::make_unique<ObserverHandler>();
    if (spnUpdatedObser_ == nullptr) {
        TELEPHONY_LOGE("IccFile::IccFile spnUpdatedObser_ create nullptr.");
        return;
    }
    recordsOverrideObser_ = std::make_unique<ObserverHandler>();
    if (recordsOverrideObser_ == nullptr) {
        TELEPHONY_LOGE("IccFile::IccFile recordsOverrideObser_ create nullptr.");
        return;
    }
    TELEPHONY_LOGI("simmgr IccFile::IccFile finish");
}

void IccFile::Init() {}

void IccFile::StartLoad()
{
    TELEPHONY_LOGI("simmgr IccFile::StarLoad() start");
}

std::string IccFile::ObtainIMSI()
{
    if (imsi_.empty()) {
        TELEPHONY_LOGI("IccFile::ObtainIMSI  is null:");
    }
    return imsi_;
}

void IccFile::UpdateImsi(std::string imsi)
{
    imsi_ = imsi;
}

std::string IccFile::ObtainIccId()
{
    return iccId_;
}

std::string IccFile::ObtainGid1()
{
    return gid1_;
}

std::string IccFile::ObtainGid2()
{
    return gid2_;
}

std::string IccFile::ObtainMsisdnNumber()
{
    return msisdn_;
}

bool IccFile::LoadedOrNot()
{
    return loaded_;
}

void IccFile::UpdateLoaded(bool loaded)
{
    loaded_ = loaded;
}

std::string IccFile::ObtainSimOperator()
{
    return operatorNumeric_;
}

std::string IccFile::ObtainIsoCountryCode()
{
    return "";
}

int IccFile::ObtainCallForwardStatus()
{
    return ICC_CALL_FORWARD_TYPE_UNKNOWN;
}

void IccFile::UpdateMsisdnNumber(
    const std::string &alphaTag, const std::string &number, const AppExecFwk::InnerEvent::Pointer &onComplete)
{}

bool IccFile::ObtainFilesFetched()
{
    return (fileToGet_ == 0) && fileQueried_;
}

bool IccFile::LockQueriedOrNot()
{
    return (fileToGet_ == 0) && lockQueried_;
}

std::string IccFile::ObtainDiallingNumberInfo()
{
    return "";
}

std::string IccFile::ObtainNAI()
{
    return "";
}

std::string IccFile::ObtainHomeNameOfPnn()
{
    return pnnHomeName_;
}

std::string IccFile::ObtainMsisdnAlphaStatus()
{
    return msisdnTag_;
}

std::string IccFile::ObtainVoiceMailNumber()
{
    return voiceMailNum_;
}

std::string IccFile::ObtainSPN()
{
    return spn_;
}

std::string IccFile::ObtainEons(const std::string &plmn, int32_t lac, bool longNameRequired)
{
    if (plmn.empty() || pnnFiles_.empty()) {
        TELEPHONY_LOGE("ObtainEons plmn or pnnFiles is empty");
        return "";
    }
    int pnnIndex = -1;
    bool isHPLMN = (plmn.compare(operatorNumeric_) == 0 ? true : false);
    TELEPHONY_LOGI("ObtainEons isHPLMN:%{public}d", isHPLMN);
    if (oplFiles_.empty()) {
        TELEPHONY_LOGI("ObtainEons oplFiles is empty");
        if (isHPLMN) {
            pnnIndex = 1;
        } else {
            return "";
        }
    } else {
        for (std::shared_ptr<OperatorPlmnInfo> opl : oplFiles_) {
            TELEPHONY_LOGI("ObtainEons plmn:%{public}s, opl->plmnNumeric:%{public}s, lac:%{public}d, "
                "opl->lacStart:%{public}d, opl->lacEnd:%{public}d, opl->pnnRecordId:%{public}d",
                plmn.c_str(), opl->plmnNumeric.c_str(), lac, opl->lacStart, opl->lacEnd, opl->pnnRecordId);
            if (plmn.compare(opl->plmnNumeric) == 0 &&
                ((opl->lacStart == 0 && opl->lacEnd == 0xfffe) || (opl->lacStart <= lac && opl->lacEnd >= lac))) {
                if (opl->pnnRecordId == 0) {
                    return "";
                }
                pnnIndex = opl->pnnRecordId;
                break;
            }
        }
    }
    std::string eons = "";
    if (pnnIndex >= 1 && pnnIndex <= (int)pnnFiles_.size()) {
        TELEPHONY_LOGI("ObtainEons longNameRequired:%{public}d, longName:%{public}s, shortName:%{public}s,",
            longNameRequired, pnnFiles_.at(pnnIndex - 1)->longName.c_str(),
            pnnFiles_.at(pnnIndex - 1)->shortName.c_str());
        if (longNameRequired) {
            eons = pnnFiles_.at(pnnIndex - 1)->longName;
            if (eons.empty()) {
                eons = pnnFiles_.at(pnnIndex - 1)->shortName;
            }
        } else {
            eons = pnnFiles_.at(pnnIndex - 1)->shortName;
            if (eons.empty()) {
                eons = pnnFiles_.at(pnnIndex - 1)->longName;
            }
        }
    }
    if (eons.empty() && !spn_.empty() && isHPLMN) {
        eons = spn_;
    }
    return eons;
}

std::string IccFile::ObtainVoiceMailInfo()
{
    return voiceMailTag_;
}

std::string IccFile::ObtainIccLanguage()
{
    return iccLanguage_;
}

std::shared_ptr<UsimFunctionHandle> IccFile::ObtainUsimFunctionHandle()
{
    return std::make_shared<UsimFunctionHandle>(nullptr, 0);
}

std::string IccFile::ObtainSpNameFromEfSpn()
{
    return "";
}

int IccFile::ObtainLengthOfMnc()
{
    return lengthOfMnc_;
}

void IccFile::ProcessEvent(const AppExecFwk::InnerEvent::Pointer &event)
{
    auto id = event->GetInnerEventId();
    bool result = false;
    TELEPHONY_LOGI("IccFile::ProcessEvent id %{public}d", id);
    switch (id) {
        case MSG_SIM_OBTAIN_ICC_FILE_DONE:
            result = ProcessIccFileObtained(event);
            ProcessFileLoaded(result);
            break;
        case MSG_ICC_REFRESH:
            ProcessIccRefresh(MSG_ID_DEFAULT);
            break;
        default:
            break;
    }
}

void IccFile::RegisterImsiLoaded(std::shared_ptr<AppExecFwk::EventHandler> eventHandler)
{
    int eventCode = RadioEvent::RADIO_IMSI_LOADED_READY;
    if (imsiReadyObser_ != nullptr) {
        imsiReadyObser_->RegObserver(eventCode, eventHandler);
    }
    if (!ObtainIMSI().empty()) {
        if (imsiReadyObser_ != nullptr) {
            imsiReadyObser_->NotifyObserver(RadioEvent::RADIO_IMSI_LOADED_READY);
        }
        PublishSimFileEvent(EventFwk::CommonEventSupport::COMMON_EVENT_SIM_STATE_CHANGED,
            ICC_STATE_IMSI, ObtainIMSI());
    }
}

void IccFile::UnregisterImsiLoaded(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    if (imsiReadyObser_ != nullptr) {
        imsiReadyObser_->Remove(RadioEvent::RADIO_IMSI_LOADED_READY, handler);
    }
}

void IccFile::RegisterAllFilesLoaded(std::shared_ptr<AppExecFwk::EventHandler> eventHandler)
{
    int eventCode = RadioEvent::RADIO_SIM_RECORDS_LOADED;
    if (filesFetchedObser_ != nullptr) {
        filesFetchedObser_->RegObserver(eventCode, eventHandler);
    }
    TELEPHONY_LOGI("IccFile::RegisterAllFilesLoaded: registerd");
    if (ObtainFilesFetched()) {
        TELEPHONY_LOGI("IccFile::RegisterAllFilesLoaded: notify");
        if (filesFetchedObser_ != nullptr) {
            filesFetchedObser_->NotifyObserver(RadioEvent::RADIO_SIM_RECORDS_LOADED, slotId_);
        }
        PublishSimFileEvent(EventFwk::CommonEventSupport::COMMON_EVENT_SIM_STATE_CHANGED, ICC_STATE_LOADED, "");
    }
}

void IccFile::UnregisterAllFilesLoaded(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    if (filesFetchedObser_ != nullptr) {
        filesFetchedObser_->Remove(RadioEvent::RADIO_SIM_RECORDS_LOADED, handler);
    }
}

void IccFile::RegisterCoreNotify(const std::shared_ptr<AppExecFwk::EventHandler> &handler, int what)
{
    switch (what) {
        case RadioEvent::RADIO_SIM_RECORDS_LOADED:
            RegisterAllFilesLoaded(handler);
            break;
        case RadioEvent::RADIO_IMSI_LOADED_READY:
            RegisterImsiLoaded(handler);
            break;
        default:
            TELEPHONY_LOGI("RegisterCoreNotify default");
    }
}

void IccFile::UnRegisterCoreNotify(const std::shared_ptr<AppExecFwk::EventHandler> &handler, int what)
{
    switch (what) {
        case RadioEvent::RADIO_SIM_RECORDS_LOADED:
            UnregisterAllFilesLoaded(handler);
            break;
        case RadioEvent::RADIO_IMSI_LOADED_READY:
            UnregisterImsiLoaded(handler);
            break;
        default:
            TELEPHONY_LOGI("RegisterCoreNotify default");
    }
}

void IccFile::UpdateSPN(const std::string spn)
{
    if (spn_ != spn) {
        spnUpdatedObser_->NotifyObserver(MSG_SIM_SPN_UPDATED);
        spn_ = spn;
    }
}

AppExecFwk::InnerEvent::Pointer IccFile::BuildCallerInfo(int eventId)
{
    std::unique_ptr<FileToControllerMsg> object = std::make_unique<FileToControllerMsg>();
    int eventParam = 0;
    AppExecFwk::InnerEvent::Pointer event = AppExecFwk::InnerEvent::Get(eventId, object, eventParam);
    event->SetOwner(shared_from_this());
    return event;
}

AppExecFwk::InnerEvent::Pointer IccFile::BuildCallerInfo(int eventId, int arg1, int arg2)
{
    std::unique_ptr<FileToControllerMsg> object = std::make_unique<FileToControllerMsg>();
    object->arg1 = arg1;
    object->arg2 = arg2;
    int eventParam = 0;
    AppExecFwk::InnerEvent::Pointer event = AppExecFwk::InnerEvent::Get(eventId, object, eventParam);
    event->SetOwner(shared_from_this());
    return event;
}

AppExecFwk::InnerEvent::Pointer IccFile::BuildCallerInfo(int eventId, std::shared_ptr<void> loader)
{
    std::unique_ptr<FileToControllerMsg> object = std::make_unique<FileToControllerMsg>();
    object->iccLoader = loader;
    int eventParam = 0;
    AppExecFwk::InnerEvent::Pointer event = AppExecFwk::InnerEvent::Get(eventId, object, eventParam);
    event->SetOwner(shared_from_this());
    return event;
}

bool IccFile::PublishSimFileEvent(const std::string &event, int eventCode, const std::string &eventData)
{
    Want want;
    want.SetAction(event);
    CommonEventData data;
    data.SetWant(want);
    data.SetCode(eventCode);
    data.SetData(eventData);
    CommonEventPublishInfo publishInfo;
    publishInfo.SetOrdered(true);
    bool publishResult = CommonEventManager::PublishCommonEvent(data, publishInfo, nullptr);
    TELEPHONY_LOGI("IccFile::PublishSimEvent result : %{public}d", publishResult);
    return publishResult;
}

bool IccFile::ProcessIccFileObtained(const AppExecFwk::InnerEvent::Pointer &event)
{
    bool isFileProcessResponse = true;
    std::shared_ptr<ControllerToFileMsg> fd = event->GetSharedObject<ControllerToFileMsg>();
    std::shared_ptr<void> baseLoad = fd->iccLoader;
    if (baseLoad != nullptr) {
        std::shared_ptr<IccFileLoaded> destLoad = std::static_pointer_cast<IccFileLoaded>(baseLoad);
        destLoad->ProcessParseFile(event);
        TELEPHONY_LOGI("ProcessIccFileObtained item %{public}s", destLoad->ObtainElementaryFileName().c_str());
    } else {
        isFileProcessResponse = false;
        TELEPHONY_LOGE("IccFile::ProcessIccFileObtained null base ponter");
    }
    return isFileProcessResponse;
}

void IccFile::UpdateIccLanguage(const std::string &langLi, const std::string &langPl)
{
    iccLanguage_ = ObtainValidLanguage(langLi);
    if (iccLanguage_.empty()) {
        iccLanguage_ = ObtainValidLanguage(langPl);
    }
    TELEPHONY_LOGI("IccFile::UpdateIccLanguage end is %{public}s", iccLanguage_.c_str());
}

std::string IccFile::ObtainValidLanguage(const std::string &langData)
{
    if (langData.empty()) {
        TELEPHONY_LOGE("langData null data!!");
        return "";
    }
    int langDataLen = 0;
    std::shared_ptr<unsigned char> ucc = SIMUtils::HexStringConvertToBytes(langData, langDataLen);
    unsigned char *data = ucc.get();

    std::string spnName((char *)data);
    TELEPHONY_LOGI("ObtainValidLanguage all is %{public}s---%{public}d", spnName.c_str(), langDataLen);
    std::string result = "";
    for (int i = 0; (i + 1) < langDataLen; i += DATA_STEP) {
        std::string langName((char *)data, i, DATA_STEP);
        TELEPHONY_LOGI("ObtainValidLanguage item is %{public}d--%{public}s", i, langName.c_str());
        if (!langName.empty()) {
            result = langName;
        }
    }

    return result;
}

IccFile::~IccFile() {}

void IccFile::SetRilAndFileController(const std::shared_ptr<Telephony::ITelRilManager> &ril,
    const std::shared_ptr<IccFileController> &file, const std::shared_ptr<IccDiallingNumbersHandler> &handler)
{
    telRilManager_ = ril;
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("IccFile set NULL TelRilManager!!");
    }

    fileController_ = file;
    if (fileController_ == nullptr) {
        TELEPHONY_LOGE("IccFile set NULL File Controller!!");
    }
    diallingNumberHandler_ = handler;
    if (fileController_ == nullptr) {
        TELEPHONY_LOGE("IccFile set NULL File Controller!!");
    }
}

AppExecFwk::InnerEvent::Pointer IccFile::CreateDiallingNumberPointer(
    int eventid, int efId, int index, std::shared_ptr<void> pobj)
{
    std::unique_ptr<DiallingNumbersHandleHolder> holder = std::make_unique<DiallingNumbersHandleHolder>();
    holder->fileID = efId;
    holder->index = index;
    holder->diallingNumber = pobj;
    int eventParam = 0;
    AppExecFwk::InnerEvent::Pointer event = AppExecFwk::InnerEvent::Get(eventid, holder, eventParam);
    event->SetOwner(shared_from_this());
    return event;
}


void IccFile::NotifyRegistrySimState(CardType type, SimState state, LockReason reason)
{
    int32_t result =
        DelayedRefSingleton<TelephonyStateRegistryClient>::GetInstance().UpdateSimState(slotId_, type, state, reason);
    TELEPHONY_LOGI("NotifyRegistrySimState msgId is %{public}d ret %{public}d", state, result);
}

bool IccFile::HasSimCard()
{
    return (stateManager_ != nullptr) ? stateManager_->HasSimCard() : false;
}

void IccFile::UnInit()
{
    imsi_ = "";
    iccId_ = "";
    UpdateSPN("");
    UpdateLoaded(false);
    operatorNumeric_ = "";
    voiceMailNum_ = "";
    voiceMailTag_ = "";
    indexOfMailbox_ = 1;
    msisdn_ = "";
    gid1_ = "";
    gid2_ = "";
    msisdnTag_ = "";
}
} // namespace Telephony
} // namespace OHOS