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

#include "core_manager_inner.h"
#include "if_system_ability_manager.h"
#include "inner_event.h"
#include "iservice_registry.h"
#include "radio_event.h"
#include "system_ability_definition.h"
#include "telephony_ext_wrapper.h"
#include "tel_event_handler.h"
#include "telephony_state_registry_client.h"

using namespace std;
using namespace OHOS::AppExecFwk;
using namespace OHOS::EventFwk;

namespace OHOS {
namespace Telephony {
constexpr int32_t OPKEY_VMSG_LENTH = 3;
constexpr int32_t VMSG_SLOTID_INDEX = 0;
constexpr int32_t VMSG_OPKEY_INDEX = 1;
constexpr int32_t VMSG_OPNAME_INDEX = 2;
std::unique_ptr<ObserverHandler> IccFile::filesFetchedObser_ = nullptr;
IccFile::IccFile(const std::string &name, std::shared_ptr<SimStateManager> simStateManager)
    : TelEventHandler(name), stateManager_(simStateManager)
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
    AddRecordsOverrideObser();
    AddOpkeyLoadObser();
    AddOperatorCacheDelObser();
    AddIccidLoadObser();
    TELEPHONY_LOGI("simmgr IccFile::IccFile finish");
}

void IccFile::Init()
{
    if (stateManager_ != nullptr) {
        stateManager_->RegisterCoreNotify(shared_from_this(), RadioEvent::RADIO_SIM_STATE_READY);
        stateManager_->RegisterCoreNotify(shared_from_this(), RadioEvent::RADIO_SIM_STATE_LOCKED);
        stateManager_->RegisterCoreNotify(shared_from_this(), RadioEvent::RADIO_SIM_STATE_SIMLOCK);
    }
}

void IccFile::StartLoad()
{
    TELEPHONY_LOGI("IccFile::StarLoad start");
}

void IccFile::SetId(int id)
{
    slotId_ = id;
    TELEPHONY_LOGI("IccFile::SetId, slotId %{public}d.", id);
    voiceMailConfig_ = std::make_shared<VoiceMailConstants>(id);
}

bool IccFile::GetIsVoiceMailFixed()
{
    return isVoiceMailFixed_;
}

void IccFile::SetVoiceMailByOperator(std::string spn)
{
    if (voiceMailConfig_ == nullptr) {
        TELEPHONY_LOGE("IccFile::SetVoiceMailByOperator, voiceMailConfig_ is null.");
        return;
    }
    if (voiceMailConfig_->ContainsCarrier(spn)) {
        std::unique_lock<std::shared_mutex> lock(voiceMailMutex_);
        isVoiceMailFixed_ = voiceMailConfig_->GetVoiceMailFixed(spn);
        voiceMailNum_ = voiceMailConfig_->GetVoiceMailNumber(spn);
        voiceMailTag_ = voiceMailConfig_->GetVoiceMailTag(spn);
    } else {
        TELEPHONY_LOGI("IccFile::SetVoiceMailByOperator, ContainsCarrier fail.");
        std::unique_lock<std::shared_mutex> lock(voiceMailMutex_);
        isVoiceMailFixed_ = false;
    }
}

std::string IccFile::ObtainIMSI()
{
    if (imsi_.empty()) {
        TELEPHONY_LOGD("IccFile::ObtainIMSI is null:");
    }
    return imsi_;
}

std::unordered_set<std::string> IccFile::ObtainEhPlmns()
{
    if (ehplmns_.empty()) {
        TELEPHONY_LOGD("IccFile::ObtainEhPlmns is null:");
    }
    return ehplmns_;
}

std::unordered_set<std::string> IccFile::ObtainSpdiPlmns()
{
    if (spdiPlmns_.empty()) {
        TELEPHONY_LOGD("IccFile::ObtainSpdiPlmns is null:");
    }
    return spdiPlmns_;
}

std::string IccFile::ObtainMCC()
{
    if (imsi_.empty()) {
        TELEPHONY_LOGI("IccFile::ObtainMCC is null:");
    }
    return mcc_;
}

std::string IccFile::ObtainMNC()
{
    if (imsi_.empty()) {
        TELEPHONY_LOGI("IccFile::ObtainMNC is null:");
    }
    return mnc_;
}

void IccFile::UpdateImsi(std::string imsi)
{
    imsi_ = imsi;
}

void IccFile::UpdateIccId(std::string iccid)
{
    iccId_ = iccid;
}

std::string IccFile::ObtainIccId()
{
    return iccId_;
}

std::string IccFile::ObtainDecIccId()
{
    return decIccId_;
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

bool IccFile::UpdateMsisdnNumber(const std::string &alphaTag, const std::string &number)
{
    return false;
}

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

int32_t IccFile::ObtainVoiceMailCount()
{
    return voiceMailCount_;
}

std::string IccFile::ObtainSPN()
{
    return spn_;
}

bool IccFile::ObtainEonsExternRules(const std::vector<std::shared_ptr<OperatorPlmnInfo>> oplFiles, bool roaming,
    std::string &eons, bool longNameRequired, const std::string &plmn)
{
    if ((oplFiles.empty() && !pnnFiles_.empty()) && pnnFiles_.at(0) != nullptr && !roaming) {
        TELEPHONY_LOGI("get PNN");
        if (longNameRequired) {
            eons = pnnFiles_.at(0)->longName; // 0 means the first record
        } else {
            eons = pnnFiles_.at(0)->shortName;
        }
        return true;
    }
    if (pnnFiles_.empty() && !roaming) {
        TELEPHONY_LOGI("get CPHS");
        if (!spnCphs_.empty()) {
            eons = spnCphs_;
            return true;
        } else if (!spnShortCphs_.empty()) {
            eons = spnShortCphs_;
            return true;
        }
    }
    if (plmn.empty() || pnnFiles_.empty() || (oplFiles.empty() && roaming)) {
        TELEPHONY_LOGE("ObtainEons is empty");
        eons = "";
        return true;
    }
    return false;
}

std::string IccFile::ObtainEons(const std::string &plmn, int32_t lac, bool longNameRequired)
{
    std::vector<std::shared_ptr<OperatorPlmnInfo>> oplFiles = oplFiles_;
    sptr<NetworkState> networkState = nullptr;
    CoreManagerInner::GetInstance().GetNetworkStatus(slotId_, networkState);
    if (!isOplFileResponsed_ || !isOpl5gFileResponsed_) {
        return "";
    }
    if (networkState != nullptr && isOpl5gFilesPresent_) {
        NrState nrState = networkState->GetNrState();
        if (nrState == NrState::NR_NSA_STATE_SA_ATTACHED) {
            oplFiles = opl5gFiles_;
        }
    }
    bool roaming = (plmn.compare(operatorNumeric_) == 0 ? false : true);
    TELEPHONY_LOGI("ObtainEons roaming:%{public}d", roaming);
    std::string eons = "";

    if (ObtainEonsExternRules(oplFiles, roaming, eons, longNameRequired, plmn)) {
        return eons;
    }
    int pnnIndex = 1;
    for (std::shared_ptr<OperatorPlmnInfo> opl : oplFiles) {
        if (opl == nullptr) {
            continue;
        }
        pnnIndex = -1;
        TELEPHONY_LOGI("ObtainEons plmn:%{public}s, opl->plmnNumeric:%{public}s, lac:%{public}d, "
                       "opl->lacStart:%{public}d, opl->lacEnd:%{public}d, opl->pnnRecordId:%{public}d",
            plmn.c_str(), opl->plmnNumeric.c_str(), lac, opl->lacStart, opl->lacEnd, opl->pnnRecordId);
        if (plmn.compare(opl->plmnNumeric) == 0 &&
            ((opl->lacStart == 0 && opl->lacEnd == 0xfffe) || (opl->lacStart <= lac && opl->lacEnd >= lac))) {
            pnnIndex = opl->pnnRecordId;
            TELEPHONY_LOGI("ObtainEons pnnIndex:%{public}d", pnnIndex);
            break;
        }
    }

    if (pnnIndex >= 1 && pnnIndex <= static_cast<int>(pnnFiles_.size())) {
        TELEPHONY_LOGI("ObtainEons longNameRequired:%{public}d, longName:%{public}s, shortName:%{public}s,",
            longNameRequired, pnnFiles_.at(pnnIndex - 1)->longName.c_str(),
            pnnFiles_.at(pnnIndex - 1)->shortName.c_str());
        if (longNameRequired) {
            eons = pnnFiles_.at(pnnIndex - 1)->longName;
        } else {
            eons = pnnFiles_.at(pnnIndex - 1)->shortName;
        }
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
    if (event == nullptr) {
        TELEPHONY_LOGE("event is nullptr!");
        return;
    }
    auto id = event->GetInnerEventId();
    bool result = false;
    TELEPHONY_LOGD("IccFile::ProcessEvent id %{public}d", id);
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

void IccFile::LoadVoiceMail()
{
    if (voiceMailConfig_ == nullptr) {
        TELEPHONY_LOGE("IccFile::LoadVoiceMail, voiceMailConfig_ is null.");
        return;
    }
    voiceMailConfig_->ResetVoiceMailLoadedFlag();
    std::string operatorNumeric = ObtainSimOperator();
    SetVoiceMailByOperator(operatorNumeric);
}

void IccFile::RegisterImsiLoaded(std::shared_ptr<AppExecFwk::EventHandler> eventHandler)
{
    int eventCode = RadioEvent::RADIO_IMSI_LOADED_READY;
    if (imsiReadyObser_ != nullptr) {
        imsiReadyObser_->RegObserver(eventCode, eventHandler);
    }
    if (!ObtainIMSI().empty()) {
        if (eventHandler != nullptr) {
            TelEventHandler::SendTelEvent(eventHandler, RadioEvent::RADIO_IMSI_LOADED_READY);
        }
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
        TELEPHONY_LOGD("IccFile::RegisterAllFilesLoaded: registerd, slotId:%{public}d", slotId_);
    }
    if (ObtainFilesFetched()) {
        TELEPHONY_LOGI("IccFile::RegisterAllFilesLoaded: notify, slotId:%{public}d", slotId_);
        if (eventHandler != nullptr) {
            TelEventHandler::SendTelEvent(eventHandler, RadioEvent::RADIO_SIM_RECORDS_LOADED, slotId_, 0);
        }
        PublishSimFileEvent(EventFwk::CommonEventSupport::COMMON_EVENT_SIM_STATE_CHANGED,
            static_cast<int32_t>(SimState::SIM_STATE_LOADED), "");
    }
}

void IccFile::UnregisterAllFilesLoaded(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    if (filesFetchedObser_ != nullptr) {
        filesFetchedObser_->Remove(RadioEvent::RADIO_SIM_RECORDS_LOADED, handler);
    }
}

void IccFile::RegisterOpkeyLoaded(std::shared_ptr<AppExecFwk::EventHandler> eventHandler)
{
    int eventCode = RadioEvent::RADIO_SIM_OPKEY_LOADED;
    if (opkeyLoadObser_ != nullptr) {
        opkeyLoadObser_->RegObserver(eventCode, eventHandler);
    }
    TELEPHONY_LOGD("IccFile::RegisterOpkeyLoaded: registered");
}

void IccFile::RegisterOperatorCacheDel(std::shared_ptr<AppExecFwk::EventHandler> eventHandler)
{
    int eventCode = RadioEvent::RADIO_OPERATOR_CACHE_DELETE;
    if (operatorCacheDelObser_ != nullptr) {
        operatorCacheDelObser_->RegObserver(eventCode, eventHandler);
    }
    TELEPHONY_LOGD("IccFile::RegisterOperatorCacheDel: registered");
}

void IccFile::RegisterIccidLoaded(std::shared_ptr<AppExecFwk::EventHandler> eventHandler)
{
    int eventCode = RadioEvent::RADIO_QUERY_ICCID_DONE;
    if (iccidLoadObser_ != nullptr) {
        iccidLoadObser_->RegObserver(eventCode, eventHandler);
        TELEPHONY_LOGI("IccFile::RegisterIccidLoaded: registered, slotId:%{public}d", slotId_);
    }
    if (!iccId_.empty()) {
        TELEPHONY_LOGI("IccFile::RegisterIccidLoaded: notify, slotId:%{public}d", slotId_);
        if (eventHandler != nullptr) {
            TelEventHandler::SendTelEvent(eventHandler, RadioEvent::RADIO_QUERY_ICCID_DONE, slotId_, 0);
        }
    }
}

void IccFile::UnregisterOpkeyLoaded(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    if (opkeyLoadObser_ != nullptr) {
        opkeyLoadObser_->Remove(RadioEvent::RADIO_SIM_OPKEY_LOADED, handler);
    }
}

void IccFile::UnregisterOperatorCacheDel(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    if (operatorCacheDelObser_ != nullptr) {
        operatorCacheDelObser_->Remove(RadioEvent::RADIO_OPERATOR_CACHE_DELETE, handler);
    }
}

void IccFile::UnregisterIccidLoaded(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    if (iccidLoadObser_ != nullptr) {
        iccidLoadObser_->Remove(RadioEvent::RADIO_QUERY_ICCID_DONE, handler);
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
        case RadioEvent::RADIO_SIM_OPKEY_LOADED:
            RegisterOpkeyLoaded(handler);
            break;
        case RadioEvent::RADIO_OPERATOR_CACHE_DELETE:
            RegisterOperatorCacheDel(handler);
            break;
        case RadioEvent::RADIO_QUERY_ICCID_DONE:
            RegisterIccidLoaded(handler);
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
        case RadioEvent::RADIO_SIM_OPKEY_LOADED:
            UnregisterOpkeyLoaded(handler);
            break;
        case RadioEvent::RADIO_OPERATOR_CACHE_DELETE:
            UnregisterOperatorCacheDel(handler);
            break;
        case RadioEvent::RADIO_QUERY_ICCID_DONE:
            UnregisterIccidLoaded(handler);
            break;
        default:
            TELEPHONY_LOGI("UnregisterCoreNotify default");
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
    if (event == nullptr) {
        TELEPHONY_LOGE("event is nullptr!");
        return AppExecFwk::InnerEvent::Pointer(nullptr, nullptr);
    }
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
    if (event == nullptr) {
        TELEPHONY_LOGE("event is nullptr!");
        return AppExecFwk::InnerEvent::Pointer(nullptr, nullptr);
    }
    event->SetOwner(shared_from_this());
    return event;
}

AppExecFwk::InnerEvent::Pointer IccFile::BuildCallerInfo(int eventId, std::shared_ptr<void> loader)
{
    std::unique_ptr<FileToControllerMsg> object = std::make_unique<FileToControllerMsg>();
    object->iccLoader = loader;
    int eventParam = 0;
    AppExecFwk::InnerEvent::Pointer event = AppExecFwk::InnerEvent::Get(eventId, object, eventParam);
    if (event == nullptr) {
        TELEPHONY_LOGE("event is nullptr!");
        return AppExecFwk::InnerEvent::Pointer(nullptr, nullptr);
    }
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
    publishInfo.SetOrdered(false);
    bool publishResult = CommonEventManager::PublishCommonEvent(data, publishInfo, nullptr);
    TELEPHONY_LOGI("IccFile::PublishSimEvent result : %{public}d", publishResult);
    return publishResult;
}

bool IccFile::ProcessIccFileObtained(const AppExecFwk::InnerEvent::Pointer &event)
{
    bool isFileProcessResponse = true;
    std::shared_ptr<ControllerToFileMsg> fd = event->GetSharedObject<ControllerToFileMsg>();
    if (fd == nullptr) {
        TELEPHONY_LOGE("fd is nullptr!");
        return isFileProcessResponse;
    }
    std::shared_ptr<void> baseLoad = fd->iccLoader;
    if (baseLoad != nullptr) {
        std::shared_ptr<IccFileLoaded> destLoad = std::static_pointer_cast<IccFileLoaded>(baseLoad);
        destLoad->ProcessParseFile(event);
        TELEPHONY_LOGI("ProcessIccFileObtained item %{public}s", destLoad->ObtainElementaryFileName().c_str());
    } else {
        isFileProcessResponse = false;
        TELEPHONY_LOGE("IccFile::ProcessIccFileObtained null base pointer");
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
    if (ucc == nullptr) {
        TELEPHONY_LOGE("ucc is nullptr!!");
        return "";
    }
    unsigned char *data = ucc.get();

    if (data == nullptr) {
        TELEPHONY_LOGE("data is nullptr!!");
        return "";
    }

    int dataLen = static_cast<int>(strlen(reinterpret_cast<char *>(data)));
    TELEPHONY_LOGI("ObtainValidLanguage all is %{public}s---%{public}d, dataLen:%{public}d",
        data, langDataLen, dataLen);
    if (langDataLen > dataLen) {
        langDataLen = dataLen;
    }
    for (int i = 0; (i + 1) < langDataLen; i += DATA_STEP) {
        std::string langName((char *)data, i, DATA_STEP);
        TELEPHONY_LOGI("ObtainValidLanguage item is %{public}d--%{public}s", i, langName.c_str());
        if (!langName.empty()) {
            return langName;
        }
    }
    return "";
}

void IccFile::SwapPairsForIccId(std::string &iccId)
{
    if (iccId.empty() || iccId.length() < LENGTH_TWO) {
        return;
    }
    std::string result = "";
    for (size_t i = 0; i < iccId.length() - 1; i += DATA_STEP) {
        if (iccId[i + 1] > '9') {
            break;
        }
        result += iccId[i + 1];
        if (iccId[i] == 'F') {
            continue;
        }
        if (iccId[i] > '9') {
            break;
        }
        result += iccId[i];
    }
    iccId = result;
}

void IccFile::GetFullIccid(std::string &iccId)
{
    if (iccId.empty() || iccId.length() < LENGTH_TWO) {
        return;
    }
    std::string result = "";
    for (size_t i = 0; i < iccId.length() - 1; i += DATA_STEP) {
        result += iccId[i + 1];
        result += iccId[i];
    }
    iccId = result;
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
    if (event == nullptr) {
        TELEPHONY_LOGE("event is nullptr!");
        return AppExecFwk::InnerEvent::Pointer(nullptr, nullptr);
    }
    event->SetOwner(shared_from_this());
    return event;
}


void IccFile::NotifyRegistrySimState(CardType type, SimState state, LockReason reason)
{
    if (stateManager_ != nullptr) {
        stateManager_->SetSimState(state);
    }
    int32_t result =
        DelayedRefSingleton<TelephonyStateRegistryClient>::GetInstance().UpdateSimState(slotId_, type, state, reason);
    TELEPHONY_LOGI("NotifyRegistrySimState slotId: %{public}d, simState: %{public}d, ret: %{public}d", slotId_, state,
        result);
}

bool IccFile::HasSimCard()
{
    return (stateManager_ != nullptr) ? stateManager_->HasSimCard() : false;
}

void IccFile::ResetVoiceMailVariable()
{
    std::unique_lock<std::shared_mutex> lock(voiceMailMutex_);
    isVoiceMailFixed_ = false;
    voiceMailNum_ = "";
    voiceMailTag_ = "";
    if (TELEPHONY_EXT_WRAPPER.resetVoiceMailManagerExt_ != nullptr) {
        TELEPHONY_EXT_WRAPPER.resetVoiceMailManagerExt_(slotId_);
    }
}

void IccFile::ClearData()
{
    TELEPHONY_LOGI("IccFile ClearData");
    imsi_ = "";
    iccId_ = "";
    decIccId_ = "";
    UpdateSPN("");
    UpdateLoaded(false);
    operatorNumeric_ = "";
    mcc_ = "";
    mnc_ = "";
    lengthOfMnc_ = UNINITIALIZED_MNC;
    indexOfMailbox_ = 1;
    msisdn_ = "";
    gid1_ = "";
    gid2_ = "";
    msisdnTag_ = "";
    spnCphs_ = "";
    spnShortCphs_ = "";
    isOpl5gFilesPresent_ = false;
    isOplFileResponsed_ = false;
    isOpl5gFileResponsed_ = false;
    fileQueried_ = false;
    pnnFiles_.clear();
    oplFiles_.clear();
    opl5gFiles_.clear();
    spdiPlmns_.clear();
    ehplmns_.clear();

    ResetVoiceMailVariable();
    auto iccFileExt = iccFile_.lock();
    if (TELEPHONY_EXT_WRAPPER.createIccFileExt_ != nullptr && iccFileExt) {
        iccFileExt->ClearData();
    }
}

void IccFile::ProcessIccLocked()
{
    TELEPHONY_LOGI("IccFile ProcessIccLocked");
    fileQueried_ = false;
    UpdateLoaded(false);
}

void IccFile::UnInit()
{
    if (stateManager_ != nullptr) {
        stateManager_->UnRegisterCoreNotify(shared_from_this(), RadioEvent::RADIO_SIM_STATE_READY);
        stateManager_->UnRegisterCoreNotify(shared_from_this(), RadioEvent::RADIO_SIM_STATE_LOCKED);
        stateManager_->UnRegisterCoreNotify(shared_from_this(), RadioEvent::RADIO_SIM_STATE_SIMLOCK);
    }
    ClearData();
}

void IccFile::SaveCountryCode()
{
    std::string countryCode = ObtainIsoCountryCode();
    std::string key = COUNTRY_CODE_KEY + std::to_string(slotId_);
    SetParameter(key.c_str(), countryCode.c_str());
}

void IccFile::ProcessExtGetFileResponse()
{
    bool response = true;
    ProcessFileLoaded(response);
}

void IccFile::ProcessExtGetFileDone(const AppExecFwk::InnerEvent::Pointer &event)
{
    ProcessEvent(event);
}

void IccFile::SetIccFile(std::shared_ptr<OHOS::Telephony::IIccFileExt>& iccFileExt)
{
    iccFile_ = iccFileExt;
}

void IccFile::OnOpkeyLoad(const std::string opkey, const std::string opName)
{
    TELEPHONY_LOGI("OnOpkeyLoad slotId: %{public}d opkey: %{public}s opName: %{public}s",
        slotId_, opkey.data(), opName.data());
    if (opkeyLoadObser_ != nullptr) {
        std::vector<std::string> vMsg(OPKEY_VMSG_LENTH, "");
        vMsg[VMSG_SLOTID_INDEX] = std::to_string(slotId_);
        vMsg[VMSG_OPKEY_INDEX] = opkey;
        vMsg[VMSG_OPNAME_INDEX] = opName;
        auto obj = std::make_shared<std::vector<std::string>>(vMsg);
        opkeyLoadObser_->NotifyObserver(RadioEvent::RADIO_SIM_OPKEY_LOADED, obj);
    }
}

bool IccFile::ExecutOriginalSimIoRequest(int32_t fileId, int fileIdDone)
{
    TELEPHONY_LOGD("ExecutOriginalSimIoRequest simfile: %{public}x doneId: %{public}x", fileId, fileIdDone);
    AppExecFwk::InnerEvent::Pointer event = BuildCallerInfo(fileIdDone);
    fileController_->ObtainBinaryFile(fileId, event);
    return true;
}

void IccFile::AddOpkeyLoadObser()
{
    opkeyLoadObser_ = std::make_unique<ObserverHandler>();
    if (opkeyLoadObser_ == nullptr) {
        TELEPHONY_LOGE("IccFile::IccFile opkeyLoadObser_ create nullptr.");
        return;
    }
}

void IccFile::AddOperatorCacheDelObser()
{
    operatorCacheDelObser_ = std::make_unique<ObserverHandler>();
    if (operatorCacheDelObser_ == nullptr) {
        TELEPHONY_LOGE("IccFile::IccFile opkeyLoadObser_ create nullptr.");
        return;
    }
}

void IccFile::AddRecordsOverrideObser()
{
    recordsOverrideObser_ = std::make_unique<ObserverHandler>();
    if (recordsOverrideObser_ == nullptr) {
        TELEPHONY_LOGE("IccFile::IccFile recordsOverrideObser_ create nullptr.");
        return;
    }
}

void IccFile::AddIccidLoadObser()
{
    iccidLoadObser_ = std::make_unique<ObserverHandler>();
    if (iccidLoadObser_ == nullptr) {
        TELEPHONY_LOGE("IccFile::IccFile iccidLoadObser_ create nullptr.");
        return;
    }
}

void IccFile::FileChangeToExt(const std::string fileName, const FileChangeType fileLoad)
{
    auto iccFileExt = iccFile_.lock();
    if (TELEPHONY_EXT_WRAPPER.createIccFileExt_ != nullptr && iccFileExt) {
        iccFileExt->FileChange(fileName, fileLoad);
    }
}

void IccFile::AddRecordsToLoadNum()
{
    fileToGet_++;
}

void IccFile::DeleteOperatorCache()
{
    if (operatorCacheDelObser_ != nullptr) {
        operatorCacheDelObser_->NotifyObserver(RadioEvent::RADIO_OPERATOR_CACHE_DELETE, slotId_);
    }
}

void IccFile::UpdateOpkeyConfig()
{
    if (filesFetchedObser_ != nullptr && ObtainFilesFetched()) {
        filesFetchedObser_->NotifyObserver(RadioEvent::RADIO_SIM_RECORDS_LOADED, slotId_);
    }
}
} // namespace Telephony
} // namespace OHOS
