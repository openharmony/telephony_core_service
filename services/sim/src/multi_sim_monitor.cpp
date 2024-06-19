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

#include "multi_sim_monitor.h"

#include <atomic>

#include "common_event_manager.h"
#include "common_event_support.h"
#include "os_account_manager_wrapper.h"
#include "operator_file_parser.h"
#include "radio_event.h"
#include "string_ex.h"
#include "telephony_errors.h"
#include "telephony_ext_wrapper.h"

namespace OHOS {
namespace Telephony {
const int64_t DELAY_TIME = 1000;
MultiSimMonitor::MultiSimMonitor(const std::shared_ptr<MultiSimController> &controller,
    std::vector<std::shared_ptr<Telephony::SimStateManager>> simStateManager,
    std::vector<std::weak_ptr<Telephony::SimFileManager>> simFileManager)
    : TelEventHandler("MultiSimMonitor"), controller_(controller), simStateManager_(simStateManager),
      simFileManager_(simFileManager)
{
    if (observerHandler_ == nullptr) {
        observerHandler_ = std::make_unique<ObserverHandler>();
    }
}

MultiSimMonitor::~MultiSimMonitor()
{
    TELEPHONY_LOGD("destory");
    UnSubscribeListeners();
}

void MultiSimMonitor::Init()
{
    TELEPHONY_LOGD("init");
    isSimAccountLoaded_.resize(SIM_SLOT_COUNT, 0);
    SendEvent(MultiSimMonitor::REGISTER_SIM_NOTIFY_EVENT);
    InitListener();
}

void MultiSimMonitor::AddExtraManagers(std::shared_ptr<Telephony::SimStateManager> simStateManager,
    std::shared_ptr<Telephony::SimFileManager> simFileManager)
{
    if (simStateManager_.size() == SIM_SLOT_COUNT) {
        simStateManager_.push_back(simStateManager);
        simFileManager_.push_back(simFileManager);
        isSimAccountLoaded_.push_back(0);
        RegisterSimNotify(SIM_SLOT_2);
    }
}

void MultiSimMonitor::ProcessEvent(const AppExecFwk::InnerEvent::Pointer &event)
{
    if (event == nullptr) {
        TELEPHONY_LOGE("start ProcessEvent but event is null!");
        return;
    }
    auto eventCode = event->GetInnerEventId();
    TELEPHONY_LOGI("eventCode is %{public}d", eventCode);
    switch (eventCode) {
        case RadioEvent::RADIO_QUERY_ICCID_DONE:
        case RadioEvent::RADIO_SIM_STATE_LOCKED:
        case RadioEvent::RADIO_SIM_STATE_READY: {
            auto slotId = event->GetParam();
            InitData(slotId);
            break;
        }
        case RadioEvent::RADIO_SIM_STATE_CHANGE: {
            auto slotId = event->GetParam();
            RefreshData(slotId);
            break;
        }
        case MultiSimMonitor::REGISTER_SIM_NOTIFY_EVENT: {
            RegisterSimNotify();
            break;
        }
        case MultiSimMonitor::RESET_OPKEY_CONFIG: {
            ClearAllOpcCache();
            UpdateAllOpkeyConfigs();
            break;
        }
        default:
            break;
    }
}

void MultiSimMonitor::CheckOpcNeedUpdata(const bool isDataShareError)
{
    TelFFRTUtils::Submit([&]() {
        bool isOpcVersionUpdated = CheckUpdateOpcVersion() == TELEPHONY_SUCCESS;
        if (isOpcVersionUpdated) {
            OperatorFileParser::ClearFilesCache();
        }
        TELEPHONY_LOGI("CheckOpcNeedUpdata isDataShareError: %{public}d, isOpcVersionUpdated: %{public}d",
            isDataShareError, isOpcVersionUpdated);
        if (isOpcVersionUpdated || isDataShareError) {
            SendEvent(MultiSimMonitor::RESET_OPKEY_CONFIG);
        }
    });
}

int32_t MultiSimMonitor::CheckUpdateOpcVersion()
{
    if (TELEPHONY_EXT_WRAPPER.checkOpcVersionIsUpdate_ != nullptr &&
        TELEPHONY_EXT_WRAPPER.updateOpcVersion_ != nullptr) {
        std::lock_guard<std::mutex> lock(mutexForData_);
        if (TELEPHONY_EXT_WRAPPER.checkOpcVersionIsUpdate_()) {
            TELEPHONY_LOGI("need update config");
            if (controller_->UpdateOpKeyInfo() != TELEPHONY_SUCCESS) {
                TELEPHONY_LOGW("UpdateOpKeyInfo error");
                return TELEPHONY_ERROR;
            }
            TELEPHONY_EXT_WRAPPER.updateOpcVersion_();
            TELEPHONY_LOGI("Version updated succ");
            return TELEPHONY_SUCCESS;
        }
    }
    return TELEPHONY_ERROR;
}

void MultiSimMonitor::ClearAllOpcCache()
{
    for (size_t slotId = 0; slotId < simFileManager_.size(); slotId++) {
        auto simFileManager = simFileManager_[slotId].lock();
        if (simFileManager == nullptr) {
            TELEPHONY_LOGE("simFileManager is nullptr, slotId : %{public}zu", slotId);
            continue;
        }
        simFileManager->DeleteOperatorCache();
    }
}

void MultiSimMonitor::UpdateAllOpkeyConfigs()
{
    for (size_t slotId = 0; slotId < simFileManager_.size(); slotId++) {
        auto simFileManager = simFileManager_[slotId].lock();
        if (simFileManager == nullptr) {
            TELEPHONY_LOGE("simFileManager is nullptr, slotId : %{public}zu", slotId);
            continue;
        }
        simFileManager->UpdateOpkeyConfig();
    }
}

void MultiSimMonitor::InitData(int32_t slotId)
{
    TELEPHONY_LOGI("MultiSimMonitor::InitData slotId = %{public}d", slotId);
    if (!IsValidSlotId(slotId)) {
        TELEPHONY_LOGE("MultiSimMonitor::InitData slotId is invalid");
        return;
    }
    if (controller_ == nullptr) {
        TELEPHONY_LOGE("MultiSimMonitor::InitData controller_ is nullptr");
        return;
    }
    if (!controller_->InitData(slotId)) {
        TELEPHONY_LOGE("MultiSimMonitor::InitData failed");
        return;
    }
    isSimAccountLoaded_[slotId] = 1;
    if (observerHandler_ == nullptr) {
        TELEPHONY_LOGE("MultiSimMonitor::InitData observerHandler_ is nullptr");
        return;
    }
    NotifySimAccountChanged();
    observerHandler_->NotifyObserver(RadioEvent::RADIO_SIM_ACCOUNT_LOADED, slotId);
}

void MultiSimMonitor::RefreshData(int32_t slotId)
{
    if (!IsValidSlotId(slotId)) {
        TELEPHONY_LOGE("MultiSimMonitor::RefreshData slotId is invalid");
        return;
    }
    auto simFileManager = simFileManager_[slotId].lock();
    if (controller_ == nullptr || simStateManager_[slotId] == nullptr || simFileManager == nullptr) {
        TELEPHONY_LOGE("MultiSimMonitor::RefreshData controller_ or simStateManager_ is nullptr");
        return;
    }
    if (simStateManager_[slotId]->GetSimState() == SimState::SIM_STATE_NOT_PRESENT) {
        TELEPHONY_LOGI("MultiSimMonitor::RefreshData clear data when sim is absent");
        controller_->ForgetAllData(slotId);
        controller_->GetListFromDataBase();
        isSimAccountLoaded_[slotId] = 0;
        simFileManager->ClearData();
    } else if (simStateManager_[slotId]->GetSimState() == SimState::SIM_STATE_UNKNOWN) {
        TELEPHONY_LOGI("MultiSimMonitor::RefreshData clear data when sim is unknown");
        simFileManager->ClearData();
    }
    if (controller_->unInitModemSlotId_ == slotId) {
        TELEPHONY_LOGI("need to recheck primary");
        controller_->ReCheckPrimary();
    }
    NotifySimAccountChanged();
}

void MultiSimMonitor::RegisterCoreNotify(
    int32_t slotId, const std::shared_ptr<AppExecFwk::EventHandler> &handler, int what)
{
    if (observerHandler_ == nullptr || handler == nullptr) {
        TELEPHONY_LOGE("observerHandler_ or handler is nullptr");
        return;
    }
    observerHandler_->RegObserver(what, handler);
    if (!IsValidSlotId(slotId)) {
        TELEPHONY_LOGE("MultiSimMonitor::RegisterCoreNotify slotId is invalid");
        return;
    }
    if (isSimAccountLoaded_[slotId] || IsVSimSlotId(slotId)) {
        TELEPHONY_LOGI("notify slotId:%{public}d sim account loaded", slotId);
        TelEventHandler::SendTelEvent(handler, RadioEvent::RADIO_SIM_ACCOUNT_LOADED, slotId, 0);
    }
}

bool MultiSimMonitor::IsValidSlotId(int32_t slotId)
{
    return (slotId >= DEFAULT_SIM_SLOT_ID) && slotId < static_cast<int32_t>(simStateManager_.size());
}

bool MultiSimMonitor::IsVSimSlotId(int32_t slotId)
{
    if (TELEPHONY_EXT_WRAPPER.getVSimSlotId_) {
        int vSimSlotId = DEFAULT_SIM_SLOT_ID_REMOVE;
        TELEPHONY_EXT_WRAPPER.getVSimSlotId_(vSimSlotId);
        return vSimSlotId == slotId;
    }
    return false;
}

void MultiSimMonitor::UnSubscribeListeners()
{
    if (dataShareSubscriber_ != nullptr && CommonEventManager::UnSubscribeCommonEvent(dataShareSubscriber_)) {
        dataShareSubscriber_ = nullptr;
        TELEPHONY_LOGI("Unsubscribe datashare ready success");
    }
    if (statusChangeListener_ != nullptr) {
        auto samgrProxy = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
        if (samgrProxy != nullptr) {
            samgrProxy->UnSubscribeSystemAbility(OHOS::COMMON_EVENT_SERVICE_ID, statusChangeListener_);
            statusChangeListener_ = nullptr;
            TELEPHONY_LOGI("Unsubscribe COMMON_EVENT_SERVICE_ID success");
        }
    }
}

void MultiSimMonitor::InitListener()
{
    auto samgrProxy = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    statusChangeListener_ = new (std::nothrow) SystemAbilityStatusChangeListener(*this);
    if (samgrProxy == nullptr || statusChangeListener_ == nullptr) {
        TELEPHONY_LOGE("samgrProxy or statusChangeListener_ is nullptr");
        return;
    }
    auto ret = samgrProxy->SubscribeSystemAbility(COMMON_EVENT_SERVICE_ID, statusChangeListener_);
    TELEPHONY_LOGI("SubscribeSystemAbility COMMON_EVENT_SERVICE_ID result is %{public}d", ret);
    CheckOpcNeedUpdata(false);
}

void MultiSimMonitor::SystemAbilityStatusChangeListener::OnAddSystemAbility(int32_t systemAbilityId,
    const std::string &deviceId)
{
    switch (systemAbilityId) {
        case COMMON_EVENT_SERVICE_ID: {
            TELEPHONY_LOGI("COMMON_EVENT_SERVICE_ID is running");
            handler_.SubscribeDataShareReady();
            break;
        }
        default:
            TELEPHONY_LOGE("systemAbilityId is invalid");
            break;
    }
}

void MultiSimMonitor::SystemAbilityStatusChangeListener::OnRemoveSystemAbility(int32_t systemAbilityId,
    const std::string &deviceId)
{
    switch (systemAbilityId) {
        case COMMON_EVENT_SERVICE_ID: {
            TELEPHONY_LOGI("COMMON_EVENT_SERVICE_ID stopped");
            break;
        }
        default:
            TELEPHONY_LOGE("systemAbilityId is invalid");
            break;
    }
}

void MultiSimMonitor::SubscribeDataShareReady()
{
    if (dataShareSubscriber_ != nullptr) {
        TELEPHONY_LOGW("datashare ready has Subscribed");
        return;
    }
    MatchingSkills matchingSkills;
    matchingSkills.AddEvent(DATASHARE_READY_EVENT);
    CommonEventSubscribeInfo subscriberInfo(matchingSkills);
    subscriberInfo.SetThreadMode(CommonEventSubscribeInfo::COMMON);
    dataShareSubscriber_ = std::make_shared<DataShareEventSubscriber>(subscriberInfo, *this);
    if (CommonEventManager::SubscribeCommonEvent(dataShareSubscriber_)) {
        TELEPHONY_LOGI("Subscribe datashare ready success");
    } else {
        dataShareSubscriber_ = nullptr;
        TELEPHONY_LOGE("Subscribe datashare ready fail");
    }
    CheckDataShareError();
}

void MultiSimMonitor::DataShareEventSubscriber::OnReceiveEvent(const CommonEventData &data)
{
    OHOS::EventFwk::Want want = data.GetWant();
    std::string action = want.GetAction();
    TELEPHONY_LOGI("action = %{public}s", action.c_str());
    if (action == DATASHARE_READY_EVENT) {
        handler_.CheckDataShareError();
    }
}

void MultiSimMonitor::CheckDataShareError()
{
    if (controller_->IsDataShareError()) {
        controller_->ResetDataShareError();
        CheckOpcNeedUpdata(true);
    }
}

int32_t MultiSimMonitor::RegisterSimAccountCallback(
    const int32_t tokenId, const sptr<SimAccountCallback> &callback)
{
    if (callback == nullptr) {
        TELEPHONY_LOGE(" callback is nullptr");
        return TELEPHONY_ERR_ARGUMENT_NULL;
    }
    std::lock_guard<std::mutex> lock(mutexInner_);
    bool isExisted = false;
    for (auto &iter : listSimAccountCallbackRecord_) {
        if (iter.tokenId == tokenId) {
            iter.simAccountCallback = callback;
            isExisted = true;
            break;
        }
    }
    if (isExisted) {
        TELEPHONY_LOGI("Ignore register action, since callback is existent");
        return TELEPHONY_SUCCESS;
    }

    SimAccountCallbackRecord simAccountRecord;
    simAccountRecord.tokenId = tokenId;
    simAccountRecord.simAccountCallback = callback;
    listSimAccountCallbackRecord_.push_back(simAccountRecord);
    TELEPHONY_LOGI("Register successfully, callback list size is %{public}zu", listSimAccountCallbackRecord_.size());
    return TELEPHONY_SUCCESS;
}

int32_t MultiSimMonitor::UnregisterSimAccountCallback(const int32_t tokenId)
{
    std::lock_guard<std::mutex> lock(mutexInner_);
    bool isSuccess = false;
    auto iter = listSimAccountCallbackRecord_.begin();
    for (; iter != listSimAccountCallbackRecord_.end();) {
        if (iter->tokenId == tokenId) {
            iter = listSimAccountCallbackRecord_.erase(iter);
            isSuccess = true;
            break;
        }
        iter++;
    }
    if (!isSuccess) {
        TELEPHONY_LOGE("Ignore unregister action, since callback is nonexistent");
        return TELEPHONY_ERROR;
    }
    TELEPHONY_LOGI("Unregister successfully, callback list size is %{public}zu", listSimAccountCallbackRecord_.size());
    return TELEPHONY_SUCCESS;
}

std::list<MultiSimMonitor::SimAccountCallbackRecord> MultiSimMonitor::GetSimAccountCallbackRecords()
{
    std::lock_guard<std::mutex> lock(mutexInner_);
    return listSimAccountCallbackRecord_;
}

void MultiSimMonitor::NotifySimAccountChanged()
{
    std::list<SimAccountCallbackRecord> CallbackRecord = GetSimAccountCallbackRecords();
    TELEPHONY_LOGD("CallbackRecord size is %{public}zu", CallbackRecord.size());
    for (auto iter : CallbackRecord) {
        if (iter.simAccountCallback != nullptr) {
            iter.simAccountCallback->OnSimAccountChanged();
        }
    }
    DelayedRefSingleton<TelephonyStateRegistryClient>::GetInstance().UpdateIccAccount();
}

void MultiSimMonitor::RegisterSimNotify()
{
    if (controller_ == nullptr) {
        TELEPHONY_LOGE("MultiSimController is null");
        return;
    }
    if (!controller_->ForgetAllData()) {
        if (remainCount_ > 0) {
            SendEvent(MultiSimMonitor::REGISTER_SIM_NOTIFY_EVENT, 0, DELAY_TIME);
            TELEPHONY_LOGI("retry remain %{public}d", static_cast<int32_t>(remainCount_));
            remainCount_--;
        }
        return;
    }
    TELEPHONY_LOGI("Register with time left %{public}d", static_cast<int32_t>(remainCount_));
    for (size_t slotId = 0; slotId < simFileManager_.size(); slotId++) {
        RegisterSimNotify(static_cast<int32_t>(slotId));
    }
}

void MultiSimMonitor::RegisterSimNotify(int32_t slotId)
{
    if (!IsValidSlotId(slotId)) {
        TELEPHONY_LOGE("RegisterSimNotify slotId is invalid");
        return;
    }
    auto simFileManager = simFileManager_[slotId].lock();
    if (simFileManager == nullptr) {
        TELEPHONY_LOGE("simFileManager is null slotId : %{public}d", slotId);
        return;
    }
    simFileManager->RegisterCoreNotify(shared_from_this(), RadioEvent::RADIO_QUERY_ICCID_DONE);
    if (simStateManager_[slotId] == nullptr) {
        TELEPHONY_LOGE("simStateManager is null slotId : %{public}d", slotId);
        return;
    }
    simStateManager_[slotId]->RegisterCoreNotify(shared_from_this(), RadioEvent::RADIO_SIM_STATE_CHANGE);
    simStateManager_[slotId]->RegisterCoreNotify(shared_from_this(), RadioEvent::RADIO_SIM_STATE_LOCKED);
    simStateManager_[slotId]->RegisterCoreNotify(shared_from_this(), RadioEvent::RADIO_SIM_STATE_READY);
    TELEPHONY_LOGI("RegisterSimNotify %{public}d", slotId);
}

void MultiSimMonitor::UnRegisterSimNotify()
{
    for (size_t slotId = 0; slotId < simFileManager_.size(); slotId++) {
        auto simFileManager = simFileManager_[slotId].lock();
        if (simFileManager == nullptr) {
            TELEPHONY_LOGE("simFileManager is null slotId : %{public}zu", slotId);
            continue;
        }
        simFileManager->UnRegisterCoreNotify(shared_from_this(), RadioEvent::RADIO_QUERY_ICCID_DONE);
        if (simStateManager_[slotId] == nullptr) {
            TELEPHONY_LOGE("simStateManager is null slotId : %{public}zu", slotId);
            continue;
        }
        simStateManager_[slotId]->UnRegisterCoreNotify(shared_from_this(), RadioEvent::RADIO_SIM_STATE_CHANGE);
        simStateManager_[slotId]->UnRegisterCoreNotify(shared_from_this(), RadioEvent::RADIO_SIM_STATE_LOCKED);
        simStateManager_[slotId]->UnRegisterCoreNotify(shared_from_this(), RadioEvent::RADIO_SIM_STATE_READY);
    }
}
} // namespace Telephony
} // namespace OHOS
