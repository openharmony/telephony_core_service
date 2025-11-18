/*
 * Copyright (C) 2021-2024 Huawei Device Co., Ltd.
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

#include "os_account_manager_wrapper.h"
#include "operator_file_parser.h"
#include "radio_event.h"
#include "string_ex.h"
#include "telephony_errors.h"
#include "telephony_ext_wrapper.h"
#include "sim_account_callback_death_recipient.h"
#include "core_manager_inner.h"

namespace OHOS {
namespace Telephony {
const int64_t DELAY_TIME = 1000;
const int64_t DELAY_THREE_SECONDS = 3000;
const int64_t RETRY_TIME = 3 * 60 * 1000;
const int32_t ACTIVE_USER_ID = 100;
const int INIT_TIMES = 15;
const int INIT_DATA_TIMES = 10;
constexpr const char *IS_BLOCK_LOAD_OPERATORCONFIG = "telephony.is_block_load_operatorconfig";
const std::string PROP_REBOOT_DETECT_SIM = "persist.ril.reboot_detect_sim";
MultiSimMonitor::MultiSimMonitor(const std::shared_ptr<MultiSimController> &controller,
    std::vector<std::shared_ptr<Telephony::SimStateManager>> simStateManager,
    std::vector<std::weak_ptr<Telephony::SimFileManager>> simFileManager)
    : TelEventHandler("MultiSimMonitor"), controller_(controller), simStateManager_(simStateManager),
      simFileManager_(simFileManager), initEsimDataRemainCount_(INIT_DATA_TIMES)
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
    initDataRemainCount_.resize(SIM_SLOT_COUNT, INIT_DATA_TIMES);
    initEsimDataRemainCount_ = INIT_DATA_TIMES;
    std::lock_guard<ffrt::shared_mutex> lock(controller_->loadedSimCardInfoMutex_);
    controller_->loadedSimCardInfo_.clear();
    SendEvent(MultiSimMonitor::REGISTER_SIM_NOTIFY_EVENT);
    InitListener();
    SendEvent(MultiSimMonitor::INIT_ESIM_DATA_EVENT);
}

void MultiSimMonitor::AddExtraManagers(std::shared_ptr<Telephony::SimStateManager> simStateManager,
    std::shared_ptr<Telephony::SimFileManager> simFileManager)
{
    if (static_cast<int32_t>(simStateManager_.size()) == SIM_SLOT_COUNT) {
        {
            std::unique_lock<ffrt::shared_mutex> lock(simStateMgrMutex_);
            simStateManager_.push_back(simStateManager);
            simFileManager_.push_back(simFileManager);
            isSimAccountLoaded_.push_back(0);
            initDataRemainCount_.push_back(INIT_DATA_TIMES);
        }
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
    switch (eventCode) {
        case MultiSimMonitor::INIT_DATA_RETRY_EVENT:
            InitData(event->GetParam());
            break;
        case MultiSimMonitor::INIT_ESIM_DATA_EVENT:
            RemoveEvent(MultiSimMonitor::INIT_ESIM_DATA_RETRY_EVENT);
            InitEsimData();
            break;
        case MultiSimMonitor::INIT_ESIM_DATA_RETRY_EVENT:
            InitEsimData();
            break;
        case RadioEvent::RADIO_QUERY_ICCID_DONE:
        case RadioEvent::RADIO_SIM_STATE_LOCKED:
        case RadioEvent::RADIO_SIM_STATE_READY:
            RemoveEvent(MultiSimMonitor::INIT_DATA_RETRY_EVENT);
            InitData(event->GetParam());
            break;
        case RadioEvent::RADIO_SIM_STATE_CHANGE:
            hasSimStateChanged_ = true;
            RefreshData(event->GetParam());
            break;
        case MultiSimMonitor::REGISTER_SIM_NOTIFY_EVENT:
            RemoveEvent(MultiSimMonitor::REGISTER_SIM_NOTIFY_RETRY_EVENT);
            RegisterSimNotify();
            break;
        case MultiSimMonitor::REGISTER_SIM_NOTIFY_RETRY_EVENT:
            RegisterSimNotify();
            break;
        case MultiSimMonitor::RESET_OPKEY_CONFIG:
            RemoveEvent(MultiSimMonitor::RETRY_RESET_OPKEY_CONFIG);
            UpdateAllOpkeyConfigs();
            break;
        case MultiSimMonitor::RETRY_RESET_OPKEY_CONFIG:
            RemoveEvent(MultiSimMonitor::RETRY_RESET_OPKEY_CONFIG);
            CheckDataShareError();
            CheckSimNotifyRegister();
            break;
        default:
            break;
    }
}

void MultiSimMonitor::CheckOpcNeedUpdata(const bool isDataShareError)
{
    TelFFRTUtils::Submit([=]() {
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
            SetBlockLoadOperatorConfig(true);
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

void MultiSimMonitor::SetBlockLoadOperatorConfig(bool isBlockLoadOperatorConfig)
{
    if (!isBlockLoadOperatorConfig) {
        return;
    }
    for (int32_t slotId = 0; slotId < SIM_SLOT_COUNT; slotId++) {
        std::string key = "";
        SetParameter(key.append(IS_BLOCK_LOAD_OPERATORCONFIG).append(std::to_string(slotId)).c_str(), "true");
    }
}

bool MultiSimMonitor::GetBlockLoadOperatorConfig()
{
    std::string key = "";
    char isBlockLoadOperatorConfig[SYSPARA_SIZE] = {0};
    for (int32_t slotId = 0; slotId < SIM_SLOT_COUNT; slotId++) {
        key.clear();
        key.append(IS_BLOCK_LOAD_OPERATORCONFIG).append(std::to_string(slotId));
        GetParameter(key.c_str(), "false", isBlockLoadOperatorConfig, SYSPARA_SIZE);
        if (strcmp(isBlockLoadOperatorConfig, "true") == 0) {
            return true;
        }
    }
    return false;
}

void MultiSimMonitor::UpdateAllOpkeyConfigs()
{
    std::shared_lock<ffrt::shared_mutex> lock(simStateMgrMutex_);
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
    if (isSimAccountLoaded_[slotId]) {
        TELEPHONY_LOGI("MultiSimMonitor::InitData simAccountInfo is already loaded");
        return;
    }
    if (controller_ == nullptr) {
        TELEPHONY_LOGE("MultiSimMonitor::InitData controller_ is nullptr");
        return;
    }
    // InitData is triggered when the sim card file changes.
    // However, it should not be excuted when the eSIM profile is disabled.
    if ((simStateManager_[slotId]->GetSimState() == SimState::SIM_STATE_UNKNOWN) && controller_->IsEsim(slotId)) {
        TELEPHONY_LOGE("MultiSimMonitor::InitData not init when esim is deactivated");
        return;
    }
    if (!controller_->InitData(slotId)) {
        TELEPHONY_LOGE("MultiSimMonitor::InitData failed");
        if (initDataRemainCount_[slotId] > 0) {
            SendEvent(MultiSimMonitor::INIT_DATA_RETRY_EVENT, slotId, DELAY_TIME);
            TELEPHONY_LOGI("retry remain %{public}d", initDataRemainCount_[slotId]);
            initDataRemainCount_[slotId]--;
        }
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

void MultiSimMonitor::InitEsimData()
{
    if (isAllSimAccountLoaded_) {
        TELEPHONY_LOGE("MultiSimMonitor::InitEsimData already loaded");
        return;
    }
    if (controller_ == nullptr) {
        TELEPHONY_LOGE("MultiSimMonitor::controller_ is nullptr");
        return;
    }
    if (!controller_->InitEsimData()) {
        TELEPHONY_LOGE("MultiSimMonitor::InitEsimData failed");
        if (initEsimDataRemainCount_ > 0) {
            SendEvent(MultiSimMonitor::INIT_ESIM_DATA_RETRY_EVENT, DELAY_THREE_SECONDS);
            TELEPHONY_LOGI("retry remain %{public}d", initEsimDataRemainCount_);
            initEsimDataRemainCount_--;
        }
        return;
    }
    isAllSimAccountLoaded_ = true;
    NotifySimAccountChanged();
}

void MultiSimMonitor::RefreshData(int32_t slotId)
{
    if (!IsValidSlotId(slotId)) {
        TELEPHONY_LOGE("MultiSimMonitor::RefreshData slotId is invalid");
        return;
    }
    std::shared_lock<ffrt::shared_mutex> lock(simStateMgrMutex_);
    auto simFileManager = simFileManager_[slotId].lock();
    if (controller_ == nullptr || simStateManager_[slotId] == nullptr || simFileManager == nullptr) {
        TELEPHONY_LOGE("MultiSimMonitor::RefreshData controller_ or simStateManager_ is nullptr");
        return;
    }
    if ((simStateManager_[slotId]->GetSimState() == SimState::SIM_STATE_NOT_PRESENT) ||
        ((simStateManager_[slotId]->GetSimState() == SimState::SIM_STATE_UNKNOWN) && controller_->IsEsim(slotId))) {
        HILOG_COMM_INFO("MultiSimMonitor::RefreshData clear data when slotId %{public}d is absent or is esim", slotId);
        simFileManager->ClearData();
        controller_->ForgetAllData(slotId);
        controller_->GetListFromDataBase();
        controller_->GetAllListFromDataBase();
        controller_->ResetSetPrimarySlotRemain(slotId);
        isSimAccountLoaded_[slotId] = 0;
        initDataRemainCount_[slotId] = INIT_DATA_TIMES;
        std::lock_guard<ffrt::shared_mutex> lock(controller_->loadedSimCardInfoMutex_);
        controller_->loadedSimCardInfo_.erase(slotId);
    } else if (simStateManager_[slotId]->GetSimState() == SimState::SIM_STATE_UNKNOWN &&
                !controller_->IsSetPrimarySlotIdInProgress()) {
        HILOG_COMM_INFO("MultiSimMonitor::RefreshData clear data when sim is unknown");
        simFileManager->ClearData();
        isSimAccountLoaded_[slotId] = 0;
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
    CoreManagerInner::GetInstance().UnregisterCommonEventCallback(dataShareSubscriber_);
    CoreManagerInner::GetInstance().UnregisterCommonEventCallback(userSwitchSubscriber_);
    dataShareSubscriber_ = nullptr;
    userSwitchSubscriber_ = nullptr;

    if (statusChangeListener_ != nullptr) {
        auto samgrProxy = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
        if (samgrProxy != nullptr) {
            samgrProxy->UnSubscribeSystemAbility(OHOS::COMMON_EVENT_SERVICE_ID, statusChangeListener_);
            samgrProxy->UnSubscribeSystemAbility(OHOS::TELEPHONY_STATE_REGISTRY_SYS_ABILITY_ID, statusChangeListener_);
            statusChangeListener_ = nullptr;
            TELEPHONY_LOGI("Unsubscribe COMMON_EVENT_SERVICE_ID success");
        }
    }
}

void MultiSimMonitor::InitListener()
{
    auto samgrProxy = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    statusChangeListener_ = new (std::nothrow) SystemAbilityStatusChangeListener(shared_from_this());
    if (samgrProxy == nullptr || statusChangeListener_ == nullptr) {
        TELEPHONY_LOGE("samgrProxy or statusChangeListener_ is nullptr");
        return;
    }
    auto retComEvt = samgrProxy->SubscribeSystemAbility(COMMON_EVENT_SERVICE_ID, statusChangeListener_);
    TELEPHONY_LOGI("SubscribeSystemAbility COMMON_EVENT_SERVICE_ID result is %{public}d", retComEvt);
    auto retStaReg = samgrProxy->SubscribeSystemAbility(TELEPHONY_STATE_REGISTRY_SYS_ABILITY_ID, statusChangeListener_);
    TELEPHONY_LOGI("SubscribeSystemAbility TELEPHONY_STATE_REGISTRY_SYS_ABILITY_ID result is %{public}d", retStaReg);
    CheckOpcNeedUpdata(false);
}

void MultiSimMonitor::SystemAbilityStatusChangeListener::OnAddSystemAbility(int32_t systemAbilityId,
    const std::string &deviceId)
{
    auto handler = handler_.lock();
    if (handler == nullptr) {
        TELEPHONY_LOGE("handler is invalid");
        return;
    }

    switch (systemAbilityId) {
        case COMMON_EVENT_SERVICE_ID:
            TELEPHONY_LOGI("COMMON_EVENT_SERVICE_ID is running");
            std::static_pointer_cast<MultiSimMonitor>(handler)->SubscribeDataShareReady();
            std::static_pointer_cast<MultiSimMonitor>(handler)->SubscribeUserSwitch();
            break;
        case TELEPHONY_STATE_REGISTRY_SYS_ABILITY_ID:
            TELEPHONY_LOGI("TELEPHONY_STATE_REGISTRY_SYS_ABILITY_ID is running");
            std::static_pointer_cast<MultiSimMonitor>(handler)->UpdateSimStateToStateRegistry();
            break;
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
            auto handler = handler_.lock();
            if (handler == nullptr) {
                TELEPHONY_LOGE("handler is invalid");
                return;
            }
            std::static_pointer_cast<MultiSimMonitor>(handler)->UnSubscribeListeners();
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
    dataShareSubscriber_ = std::make_shared<DataShareEventSubscriber>(shared_from_this());
    CoreManagerInner::GetInstance().RegisterCommonEventCallback(
        dataShareSubscriber_, {TelCommonEvent::DATA_SHARE_READY});
    SendEvent(MultiSimMonitor::RETRY_RESET_OPKEY_CONFIG, 0, RETRY_TIME);
}

void MultiSimMonitor::SubscribeUserSwitch()
{
    if (userSwitchSubscriber_ != nullptr) {
        TELEPHONY_LOGW("UserSwitch has Subscribed");
        return;
    }
    userSwitchSubscriber_ = std::make_shared<UserSwitchEventSubscriber>(shared_from_this());
    CoreManagerInner::GetInstance().RegisterCommonEventCallback(
        userSwitchSubscriber_, {TelCommonEvent::USER_SWITCHED});
}

void MultiSimMonitor::DataShareEventSubscriber::OnDataShareReady()
{
    std::vector<int32_t> activeList = { 0 };
    DelayedSingleton<AppExecFwk::OsAccountManagerWrapper>::GetInstance()->QueryActiveOsAccountIds(activeList);
    auto handler = handler_.lock();
    if (handler == nullptr) {
        TELEPHONY_LOGE("handler is invalid");
        return;
    }
    std::static_pointer_cast<MultiSimMonitor>(handler)->isDataShareReady_ = true;
    if (activeList[0] == ACTIVE_USER_ID) {
        std::static_pointer_cast<MultiSimMonitor>(handler)->CheckDataShareError();
        std::static_pointer_cast<MultiSimMonitor>(handler)->CheckSimNotifyRegister();
        std::static_pointer_cast<MultiSimMonitor>(handler)->CheckSimPresentWhenReboot();
    }
}

void MultiSimMonitor::UserSwitchEventSubscriber::OnUserSwitched(int32_t userId)
{
    TELEPHONY_LOGI("current user id is :%{public}d", userId);
    auto handler = handler_.lock();
    if (handler == nullptr) {
        TELEPHONY_LOGE("handler is invalid");
        return;
    }
    if (userId == ACTIVE_USER_ID && std::static_pointer_cast<MultiSimMonitor>(handler)->isDataShareReady_) {
        std::static_pointer_cast<MultiSimMonitor>(handler)->CheckDataShareError();
        std::static_pointer_cast<MultiSimMonitor>(handler)->CheckSimNotifyRegister();
    }
    std::static_pointer_cast<MultiSimMonitor>(handler)->UpdataAllSimData(userId);
    std::static_pointer_cast<MultiSimMonitor>(handler)->SetPrivateUserId(userId);
}

void MultiSimMonitor::SetPrivateUserId(int32_t userId) {
    privateUserId_ = userId != ACTIVE_USER_ID ? userId : privateUserId_;
}

void MultiSimMonitor::UpdataAllSimData(int32_t userId)
{
    if ((userId != ACTIVE_USER_ID && userId != privateUserId_) ||
        ((userId == ACTIVE_USER_ID || userId == privateUserId_) && hasSimStateChanged_)) {
        hasSimStateChanged_ = false;
        SendEvent(MultiSimMonitor::RESET_OPKEY_CONFIG);
    }
}

void MultiSimMonitor::CheckSimPresentWhenReboot()
{
    for (int32_t slotId = 0; slotId < SIM_SLOT_COUNT; slotId++) {
        if (OHOS::system::GetParameter(PROP_REBOOT_DETECT_SIM + std::to_string(slotId), "0") == "1" &&
            !hasCheckedSimPresent_) {
            TELEPHONY_LOGE("reboot detect true, need update sim present");
            controller_->UpdateSimPresent(slotId, true);
            OHOS::system::SetParameter(PROP_REBOOT_DETECT_SIM + std::to_string(slotId), "0");
        }
    }
    hasCheckedSimPresent_ = true;
}

void MultiSimMonitor::CheckSimNotifyRegister()
{
    RemoveEvent(MultiSimMonitor::REGISTER_SIM_NOTIFY_RETRY_EVENT);
    SetRemainCount(INIT_TIMES);
    RegisterSimNotify();
}

void MultiSimMonitor::CheckDataShareError()
{
    if (controller_->IsDataShareError() || GetBlockLoadOperatorConfig()) {
        TELEPHONY_LOGI("CheckDataShareError or GetBlockLoadOperatorConfig is true, need Reset Opkey");
        CheckOpcNeedUpdata(true);
    }
}

void MultiSimMonitor::SetRemainCount(int remainCount)
{
    remainCount_ = remainCount;
}

int32_t MultiSimMonitor::RegisterSimAccountCallback(
    const int32_t tokenId, const sptr<SimAccountCallback> &callback)
{
    if (callback == nullptr) {
        TELEPHONY_LOGE("callback is nullptr");
        return TELEPHONY_ERR_ARGUMENT_NULL;
    }
    std::lock_guard<std::mutex> lock(mutexInner_);
    bool isExisted = false;
    for (auto &iter : listSimAccountCallbackRecord_) {
        if (iter.simAccountCallback == nullptr) {
            continue;
        }
        if (iter.simAccountCallback->AsObject().GetRefPtr() == callback->AsObject().GetRefPtr()) {
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
    deathRecipient_ = new (std::nothrow) SimAccountCallbackDeathRecipient(shared_from_this());
    if (deathRecipient_ == nullptr) {
        TELEPHONY_LOGE("deathRecipient is null");
        return TELEPHONY_ERR_STRCPY_FAIL;
    }
    if (!callback->AsObject()->AddDeathRecipient(deathRecipient_)) {
        TELEPHONY_LOGE("simAccountCallback remote server add death recipient failed");
    }
    listSimAccountCallbackRecord_.push_back(simAccountRecord);
    TELEPHONY_LOGI("Register successfully, callback list size is %{public}zu", listSimAccountCallbackRecord_.size());
    return TELEPHONY_SUCCESS;
}

int32_t MultiSimMonitor::UnregisterSimAccountCallback(const sptr<SimAccountCallback> &callback)
{
    if (callback == nullptr) {
        TELEPHONY_LOGE("callback is nullptr");
        return TELEPHONY_ERR_ARGUMENT_NULL;
    }
    std::lock_guard<std::mutex> lock(mutexInner_);
    bool isSuccess = false;
    auto iter = listSimAccountCallbackRecord_.begin();
    for (; iter != listSimAccountCallbackRecord_.end();) {
        if (iter->simAccountCallback == nullptr) {
            iter++;
            continue;
        }
        if (iter->simAccountCallback->AsObject().GetRefPtr() == callback->AsObject().GetRefPtr()) {
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
    if (isForgetAllDataDone_) {
        TELEPHONY_LOGI("RegisterSimNotify has done");
        return;
    }
    if (controller_ == nullptr) {
        TELEPHONY_LOGE("MultiSimController is null");
        return;
    }
    if (!controller_->ForgetAllData()) {
        if (remainCount_ > 0) {
            SendEvent(MultiSimMonitor::REGISTER_SIM_NOTIFY_RETRY_EVENT, 0, DELAY_TIME);
            TELEPHONY_LOGI("retry remain %{public}d", static_cast<int32_t>(remainCount_));
            remainCount_--;
        }
        return;
    }
    isForgetAllDataDone_ = true;
    TELEPHONY_LOGI("Register with time left %{public}d", static_cast<int32_t>(remainCount_));
    for (size_t slotId = 0; slotId < simFileManager_.size(); slotId++) {
        RegisterSimNotify(static_cast<int32_t>(slotId));
    }
}

int32_t MultiSimMonitor::ResetSimLoadAccount(int32_t slotId)
{
    if (!IsValidSlotId(slotId)) {
        TELEPHONY_LOGE("ResetSimLoadAccount slotId is invalid");
        return TELEPHONY_ERR_SLOTID_INVALID;
    }
    isSimAccountLoaded_[slotId] = 0;
    initDataRemainCount_[slotId] = INIT_DATA_TIMES;
    return TELEPHONY_SUCCESS;
}

void MultiSimMonitor::RegisterSimNotify(int32_t slotId)
{
    if (!IsValidSlotId(slotId)) {
        TELEPHONY_LOGE("RegisterSimNotify slotId is invalid");
        return;
    }
    std::shared_lock<ffrt::shared_mutex> lock(simStateMgrMutex_);
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
    std::shared_lock<ffrt::shared_mutex> lock(simStateMgrMutex_);
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

void MultiSimMonitor::UpdateSimStateToStateRegistry()
{
    std::shared_lock<ffrt::shared_mutex> lock(simStateMgrMutex_);
    for (size_t slotId = 0; slotId < simStateManager_.size(); slotId++) {
        if (simStateManager_[slotId] != nullptr) {
            simStateManager_[slotId]->UpdateSimStateToStateRegistry();
        }
    }
}

} // namespace Telephony
} // namespace OHOS
