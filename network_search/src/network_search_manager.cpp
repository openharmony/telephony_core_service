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

#include "network_search_manager.h"
#include <securec.h>
#include <string_ex.h>
#include "core_manager.h"
#include "mcc_pool.h"
#include "tel_profile_util.h"
#include "telephony_errors.h"
#include "telephony_log_wrapper.h"

namespace OHOS {
namespace Telephony {
NetworkSearchManager::NetworkSearchManager(std::shared_ptr<IRilManager> rilManager,
    std::shared_ptr<ISimStateManager> simStateManager, std::shared_ptr<ISimFileManager> simFileManager)
    : rilManager_(rilManager), simStateManager_(simStateManager), simFileManager_(simFileManager)
{
    TELEPHONY_LOGI("NetworkSearchManager");
}

void NetworkSearchManager::Init()
{
    if (state_ == HandleRunningState::STATE_RUNNING) {
        TELEPHONY_LOGE("NetworkSearchManager::Init HandleRunningState started.");
        return;
    }
    if (rilManager_ == nullptr) {
        TELEPHONY_LOGE("NetworkSearchManager::Init rilManager_ is null.");
        return;
    }
    if (simStateManager_ == nullptr) {
        TELEPHONY_LOGE("NetworkSearchManager::Init simStateManager_ is null.");
        return;
    }
    if (simFileManager_ == nullptr) {
        TELEPHONY_LOGE("NetworkSearchManager::Init simFileManager_ is null.");
        return;
    }
    eventLoop_ = AppExecFwk::EventRunner::Create("NetworkSearchManager");
    if (eventLoop_.get() == nullptr) {
        TELEPHONY_LOGE("NetworkSearchManager failed to create EventRunner");
        return;
    }
    observerHandler_ = std::make_unique<ObserverHandler>();
    if (observerHandler_ == nullptr) {
        TELEPHONY_LOGE("failed to create new ObserverHandler");
        return;
    }
    networkSearchState_ = std::make_shared<NetworkSearchState>(shared_from_this());
    if (networkSearchState_ == nullptr) {
        TELEPHONY_LOGE("failed to create new NetworkSearchState");
        return;
    }
    networkSearchState_->Init();

    networkSearchHandler_ = std::make_shared<NetworkSearchHandler>(eventLoop_, shared_from_this());
    if (networkSearchHandler_ == nullptr) {
        TELEPHONY_LOGE("failed to create new NetworkSearchHandler");
        return;
    }
    networkSearchHandler_->Init();

    DelayedSingleton<NetworkSearchNotify>::GetInstance().get()->ConnectService();
    networkSearchResult_ = std::make_unique<NetworkSearchResult>();
    if (networkSearchResult_ == nullptr) {
        TELEPHONY_LOGE("failed to create new NetworkSearchResult");
        return;
    }

    eventLoop_->Run();
    state_ = HandleRunningState::STATE_RUNNING;
    TELEPHONY_LOGI("NetworkSearchManager::Init eventLoop_->Run()");

    SetRadioState(CORE_SERVICE_POWER_ON, 0);
}

std::shared_ptr<NetworkSearchState> NetworkSearchManager::GetNetworkSearchState() const
{
    return networkSearchState_;
}

std::shared_ptr<ISimFileManager> NetworkSearchManager::GetSimFileManager() const
{
    return simFileManager_;
}

std::shared_ptr<IRilManager> NetworkSearchManager::GetRilManager() const
{
    return rilManager_;
}

std::shared_ptr<ISimStateManager> NetworkSearchManager::GetSimStateManager() const
{
    return simStateManager_;
}

void NetworkSearchManager::SetRadioState(bool isOn, int32_t rst)
{
    if (rilManager_ != nullptr) {
        TELEPHONY_LOGI("NetworkSearchManager SetRadioState isOn:%{public}d", isOn);
        auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_SET_STATUS, isOn);
        if (event != nullptr) {
            event->SetOwner(networkSearchHandler_);
            rilManager_->SetRadioStatus(isOn, rst, event);
        }
    }
}

bool NetworkSearchManager::SetRadioState(bool isOn, int32_t rst, const sptr<INetworkSearchCallback> &callback)
{
    if (rilManager_ == nullptr) {
        return false;
    }

    int64_t index = GetCallbackIndex64bit();
    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_SET_STATUS, index);
    if (event == nullptr) {
        return false;
    }
    event->SetOwner(networkSearchHandler_);
    rilManager_->SetRadioStatus(isOn, rst, event);

    std::shared_ptr<NetworkSearchCallbackInfo> callbackInfo =
        std::make_shared<NetworkSearchCallbackInfo>(isOn, callback);
    if (callbackInfo != nullptr) {
        if (!AddNetworkSearchCallBack(index, callbackInfo)) {
            TELEPHONY_LOGE("NetworkSearchManager::SetRadioState Error!!");
        }
        return true;
    }
    return false;
}

void NetworkSearchManager::RegisterPhoneNotify(
    const std::shared_ptr<AppExecFwk::EventHandler> &handler, int what, void *obj)
{
    TELEPHONY_LOGI("NetworkSearchManager::RegisterPhoneNotify  %{public}d", what);
    if (observerHandler_ != nullptr) {
        observerHandler_->RegObserver(what, handler);
    }
}

void NetworkSearchManager::UnRegisterPhoneNotify(const std::shared_ptr<AppExecFwk::EventHandler> &handler, int what)
{
    TELEPHONY_LOGI("NetworkSearchManager::UnRegisterPhoneNotify %{public}d", what);
    if (observerHandler_ != nullptr) {
        observerHandler_->Remove(what, handler);
    }
}

void NetworkSearchManager::NotifyPSRoamingOpenChanged()
{
    TELEPHONY_LOGI("NetworkSearchManager::NotifyPSRoamingOpenChanged");
    if (observerHandler_ != nullptr) {
        observerHandler_->NotifyObserver(ObserverHandler::RADIO_PS_ROAMING_OPEN);
    }
}

void NetworkSearchManager::NotifyPSRoamingCloseChanged()
{
    TELEPHONY_LOGI("NetworkSearchManager::NotifyPSRoamingCloseChanged");
    if (observerHandler_ != nullptr) {
        observerHandler_->NotifyObserver(ObserverHandler::RADIO_PS_ROAMING_CLOSE);
    }
}

void NetworkSearchManager::NotifyPSConnectionAttachedChanged()
{
    TELEPHONY_LOGI("NetworkSearchManager::NotifyPSConnectionAttachedChanged");
    if (observerHandler_ != nullptr) {
        observerHandler_->NotifyObserver(ObserverHandler::RADIO_PS_CONNECTION_ATTACHED);
    }
}

void NetworkSearchManager::NotifyPSConnectionDetachedChanged()
{
    TELEPHONY_LOGI("NetworkSearchManager::NotifyPSConnectionDetachedChanged");
    if (observerHandler_ != nullptr) {
        observerHandler_->NotifyObserver(ObserverHandler::RADIO_PS_CONNECTION_DETACHED);
    }
}

int32_t NetworkSearchManager::GetPsRadioTech(int32_t slotId) const
{
    if (networkSearchState_ != nullptr && networkSearchHandler_ != nullptr) {
        auto event = networkSearchState_->GetNetworkStatus()->GetPsRadioTech();
        networkSearchHandler_->GetRilPsRegistration();
        TELEPHONY_LOGI("NetworkSearchManager::GetPsRadioTech result=%{public}d", event);
        return event;
    }
    TELEPHONY_LOGE("NetworkSearchManager::GetPsRadioTech Failed");
    return TELEPHONY_ERROR;
}

int32_t NetworkSearchManager::GetCsRadioTech(int32_t slotId) const
{
    if (networkSearchState_ != nullptr && networkSearchHandler_ != nullptr) {
        auto event = networkSearchState_->GetNetworkStatus()->GetCsRadioTech();
        networkSearchHandler_->GetRilCsRegistration();
        TELEPHONY_LOGI("NetworkSearchManager::GetCsRadioTech result=%{public}d", event);
        return event;
    }
    TELEPHONY_LOGE("NetworkSearchManager::GetCsRadioTech Failed");
    return TELEPHONY_ERROR;
}

std::u16string NetworkSearchManager::GetOperatorNumeric(int32_t slotId) const
{
    TELEPHONY_LOGI("NetworkSearchManager::GetOperatorNumeric start");
    std::u16string str;
    if (networkSearchHandler_ != nullptr) {
        networkSearchHandler_->GetRilOperatorInfo();
        auto event = networkSearchState_->GetNetworkStatus()->GetPlmnNumeric();
        str = Str8ToStr16(event);
        TELEPHONY_LOGI("NetworkSearchManager::GetOperatorNumeric result=%{public}s", event.c_str());
    }
    return str;
}

std::u16string NetworkSearchManager::GetOperatorName(int32_t slotId) const
{
    std::u16string str;
    if (networkSearchState_ != nullptr) {
        auto event = networkSearchState_->GetNetworkStatus()->GetLongOperatorName();
        str = Str8ToStr16(event);
        TELEPHONY_LOGI("NetworkSearchManager::GetOperatorName result=%{public}s", event.c_str());
    }
    return str;
}

sptr<NetworkState> NetworkSearchManager::GetNetworkStatus(int32_t slotId) const
{
    if (networkSearchState_ != nullptr) {
        auto networkState = networkSearchState_->GetNetworkStatus().release();
        return networkState;
    } else {
        return nullptr;
    }
}
void NetworkSearchManager::SetRadioStatusValue(ModemPowerState radioStatus)
{
    radioStatus_ = radioStatus;
}

void NetworkSearchManager::SetNetworkSelectionValue(SelectionMode selection)
{
    selection_ = selection;
}

ModemPowerState NetworkSearchManager::GetRadioStatusValue() const
{
    return radioStatus_;
}

int32_t NetworkSearchManager::GetRadioState() const
{
    if (rilManager_ != nullptr) {
        auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_GET_STATUS);
        if (event != nullptr) {
            event->SetOwner(networkSearchHandler_);
            rilManager_->GetRadioStatus(event);
        }
    }
    return radioStatus_;
}

bool NetworkSearchManager::GetRadioState(const sptr<INetworkSearchCallback> &callback)
{
    TELEPHONY_LOGI("NetworkSearchManager::GetRadioState...");
    if (rilManager_ == nullptr) {
        return false;
    }
    int64_t index = GetCallbackIndex64bit();
    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_GET_STATUS, index);
    if (event == nullptr) {
        return false;
    }
    event->SetOwner(networkSearchHandler_);
    rilManager_->GetRadioStatus(event);

    std::shared_ptr<NetworkSearchCallbackInfo> callbackInfo =
        std::make_shared<NetworkSearchCallbackInfo>(0, callback);
    if (callbackInfo != nullptr) {
        if (!AddNetworkSearchCallBack(index, callbackInfo)) {
            TELEPHONY_LOGE("NetworkSearchManager::GetRadioState Error!!");
        }
        return true;
    }
    return false;
}

std::vector<sptr<SignalInformation>> NetworkSearchManager::GetSignalInfoList(int32_t slotId) const
{
    std::vector<sptr<SignalInformation>> vec;
    if (networkSearchHandler_ != nullptr) {
        networkSearchHandler_->GetSignalInfo(vec);
    }
    return vec;
}

bool NetworkSearchManager::GetNetworkSearchResult(int32_t slotId, const sptr<INetworkSearchCallback> &callback)
{
    if (rilManager_ == nullptr) {
        return false;
    }

    int64_t index = GetCallbackIndex64bit();
    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_NETWORK_SEARCH_RESULT, index);
    if (event == nullptr) {
        return false;
    }
    event->SetOwner(networkSearchHandler_);
    rilManager_->GetNetworkSearchInformation(event);

    std::shared_ptr<NetworkSearchCallbackInfo> callbackInfo =
        std::make_shared<NetworkSearchCallbackInfo>(0, callback);
    if (callbackInfo != nullptr) {
        if (!AddNetworkSearchCallBack(index, callbackInfo)) {
            TELEPHONY_LOGE("AddNetworkSearchCallBack Error!!");
        }
        return true;
    }
    return false;
}

void NetworkSearchManager::SetNetworkSearchResultValue(
    int32_t listSize, std::vector<NetworkInformation> &operatorInfo)
{
    if (networkSearchResult_ != nullptr) {
        networkSearchResult_->SetNetworkSearchResultValue(listSize, operatorInfo);
    }
}

sptr<NetworkSearchResult> NetworkSearchManager::GetNetworkSearchResultValue() const
{
    sptr<NetworkSearchResult> networkSearchResult = new (std::nothrow) NetworkSearchResult;
    if (networkSearchResult == nullptr) {
        TELEPHONY_LOGE("GetNetworkSearchResultValue failed to create new NetWorkSearchResult");
        return nullptr;
    }
    if (networkSearchResult_ == nullptr) {
        TELEPHONY_LOGE("GetNetworkSearchResultValue networkSearchResult_ is null");
        return nullptr;
    }

    int32_t listSize = networkSearchResult_->GetNetworkSearchResultSize();
    std::vector<NetworkInformation> operatorInfoList = networkSearchResult_->GetNetworkSearchResult();
    networkSearchResult->SetNetworkSearchResultValue(listSize, operatorInfoList);
    return networkSearchResult;
}

int32_t NetworkSearchManager::GetNetworkSelectionMode(int32_t slotId) const
{
    if (rilManager_ != nullptr) {
        auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_GET_NETWORK_SELECTION_MODE);
        if (event != nullptr) {
            event->SetOwner(networkSearchHandler_);
            rilManager_->GetNetworkSelectionMode(event);
        }
    }
    return selection_;
}

bool NetworkSearchManager::GetNetworkSelectionMode(int32_t slotId, const sptr<INetworkSearchCallback> &callback)
{
    if (rilManager_ == nullptr) {
        return false;
    }

    int64_t index = GetCallbackIndex64bit();
    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_GET_NETWORK_SELECTION_MODE, index);
    if (event != nullptr) {
        event->SetOwner(networkSearchHandler_);
        rilManager_->GetNetworkSelectionMode(event);

        std::shared_ptr<NetworkSearchCallbackInfo> callbackInfo =
            std::make_shared<NetworkSearchCallbackInfo>(0, callback);
        if (callbackInfo == nullptr) {
            return false;
        }

        if (!AddNetworkSearchCallBack(index, callbackInfo)) {
            TELEPHONY_LOGE("GetNetworkSelectionMode Error!!");
        }
        return true;
    }
    return false;
}

bool NetworkSearchManager::SetNetworkSelectionMode(
    int32_t slotId, int32_t selectMode, const sptr<NetworkInformation> &networkInformation, bool resumeSelection)
{
    if (rilManager_ != nullptr) {
        TELEPHONY_LOGI("NetworkSearchManager SetNetworkSelectionMode selectMode:%{public}d", selectMode);
        auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_SET_NETWORK_SELECTION_MODE, selectMode);
        if (event != nullptr) {
            event->SetOwner(networkSearchHandler_);
            std::string plmnNumeric = "";
            if (networkInformation != nullptr) {
                plmnNumeric = networkInformation->GetOperatorNumeric();
            }
            rilManager_->SetNetworkSelectionMode(selectMode, plmnNumeric, event);
            return true;
        }
    }

    if (resumeSelection) {
        TELEPHONY_LOGI("NetworkSearchManager::SetNetworkSelectionMode to update the database");
    } else {
        TELEPHONY_LOGI("NetworkSearchManager::SetNetworkSelectionMode to clear the database");
    }
    return false;
}

bool NetworkSearchManager::SetNetworkSelectionMode(int32_t slotId, int32_t selectMode,
    const sptr<NetworkInformation> &networkInformation, bool resumeSelection,
    const sptr<INetworkSearchCallback> &callback)
{
    if (rilManager_ == nullptr) {
        return false;
    }

    TELEPHONY_LOGI("NetworkSearchManager SetNetworkSelectionMode selectMode:%{public}d", selectMode);
    int64_t index = GetCallbackIndex64bit();
    auto event = AppExecFwk::InnerEvent::Get(ObserverHandler::RADIO_SET_NETWORK_SELECTION_MODE, index);
    if (event == nullptr) {
        return false;
    }

    event->SetOwner(networkSearchHandler_);
    std::string plmnNumeric = "";
    if (networkInformation != nullptr) {
        plmnNumeric = networkInformation->GetOperatorNumeric();
    }
    rilManager_->SetNetworkSelectionMode(selectMode, plmnNumeric, event);

    std::shared_ptr<NetworkSearchCallbackInfo> callbackInfo =
        std::make_shared<NetworkSearchCallbackInfo>(selectMode, callback);
    if (callbackInfo != nullptr) {
        if (AddNetworkSearchCallBack(index, callbackInfo)) {
            return true;
        }
    }

    if (resumeSelection) {
        TELEPHONY_LOGI("NetworkSearchManager::SetNetworkSelectionMode to update the database");
    } else {
        TELEPHONY_LOGI("NetworkSearchManager::SetNetworkSelectionMode to clear the database");
    }
    return false;
}

bool NetworkSearchManager::AddNetworkSearchCallBack(
    int64_t id, std::shared_ptr<NetworkSearchCallbackInfo> &callback)
{
    if (callback != nullptr) {
        std::lock_guard<std::mutex> guard(callbackMapMutex_);
        auto result = networkSearchCacheMap_.emplace(id, callback);
        return result.second;
    }
    TELEPHONY_LOGE("NetworkSearchManager::AddNetworkSearchCallBack callback is null!");
    return false;
}

std::shared_ptr<NetworkSearchCallbackInfo> NetworkSearchManager::FindNetworkSearchCallback(int64_t index)
{
    std::lock_guard<std::mutex> guard(callbackMapMutex_);
    auto iter = networkSearchCacheMap_.find(index);
    if (iter != networkSearchCacheMap_.end()) {
        std::shared_ptr<NetworkSearchCallbackInfo> callback = iter->second;
        return callback;
    }
    return nullptr;
}

bool NetworkSearchManager::RemoveCallbackFromMap(int64_t index)
{
    std::lock_guard<std::mutex> guard(callbackMapMutex_);
    return (networkSearchCacheMap_.erase(index) != 0);
}

int64_t NetworkSearchManager::GetCallbackIndex64bit()
{
    if (callbackIndex64bit_ > MAX_INDEX) {
        callbackIndex64bit_ = 0;
    }
    return ++callbackIndex64bit_;
}

std::u16string NetworkSearchManager::GetIsoCountryCodeForNetwork(int32_t slotId) const
{
    std::string iso = "";
    if (networkSearchHandler_ != nullptr) {
        std::string plmn = networkSearchState_->GetNetworkStatus()->GetPlmnNumeric();
        int len = plmn.length();
        if (len >= MCC_LEN) {
            std::string mcc = plmn.substr(0, MCC_LEN);
            int value = 0;
            bool succ = StrToInt(mcc, value);
            if (succ) {
                iso = MccPool::MccCountryCode(value);
            } else {
                TELEPHONY_LOGE("GetIsoCountryCodeForNetwork parse Failed!!");
            }
            TELEPHONY_LOGI("NetworkSearchManager::GetIsoCountryCodeForNetwork mcc=%{public}s code=%{public}d",
                mcc.c_str(), value);
        }
    }
    return Str8ToStr16(iso);
}
} // namespace Telephony
} // namespace OHOS
