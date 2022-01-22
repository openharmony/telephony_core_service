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
#include <cinttypes>

#include "mcc_pool.h"
#include "tel_profile_util.h"
#include "telephony_errors.h"
#include "telephony_log_wrapper.h"

namespace OHOS {
namespace Telephony {
const std::string KEY_DEFAULT_PREFERRED_NETWORK_MODE = "preferred_network_mode";

NetworkSearchManager::NetworkSearchManager(
    std::shared_ptr<ITelRilManager> telRilManager, std::shared_ptr<ISimManager> simManager)
    : telRilManager_(telRilManager), simManager_(simManager)
{
    TELEPHONY_LOGI("NetworkSearchManager");
}

bool NetworkSearchManager::InitPointer(std::shared_ptr<NetworkSearchManagerInner> &inner, int32_t slotId)
{
    if (inner == nullptr) {
        TELEPHONY_LOGE("NetworkSearchManager::InitPointer failed . inner is null");
        return false;
    }
    std::string name = "NetworkSearchManager_";
    name.append(std::to_string(slotId));
    inner->eventLoop_ = AppExecFwk::EventRunner::Create(name.c_str());
    if (inner->eventLoop_.get() == nullptr) {
        TELEPHONY_LOGE("NetworkSearchManager failed to create EventRunner slotId:%{public}d", slotId);
        return false;
    }
    inner->observerHandler_ = std::make_unique<ObserverHandler>();
    if (inner->observerHandler_ == nullptr) {
        TELEPHONY_LOGE("failed to create new ObserverHandler slotId:%{public}d", slotId);
        return false;
    }
    inner->networkSearchState_ = std::make_shared<NetworkSearchState>(shared_from_this(), slotId);
    if (inner->networkSearchState_ == nullptr) {
        TELEPHONY_LOGE("failed to create new NetworkSearchState slotId:%{public}d", slotId);
        return false;
    }
    inner->networkSearchHandler_ = std::make_shared<NetworkSearchHandler>(
        inner->eventLoop_, shared_from_this(), telRilManager_, simManager_, slotId);
    if (inner->networkSearchHandler_ == nullptr) {
        TELEPHONY_LOGE("failed to create new NetworkSearchHandler slotId:%{public}d", slotId);
        return false;
    }
    inner->networkSearchResult_ = std::make_unique<NetworkSearchResult>();
    if (inner->networkSearchResult_ == nullptr) {
        TELEPHONY_LOGE("failed to create new NetworkSearchResult slotId:%{public}d", slotId);
        return false;
    }
    return true;
}

bool NetworkSearchManager::OnInit()
{
    TELEPHONY_LOGI("NetworkSearchManager::Init");
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("NetworkSearchManager::Init telRilManager_ is null.");
        return false;
    }
    if (simManager_ == nullptr) {
        TELEPHONY_LOGE("NetworkSearchManager::Init simManager_ is null.");
        return false;
    }
    eventSender_ = std::make_unique<EventSender>(telRilManager_, shared_from_this());
    if (eventSender_ == nullptr) {
        TELEPHONY_LOGE("failed to create new EventSender");
        return false;
    }
    ClearManagerInner();
    for (int32_t slotId = 0; slotId < SIM_SLOT_COUNT; slotId++) {
        std::shared_ptr<NetworkSearchManagerInner> inner = FindManagerInner(slotId);
        if (inner == nullptr) {
            inner = std::make_shared<NetworkSearchManagerInner>();
            AddManagerInner(slotId, inner);
        }
        if (inner != nullptr) {
            if (inner->state_ == HandleRunningState::STATE_RUNNING) {
                TELEPHONY_LOGE(
                    "NetworkSearchManager::Init HandleRunningState is running. slotId:%{public}d", slotId);
                continue;
            }
            if (!InitPointer(inner, slotId)) {
                ClearManagerInner();
                continue;
            }
            if (!inner->Init()) {
                ClearManagerInner();
                return false;
            }
            TELEPHONY_LOGI("NetworkSearchManager::Init inner init slotId:%{public}d", slotId);
            // Prevent running crash and query the radio status at startup
            eventSender_->SendBase(slotId, RadioEvent::RADIO_GET_STATUS);
        }
    }
    return true;
}

std::shared_ptr<NetworkSearchState> NetworkSearchManager::GetNetworkSearchState(int32_t slotId)
{
    auto inner = FindManagerInner(slotId);
    if (inner != nullptr) {
        TELEPHONY_LOGI("NetworkSearchManager::GetNetworkSearchState %{public}p slotId:%{public}d",
            inner->networkSearchState_.get(), slotId);
        return inner->networkSearchState_;
    }
    return nullptr;
}

void NetworkSearchManager::SetRadioState(int32_t slotId, bool isOn, int32_t rst)
{
    TELEPHONY_LOGI("NetworkSearchManager SetRadioState isOn:%{public}d slotId:%{public}d", isOn, slotId);
    int32_t fun = static_cast<int32_t>(isOn);
    eventSender_->SendBase(slotId, RadioEvent::RADIO_SET_STATUS, fun, rst);
}

bool NetworkSearchManager::SetRadioState(int32_t slotId, bool isOn, int32_t rst, NSCALLBACK &callback)
{
    TELEPHONY_LOGI("NetworkSearchManager SetRadioState isOn:%{public}d slotId:%{public}d", isOn, slotId);
    AirplaneMode_ = isOn ? false : true;
    int32_t fun = static_cast<int32_t>(isOn);
    return eventSender_->SendCallback(slotId, RadioEvent::RADIO_SET_STATUS, &callback, fun, rst);
}

void NetworkSearchManager::RegisterCoreNotify(int32_t slotId, HANDLE &handler, int32_t what)
{
    TELEPHONY_LOGI("NetworkSearchManager::RegisterCoreNotify  %{public}d slotId:%{public}d", what, slotId);
    auto inner = FindManagerInner(slotId);
    if (inner != nullptr) {
        if (inner->observerHandler_ != nullptr) {
            inner->observerHandler_->RegObserver(what, handler);
        }
    }
}

void NetworkSearchManager::UnRegisterCoreNotify(int32_t slotId, HANDLE &handler, int32_t what)
{
    TELEPHONY_LOGI("NetworkSearchManager::UnRegisterCoreNotify %{public}d slotId:%{public}d", what, slotId);
    auto inner = FindManagerInner(slotId);
    if (inner != nullptr) {
        if (inner->observerHandler_ != nullptr) {
            inner->observerHandler_->Remove(what, handler);
        }
    }
}

void NetworkSearchManager::RegisterCellularDataObject(const sptr<NetworkSearchCallBackBase> &callback)
{
    cellularDataCallBack_ = callback;
}

void NetworkSearchManager::UnRegisterCellularDataObject(const sptr<NetworkSearchCallBackBase> &callback)
{
    cellularDataCallBack_ = nullptr;
}

void NetworkSearchManager::RegisterCellularCallObject(const sptr<NetworkSearchCallBackBase> &callback)
{
    cellularCallCallBack_ = callback;
}

void NetworkSearchManager::UnRegisterCellularCallObject(const sptr<NetworkSearchCallBackBase> &callback)
{
    cellularCallCallBack_ = nullptr;
}

void NetworkSearchManager::NotifyPsRoamingOpenChanged(int32_t slotId)
{
    TELEPHONY_LOGI("NetworkSearchManager::NotifyPsRoamingOpenChanged slotId:%{public}d", slotId);
    auto inner = FindManagerInner(slotId);
    if (inner != nullptr) {
        if (inner->observerHandler_ != nullptr) {
            inner->observerHandler_->NotifyObserver(RadioEvent::RADIO_PS_ROAMING_OPEN);
        }
    }
}

void NetworkSearchManager::NotifyPsRoamingCloseChanged(int32_t slotId)
{
    TELEPHONY_LOGI("NetworkSearchManager::NotifyPsRoamingCloseChanged slotId:%{public}d", slotId);
    auto inner = FindManagerInner(slotId);
    if (inner != nullptr) {
        if (inner->observerHandler_ != nullptr) {
            inner->observerHandler_->NotifyObserver(RadioEvent::RADIO_PS_ROAMING_CLOSE);
        }
    }
}

void NetworkSearchManager::NotifyEmergencyOpenChanged(int32_t slotId)
{
    TELEPHONY_LOGI("NetworkSearchManager::NotifyEmergencyOpenChanged slotId:%{public}d", slotId);
    auto inner = FindManagerInner(slotId);
    if (inner != nullptr) {
        if (inner->observerHandler_ != nullptr) {
            inner->observerHandler_->NotifyObserver(RadioEvent::RADIO_EMERGENCY_STATE_OPEN);
        }
    }
}

void NetworkSearchManager::NotifyEmergencyCloseChanged(int32_t slotId)
{
    TELEPHONY_LOGI("NetworkSearchManager::NotifyEmergencyCloseChanged slotId:%{public}d", slotId);
    auto inner = FindManagerInner(slotId);
    if (inner != nullptr) {
        if (inner->observerHandler_ != nullptr) {
            inner->observerHandler_->NotifyObserver(RadioEvent::RADIO_EMERGENCY_STATE_CLOSE);
        }
    }
}

void NetworkSearchManager::NotifyPsRatChanged(int32_t slotId)
{
    TELEPHONY_LOGI("NetworkSearchManager::NotifyPsRatChanged slotId:%{public}d", slotId);
    auto inner = FindManagerInner(slotId);
    if (inner != nullptr) {
        if (inner->observerHandler_ != nullptr) {
            inner->observerHandler_->NotifyObserver(RadioEvent::RADIO_PS_RAT_CHANGED);
        }
    }
}

void NetworkSearchManager::NotifyPsConnectionAttachedChanged(int32_t slotId)
{
    TELEPHONY_LOGI("NetworkSearchManager::NotifyPsConnectionAttachedChanged slotId:%{public}d", slotId);
    auto inner = FindManagerInner(slotId);
    if (inner != nullptr) {
        if (inner->observerHandler_ != nullptr) {
            inner->observerHandler_->NotifyObserver(RadioEvent::RADIO_PS_CONNECTION_ATTACHED);
        }
    }
}

void NetworkSearchManager::NotifyPsConnectionDetachedChanged(int32_t slotId)
{
    TELEPHONY_LOGI("NetworkSearchManager::NotifyPsConnectionDetachedChanged slotId:%{public}d", slotId);
    auto inner = FindManagerInner(slotId);
    if (inner != nullptr) {
        if (inner->observerHandler_ != nullptr) {
            inner->observerHandler_->NotifyObserver(RadioEvent::RADIO_PS_CONNECTION_DETACHED);
        }
    }
}

void NetworkSearchManager::NotifyImsRegStateChanged(int32_t slotId)
{
    TELEPHONY_LOGI("NetworkSearchManager::NotifyImsRegStateChanged slotId:%{public}d", slotId);
    auto inner = FindManagerInner(slotId);
    if (inner != nullptr) {
        if (inner->observerHandler_ != nullptr) {
            inner->observerHandler_->NotifyObserver(RadioEvent::RADIO_IMS_REG_STATUS_UPDATE);
        }
    }
}

void NetworkSearchManager::NotifyNrStateChanged(int32_t slotId)
{
    TELEPHONY_LOGI("NetworkSearchManager::NotifyNrStateChanged slotId:%{public}d", slotId);
    auto inner = FindManagerInner(slotId);
    if (inner != nullptr) {
        if (inner->observerHandler_ != nullptr) {
            inner->observerHandler_->NotifyObserver(RadioEvent::RADIO_NR_STATE_CHANGED);
        }
    }
}

void NetworkSearchManager::NotifyNrFrequencyChanged(int32_t slotId)
{
    TELEPHONY_LOGI("NetworkSearchManager::NotifyNrFrequencyChanged slotId:%{public}d", slotId);
    auto inner = FindManagerInner(slotId);
    if (inner != nullptr) {
        if (inner->observerHandler_ != nullptr) {
            inner->observerHandler_->NotifyObserver(RadioEvent::RADIO_NR_FREQUENCY_CHANGED);
        }
    }
}

int32_t NetworkSearchManager::GetPsRadioTech(int32_t slotId)
{
    auto inner = FindManagerInner(slotId);
    if (inner != nullptr) {
        if (inner->networkSearchState_ != nullptr && inner->networkSearchHandler_ != nullptr) {
            auto event = static_cast<int32_t>(inner->networkSearchState_->GetNetworkStatus()->GetPsRadioTech());
            TELEPHONY_LOGI(
                "NetworkSearchManager::GetPsRadioTech result=%{public}d slotId:%{public}d", event, slotId);
            return event;
        }
    }
    TELEPHONY_LOGE("NetworkSearchManager::GetPsRadioTech Failed slotId:%{public}d", slotId);
    return TELEPHONY_ERROR;
}

int32_t NetworkSearchManager::GetCsRadioTech(int32_t slotId)
{
    auto inner = FindManagerInner(slotId);
    if (inner != nullptr) {
        if (inner->networkSearchState_ != nullptr && inner->networkSearchHandler_ != nullptr) {
            auto event = static_cast<int32_t>(inner->networkSearchState_->GetNetworkStatus()->GetCsRadioTech());
            TELEPHONY_LOGI(
                "NetworkSearchManager::GetCsRadioTech result=%{public}d slotId:%{public}d", event, slotId);
            return event;
        }
    }
    TELEPHONY_LOGE("NetworkSearchManager::GetCsRadioTech Failed slotId:%{public}d", slotId);
    return TELEPHONY_ERROR;
}

int32_t NetworkSearchManager::GetPsRegState(int32_t slotId)
{
    auto inner = FindManagerInner(slotId);
    if (inner != nullptr) {
        if (inner->networkSearchState_ != nullptr && inner->networkSearchHandler_ != nullptr) {
            auto event = static_cast<int32_t>(inner->networkSearchState_->GetNetworkStatus()->GetPsRegStatus());
            TELEPHONY_LOGI(
                "NetworkSearchManager::GetPsRegState result=%{public}d slotId:%{public}d", event, slotId);
            return event;
        }
    }
    TELEPHONY_LOGE("NetworkSearchManager::GetPsRegState Failed slotId:%{public}d", slotId);
    return TELEPHONY_ERROR;
}

int32_t NetworkSearchManager::GetCsRegState(int32_t slotId)
{
    auto inner = FindManagerInner(slotId);
    if (inner != nullptr) {
        if (inner->networkSearchState_ != nullptr && inner->networkSearchHandler_ != nullptr) {
            auto event = static_cast<int32_t>(inner->networkSearchState_->GetNetworkStatus()->GetCsRegStatus());
            TELEPHONY_LOGI(
                "NetworkSearchManager::GetCsRegState result=%{public}d slotId:%{public}d", event, slotId);
            return event;
        }
    }
    TELEPHONY_LOGE("NetworkSearchManager::GetCsRegState Failed slotId:%{public}d", slotId);
    return TELEPHONY_ERROR;
}

int32_t NetworkSearchManager::GetPsRoamingState(int32_t slotId)
{
    auto inner = FindManagerInner(slotId);
    if (inner != nullptr) {
        if (inner->networkSearchState_ != nullptr && inner->networkSearchHandler_ != nullptr) {
            auto event = static_cast<int32_t>(inner->networkSearchState_->GetNetworkStatus()->GetPsRoamingStatus());
            TELEPHONY_LOGI(
                "NetworkSearchManager::GetPsRoamingState result=%{public}d slotId:%{public}d", event, slotId);
            return event;
        }
    }
    TELEPHONY_LOGE("NetworkSearchManager::GetPsRoamingState Failed slotId:%{public}d", slotId);
    return TELEPHONY_ERROR;
}

std::u16string NetworkSearchManager::GetOperatorNumeric(int32_t slotId)
{
    TELEPHONY_LOGI("NetworkSearchManager::GetOperatorNumeric start slotId:%{public}d", slotId);
    std::u16string str;
    auto inner = FindManagerInner(slotId);
    if (inner != nullptr) {
        if (inner->networkSearchHandler_ != nullptr) {
            auto event = inner->networkSearchState_->GetNetworkStatus()->GetPlmnNumeric();
            str = Str8ToStr16(event);
            TELEPHONY_LOGI("NetworkSearchManager::GetOperatorNumeric result=%{public}s slotId:%{public}d",
                event.c_str(), slotId);
        }
    }
    return str;
}

std::u16string NetworkSearchManager::GetOperatorName(int32_t slotId)
{
    std::u16string str;
    auto inner = FindManagerInner(slotId);
    if (inner != nullptr) {
        if (inner->networkSearchState_ != nullptr) {
            auto event = inner->networkSearchState_->GetNetworkStatus()->GetLongOperatorName();
            str = Str8ToStr16(event);
            TELEPHONY_LOGI("NetworkSearchManager::GetOperatorName result=%{public}s slotId:%{public}d",
                event.c_str(), slotId);
        }
    }
    return str;
}

sptr<NetworkState> NetworkSearchManager::GetNetworkStatus(int32_t slotId)
{
    auto inner = FindManagerInner(slotId);
    if (inner != nullptr) {
        if (inner->networkSearchState_ != nullptr) {
            auto networkState = inner->networkSearchState_->GetNetworkStatus().release();
            return networkState;
        }
    }
    return nullptr;
}

void NetworkSearchManager::SetRadioStateValue(int32_t slotId, ModemPowerState radioState)
{
    auto inner = FindManagerInner(slotId);
    if (inner != nullptr) {
        inner->radioState_ = radioState;
    }
}

void NetworkSearchManager::SetNetworkSelectionValue(int32_t slotId, SelectionMode selection)
{
    auto inner = FindManagerInner(slotId);
    if (inner != nullptr) {
        inner->selection_ = selection;
    }
}

int32_t NetworkSearchManager::GetRadioState(int32_t slotId)
{
    auto inner = FindManagerInner(slotId);
    if (inner != nullptr) {
        return inner->radioState_;
    }
    return ModemPowerState::CORE_SERVICE_POWER_NOT_AVAILABLE;
}

bool NetworkSearchManager::GetRadioState(int32_t slotId, NSCALLBACK &callback)
{
    TELEPHONY_LOGI("NetworkSearchManager::GetRadioState... slotId:%{public}d", slotId);
    return eventSender_->SendCallback(slotId, RadioEvent::RADIO_GET_STATUS, &callback);
}

std::vector<sptr<SignalInformation>> NetworkSearchManager::GetSignalInfoList(int32_t slotId)
{
    std::vector<sptr<SignalInformation>> vec;
    auto inner = FindManagerInner(slotId);
    if (inner != nullptr) {
        if (inner->networkSearchHandler_ != nullptr) {
            inner->networkSearchHandler_->GetSignalInfo(vec);
        }
    }
    return vec;
}

bool NetworkSearchManager::GetNetworkSearchInformation(int32_t slotId, NSCALLBACK &callback)
{
    return eventSender_->SendCallback(slotId, RadioEvent::RADIO_NETWORK_SEARCH_RESULT, &callback);
}

void NetworkSearchManager::SetNetworkSearchResultValue(
    int32_t slotId, int32_t listSize, std::vector<NetworkInformation> &operatorInfo)
{
    auto inner = FindManagerInner(slotId);
    if (inner != nullptr) {
        if (inner->networkSearchResult_ != nullptr) {
            inner->networkSearchResult_->SetNetworkSearchResultValue(listSize, operatorInfo);
        }
    }
}

sptr<NetworkSearchResult> NetworkSearchManager::GetNetworkSearchInformationValue(int32_t slotId)
{
    sptr<NetworkSearchResult> networkSearchResult = new (std::nothrow) NetworkSearchResult;
    if (networkSearchResult == nullptr) {
        TELEPHONY_LOGE(
            "GetNetworkSearchInformationValue failed to create new NetWorkSearchResult slotId:%{public}d", slotId);
        return nullptr;
    }

    auto inner = FindManagerInner(slotId);
    if (inner != nullptr) {
        if (inner->networkSearchResult_ == nullptr) {
            TELEPHONY_LOGE(
                "GetNetworkSearchInformationValue networkSearchResult_ is null slotId:%{public}d", slotId);
            return nullptr;
        }

        int32_t listSize = inner->networkSearchResult_->GetNetworkSearchInformationSize();
        std::vector<NetworkInformation> operatorInfoList =
            inner->networkSearchResult_->GetNetworkSearchInformation();
        networkSearchResult->SetNetworkSearchResultValue(listSize, operatorInfoList);
        return networkSearchResult;
    }
    return nullptr;
}

int32_t NetworkSearchManager::GetNetworkSelectionMode(int32_t slotId)
{
    auto inner = FindManagerInner(slotId);
    if (inner != nullptr) {
        eventSender_->SendBase(slotId, RadioEvent::RADIO_GET_NETWORK_SELECTION_MODE);
        return static_cast<int32_t>(inner->selection_);
    }
    return static_cast<int32_t>(SelectionMode::MODE_TYPE_UNKNOWN);
}

bool NetworkSearchManager::GetNetworkSelectionMode(int32_t slotId, NSCALLBACK &callback)
{
    return eventSender_->SendCallback(slotId, RadioEvent::RADIO_GET_NETWORK_SELECTION_MODE, &callback);
}

bool NetworkSearchManager::SetNetworkSelectionMode(
    int32_t slotId, int32_t selectMode, const sptr<NetworkInformation> &networkInformation, bool resumeSelection)
{
    TELEPHONY_LOGI("NetworkSearchManager SetNetworkSelectionMode selectMode:%{public}d slotId:%{public}d",
        selectMode, slotId);
    std::string plmnNumeric = "";
    if (networkInformation != nullptr) {
        plmnNumeric = networkInformation->GetOperatorNumeric();
    }
    return eventSender_->SendBase(slotId, RadioEvent::RADIO_SET_NETWORK_SELECTION_MODE, selectMode, plmnNumeric);
}

bool NetworkSearchManager::SetNetworkSelectionMode(int32_t slotId, int32_t selectMode,
    const sptr<NetworkInformation> &networkInformation, bool resumeSelection, NSCALLBACK &callback)
{
    TELEPHONY_LOGI("NetworkSearchManager SetNetworkSelectionMode selectMode:%{public}d slotId:%{public}d",
        selectMode, slotId);
    std::string plmnNumeric = "";
    if (networkInformation != nullptr) {
        plmnNumeric = networkInformation->GetOperatorNumeric();
    }
    return eventSender_->SendCallback(
        slotId, RadioEvent::RADIO_SET_NETWORK_SELECTION_MODE, &callback, selectMode, plmnNumeric);
}

std::u16string NetworkSearchManager::GetIsoCountryCodeForNetwork(int32_t slotId)
{
    const int32_t MCC_LEN = 3;
    std::string iso = "";
    auto inner = FindManagerInner(slotId);
    if (inner == nullptr) {
        return Str8ToStr16(iso);
    }
    if (inner->networkSearchHandler_ == nullptr) {
        return Str8ToStr16(iso);
    }
    std::string plmn = inner->networkSearchState_->GetNetworkStatus()->GetPlmnNumeric();
    int32_t len = plmn.length();
    if (len >= MCC_LEN) {
        std::string mcc = plmn.substr(0, MCC_LEN);
        int32_t value = 0;
        bool succ = StrToInt(mcc, value);
        if (succ) {
            iso = MccPool::MccCountryCode(value);
        } else {
            TELEPHONY_LOGE("GetIsoCountryCodeForNetwork parse Failed!! slotId:%{public}d", slotId);
        }
        TELEPHONY_LOGI(
            "NetworkSearchManager::GetIsoCountryCodeForNetwork mcc=%{public}s code=%{public}d slotId:%{public}d",
            mcc.c_str(), value, slotId);
    }
    return Str8ToStr16(iso);
}

bool NetworkSearchManager::GetPreferredNetwork(int32_t slotId, NSCALLBACK &callback)
{
    return eventSender_->SendCallback(slotId, RadioEvent::RADIO_GET_PREFERRED_NETWORK_MODE, &callback);
}

bool NetworkSearchManager::SetPreferredNetwork(int32_t slotId, int32_t networkMode, NSCALLBACK &callback)
{
    auto inner = FindManagerInner(slotId);
    if (inner != nullptr) {
        int32_t modemRaf = inner->radioCapability_.ratFamily;
        int32_t raf = NetworkUtils::GetRafFromNetworkMode(static_cast<PreferredNetworkMode>(networkMode));
        if (modemRaf == RAF_UNKNOWN || raf == RAF_UNKNOWN) {
            TELEPHONY_LOGE(
                "SetPreferredNetwork failed RadioAccessFamily is unknown!%{public}d %{public}d slotId:%{public}d",
                modemRaf, raf, slotId);
            return false;
        }
        int32_t filterRaf = modemRaf & raf;
        PreferredNetworkMode filterMode = NetworkUtils::GetNetworkModeFromRaf(filterRaf);
        TELEPHONY_LOGI("SetPreferredNetwork RadioAccessFamily is %{public}d %{public}d slotId:%{public}d",
            modemRaf, raf, slotId);
        return eventSender_->SendCallbackEx(
            slotId, RadioEvent::RADIO_SET_PREFERRED_NETWORK_MODE, &callback, static_cast<int32_t>(filterMode));
    }
    return false;
}

bool NetworkSearchManager::GetPreferredNetwork(int32_t slotId)
{
    TELEPHONY_LOGI("NetworkSearchManager GetPreferredNetwork slotId:%{public}d", slotId);
    return eventSender_->SendBase(slotId, RadioEvent::RADIO_GET_PREFERRED_NETWORK_MODE);
}

bool NetworkSearchManager::SetPreferredNetwork(int32_t slotId, int32_t networkMode)
{
    TELEPHONY_LOGI(
        "NetworkSearchManager SetPreferredNetwork networkMode:%{public}d slotId:%{public}d", networkMode, slotId);
    auto inner = FindManagerInner(slotId);
    if (inner != nullptr) {
        int32_t modemRaf = inner->radioCapability_.ratFamily;
        int32_t raf = NetworkUtils::GetRafFromNetworkMode(static_cast<PreferredNetworkMode>(networkMode));
        if (modemRaf == RAF_UNKNOWN || raf == RAF_UNKNOWN) {
            TELEPHONY_LOGE(
                "SetPreferredNetwork failed RadioAccessFamily is unknown!%{public}d %{public}d slotId:%{public}d",
                modemRaf, raf, slotId);
            return false;
        }
        int32_t filterRaf = modemRaf & raf;
        PreferredNetworkMode filterMode = NetworkUtils::GetNetworkModeFromRaf(filterRaf);
        return eventSender_->SendBase(
            slotId, RadioEvent::RADIO_SET_PREFERRED_NETWORK_MODE, static_cast<int32_t>(filterMode));
    }
    return false;
}
void NetworkSearchManager::SavePreferredNetworkValue(int32_t slotId, int32_t networkMode)
{
    TELEPHONY_LOGI("NetworkSearchManager SavePreferredNetworkValue slotId:%{public}d, networkMode:%{public}d",
        slotId, networkMode);
    TelProfileUtil *utils = DelayedSingleton<TelProfileUtil>::GetInstance().get();
    std::string str_key = KEY_DEFAULT_PREFERRED_NETWORK_MODE;
    str_key.append(std::to_string(slotId));
    int32_t result = utils->SaveInt(str_key, networkMode);
    if (result == NativePreferences::E_OK) {
        utils->Refresh();
    }
}

int32_t NetworkSearchManager::GetPreferredNetworkValue(int32_t slotId) const
{
    TelProfileUtil *utils = DelayedSingleton<TelProfileUtil>::GetInstance().get();
    std::string str_key = KEY_DEFAULT_PREFERRED_NETWORK_MODE;
    str_key.append(std::to_string(slotId));
    int32_t networkMode = utils->ObtainInt(str_key, 0);
    TELEPHONY_LOGI("NetworkSearchManager GetPreferredNetworkValue slotId:%{public}d, networkMode:%{public}d",
        slotId, networkMode);
    return networkMode;
}

void NetworkSearchManager::UpdatePhone(int32_t slotId, RadioTech csRadioTech)
{
    auto inner = FindManagerInner(slotId);
    if (inner != nullptr) {
        if (inner->networkSearchHandler_ != nullptr) {
            inner->networkSearchHandler_->UpdatePhone(csRadioTech);
            if (inner->networkSearchHandler_->GetPhoneType() == PhoneType::PHONE_TYPE_IS_CDMA) {
                SetImei(slotId, u"");
            } else {
                SetMeid(slotId, u"");
            }
        }
    }
}

bool NetworkSearchManager::GetImsRegStatus(int32_t slotId)
{
    auto inner = FindManagerInner(slotId);
    if (inner != nullptr) {
        if (inner->networkSearchState_ == nullptr) {
            TELEPHONY_LOGE(
                "NetworkSearchManager GetImsRegStatus networkSearchState is null slotId:%{public}d", slotId);
            return false;
        }
        return inner->networkSearchState_->GetImsStatus();
    }
    return false;
}

bool NetworkSearchManager::SetPsAttachStatus(int32_t slotId, int32_t psAttachStatus, NSCALLBACK &callback)
{
    return eventSender_->SendCallbackEx(slotId, RadioEvent::RADIO_SET_PS_ATTACH_STATUS, &callback, psAttachStatus);
}

void NetworkSearchManager::SetImei(int32_t slotId, std::u16string imei)
{
    auto inner = FindManagerInner(slotId);
    if (inner != nullptr) {
        inner->imei_ = imei;
    }
}

std::u16string NetworkSearchManager::GetImei(int32_t slotId)
{
    TELEPHONY_LOGI("NetworkSearchManager::GetImei start slotId:%{public}d", slotId);
    auto inner = FindManagerInner(slotId);
    if (inner != nullptr) {
        eventSender_->SendBase(slotId, RadioEvent::RADIO_GET_IMEI);
        return inner->imei_;
    }
    return std::u16string();
}

std::vector<sptr<CellInformation>> NetworkSearchManager::GetCellInfoList(int32_t slotId)
{
    std::vector<sptr<CellInformation>> vec;
    auto inner = FindManagerInner(slotId);
    if (inner != nullptr) {
        if (inner->networkSearchHandler_ != nullptr) {
            inner->networkSearchHandler_->GetCellInfoList(vec);
        }
    }
    return vec;
}

bool NetworkSearchManager::SendUpdateCellLocationRequest(int32_t slotId)
{
    auto inner = FindManagerInner(slotId);
    if (inner != nullptr) {
        if (inner->networkSearchHandler_ == nullptr || GetRadioState(slotId) == CORE_SERVICE_POWER_OFF) {
            return false;
        } else {
            inner->networkSearchHandler_->SendUpdateCellLocationRequest();
            return true;
        }
    }
    return false;
}

void NetworkSearchManager::UpdateCellLocation(int32_t slotId, int32_t techType, int32_t cellId, int32_t lac)
{
    auto inner = FindManagerInner(slotId);
    if (inner != nullptr) {
        if (inner->networkSearchHandler_ != nullptr) {
            inner->networkSearchHandler_->UpdateCellLocation(techType, cellId, lac);
        }
    }
}

sptr<CellLocation> NetworkSearchManager::GetCellLocation(int32_t slotId)
{
    auto inner = FindManagerInner(slotId);
    if (inner != nullptr) {
        if (inner->networkSearchHandler_ != nullptr) {
            return inner->networkSearchHandler_->GetCellLocation();
        }
    }
    return nullptr;
}

void NetworkSearchManager::SetMeid(int32_t slotId, std::u16string meid)
{
    auto inner = FindManagerInner(slotId);
    if (inner != nullptr) {
        inner->meid_ = meid;
    }
}

std::u16string NetworkSearchManager::GetMeid(int32_t slotId)
{
    TELEPHONY_LOGI("NetworkSearchManager::GetMeid start slotId:%{public}d", slotId);
    auto inner = FindManagerInner(slotId);
    if (inner != nullptr) {
        eventSender_->SendBase(slotId, RadioEvent::RADIO_GET_MEID);
        return inner->meid_;
    }
    return std::u16string();
}

std::u16string NetworkSearchManager::GetUniqueDeviceId(int32_t slotId)
{
    TELEPHONY_LOGI("NetworkSearchManager::GetUniqueDeviceId start slotId:%{public}d", slotId);
    auto inner = FindManagerInner(slotId);
    if (inner != nullptr) {
        if (!inner->imei_.empty()) {
            return inner->imei_;
        }
        if (!inner->meid_.empty()) {
            return inner->meid_;
        }
    }
    return std::u16string();
}

PhoneType NetworkSearchManager::GetPhoneType(int32_t slotId)
{
    PhoneType phoneType = PhoneType::PHONE_TYPE_IS_NONE;
    auto inner = FindManagerInner(slotId);
    if (inner != nullptr) {
        if (inner->networkSearchHandler_ != nullptr) {
            phoneType = inner->networkSearchHandler_->GetPhoneType();
        }
    }
    TELEPHONY_LOGI("NetworkSearchManager::GetPhoneType type:%{public}d start slotId:%{public}d",
        phoneType, slotId);
    return phoneType;
}

void NetworkSearchManager::GetVoiceTech(int32_t slotId)
{
    eventSender_->SendBase(slotId, RadioEvent::RADIO_GET_VOICE_TECH);
}

bool NetworkSearchManager::IsNrSupported(int32_t slotId)
{
    GetRadioCapability(slotId);
    auto inner = FindManagerInner(slotId);
    if (inner != nullptr) {
        return (inner->radioCapability_.ratFamily & static_cast<int32_t>(RAF_NR)) == static_cast<int32_t>(RAF_NR);
    }
    return false;
}

int32_t NetworkSearchManager::GetRadioCapability(int32_t slotId)
{
    eventSender_->SendBase(slotId, RadioEvent::RADIO_GET_RADIO_CAPABILITY);
    auto inner = FindManagerInner(slotId);
    if (inner != nullptr) {
        return inner->radioCapability_.ratFamily;
    }
    return false;
}

bool NetworkSearchManager::SetRadioCapability(int32_t slotId, RadioCapabilityInfo &radioCapability)
{
    return eventSender_->SendBase(slotId, RadioEvent::RADIO_SET_RADIO_CAPABILITY, radioCapability);
}

NrMode NetworkSearchManager::GetNrOptionMode(int32_t slotId)
{
    auto inner = FindManagerInner(slotId);
    if (inner != nullptr) {
        return inner->nrMode_;
    }
    return NrMode::NR_MODE_UNKNOWN;
}

void NetworkSearchManager::SetNrOptionMode(int32_t slotId, NrMode mode)
{
    auto inner = FindManagerInner(slotId);
    if (inner != nullptr) {
        inner->nrMode_ = mode;
    }
}

void NetworkSearchManager::SetFrequencyType(int32_t slotId, FrequencyType type)
{
    auto inner = FindManagerInner(slotId);
    if (inner != nullptr) {
        inner->freqType_ = type;
    }
}

FrequencyType NetworkSearchManager::GetFrequencyType(int32_t slotId)
{
    auto inner = FindManagerInner(slotId);
    if (inner != nullptr) {
        return inner->freqType_;
    }
    return FrequencyType::FREQ_TYPE_UNKNOWN;
}

NrState NetworkSearchManager::GetNrState(int32_t slotId)
{
    auto inner = FindManagerInner(slotId);
    if (inner != nullptr) {
        if (inner->networkSearchState_ != nullptr && inner->networkSearchHandler_ != nullptr) {
            auto event = inner->networkSearchState_->GetNetworkStatus()->GetNrState();
            TELEPHONY_LOGI("NetworkSearchManager::GetNrState result=%{public}d slotId:%{public}d", event, slotId);
            return event;
        }
    }
    TELEPHONY_LOGE("NetworkSearchManager::GetNrState Failed slotId:%{public}d", slotId);
    return NrState::NR_STATE_NOT_SUPPORT;
}

void NetworkSearchManager::DcPhysicalLinkActiveUpdate(int32_t slotId, bool isActive)
{
    auto inner = FindManagerInner(slotId);
    if (inner != nullptr) {
        if (inner->networkSearchHandler_ != nullptr) {
            inner->networkSearchHandler_->DcPhysicalLinkActiveUpdate(isActive);
        }
    }
}

std::shared_ptr<NetworkSearchManagerInner> NetworkSearchManager::FindManagerInner(int32_t slotId)
{
    {
        std::lock_guard<std::mutex> lock(mutexInner_);
        auto iter = mapManagerInner_.find(slotId);
        if (iter != mapManagerInner_.end()) {
            return iter->second;
        }
    }
    TELEPHONY_LOGE("NetworkSearchManager::FindManagerInner not find inner object. slotId:%{public}d", slotId);
    return nullptr;
}

void NetworkSearchManager::ClearManagerInner()
{
    std::lock_guard<std::mutex> lock(mutexInner_);
    mapManagerInner_.clear();
}

void NetworkSearchManager::AddManagerInner(int32_t slotId, std::shared_ptr<NetworkSearchManagerInner> inner)
{
    if (inner != nullptr) {
        std::lock_guard<std::mutex> lock(mutexInner_);
        mapManagerInner_.emplace(slotId, inner);
        TELEPHONY_LOGE(
            "NetworkSearchManager::AddManagerInner %{public}d %{public}zu", slotId, mapManagerInner_.size());
    }
}

bool NetworkSearchManager::RemoveManagerInner(int32_t slotId)
{
    std::lock_guard<std::mutex> lock(mutexInner_);
    bool ret = (mapManagerInner_.erase(slotId) != 0);
    TELEPHONY_LOGE(
        "NetworkSearchManager::RemoveManagerInner %{public}d %{public}zu", slotId, mapManagerInner_.size());
    return ret;
}

void NetworkSearchManager::TriggerSimRefresh(int32_t slotId)
{
    TELEPHONY_LOGI("NetworkSearchManager::TriggerSimRefresh  %{public}d", slotId);
    auto inner = FindManagerInner(slotId);
    if (inner != nullptr && simManager_ != nullptr) {
        if (inner->networkSearchHandler_ != nullptr) {
            simManager_->RegisterCoreNotify(slotId, inner->networkSearchHandler_,
                RadioEvent::RADIO_IMSI_LOADED_READY);
        }
    }
}

void NetworkSearchManager::TriggerTimezoneRefresh(int32_t slotId)
{
    auto inner = FindManagerInner(slotId);
    if (inner != nullptr) {
        if (inner->networkSearchHandler_ != nullptr) {
            inner->networkSearchHandler_->TimezoneRefresh();
        }
    }
    TELEPHONY_LOGE("NetworkSearchManager::TriggerTimezoneRefresh Failed slotId:%{public}d", slotId);
}
} // namespace Telephony
} // namespace OHOS
