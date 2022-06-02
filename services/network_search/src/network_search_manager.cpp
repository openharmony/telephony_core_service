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

NetworkSearchManager::~NetworkSearchManager()
{
    for (int32_t slotId = 0; slotId < SIM_SLOT_COUNT; slotId++) {
        std::shared_ptr<NetworkSearchManagerInner> inner = FindManagerInner(slotId);
        if (inner != nullptr) {
            inner->UnRegisterSetting();
        }
    }
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

bool NetworkSearchManagerInner::RegisterSetting()
{
    settingAutoTimeObserver_ = std::make_unique<AutoTimeObserver>(networkSearchHandler_).release();
    settingAutoTimezoneObserver_ = std::make_unique<AutoTimezoneObserver>(networkSearchHandler_).release();
    airplaneModeObserver_ = std::make_unique<AirplaneModeObserver>(networkSearchHandler_).release();
    std::shared_ptr<SettingUtils> settingHelper = SettingUtils::GetInstance();
    if (settingAutoTimeObserver_ == nullptr || settingAutoTimezoneObserver_ == nullptr ||
        airplaneModeObserver_ == nullptr || settingHelper == nullptr) {
        TELEPHONY_LOGE("NetworkSearchManager::RegisterSetting is null.");
        return false;
    }

    Uri autoTimeUri(SettingUtils::NETWORK_SEARCH_SETTING_AUTO_TIME_URI);
    Uri autoTimezoneUri(SettingUtils::NETWORK_SEARCH_SETTING_AUTO_TIMEZONE_URI);
    Uri airplaneModeUri(SettingUtils::NETWORK_SEARCH_SETTING_AIRPLANE_MODE_URI);
    settingHelper->RegisterSettingsObserver(autoTimeUri, settingAutoTimeObserver_);
    settingHelper->RegisterSettingsObserver(autoTimezoneUri, settingAutoTimezoneObserver_);
    settingHelper->RegisterSettingsObserver(airplaneModeUri, airplaneModeObserver_);
    return true;
}

bool NetworkSearchManagerInner::UnRegisterSetting()
{
    std::shared_ptr<SettingUtils> settingHelper = SettingUtils::GetInstance();
    if (settingHelper == nullptr) {
        TELEPHONY_LOGE("NetworkSearchManager::UnRegisterSetting is null.");
        return false;
    }

    Uri autoTimeUri(SettingUtils::NETWORK_SEARCH_SETTING_AUTO_TIME_URI);
    Uri autoTimezoneUri(SettingUtils::NETWORK_SEARCH_SETTING_AUTO_TIMEZONE_URI);
    Uri airplaneModeUri(SettingUtils::NETWORK_SEARCH_SETTING_AIRPLANE_MODE_URI);
    settingHelper->UnRegisterSettingsObserver(autoTimeUri, settingAutoTimeObserver_);
    settingHelper->UnRegisterSettingsObserver(autoTimezoneUri, settingAutoTimezoneObserver_);
    settingHelper->UnRegisterSettingsObserver(airplaneModeUri, airplaneModeObserver_);
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
                return false;
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
    TELEPHONY_LOGI("NetworkSearchManager::Init success");
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
    auto inner = FindManagerInner(slotId);
    if (inner == nullptr) {
        return;
    }
    int32_t fun = static_cast<int32_t>(isOn);
    eventSender_->SendBase(slotId, RadioEvent::RADIO_SET_STATUS, fun, rst);
}

bool NetworkSearchManager::SetRadioState(int32_t slotId, bool isOn, int32_t rst, NSCALLBACK &callback)
{
    TELEPHONY_LOGI("NetworkSearchManager SetRadioState isOn:%{public}d slotId:%{public}d", isOn, slotId);
    auto inner = FindManagerInner(slotId);
    if (inner == nullptr) {
        return false;
    }
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
        if (inner->networkSearchState_ != nullptr && inner->networkSearchState_->GetNetworkStatus() != nullptr) {
            auto event = static_cast<int32_t>(inner->networkSearchState_->GetNetworkStatus()->GetPsRadioTech());
            TELEPHONY_LOGI(
                "NetworkSearchManager::GetPsRadioTech result=%{public}d slotId:%{public}d", event, slotId);
            return event;
        }
        TELEPHONY_LOGE("NetworkSearchManager::GetPsRadioTech failed due to nullptr!");
    }
    TELEPHONY_LOGE("NetworkSearchManager::GetPsRadioTech Failed slotId:%{public}d", slotId);
    return TELEPHONY_ERROR;
}

int32_t NetworkSearchManager::GetCsRadioTech(int32_t slotId)
{
    auto inner = FindManagerInner(slotId);
    if (inner != nullptr) {
        if (inner->networkSearchState_ != nullptr && inner->networkSearchState_->GetNetworkStatus() != nullptr) {
            auto event = static_cast<int32_t>(inner->networkSearchState_->GetNetworkStatus()->GetCsRadioTech());
            TELEPHONY_LOGI(
                "NetworkSearchManager::GetCsRadioTech result=%{public}d slotId:%{public}d", event, slotId);
            return event;
        }
        TELEPHONY_LOGE("NetworkSearchManager::GetCsRadioTech failed due to nullptr!");
    }
    TELEPHONY_LOGE("NetworkSearchManager::GetCsRadioTech Failed slotId:%{public}d", slotId);
    return TELEPHONY_ERROR;
}

int32_t NetworkSearchManager::GetPsRegState(int32_t slotId)
{
    auto inner = FindManagerInner(slotId);
    if (inner != nullptr) {
        if (inner->networkSearchState_ != nullptr && inner->networkSearchState_->GetNetworkStatus() != nullptr) {
            auto event = static_cast<int32_t>(inner->networkSearchState_->GetNetworkStatus()->GetPsRegStatus());
            TELEPHONY_LOGI(
                "NetworkSearchManager::GetPsRegState result=%{public}d slotId:%{public}d", event, slotId);
            return event;
        }
        TELEPHONY_LOGE("NetworkSearchManager::GetPsRegState failed due to nullptr!");
    }
    TELEPHONY_LOGE("NetworkSearchManager::GetPsRegState Failed slotId:%{public}d", slotId);
    return TELEPHONY_ERROR;
}

int32_t NetworkSearchManager::GetCsRegState(int32_t slotId)
{
    auto inner = FindManagerInner(slotId);
    if (inner != nullptr) {
        if (inner->networkSearchState_ != nullptr && inner->networkSearchState_->GetNetworkStatus() != nullptr) {
            auto event = static_cast<int32_t>(inner->networkSearchState_->GetNetworkStatus()->GetCsRegStatus());
            TELEPHONY_LOGI(
                "NetworkSearchManager::GetCsRegState result=%{public}d slotId:%{public}d", event, slotId);
            return event;
        }
        TELEPHONY_LOGE("NetworkSearchManager::GetCsRegState failed due to nullptr!");
    }
    TELEPHONY_LOGE("NetworkSearchManager::GetCsRegState Failed slotId:%{public}d", slotId);
    return TELEPHONY_ERROR;
}

int32_t NetworkSearchManager::GetPsRoamingState(int32_t slotId)
{
    auto inner = FindManagerInner(slotId);
    if (inner != nullptr) {
        if (inner->networkSearchState_ != nullptr && inner->networkSearchState_->GetNetworkStatus() != nullptr) {
            auto event = static_cast<int32_t>(inner->networkSearchState_->GetNetworkStatus()->GetPsRoamingStatus());
            TELEPHONY_LOGI(
                "NetworkSearchManager::GetPsRoamingState result=%{public}d slotId:%{public}d", event, slotId);
            return event;
        }
        TELEPHONY_LOGE("NetworkSearchManager::GetPsRoamingState failed due to nullptr!");
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
        if (inner->networkSearchState_ != nullptr && inner->networkSearchState_->GetNetworkStatus() != nullptr) {
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
        if (inner->networkSearchState_ != nullptr &&
            inner->networkSearchState_->GetNetworkStatus() != nullptr) {
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
    auto inner = FindManagerInner(slotId);
    if (inner == nullptr) {
        return false;
    }
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
    auto inner = FindManagerInner(slotId);
    if (inner == nullptr) {
        return false;
    }
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
    auto inner = FindManagerInner(slotId);
    if (inner == nullptr) {
        return false;
    }
    return eventSender_->SendCallback(slotId, RadioEvent::RADIO_GET_NETWORK_SELECTION_MODE, &callback);
}

bool NetworkSearchManager::SetNetworkSelectionMode(
    int32_t slotId, int32_t selectMode, const sptr<NetworkInformation> &networkInformation, bool resumeSelection)
{
    TELEPHONY_LOGI("NetworkSearchManager SetNetworkSelectionMode selectMode:%{public}d slotId:%{public}d",
        selectMode, slotId);
    auto inner = FindManagerInner(slotId);
    if (inner == nullptr) {
        return false;
    }
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
    auto inner = FindManagerInner(slotId);
    if (inner == nullptr) {
        return false;
    }
    std::string plmnNumeric = "";
    if (networkInformation != nullptr) {
        plmnNumeric = networkInformation->GetOperatorNumeric();
    }
    return eventSender_->SendCallback(
        slotId, RadioEvent::RADIO_SET_NETWORK_SELECTION_MODE, &callback, selectMode, plmnNumeric);
}

std::u16string NetworkSearchManager::GetIsoCountryCodeForNetwork(int32_t slotId)
{
    const size_t MCC_LEN = 3;
    std::string iso = "";
    auto inner = FindManagerInner(slotId);
    if (inner == nullptr) {
        return Str8ToStr16(iso);
    }
    if (inner->networkSearchHandler_ == nullptr) {
        return Str8ToStr16(iso);
    }
    if (inner->networkSearchState_ != nullptr && inner->networkSearchState_->GetNetworkStatus() != nullptr) {
        std::string plmn = inner->networkSearchState_->GetNetworkStatus()->GetPlmnNumeric();
        size_t len = plmn.length();
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
    } else {
        TELEPHONY_LOGE(
            "NetworkSearchManager::GetIsoCountryCodeForNetwork Failed due to nullptr, slotId:%{public}d", slotId);
    }
    return Str8ToStr16(iso);
}

bool NetworkSearchManager::GetPreferredNetwork(int32_t slotId, NSCALLBACK &callback)
{
    auto inner = FindManagerInner(slotId);
    if (inner == nullptr) {
        return false;
    }
    return eventSender_->SendCallback(slotId, RadioEvent::RADIO_GET_PREFERRED_NETWORK_MODE, &callback);
}

bool NetworkSearchManager::SetPreferredNetwork(int32_t slotId, int32_t networkMode, NSCALLBACK &callback)
{
    auto inner = FindManagerInner(slotId);
    if (inner != nullptr) {
        uint32_t modemRaf = static_cast<uint32_t>(inner->radioCapability_.ratFamily);
        uint32_t raf = static_cast<uint32_t>(NetworkUtils::GetRafFromNetworkMode(
            static_cast<PreferredNetworkMode>(networkMode)));
        if (modemRaf == RAF_UNKNOWN || raf == RAF_UNKNOWN) {
            TELEPHONY_LOGE(
                "SetPreferredNetwork failed RadioAccessFamily is unknown!%{public}d %{public}d slotId:%{public}d",
                modemRaf, raf, slotId);
            return false;
        }
        uint32_t filterRaf = modemRaf & raf;
        PreferredNetworkMode filterMode = NetworkUtils::GetNetworkModeFromRaf(
            static_cast<uint32_t>(filterRaf));
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
    auto inner = FindManagerInner(slotId);
    if (inner == nullptr) {
        return false;
    }
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
    std::shared_ptr<SettingUtils> settingHelper = SettingUtils::GetInstance();
    if (settingHelper == nullptr) {
        TELEPHONY_LOGI("settingHelper is null");
        return;
    }

    Uri uri(SettingUtils::NETWORK_SEARCH_SETTING_PREFERRED_NETWORK_MODE_URI);
    std::string key = SettingUtils::SETTINGS_NETWORK_SEARCH_PREFERRED_NETWORK_MODE +
        "_" + std::to_string(slotId);
    std::string value = std::to_string(networkMode);
    if (!settingHelper->Update(uri, key, value)) {
        TELEPHONY_LOGE("Update %{public}s fail", key.c_str());
    }
}

int32_t NetworkSearchManager::GetPreferredNetworkValue(int32_t slotId) const
{
    int32_t networkMode = static_cast<int32_t>(PreferredNetworkMode::CORE_NETWORK_MODE_LTE_WCDMA_GSM);
    std::shared_ptr<SettingUtils> settingHelper = SettingUtils::GetInstance();
    if (settingHelper == nullptr) {
        TELEPHONY_LOGI("settingHelper is null");
        return networkMode;
    }

    Uri uri(SettingUtils::NETWORK_SEARCH_SETTING_PREFERRED_NETWORK_MODE_URI);
    std::string key = SettingUtils::SETTINGS_NETWORK_SEARCH_PREFERRED_NETWORK_MODE +
        "_" + std::to_string(slotId);
    std::string value = "";
    if (!settingHelper->Query(uri, key, value)) {
        TELEPHONY_LOGI("Query %{public}s fail", key.c_str());
        return networkMode;
    }

    bool succ = StrToInt(value, networkMode);
    TELEPHONY_LOGI("NetworkSearchManager GetPreferredNetworkValue succ:%{public}d, slotId:%{public}d, "
        "networkMode:%{public}d", slotId, succ, networkMode);
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

ImsRegInfo NetworkSearchManager::GetImsRegStatus(int32_t slotId, ImsServiceType imsSrvType)
{
    auto inner = FindManagerInner(slotId);
    if (inner != nullptr) {
        if (inner->networkSearchState_ == nullptr) {
            TELEPHONY_LOGE(
                "GetImsRegStatus networkSearchState is null, slotId:%{public}d, imsSrvType:%{public}d",
                slotId, imsSrvType);
            return ERROR_IMS_REG_INFO;
        }
        return inner->networkSearchState_->GetImsStatus(imsSrvType);
    }
    return ERROR_IMS_REG_INFO;
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

void NetworkSearchManager::SetLocateUpdate(int32_t slotId)
{
    TELEPHONY_LOGI("NetworkSearchManager::SetLocateUpdate start slotId:%{public}d", slotId);
    auto inner = FindManagerInner(slotId);
    if (inner == nullptr) {
        TELEPHONY_LOGI("NetworkSearchManager::SetLocateUpdate inner null slotId:%{public}d", slotId);
        return;
    }

    auto event = AppExecFwk::InnerEvent::Get(RadioEvent::RADIO_SET_LOCATION_UPDATE);
    if (event != nullptr && inner->networkSearchHandler_ != nullptr) {
        event->SetOwner(inner->networkSearchHandler_);
        telRilManager_->SetLocateUpdates(slotId, HRilRegNotifyMode::REG_NOTIFY_STAT_LAC_CELLID, event);
    }
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
    auto inner = FindManagerInner(slotId);
    if (inner == nullptr) {
        return;
    }
    eventSender_->SendBase(slotId, RadioEvent::RADIO_GET_VOICE_TECH);
    eventSender_->SendBase(slotId, RadioEvent::RADIO_OPERATOR);
}

bool NetworkSearchManager::IsNrSupported(int32_t slotId)
{
    auto inner = FindManagerInner(slotId);
    if (inner == nullptr) {
        return false;
    }
    GetRadioCapability(slotId);
    uint32_t modemRaf = static_cast<uint32_t>(inner->radioCapability_.ratFamily);
    return (modemRaf & static_cast<uint32_t>(RAF_NR)) == static_cast<uint32_t>(RAF_NR);
}

int32_t NetworkSearchManager::GetRadioCapability(int32_t slotId)
{
    auto inner = FindManagerInner(slotId);
    if (inner == nullptr) {
        return NetworkSearchManagerInner::DEFAULT_RAF;
    }
    eventSender_->SendBase(slotId, RadioEvent::RADIO_GET_RADIO_CAPABILITY);
    return inner->radioCapability_.ratFamily;
}

NrMode NetworkSearchManager::GetNrOptionMode(int32_t slotId)
{
    auto inner = FindManagerInner(slotId);
    if (inner != nullptr) {
        std::lock_guard<std::mutex> lock(inner->mutex_);
        return inner->nrMode_;
    }
    return NrMode::NR_MODE_UNKNOWN;
}

void NetworkSearchManager::SetNrOptionMode(int32_t slotId, NrMode mode)
{
    auto inner = FindManagerInner(slotId);
    if (inner != nullptr) {
        std::lock_guard<std::mutex> lock(inner->mutex_);
        inner->nrMode_ = mode;
    }
}

void NetworkSearchManager::SetFrequencyType(int32_t slotId, FrequencyType type)
{
    auto inner = FindManagerInner(slotId);
    if (inner != nullptr) {
        std::lock_guard<std::mutex> lock(inner->mutex_);
        inner->freqType_ = type;
    }
}

FrequencyType NetworkSearchManager::GetFrequencyType(int32_t slotId)
{
    auto inner = FindManagerInner(slotId);
    if (inner != nullptr) {
        std::lock_guard<std::mutex> lock(inner->mutex_);
        return inner->freqType_;
    }
    return FrequencyType::FREQ_TYPE_UNKNOWN;
}

NrState NetworkSearchManager::GetNrState(int32_t slotId)
{
    auto inner = FindManagerInner(slotId);
    if (inner != nullptr) {
        if (inner->networkSearchState_ != nullptr && inner->networkSearchState_->GetNetworkStatus() != nullptr) {
            auto event = inner->networkSearchState_->GetNetworkStatus()->GetNrState();
            TELEPHONY_LOGI("NetworkSearchManager::GetNrState result=%{public}d slotId:%{public}d", event, slotId);
            return event;
        }
        TELEPHONY_LOGE("NetworkSearchManager::GetNrState failed due to nullptr!");
    }
    TELEPHONY_LOGE("NetworkSearchManager::GetNrState Failed slotId:%{public}d", slotId);
    return NrState::NR_STATE_NOT_SUPPORT;
}

void NetworkSearchManager::DcPhysicalLinkActiveUpdate(int32_t slotId, bool isActive)
{
    auto inner = FindManagerInner(slotId);
    if (inner != nullptr) {
        if (inner->networkSearchHandler_ != nullptr) {
            int active = isActive ? 1 : 0;
            auto event = AppExecFwk::InnerEvent::Get(RadioEvent::RADIO_SET_DATA_CONNECT_ACTIVE, active);
            inner->networkSearchHandler_->SendEvent(event);
        }
    }
}

bool NetworkSearchManager::IsRadioFirstPowerOn(int32_t slotId)
{
    auto inner = FindManagerInner(slotId);
    if (inner != nullptr) {
        std::lock_guard<std::mutex> lock(inner->mutex_);
        return inner->isRadioFirstPowerOn_;
    }
    return false;
}

void NetworkSearchManager::SetRadioFirstPowerOn(int32_t slotId, bool isFirstPowerOn)
{
    auto inner = FindManagerInner(slotId);
    if (inner != nullptr) {
        std::lock_guard<std::mutex> lock(inner->mutex_);
        inner->isRadioFirstPowerOn_ = isFirstPowerOn;
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

void NetworkSearchManager::AddManagerInner(int32_t slotId, const std::shared_ptr<NetworkSearchManagerInner> &inner)
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
    TELEPHONY_LOGE("NetworkSearchManager::TriggerTimezoneRefresh slotId:%{public}d", slotId);
}

bool NetworkSearchManager::GetAirplaneMode()
{
#ifndef TELEPHONY_SUPPORT_AIRPLANE_MODE
    TELEPHONY_LOGI("do not support airplane mode, return true");
    return true;
#else
    std::shared_ptr<SettingUtils> settingHelper = SettingUtils::GetInstance();
    if (settingHelper == nullptr) {
        TELEPHONY_LOGI("settingHelper is null");
        return false;
    }

    Uri uri(SettingUtils::NETWORK_SEARCH_SETTING_AIRPLANE_MODE_URI);
    std::string value = "";
    std::string key = SettingUtils::SETTINGS_NETWORK_SEARCH_AIRPLANE_MODE;
    if (!settingHelper->Query(uri, key, value)) {
        TELEPHONY_LOGI("Query airplane mode fail");
        return false;
    }
    bool airplaneMode = value == "1";
    TELEPHONY_LOGI("Get airplane mode:%{public}d", airplaneMode);
    return airplaneMode;
#endif
}

int32_t NetworkSearchManager::RegImsCallback(MessageParcel &data)
{
    int32_t imsSrvType = data.ReadInt32();
    ImsServiceType type = static_cast<ImsServiceType>(imsSrvType);
    int32_t slotId = data.ReadInt32();
    TELEPHONY_LOGI("slotId is %{public}d", slotId);
    sptr<IRemoteObject> callback = data.ReadRemoteObject();
    sptr<ImsVoiceCallback> voiceCallback = nullptr;
    sptr<ImsVideoCallback> videoCallback = nullptr;
    sptr<ImsUtCallback> utCallback = nullptr;
    sptr<ImsSmsCallback> smsCallback = nullptr;
    int32_t ret;
    if (callback == nullptr) {
        TELEPHONY_LOGE("callback ptr is nullptr.");
        return ERROR;
    }
    switch (type) {
        case TYPE_VOICE:
            voiceCallback = iface_cast<ImsVoiceCallback>(callback);
            ret = RegImsVoiceCallback(slotId, voiceCallback);
            break;
        case TYPE_VIDEO:
            videoCallback = iface_cast<ImsVideoCallback>(callback);
            ret = RegImsVideoCallback(slotId, videoCallback);
            break;
        case TYPE_UT:
            utCallback = iface_cast<ImsUtCallback>(callback);
            ret = RegImsUtCallback(slotId, utCallback);
            break;
        case TYPE_SMS:
            smsCallback = iface_cast<ImsSmsCallback>(callback);
            ret = RegImsSmsCallback(slotId, smsCallback);
            break;
        default:
            TELEPHONY_LOGE("%{public}d unkunow ims service type!", type);
            return ERROR;
            break;
    }
    return ret;
}

int32_t NetworkSearchManager::UnRegImsCallback(MessageParcel &data)
{
    int32_t imsSrvType = data.ReadInt32();
    ImsServiceType type = static_cast<ImsServiceType>(imsSrvType);
    int32_t slotId = data.ReadInt32();
    sptr<IRemoteObject> remote  = data.ReadRemoteObject();
    sptr<ImsVoiceCallback> voiceCallback = nullptr;
    sptr<ImsVideoCallback> videoCallback = nullptr;
    sptr<ImsUtCallback> utCallback = nullptr;
    sptr<ImsSmsCallback> smsCallback = nullptr;
    int32_t ret;
    if (remote == nullptr) {
        TELEPHONY_LOGE("callback ptr is nullptr.");
        return ERROR;
    }
    switch (type) {
        case TYPE_VOICE:
            voiceCallback = iface_cast<ImsVoiceCallback>(remote);
            ret = UnRegImsVoiceCallback(slotId, voiceCallback);
            break;
        case TYPE_VIDEO:
            videoCallback = iface_cast<ImsVideoCallback>(remote);
            ret = UnRegImsVideoCallback(slotId, videoCallback);
            break;
        case TYPE_UT:
            utCallback = iface_cast<ImsUtCallback>(remote);
            ret = UnRegImsUtCallback(slotId, utCallback);
            break;
        case TYPE_SMS:
            smsCallback = iface_cast<ImsSmsCallback>(remote);
            ret = UnRegImsSmsCallback(slotId, smsCallback);
            break;
        default:
            TELEPHONY_LOGE("%{public}d unkunow ims service type!", type);
            return ERROR;
            break;
    }
    return ret;
}

void NetworkSearchManager::NotifyImsCallback(int32_t slotId, ImsServiceType imsSrvType, ImsRegInfo info)
{
    switch (imsSrvType) {
        case TYPE_VOICE:
            NotifyImsVoiceCallback(slotId, info);
            break;
        case TYPE_VIDEO:
            NotifyImsVideoCallback(slotId, info);
            break;
        case TYPE_UT:
            NotifyImsUtCallback(slotId, info);
            break;
        case TYPE_SMS:
            NotifyImsSmsCallback(slotId, info);
            break;
        default:
            TELEPHONY_LOGE("%{public}d unkunow ims service type!", imsSrvType);
            break;
    }
}

int32_t NetworkSearchManager::RegImsVoiceCallback(int32_t slotId, sptr<ImsVoiceCallback> callback)
{
    if (callback == nullptr) {
        TELEPHONY_LOGE("RegImsVoiceCallback:callback is nullptr");
        return ERROR;
    }
    auto iter = mapImsVoiceCallback_.find(slotId);
    if (iter != mapImsVoiceCallback_.end()) {
        std::list<sptr<ImsVoiceCallback>> &callbacks = iter->second;
        auto it = find(callbacks.begin(), callbacks.end(), callback);
        if (it == callbacks.end()) {
            callbacks.push_back(callback);
        }
        TELEPHONY_LOGI("NetworkSearchManager::RegImsVoiceCallBack update callback what: %{public}d,"
            " list size: %{public}zu", slotId, callbacks.size());
    } else {
        TELEPHONY_LOGI("NetworkSearchManager::RegImsVoiceCallBack callback what: %{public}d", slotId);
        std::list<sptr<ImsVoiceCallback>> callbacks;
        callbacks.push_back(callback);
        mapImsVoiceCallback_.emplace(slotId, callbacks);
    }
    return SUCCESS;
}

int32_t NetworkSearchManager::UnRegImsVoiceCallback(int32_t slotId, sptr<ImsVoiceCallback> callback)
{
    if (callback == nullptr) {
        TELEPHONY_LOGE("UnRegImsVoiceCallback:callback is nullptr");
        return ERROR;
    }

    auto iter = mapImsVoiceCallback_.find(slotId);
    if (iter != mapImsVoiceCallback_.end()) {
        std::list<sptr<ImsVoiceCallback>> &callbacks = iter->second;
        auto it = find(callbacks.begin(), callbacks.end(), callback);
        if (it != callbacks.end()) {
            callbacks.erase(it);
        }
        TELEPHONY_LOGI("NetworkSearchManager::UnRegImsVoiceCallBack Remove callbacks list: "
            "%{public}zu", callbacks.size());
    }
    return SUCCESS;
}

void NetworkSearchManager::RemoveAllImsVoiceCallback()
{
    mapImsVoiceCallback_.clear();
}

void NetworkSearchManager::NotifyImsVoiceCallback(int32_t slotId, ImsRegInfo info)
{
    auto iter = mapImsVoiceCallback_.find(slotId);
    if (iter == mapImsVoiceCallback_.end()) {
        TELEPHONY_LOGE("this %{public}d slot not register ImsVoiceCallback", slotId);
        return;
    }
    for (auto callback : iter->second) {
        TELEPHONY_LOGI("NotifyImsVoiceCallback slotId:%{public}d, ImsRegState:%{public}d, "
            "ImsRegTech:%{public}d", slotId, info.imsRegState, info.imsRegTech);
        callback->OnImsStateCallback(info);
    }
}

int32_t NetworkSearchManager::RegImsVideoCallback(int32_t slotId, sptr<ImsVideoCallback> callback)
{
    if (callback == nullptr) {
        TELEPHONY_LOGE("RegImsVideoCallback:callback is nullptr");
        return ERROR;
    }
    auto iter = mapImsVideoCallback_.find(slotId);
    if (iter != mapImsVideoCallback_.end()) {
        std::list<sptr<ImsVideoCallback>> &callbacks = iter->second;
        auto it = find(callbacks.begin(), callbacks.end(), callback);
        if (it == callbacks.end()) {
            callbacks.push_back(callback);
        }
        TELEPHONY_LOGI("NetworkSearchManager::RegImsVideoCallback update callback what: %{public}d,"
            " list size: %{public}zu", slotId, callbacks.size());
    } else {
        TELEPHONY_LOGI("NetworkSearchManager::RegImsVideoCallback callback what: %{public}d", slotId);
        std::list<sptr<ImsVideoCallback>> callbacks;
        callbacks.push_back(callback);
        mapImsVideoCallback_.emplace(slotId, callbacks);
    }
    return SUCCESS;
}

int32_t NetworkSearchManager::UnRegImsVideoCallback(int32_t slotId, sptr<ImsVideoCallback> callback)
{
    if (callback == nullptr) {
        TELEPHONY_LOGE("UnRegImsVideoCallback:callback is nullptr!");
        return ERROR;
    }

    auto iter = mapImsVideoCallback_.find(slotId);
    if (iter != mapImsVideoCallback_.end()) {
        std::list<sptr<ImsVideoCallback>> &callbacks = iter->second;
        auto it = find(callbacks.begin(), callbacks.end(), callback);
        if (it != callbacks.end()) {
            callbacks.erase(it);
        }
        TELEPHONY_LOGI("NetworkSearchManager::UnRegImsVideoCallback Remove callbacks list: "
            "%{public}zu", callbacks.size());
    }
    return SUCCESS;
}

void NetworkSearchManager::RemoveAllImsVideoCallback()
{
    mapImsVideoCallback_.clear();
}

void NetworkSearchManager::NotifyImsVideoCallback(int32_t slotId, ImsRegInfo info)
{
    auto iter = mapImsVideoCallback_.find(slotId);
    if (iter == mapImsVideoCallback_.end()) {
        TELEPHONY_LOGE("this %{public}d slot not register ImsVideoCallback", slotId);
        return;
    }
    for (auto callback : iter->second) {
        TELEPHONY_LOGI("NotifyImsVideoCallback slotId:%{public}d, ImsRegState:%{public}d, "
            "ImsRegTech:%{public}d", slotId, info.imsRegState, info.imsRegTech);
        callback->OnImsStateCallback(info);
    }
}

int32_t NetworkSearchManager::RegImsUtCallback(int32_t slotId, sptr<ImsUtCallback> callback)
{
    if (callback == nullptr) {
        TELEPHONY_LOGE("RegImsUtCallback:callback is nullptr");
        return ERROR;
    }
    auto iter = mapImsUtCallback_.find(slotId);
    if (iter != mapImsUtCallback_.end()) {
        std::list<sptr<ImsUtCallback>> &callbacks = iter->second;
        auto it = find(callbacks.begin(), callbacks.end(), callback);
        if (it == callbacks.end()) {
            callbacks.push_back(callback);
        }
        TELEPHONY_LOGI("NetworkSearchManager::RegImsUtCallback update callback what: %{public}d,"
            " list size: %{public}zu", slotId, callbacks.size());
    } else {
        TELEPHONY_LOGI("NetworkSearchManager::RegImsUtCallback callback what: %{public}d", slotId);
        std::list<sptr<ImsUtCallback>> callbacks;
        callbacks.push_back(callback);
        mapImsUtCallback_.emplace(slotId, callbacks);
    }
    return SUCCESS;
}

int32_t NetworkSearchManager::UnRegImsUtCallback(int32_t slotId, sptr<ImsUtCallback> callback)
{
    if (callback == nullptr) {
        TELEPHONY_LOGE("UnRegImsUtCallback:callback is nullptr!");
        return ERROR;
    }

    auto iter = mapImsUtCallback_.find(slotId);
    if (iter != mapImsUtCallback_.end()) {
        std::list<sptr<ImsUtCallback>> &callbacks = iter->second;
        auto it = find(callbacks.begin(), callbacks.end(), callback);
        if (it != callbacks.end()) {
            callbacks.erase(it);
        }
        TELEPHONY_LOGI("NetworkSearchManager::UnRegImsUtCallback Remove callbacks list: "
            "%{public}zu", callbacks.size());
    }
    return SUCCESS;
}

void NetworkSearchManager::RemoveAllImsUtCallback()
{
    mapImsUtCallback_.clear();
}

void NetworkSearchManager::NotifyImsUtCallback(int32_t slotId, ImsRegInfo info)
{
    auto iter = mapImsUtCallback_.find(slotId);
    if (iter == mapImsUtCallback_.end()) {
        TELEPHONY_LOGE("this %{public}d slot not register ImsUtCallback", slotId);
        return;
    }
    for (auto callback : iter->second) {
        TELEPHONY_LOGI("NotifyImsUtCallback slotId:%{public}d, ImsRegState:%{public}d, "
            "ImsRegTech:%{public}d", slotId, info.imsRegState, info.imsRegTech);
        callback->OnImsStateCallback(info);
    }
}

int32_t NetworkSearchManager::RegImsSmsCallback(int32_t slotId, sptr<ImsSmsCallback> callback)
{
    if (callback == nullptr) {
        TELEPHONY_LOGE("RegImsSmsCallback:callback is nullptr");
        return ERROR;
    }
    auto iter = mapImsSmsCallback_.find(slotId);
    if (iter != mapImsSmsCallback_.end()) {
        std::list<sptr<ImsSmsCallback>> &callbacks = iter->second;
        auto it = find(callbacks.begin(), callbacks.end(), callback);
        if (it == callbacks.end()) {
            callbacks.push_back(callback);
        }
        TELEPHONY_LOGI("NetworkSearchManager::RegImsSmsCallback update callback what: %{public}d,"
            " list size: %{public}zu", slotId, callbacks.size());
    } else {
        TELEPHONY_LOGI("NetworkSearchManager::RegImsSmsCallback callback what: %{public}d", slotId);
        std::list<sptr<ImsSmsCallback>> callbacks;
        callbacks.push_back(callback);
        mapImsSmsCallback_.emplace(slotId, callbacks);
    }
    return SUCCESS;
}

int32_t NetworkSearchManager::UnRegImsSmsCallback(int32_t slotId, sptr<ImsSmsCallback> callback)
{
    if (callback == nullptr) {
        TELEPHONY_LOGE("UnRegImsSmsCallback:callback is nullptr!");
        return ERROR;
    }

    auto iter = mapImsSmsCallback_.find(slotId);
    if (iter != mapImsSmsCallback_.end()) {
        std::list<sptr<ImsSmsCallback>> &callbacks = iter->second;
        auto it = find(callbacks.begin(), callbacks.end(), callback);
        if (it != callbacks.end()) {
            callbacks.erase(it);
        }
        TELEPHONY_LOGI("NetworkSearchManager::UnRegImsSmsCallback Remove callbacks list: "
            "%{public}zu", callbacks.size());
    }
    return SUCCESS;
}

void NetworkSearchManager::RemoveAllImsSmsCallback()
{
    mapImsSmsCallback_.clear();
}

void NetworkSearchManager::NotifyImsSmsCallback(int32_t slotId, ImsRegInfo info)
{
    auto iter = mapImsSmsCallback_.find(slotId);
    if (iter == mapImsSmsCallback_.end()) {
        TELEPHONY_LOGE("this %{public}d slot not register ImsSmsCallback", slotId);
        return;
    }
    for (auto callback : iter->second) {
        TELEPHONY_LOGI("NotifyImsSmsCallback slotId:%{public}d, ImsRegState:%{public}d, "
            "ImsRegTech:%{public}d", slotId, info.imsRegState, info.imsRegTech);
        callback->OnImsStateCallback(info);
    }
}
} // namespace Telephony
} // namespace OHOS
