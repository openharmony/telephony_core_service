/*
 * Copyright (C) 2022-2024 Huawei Device Co., Ltd.
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

#include "setting_utils.h"

#include "common_event_manager.h"
#include "rdb_errno.h"
#include "telephony_errors.h"
#include "telephony_log_wrapper.h"
#include "want.h"
#include "datashare_errno.h"

namespace OHOS {
namespace Telephony {
using namespace AppExecFwk;

const std::string SettingUtils::NETWORK_SEARCH_SETTING_URI =
    "datashare:///com.ohos.settingsdata/entry/settingsdata/SETTINGSDATA?Proxy=true";
static const std::string NETWORK_SEARCH_SETTING_EXT_URI = "datashare:///com.ohos.settingsdata.DataAbility";
const std::string SettingUtils::NETWORK_SEARCH_SETTING_AUTO_TIME_URI =
    "datashare:///com.ohos.settingsdata/entry/settingsdata/SETTINGSDATA?Proxy=true&key=auto_time";
const std::string SettingUtils::NETWORK_SEARCH_SETTING_AUTO_TIMEZONE_URI =
    "datashare:///com.ohos.settingsdata/entry/settingsdata/SETTINGSDATA?Proxy=true&key=auto_timezone";
const std::string SettingUtils::NETWORK_SEARCH_SETTING_AIRPLANE_MODE_URI =
    "datashare:///com.ohos.settingsdata/entry/settingsdata/SETTINGSDATA?Proxy=true&key=airplane_mode";
const std::string SettingUtils::NETWORK_SEARCH_SETTING_PREFERRED_NETWORK_MODE_URI =
    "datashare:///com.ohos.settingsdata/entry/settingsdata/SETTINGSDATA?Proxy=true&key=preferred_network_mode";

const std::string SettingUtils::SETTINGS_NETWORK_SEARCH_AUTO_TIME = "auto_time";
const std::string SettingUtils::SETTINGS_NETWORK_SEARCH_AUTO_TIMEZONE = "auto_timezone";
const std::string SettingUtils::SETTINGS_NETWORK_SEARCH_AIRPLANE_MODE = "settings.telephony.airplanemode";
const std::string SettingUtils::SETTINGS_NETWORK_SEARCH_PREFERRED_NETWORK_MODE =
    "settings.telephony.preferrednetworkmode";
const std::string SettingUtils::COMMON_EVENT_DATA_SHARE_READY = "usual.event.DATA_SHARE_READY";

SettingUtils::SettingUtils() = default;

SettingUtils::~SettingUtils() = default;

std::shared_ptr<DataShare::DataShareHelper> SettingUtils::CreateDataShareHelper()
{
    sptr<ISystemAbilityManager> saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (saManager == nullptr) {
        TELEPHONY_LOGE("SettingUtils: GetSystemAbilityManager failed.");
        return nullptr;
    }
    sptr<IRemoteObject> remoteObj = saManager->GetSystemAbility(TELEPHONY_CORE_SERVICE_SYS_ABILITY_ID);
    if (remoteObj == nullptr) {
        TELEPHONY_LOGE("SettingUtils: GetSystemAbility Service Failed.");
        return nullptr;
    }
    return DataShare::DataShareHelper::Creator(remoteObj, NETWORK_SEARCH_SETTING_URI, NETWORK_SEARCH_SETTING_EXT_URI);
}

std::shared_ptr<DataShare::DataShareHelper> SettingUtils::CreateNonBlockDataShareHelper()
{
    sptr<ISystemAbilityManager> saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (saManager == nullptr) {
        TELEPHONY_LOGE("SettingUtils: GetSystemAbilityManager failed.");
        return nullptr;
    }
    sptr<IRemoteObject> remoteObj = saManager->GetSystemAbility(TELEPHONY_CORE_SERVICE_SYS_ABILITY_ID);
    if (remoteObj == nullptr) {
        TELEPHONY_LOGE("SettingUtils: GetSystemAbility Service Failed.");
        return nullptr;
    }
    if (!isDdsReady_.load()) {
        TELEPHONY_LOGE("SettingUtils: distributedData is not started.");
        return nullptr;
    }
    auto [ret, helper] = DataShare::DataShareHelper::Create(remoteObj, NETWORK_SEARCH_SETTING_URI,
        NETWORK_SEARCH_SETTING_EXT_URI);
    if (ret == DataShare::E_OK) {
        return helper;
    } else if (ret == DataShare::E_DATA_SHARE_NOT_READY) {
        TELEPHONY_LOGE("SettingUtils: datashare not ready.");
        return nullptr;
    } else {
        TELEPHONY_LOGE("SettingUtils: create datashare fail, ret = %{public}d.", ret);
        return nullptr;
    }
}

bool SettingUtils::UnRegisterSettingsObserver(
    const Uri &uri, const sptr<AAFwk::IDataAbilityObserver> &dataObserver)
{
    std::lock_guard<ffrt::mutex> lock(mtx_);
    auto it = registerInfos_.begin();
    for (; it != registerInfos_.end();) {
        if (it->first == uri && it->second == dataObserver) {
            it = registerInfos_.erase(it);
        } else {
            it++;
        }
    }
    std::shared_ptr<DataShare::DataShareHelper> settingHelper = CreateNonBlockDataShareHelper();
    if (settingHelper == nullptr) {
        TELEPHONY_LOGE("settingHelper is null");
        return false;
    }
    settingHelper->UnregisterObserver(uri, dataObserver);
    settingHelper->Release();
    TELEPHONY_LOGI("SettingUtils: UnRegisterObserver Success");
    return true;
}

bool SettingUtils::RegisterSettingsObserver(
    const Uri &uri, const sptr<AAFwk::IDataAbilityObserver> &dataObserver)
{
    std::lock_guard<ffrt::mutex> lock(mtx_);
    auto it = registerInfos_.begin();
    for (; it != registerInfos_.end(); it++) {
        if (it->first == uri && it->second == dataObserver) {
            break;
        }
    }
    if (it == registerInfos_.end()) {
        registerInfos_.emplace_back(std::make_pair(uri, dataObserver));
    }
    return RegisterToDataShare(uri, dataObserver);
}

void SettingUtils::RegisterSettingsObserver()
{
    std::lock_guard<ffrt::mutex> lock(mtx_);
    for (auto it = registerInfos_.begin(); it != registerInfos_.end(); it++) {
        if (it->second == nullptr) {
            continue;
        }
        RegisterToDataShare(it->first, it->second);
        if (it->first.ToString() == NETWORK_SEARCH_SETTING_AIRPLANE_MODE_URI) {
            it->second->OnChange();
        }
    }
}

bool SettingUtils::RegisterToDataShare(
    const Uri &uri, const sptr<AAFwk::IDataAbilityObserver> &dataObserver)
{
    std::shared_ptr<DataShare::DataShareHelper> settingHelper = CreateNonBlockDataShareHelper();
    if (settingHelper == nullptr) {
        TELEPHONY_LOGE("settingHelper is null");
        return false;
    }
    settingHelper->RegisterObserver(uri, dataObserver);
    settingHelper->Release();
    TELEPHONY_LOGI("SettingUtils: RegisterObserver Success");
    return true;
}

int32_t SettingUtils::Query(Uri uri, const std::string &key, std::string &value)
{
    TELEPHONY_LOGI("SettingUtils:Query");
    std::shared_ptr<DataShare::DataShareHelper> settingHelper = CreateNonBlockDataShareHelper();
    if (settingHelper == nullptr) {
        TELEPHONY_LOGE("settingHelper is null");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }

    std::vector<std::string> columns;
    DataShare::DataSharePredicates predicates;
    predicates.EqualTo(SETTING_KEY, key);
    auto result = settingHelper->Query(uri, predicates, columns);
    if (result == nullptr) {
        TELEPHONY_LOGE("SettingUtils: query error, result is null");
        settingHelper->Release();
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }

    if (result->GoToFirstRow() != DataShare::E_OK) {
        TELEPHONY_LOGE("SettingUtils: query error, go to first row error");
        result->Close();
        settingHelper->Release();
        return TELEPHONY_ERR_DATABASE_READ_FAIL;
    }

    int columnIndex = 0;
    result->GetColumnIndex(SETTING_VALUE, columnIndex);
    result->GetString(columnIndex, value);
    result->Close();
    settingHelper->Release();
    TELEPHONY_LOGI("SettingUtils: query success");
    return TELEPHONY_SUCCESS;
}

int32_t SettingUtils::Insert(Uri uri, const std::string &key, const std::string &value)
{
    TELEPHONY_LOGI("SettingUtils: insert start");
    std::shared_ptr<DataShare::DataShareHelper> settingHelper = CreateNonBlockDataShareHelper();
    if (settingHelper == nullptr) {
        TELEPHONY_LOGE("settingHelper is null");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    DataShare::DataShareValuesBucket valuesBucket;
    DataShare::DataShareValueObject keyObj(key);
    DataShare::DataShareValueObject valueObj(value);
    valuesBucket.Put(SETTING_KEY, keyObj);
    valuesBucket.Put(SETTING_VALUE, valueObj);
    int32_t result = settingHelper->Insert(uri, valuesBucket);
    if (result == RDB_INVALID_VALUE) {
        settingHelper->Release();
        return TELEPHONY_ERR_DATABASE_WRITE_FAIL;
    }
    TELEPHONY_LOGI("SettingUtils: insert success");
    settingHelper->NotifyChange(uri);
    settingHelper->Release();
    return TELEPHONY_SUCCESS;
}

int32_t SettingUtils::Update(Uri uri, const std::string &key, const std::string &value)
{
    TELEPHONY_LOGI("SettingUtils:update");
    std::string queryValue = "";
    if (Query(uri, key, queryValue) != TELEPHONY_SUCCESS) {
        return Insert(uri, key, value);
    }
    std::shared_ptr<DataShare::DataShareHelper> settingHelper = CreateNonBlockDataShareHelper();
    if (settingHelper == nullptr) {
        TELEPHONY_LOGE("settingHelper is null");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    DataShare::DataShareValuesBucket valuesBucket;
    DataShare::DataShareValueObject valueObj(value);
    valuesBucket.Put(SETTING_VALUE, valueObj);
    DataShare::DataSharePredicates predicates;
    predicates.EqualTo(SETTING_KEY, key);
    int32_t result = settingHelper->Update(uri, predicates, valuesBucket);
    if (result == RDB_INVALID_VALUE) {
        settingHelper->Release();
        return TELEPHONY_ERR_DATABASE_WRITE_FAIL;
    }
    TELEPHONY_LOGI("SettingUtils: update success");
    settingHelper->NotifyChange(uri);
    settingHelper->Release();
    return TELEPHONY_SUCCESS;
}

void SettingUtils::SetCommonEventSubscribeInfo(const EventFwk::CommonEventSubscribeInfo &subscribeInfo)
{
    std::lock_guard<ffrt::mutex> lock(mtx_);
    commonEventSubscriber_ = std::make_shared<BroadcastSubscriber>(subscribeInfo);
}

std::shared_ptr<EventFwk::CommonEventSubscriber> SettingUtils::GetCommonEventSubscriber()
{
    std::lock_guard<ffrt::mutex> lock(mtx_);
    return commonEventSubscriber_;
}

void SettingUtils::UpdateDdsState(bool isReady)
{
    if (isReady == isDdsReady_.load()) {
        return;
    }
    isDdsReady_.store(isReady);
    if (isReady) {
        TELEPHONY_LOGI("Distributed data service start.");
        RegisterSettingsObserver();
    }
}

SettingUtils::BroadcastSubscriber::BroadcastSubscriber(const EventFwk::CommonEventSubscribeInfo &sp)
    : EventFwk::CommonEventSubscriber(sp)
{}

void SettingUtils::BroadcastSubscriber::OnReceiveEvent(const EventFwk::CommonEventData &data)
{
    const AAFwk::Want &want = data.GetWant();
    std::string action = want.GetAction();
    if (action != COMMON_EVENT_DATA_SHARE_READY) {
        TELEPHONY_LOGE("SettingUtils::CommonEventSubscriber event is not COMMON_EVENT_DATA_SHARE_READY");
        return;
    }
    SettingUtils::GetInstance()->RegisterSettingsObserver();
    TELEPHONY_LOGI("SettingUtils::OnReceiveEvent datashare is ready!");
}

AutoTimeObserver::AutoTimeObserver(std::shared_ptr<NetworkSearchHandler> &networkSearchHandler)
    : networkSearchHandler_(networkSearchHandler)
{}

void AutoTimeObserver::OnChange()
{
    TELEPHONY_LOGI("AutoTimeObserver::OnChange");
    if (networkSearchHandler_ != nullptr) {
        InnerEvent::Pointer event = InnerEvent::Get(SettingEventCode::MSG_AUTO_TIME);
        networkSearchHandler_->SendEvent(event);
    }
}

AutoTimezoneObserver::AutoTimezoneObserver(std::shared_ptr<NetworkSearchHandler> &networkSearchHandler)
    : networkSearchHandler_(networkSearchHandler)
{}

void AutoTimezoneObserver::OnChange()
{
    TELEPHONY_LOGI("AutoTimezoneObserver::OnChange");
    if (networkSearchHandler_ != nullptr) {
        InnerEvent::Pointer event = InnerEvent::Get(SettingEventCode::MSG_AUTO_TIMEZONE);
        networkSearchHandler_->SendEvent(event);
    }
}

AirplaneModeObserver::AirplaneModeObserver(std::shared_ptr<NetworkSearchHandler> &networkSearchHandler)
    : networkSearchHandler_(networkSearchHandler)
{}

void AirplaneModeObserver::OnChange()
{
    TELEPHONY_LOGI("AirplaneModeObserver::OnChange");
    if (networkSearchHandler_ != nullptr) {
        InnerEvent::Pointer event = InnerEvent::Get(SettingEventCode::MSG_AUTO_AIRPLANE_MODE);
        networkSearchHandler_->SendEvent(event);
    }
}
} // namespace Telephony
} // namespace OHOS
