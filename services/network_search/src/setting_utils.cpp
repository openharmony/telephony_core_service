/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#include "rdb_errno.h"

#include "telephony_log_wrapper.h"

namespace OHOS {
namespace Telephony {
using namespace AppExecFwk;

const std::string SettingUtils::NETWORK_SEARCH_SETTING_URI =
    "datashare:///com.ohos.settingsdata/entry/settingsdata/SETTINGSDATA?Proxy=true";
const std::string SettingUtils::NETWORK_SEARCH_SETTING_AUTO_TIME_URI =
    "datashare:///com.ohos.settingsdata/entry/settingsdata/SETTINGSDATA?Proxy=true&key=auto_time";
const std::string SettingUtils::NETWORK_SEARCH_SETTING_AUTO_TIMEZONE_URI =
    "datashare:///com.ohos.settingsdata/entry/settingsdata/SETTINGSDATA?Proxy=true&key=auto_timezone";
const std::string SettingUtils::NETWORK_SEARCH_SETTING_AIRPLANE_MODE_URI =
    "datashare:///com.ohos.settingsdata/entry/settingsdata/SETTINGSDATA?Proxy=true&key=airplane_mode";
const std::string SettingUtils::NETWORK_SEARCH_SETTING_PREFERRED_NETWORK_MODE_URI =
    "datashare:///com.ohos.settingsdata/entry/settingsdata/SETTINGSDATA?Proxy=true&key=preferred_network_mode";

const std::string SettingUtils::SETTINGS_NETWORK_SEARCH_AUTO_TIME = "settings.telephony.autotime";
const std::string SettingUtils::SETTINGS_NETWORK_SEARCH_AUTO_TIMEZONE = "settings.telephony.autotimezone";
const std::string SettingUtils::SETTINGS_NETWORK_SEARCH_AIRPLANE_MODE = "settings.telephony.airplanemode";
const std::string SettingUtils::SETTINGS_NETWORK_SEARCH_PREFERRED_NETWORK_MODE =
    "settings.telephony.preferrednetworkmode";

SettingUtils::SettingUtils()
{
    settingHelper_ = CreateDataShareHelper();
}

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
    return DataShare::DataShareHelper::Creator(remoteObj, NETWORK_SEARCH_SETTING_URI);
}

bool SettingUtils::UnRegisterSettingsObserver(
    const Uri &uri, const sptr<AAFwk::IDataAbilityObserver> &dataObserver)
{
    if (settingHelper_ == nullptr) {
        TELEPHONY_LOGE("settingHelper_ is null");
        return false;
    }
    settingHelper_->UnregisterObserver(uri, dataObserver);
    TELEPHONY_LOGI("SettingUtils: UnRegisterObserver Success");
    return true;
}

bool SettingUtils::RegisterSettingsObserver(
    const Uri &uri, const sptr<AAFwk::IDataAbilityObserver> &dataObserver)
{
    if (settingHelper_ == nullptr) {
        TELEPHONY_LOGE("settingHelper_ is null");
        return false;
    }
    settingHelper_->RegisterObserver(uri, dataObserver);
    TELEPHONY_LOGI("SettingUtils: RegisterObserver Success");
    return true;
}

bool SettingUtils::Query(Uri uri, const std::string &key, std::string &value)
{
    TELEPHONY_LOGI("SettingUtils:Query");
    if (settingHelper_ == nullptr) {
        TELEPHONY_LOGE("settingHelper_ is null");
        return false;
    }

    std::vector<std::string> columns;
    DataShare::DataSharePredicates predicates;
    predicates.EqualTo(SETTING_KEY, key);
    auto result = settingHelper_->Query(uri, predicates, columns);
    if (result == nullptr) {
        TELEPHONY_LOGE("SettingUtils: query error, result is null");
        return false;
    }

    if (result->GoToFirstRow() != NativeRdb::E_OK) {
        TELEPHONY_LOGE("SettingUtils: query error, go to first row error");
        return false;
    }

    int columnIndex = 0;
    result->GetColumnIndex(SETTING_VALUE, columnIndex);
    result->GetString(columnIndex, value);
    result->Close();
    TELEPHONY_LOGI("SettingUtils: query success");
    return true;
}

bool SettingUtils::Insert(Uri uri, const std::string &key, const std::string &value)
{
    TELEPHONY_LOGI("SettingUtils: insert start");
    if (settingHelper_ == nullptr) {
        TELEPHONY_LOGE("settingHelper_ is null");
        return false;
    }
    DataShare::DataShareValuesBucket valuesBucket;
    DataShare::DataShareValueObject keyObj(key);
    DataShare::DataShareValueObject valueObj(value);
    valuesBucket.Put(SETTING_KEY, keyObj);
    valuesBucket.Put(SETTING_VALUE, valueObj);
    int32_t result = settingHelper_->Insert(uri, valuesBucket);
    if (result == RDB_INVALID_VALUE) {
        return false;
    }
    TELEPHONY_LOGI("SettingUtils: insert success");
    settingHelper_->NotifyChange(uri);
    return true;
}

bool SettingUtils::Update(Uri uri, const std::string &key, const std::string &value)
{
    TELEPHONY_LOGI("SettingUtils:update");
    if (settingHelper_ == nullptr) {
        TELEPHONY_LOGE("settingHelper_ is null");
        return false;
    }
    std::string queryValue = "";
    bool ret = Query(uri, key, queryValue);
    if (!ret) {
        return Insert(uri, key, value);
    }

    DataShare::DataShareValuesBucket valuesBucket;
    DataShare::DataShareValueObject valueObj(value);
    valuesBucket.Put(SETTING_VALUE, valueObj);
    DataShare::DataSharePredicates predicates;
    predicates.EqualTo(SETTING_KEY, key);
    int32_t result = settingHelper_->Update(uri, predicates, valuesBucket);
    if (result == RDB_INVALID_VALUE) {
        return false;
    }
    TELEPHONY_LOGI("SettingUtils: update success");
    settingHelper_->NotifyChange(uri);
    return true;
}

AutoTimeObserver::AutoTimeObserver(std::shared_ptr<NetworkSearchHandler> &networkSearchHandler)
    : networkSearchHandler_(networkSearchHandler)
{}

void AutoTimeObserver::OnChange()
{
    std::shared_ptr<SettingUtils> settingHelper = SettingUtils::GetInstance();
    if (settingHelper == nullptr) {
        TELEPHONY_LOGI("settingHelper is null");
        return;
    }

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
    std::shared_ptr<SettingUtils> settingHelper = SettingUtils::GetInstance();
    if (settingHelper == nullptr) {
        TELEPHONY_LOGI("settingHelper is null");
        return;
    }

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
    std::shared_ptr<SettingUtils> settingHelper = SettingUtils::GetInstance();
    if (settingHelper == nullptr) {
        TELEPHONY_LOGI("settingHelper is null");
        return;
    }

    TELEPHONY_LOGI("AirplaneModeObserver::OnChange");
    if (networkSearchHandler_ != nullptr) {
        InnerEvent::Pointer event = InnerEvent::Get(SettingEventCode::MSG_AUTO_AIRPLANE_MODE);
        networkSearchHandler_->SendEvent(event);
    }
}
} // namespace Telephony
} // namespace OHOS