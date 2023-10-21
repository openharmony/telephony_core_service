/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

#include "time_zone_updater.h"

#include "common_event.h"
#include "common_event_manager.h"
#include "common_event_support.h"
#include "net_all_capabilities.h"
#include "power_mgr_client.h"
#include "setting_utils.h"
#include "telephony_errors.h"
#include "telephony_log_wrapper.h"
#include "time_service_client.h"
#include "zone_util.h"

using namespace OHOS::EventFwk;
namespace OHOS {
namespace Telephony {
using namespace AppExecFwk;
const std::string NET_TYPE = "NetType";
const std::string STRING_TRUE = "1";
const std::string PARAM_TIME_ZONE = "time-zone";
const std::string SHIELD_COUNTRY_CODE_RU = "ru";
const std::string SHIELD_TIME_ZONE_RU = "asia/omsk";
const std::string MULTI_TIMEZONE_COUNTRY_CODE[] = { "au", "br", "ca", "cd", "cl", "cy", "ec", "es", "fm", "gl", "id",
    "ki", "kz", "mn", "mx", "nz", "pf", "pg", "pt", "ru", "um", "us" };
constexpr int32_t TIMEZONE_OFFSET_INVALID = 0xFFFFFFFF;
constexpr uint32_t QUARTER_TO_MILLISECOND = 15 * 60 * 1000;
constexpr int LOCATION_TIME_OUT_MS = 30 * 1000;

TimeZoneUpdater::TimeZoneUpdater(const std::shared_ptr<EventRunner> &runner) : EventHandler(runner)
{
    offset_ = TIMEZONE_OFFSET_INVALID;
    memberFuncMap_[SettingEventCode::MSG_AUTO_TIMEZONE] = &TimeZoneUpdater::HandleAutoTimeZoneChange;
    memberFuncMap_[SettingEventCode::MSG_AUTO_AIRPLANE_MODE] = &TimeZoneUpdater::HandleAirplaneModeChange;
    memberFuncMap_[TimeZoneEventCode::EVENT_LOCATION_TIMEOUT] = &TimeZoneUpdater::HandleLocationTimeOut;
    memberFuncMap_[TimeZoneEventCode::EVENT_SCREEN_ON] = &TimeZoneUpdater::HandleScreenOnEvent;
    memberFuncMap_[TimeZoneEventCode::EVENT_COUNTRY_CODE_CHANGE] = &TimeZoneUpdater::HandleCountryCodeChange;
    memberFuncMap_[TimeZoneEventCode::EVENT_NETWORK_CONNECTED] = &TimeZoneUpdater::HandleNetworkConnected;
    memberFuncMap_[TimeZoneEventCode::EVENT_REQUEST_LOCATION_UPDATE] = &TimeZoneUpdater::HandleRequestLocationUpdate;
    memberFuncMap_[TimeZoneEventCode::EVENT_REQUEST_LOCATION_COUNTRY_CODE] =
        &TimeZoneUpdater::HandleRequestLocationCountryCode;
}

TimeZoneUpdater::~TimeZoneUpdater()
{
    UnInit();
}

void TimeZoneUpdater::ProcessEvent(const InnerEvent::Pointer &event)
{
    if (event == nullptr) {
        return;
    }
    auto msgType = event->GetInnerEventId();
    auto itFunc = memberFuncMap_.find(static_cast<RadioEvent>(msgType));
    if (itFunc != memberFuncMap_.end()) {
        auto memberFunc = itFunc->second;
        if (memberFunc != nullptr) {
            (this->*memberFunc)(event);
        }
    }
}

void TimeZoneUpdater::Init()
{
    if (locationSuggester_ != nullptr) {
        TELEPHONY_LOGE("TimeZoneUpdater already initialized");
        return;
    }

    locationSuggester_ = std::make_shared<TimeZoneLocationSuggester>(GetEventRunner());
    if (locationSuggester_ == nullptr) {
        TELEPHONY_LOGE("failed to create new TimeZoneLocationSuggester");
        return;
    }
    locationSuggester_->Init();

    autoTimeZone_ = IsAutoTimeZone();
    RegisterSetting();

    locationUpdate_ = std::make_shared<TimeZoneLocationUpdate>(locationSuggester_);
    if (locationUpdate_ == nullptr) {
        TELEPHONY_LOGE("failed to create new LocationUpdate");
        return;
    }
}

void TimeZoneUpdater::UnInit()
{
    UnRegisterSetting();
}

void TimeZoneUpdater::RegisterSetting()
{
    settingAutoTimezoneObserver_ = sptr<TimeZoneUpdater::AutoTimezoneObserver>(
        new (std::nothrow) TimeZoneUpdater::AutoTimezoneObserver(shared_from_this()));
    airplaneModeObserver_ = sptr<TimeZoneUpdater::AirplaneModeObserver>(
        new (std::nothrow) TimeZoneUpdater::AirplaneModeObserver(shared_from_this()));
    std::shared_ptr<SettingUtils> settingHelper = SettingUtils::GetInstance();
    if (settingAutoTimezoneObserver_ == nullptr || airplaneModeObserver_ == nullptr || settingHelper == nullptr) {
        TELEPHONY_LOGE("RegisterSetting is null.");
        return;
    }
    Uri autoTimezoneUri(SettingUtils::NETWORK_SEARCH_SETTING_AUTO_TIMEZONE_URI);
    Uri airplaneModeUri(SettingUtils::NETWORK_SEARCH_SETTING_AIRPLANE_MODE_URI);
    settingHelper->RegisterSettingsObserver(autoTimezoneUri, settingAutoTimezoneObserver_);
    settingHelper->RegisterSettingsObserver(airplaneModeUri, airplaneModeObserver_);
}

void TimeZoneUpdater::UnRegisterSetting()
{
    std::shared_ptr<SettingUtils> settingHelper = SettingUtils::GetInstance();
    if (settingHelper == nullptr) {
        TELEPHONY_LOGE("UnRegisterSetting is null.");
        return;
    }
    Uri autoTimezoneUri(SettingUtils::NETWORK_SEARCH_SETTING_AUTO_TIMEZONE_URI);
    Uri airplaneModeUri(SettingUtils::NETWORK_SEARCH_SETTING_AIRPLANE_MODE_URI);
    settingHelper->UnRegisterSettingsObserver(autoTimezoneUri, settingAutoTimezoneObserver_);
    settingHelper->UnRegisterSettingsObserver(airplaneModeUri, airplaneModeObserver_);
}

void TimeZoneUpdater::StartEventSubscriber()
{
    if (hasEventSubscriber_) {
        return;
    }
    hasEventSubscriber_ = true;
    if (locationUpdate_ != nullptr) {
        locationUpdate_->StartPassiveUpdate();
        if (IsScreenOn()) {
            RequestLocationUpdate();
        }
    }

    EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent(CommonEventSupport::COMMON_EVENT_CONNECTIVITY_CHANGE);
    matchingSkills.AddEvent(CommonEventSupport::COMMON_EVENT_SCREEN_ON);
    EventFwk::CommonEventSubscribeInfo subscriberInfo(matchingSkills);
    subscriberInfo.SetThreadMode(EventFwk::CommonEventSubscribeInfo::COMMON);
    eventSubscriber_ = std::make_shared<DeviceStateEventSubscriber>(subscriberInfo, shared_from_this());
    if (eventSubscriber_ == nullptr) {
        TELEPHONY_LOGE("failed to create new eventSubscriber");
        return;
    }
    auto samgrProxy = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    statusChangeListener_ = new (std::nothrow) SystemAbilityStatusChangeListener(eventSubscriber_);
    if (samgrProxy == nullptr || statusChangeListener_ == nullptr) {
        TELEPHONY_LOGE("samgrProxy or statusChangeListener_ is nullptr");
    } else {
        int32_t ret = samgrProxy->SubscribeSystemAbility(COMMON_EVENT_SERVICE_ID, statusChangeListener_);
        TELEPHONY_LOGI("SubscribeSystemAbility result:%{public}d", ret);
    }
}

void TimeZoneUpdater::StopEventSubscriber()
{
    if (!hasEventSubscriber_) {
        return;
    }
    hasEventSubscriber_ = false;
    if (locationUpdate_ != nullptr) {
        locationUpdate_->StopPassiveUpdate();
    }
    if (eventSubscriber_ != nullptr) {
        bool subscribeResult = CommonEventManager::UnSubscribeCommonEvent(eventSubscriber_);
        eventSubscriber_ = nullptr;
        TELEPHONY_LOGI("StopEventSubscriber subscribeResult = %{public}d", subscribeResult);
    }
}

void TimeZoneUpdater::QuerySetting(Uri &uri, std::string &key, std::string &value)
{
    std::shared_ptr<SettingUtils> settingHelper = SettingUtils::GetInstance();
    if (settingHelper == nullptr) {
        TELEPHONY_LOGE("settingHelper is null");
        return;
    }
    if (settingHelper->Query(uri, key, value) != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("Query %{public}s fail", key.c_str());
        return;
    }
}

bool TimeZoneUpdater::IsAutoTimeZone()
{
    Uri uri(SettingUtils::NETWORK_SEARCH_SETTING_AUTO_TIMEZONE_URI);
    std::string key = SettingUtils::SETTINGS_NETWORK_SEARCH_AUTO_TIMEZONE;
    std::string value = "";
    QuerySetting(uri, key, value);
    return value == STRING_TRUE;
}

bool TimeZoneUpdater::IsAirplaneMode()
{
    Uri uri(SettingUtils::NETWORK_SEARCH_SETTING_AIRPLANE_MODE_URI);
    std::string value = "";
    std::string key = SettingUtils::SETTINGS_NETWORK_SEARCH_AIRPLANE_MODE;
    QuerySetting(uri, key, value);
    return value == STRING_TRUE;
}

bool TimeZoneUpdater::IsLocationTimeZoneEnabled()
{
    return true;
}

bool TimeZoneUpdater::IsScreenOn()
{
    return PowerMgr::PowerMgrClient::GetInstance().IsScreenOn();
}

std::string TimeZoneUpdater::StringToLower(const std::string &str)
{
    std::string res = str;
    std::transform(res.begin(), res.end(), res.begin(), tolower);
    return res;
}

bool TimeZoneUpdater::IsMultiTimeZoneCountry(std::string &countryCode)
{
    if (countryCode.empty()) {
        TELEPHONY_LOGI("IsMultiTimeZoneCountry: countryCode is empty, false");
        return false;
    }
    for (size_t i = 0; i < sizeof(MULTI_TIMEZONE_COUNTRY_CODE) / sizeof(MULTI_TIMEZONE_COUNTRY_CODE[0]); i++) {
        if (countryCode == MULTI_TIMEZONE_COUNTRY_CODE[i]) {
            TELEPHONY_LOGI("IsMultiTimeZoneCountry: [%{public}s] true", countryCode.c_str());
            return true;
        }
    }
    TELEPHONY_LOGI("IsMultiTimeZoneCountry: [%{public}s] false", countryCode.c_str());
    return false;
}

void TimeZoneUpdater::HandleAutoTimeZoneChange(const InnerEvent::Pointer &)
{
    autoTimeZone_ = IsAutoTimeZone();
    if (!autoTimeZone_) {
        StopEventSubscriber();
        return;
    }
    if (IsLocationTimeZoneEnabled() && multiTimeZone_) {
        StartEventSubscriber();
        if (locationUpdate_ == nullptr || !locationUpdate_->IsLocationEnabled()) {
            UpdateTelephonyTimeZone();
        }
    } else {
        UpdateTelephonyTimeZone();
    }
}

void TimeZoneUpdater::HandleAirplaneModeChange(const InnerEvent::Pointer &)
{
    bool isAirplaneMode = IsAirplaneMode();
    if (!IsAirplaneMode()) {
        return;
    }
    if (locationSuggester_ != nullptr) {
        TELEPHONY_LOGI("HandleAirplaneModeChange: isAirplaneMode[%{public}d] clear location", isAirplaneMode);
        locationSuggester_->ClearLocation();
    }
}

void TimeZoneUpdater::HandleScreenOnEvent(const InnerEvent::Pointer &)
{
    if (!autoTimeZone_ || !IsLocationTimeZoneEnabled() || !multiTimeZone_) {
        return;
    }
    if (locationSuggester_ == nullptr) {
        TELEPHONY_LOGE("HandleScreenOnEvent: locationSuggester is null");
        return;
    }
    if (!locationSuggester_->HasLocation() || locationSuggester_->IsLocationExpired()) {
        RequestLocationUpdate();
    }
}

void TimeZoneUpdater::HandleNetworkConnected(const InnerEvent::Pointer &)
{
    if (!autoTimeZone_ || !IsLocationTimeZoneEnabled() || !multiTimeZone_) {
        return;
    }
    if (locationSuggester_ == nullptr) {
        TELEPHONY_LOGE("HandleNetworkConnected: locationSuggester is null");
        return;
    }
    if (!locationSuggester_->HasLocation()) {
        RequestLocationUpdate();
    }
}

void TimeZoneUpdater::HandleRequestLocationUpdate(const InnerEvent::Pointer &)
{
    if (!autoTimeZone_ || !IsLocationTimeZoneEnabled() || !multiTimeZone_) {
        TELEPHONY_LOGW("HandleRequestLocationUpdate: autoTimeZone[%{public}d] multiTimeZone[%{public}d]", autoTimeZone_,
            multiTimeZone_);
        return;
    }
    RequestLocationUpdate();
}

void TimeZoneUpdater::HandleRequestLocationCountryCode(const InnerEvent::Pointer &)
{
    if (!autoTimeZone_ || !IsLocationTimeZoneEnabled() || !multiTimeZone_) {
        TELEPHONY_LOGW("HandleRequestLocationCountryCode: autoTimeZone[%{public}d] multiTimeZone[%{public}d]",
            autoTimeZone_, multiTimeZone_);
        return;
    }
    if (locationUpdate_ == nullptr) {
        TELEPHONY_LOGE("locationUpdate is null");
        return;
    }
    std::string countryCode = locationUpdate_->GetIsoCountryCode();
    if (countryCode.empty()) {
        TELEPHONY_LOGE("countryCode is empty");
        return;
    }
    UpdateTelephonyTimeZone(countryCode);
}

void TimeZoneUpdater::HandleCountryCodeChange(const AppExecFwk::InnerEvent::Pointer &)
{
    if (IsLocationTimeZoneEnabled() && multiTimeZone_) {
        TELEPHONY_LOGI("StartEventSubscriber");
        StartEventSubscriber();
        if (locationUpdate_ == nullptr || !locationUpdate_->IsLocationEnabled()) {
            UpdateTelephonyTimeZone();
        }
    } else {
        TELEPHONY_LOGI("StopEventSubscriber");
        StopEventSubscriber();
        UpdateTelephonyTimeZone();
    }
}
} // namespace Telephony
} // namespace OHOS
