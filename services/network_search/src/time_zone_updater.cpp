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
#ifdef ABILITY_POWER_SUPPORT
#include "power_mgr_client.h"
#endif
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
const std::string STRING_FALSE = "0";
const std::string PARAM_TIME_ZONE = "time-zone";
const std::string SHIELD_COUNTRY_CODE_RU = "ru";
const std::string SHIELD_TIME_ZONE_RU = "asia/omsk";
const std::string MULTI_TIMEZONE_COUNTRY_CODE[] = { "au", "br", "ca", "cd", "cl", "cy", "ec", "es", "fm", "gl", "id",
    "ki", "kz", "mn", "mx", "nz", "pf", "pg", "pt", "ru", "um", "us" };
constexpr int32_t TIMEZONE_OFFSET_MAX = 24 * 4;
constexpr int32_t TIMEZONE_OFFSET_MIN = -24 * 4;
constexpr int32_t TIMEZONE_OFFSET_INVALID = TIMEZONE_OFFSET_MAX + 1;
constexpr int32_t QUARTER_TO_MILLISECOND = 15 * 60 * 1000;
constexpr int LOCATION_TIME_OUT_MS = 30 * 1000;

TimeZoneUpdater::TimeZoneUpdater() : TelEventHandler("TimeZoneUpdater")
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

    locationSuggester_ = std::make_shared<TimeZoneLocationSuggester>();
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
    bool isAutoTimeZone = true;
    if (value == STRING_FALSE) {
        isAutoTimeZone = false;
    }
    return isAutoTimeZone;
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
    bool isScreenOn = false;
#ifdef ABILITY_POWER_SUPPORT
    isScreenOn = PowerMgr::PowerMgrClient::GetInstance().IsScreenOn();
#endif
    return isScreenOn;
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

void TimeZoneUpdater::UpdateCountryCode(std::string &countryCode, int32_t slotId)
{
    if (countryCode.empty()) {
        TELEPHONY_LOGE("countryCode is empty");
        return;
    }
    std::string lowerCountryCode = StringToLower(countryCode);
    if (countryCode_ == lowerCountryCode) {
        TELEPHONY_LOGI("same countryCode");
        return;
    }
    slotId_ = slotId;
    countryCode_ = lowerCountryCode;
    offset_ = TIMEZONE_OFFSET_INVALID;
    multiTimeZone_ = IsMultiTimeZoneCountry(countryCode_);
    if (!autoTimeZone_) {
        return;
    }
    InnerEvent::Pointer event = InnerEvent::Get(TimeZoneEventCode::EVENT_COUNTRY_CODE_CHANGE);
    SendEvent(event);
}

void TimeZoneUpdater::UpdateTimeZoneOffset(int32_t offset, int32_t slotId)
{
    if (offset > TIMEZONE_OFFSET_MAX || offset < TIMEZONE_OFFSET_MIN) {
        TELEPHONY_LOGE("offset is invalid");
        return;
    }
    if (offset_ == offset) {
        return;
    }
    OHOS::Global::I18n::ZoneUtil util;
    std::string timeZone = util.GetDefaultZone(countryCode_, offset * QUARTER_TO_MILLISECOND);
    if (timeZone.empty()) {
        TELEPHONY_LOGE("invalid nitz: countryCode[%{public}s] offset[%{public}d]", countryCode_.c_str(), offset);
        return;
    }
    slotId_ = slotId;
    offset_ = offset;
    if (locationSuggester_ != nullptr) {
        locationSuggester_->NitzUpdate();
    }
    if (!autoTimeZone_) {
        return;
    }
    if (!UpdateTelephonyTimeZone(offset)) {
        TELEPHONY_LOGE("failed to update timezone");
        return;
    }
}

void TimeZoneUpdater::SendUpdateLocationRequest()
{
    InnerEvent::Pointer event = InnerEvent::Get(TimeZoneEventCode::EVENT_REQUEST_LOCATION_UPDATE);
    SendEvent(event);
}

void TimeZoneUpdater::SendUpdateLocationCountryCodeRequest()
{
    InnerEvent::Pointer event = InnerEvent::Get(TimeZoneEventCode::EVENT_REQUEST_LOCATION_COUNTRY_CODE);
    SendEvent(event);
}

void TimeZoneUpdater::UpdateTelephonyTimeZone()
{
    if (offset_ != TIMEZONE_OFFSET_INVALID) {
        if (!UpdateTelephonyTimeZone(offset_)) {
            TELEPHONY_LOGE("failed to update time zone");
        }
        return;
    }
    if (countryCode_.empty()) {
        TELEPHONY_LOGE("countryCode is empty");
        return;
    }
    OHOS::Global::I18n::ZoneUtil util;
    std::string timeZone = util.GetDefaultZone(countryCode_);
    if (timeZone.empty()) {
        TELEPHONY_LOGE("failed to get time zone");
        return;
    }
    TELEPHONY_LOGI(
        "save time zone, [%{public}s] from telephony countrycode[%{public}s]", timeZone.c_str(), countryCode_.c_str());
    if (!SaveTimeZone(timeZone)) {
        TELEPHONY_LOGE("failed to save time zone");
    }
}

bool TimeZoneUpdater::UpdateTelephonyTimeZone(int32_t offset)
{
    if (offset > TIMEZONE_OFFSET_MAX || offset < TIMEZONE_OFFSET_MIN) {
        TELEPHONY_LOGE("offset is invalid");
        return false;
    }
    OHOS::Global::I18n::ZoneUtil util;
    std::string timeZone = util.GetDefaultZone(countryCode_, offset * QUARTER_TO_MILLISECOND);
    if (timeZone.empty()) {
        TELEPHONY_LOGE("failed to get time zone");
        return false;
    }
    TELEPHONY_LOGI("save time zone, [%{public}s] from telephony nitz[%{public}s - %{public}d]", timeZone.c_str(),
        countryCode_.c_str(), offset_);
    return SaveTimeZone(timeZone);
}

void TimeZoneUpdater::UpdateTelephonyTimeZone(std::string &countryCode)
{
    if (countryCode.empty()) {
        TELEPHONY_LOGE("countryCode is empty");
        return;
    }
    OHOS::Global::I18n::ZoneUtil util;
    std::string timeZone = util.GetDefaultZone(countryCode);
    if (timeZone.empty()) {
        TELEPHONY_LOGE("failed to get time zone");
        return;
    }
    TELEPHONY_LOGI(
        "save time zone, [%{public}s] from location countrycode[%{public}s]", timeZone.c_str(), countryCode.c_str());
    if (!SaveTimeZone(timeZone)) {
        TELEPHONY_LOGE("failed to save time zone");
    }
}

bool TimeZoneUpdater::IsTimeZoneMatchCountryCode(std::string &timeZone)
{
    if (countryCode_.empty()) {
        return true;
    }
    if (timeZone.empty()) {
        TELEPHONY_LOGE("timeZone is empty, return false");
        return false;
    }
    std::vector<std::string> zoneList;
    OHOS::Global::I18n::ZoneUtil util;
    util.GetZoneList(countryCode_, zoneList);
    if (std::find(zoneList.begin(), zoneList.end(), timeZone) == zoneList.end()) {
        TELEPHONY_LOGW("countryCode[%{public}s] timeZone[%{public}s] not found, return false", countryCode_.c_str(),
            timeZone.c_str());
        return false;
    }
    return true;
}

bool TimeZoneUpdater::NeedUpdateLocationTimeZone(std::string &timeZone)
{
    if (StringToLower(timeZone) == SHIELD_TIME_ZONE_RU && countryCode_ == SHIELD_COUNTRY_CODE_RU) {
        TELEPHONY_LOGE("Special time zone, not need update");
        return false;
    }
    if (!IsTimeZoneMatchCountryCode(timeZone)) {
        TELEPHONY_LOGE("TimeZone not match country code");
        return false;
    }
    return true;
}

bool TimeZoneUpdater::UpdateLocationTimeZone(std::string &timeZone)
{
    if (timeZone.empty()) {
        TELEPHONY_LOGE("timezone is empty");
        return false;
    }
    if (!NeedUpdateLocationTimeZone(timeZone)) {
        TELEPHONY_LOGI("not need update time zone[%{public}s]", timeZone.c_str());
        return false;
    }
    TELEPHONY_LOGI("save time zone, [%{public}s] from location", timeZone.c_str());
    return SaveTimeZone(timeZone);
}

bool TimeZoneUpdater::SaveTimeZone(std::string &timeZone)
{
    std::string lastTimeZone = OHOS::MiscServices::TimeServiceClient::GetInstance()->GetTimeZone();
    if (timeZone == lastTimeZone) {
        TELEPHONY_LOGW("same time zone");
        return true;
    }
    bool result = OHOS::MiscServices::TimeServiceClient::GetInstance()->SetTimeZone(timeZone);
    TELEPHONY_LOGI("SetTimeZone result:%{public}d timezone:%{public}s", result, timeZone.c_str());

    std::string param = PARAM_TIME_ZONE;
    AAFwk::Want want;
    want.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_NITZ_TIMEZONE_CHANGED);
    want.SetParam(param, timeZone);
    CommonEventData data;
    data.SetWant(want);
    CommonEventPublishInfo publishInfo;
    publishInfo.SetSticky(true);
    bool publishResult = CommonEventManager::PublishCommonEvent(data, publishInfo, nullptr);
    if (!publishResult) {
        TELEPHONY_LOGE("PublishCommonEvent result:%{public}d", publishResult);
    }

    return result;
}

void TimeZoneUpdater::RequestLocationUpdate()
{
    if (locationUpdate_ == nullptr) {
        TELEPHONY_LOGE("locationUpdate is null");
        return;
    }
    if (!locationUpdate_->IsLocationEnabled()) {
        TELEPHONY_LOGE("location is disabled");
        return;
    }
    uint32_t eventId = static_cast<uint32_t>(TimeZoneEventCode::EVENT_LOCATION_TIMEOUT);
    if (HasInnerEvent(eventId)) {
        RemoveEvent(eventId);
        locationUpdate_->CancelUpdate();
    }
    InnerEvent::Pointer event = InnerEvent::Get(eventId);
    SendEvent(event, LOCATION_TIME_OUT_MS);
    locationUpdate_->RequestUpdate();
}

void TimeZoneUpdater::HandleLocationTimeOut(const InnerEvent::Pointer &)
{
    if (locationUpdate_ != nullptr) {
        locationUpdate_->CancelUpdate();
    }
}

TimeZoneUpdater::AutoTimezoneObserver::AutoTimezoneObserver(std::shared_ptr<EventHandler> eventHandler)
    : eventHandler_(eventHandler)
{}

void TimeZoneUpdater::AutoTimezoneObserver::OnChange()
{
    if (eventHandler_ != nullptr) {
        InnerEvent::Pointer event = InnerEvent::Get(SettingEventCode::MSG_AUTO_TIMEZONE);
        TelEventHandler::SendTelEvent(eventHandler_, event);
    }
}

TimeZoneUpdater::AirplaneModeObserver::AirplaneModeObserver(std::shared_ptr<EventHandler> eventHandler)
    : eventHandler_(eventHandler)
{}

void TimeZoneUpdater::AirplaneModeObserver::OnChange()
{
    if (eventHandler_ != nullptr) {
        InnerEvent::Pointer event = InnerEvent::Get(SettingEventCode::MSG_AUTO_AIRPLANE_MODE);
        TelEventHandler::SendTelEvent(eventHandler_, event);
    }
}

TimeZoneUpdater::DeviceStateEventSubscriber::DeviceStateEventSubscriber(
    const EventFwk::CommonEventSubscribeInfo &info, std::shared_ptr<EventHandler> eventHandler)
    : EventFwk::CommonEventSubscriber(info), eventHandler_(eventHandler)
{}

void TimeZoneUpdater::DeviceStateEventSubscriber::OnReceiveEvent(const EventFwk::CommonEventData &data)
{
    if (eventHandler_ == nullptr) {
        TELEPHONY_LOGE("eventHandler is null");
        return;
    }
    const AAFwk::Want &want = data.GetWant();
    std::string action = want.GetAction();
    if (action == CommonEventSupport::COMMON_EVENT_SCREEN_ON) {
        InnerEvent::Pointer event = InnerEvent::Get(TimeZoneEventCode::EVENT_SCREEN_ON);
        TelEventHandler::SendTelEvent(eventHandler_, event);
    } else if (action == CommonEventSupport::COMMON_EVENT_CONNECTIVITY_CHANGE) {
        int32_t bearType = data.GetWant().GetIntParam(NET_TYPE, NetManagerStandard::NetBearType::BEARER_DEFAULT);
        if (bearType != NetManagerStandard::NetBearType::BEARER_WIFI &&
            bearType != NetManagerStandard::NetBearType::BEARER_CELLULAR) {
            return;
        }
        bool isConnected = data.GetCode() == NetManagerStandard::NetConnState::NET_CONN_STATE_CONNECTED;
        if (isConnected) {
            InnerEvent::Pointer event = InnerEvent::Get(TimeZoneEventCode::EVENT_NETWORK_CONNECTED);
            TelEventHandler::SendTelEvent(eventHandler_, event);
        }
    }
}

TimeZoneUpdater::SystemAbilityStatusChangeListener::SystemAbilityStatusChangeListener(
    std::shared_ptr<DeviceStateEventSubscriber> &eventSubscriber)
    : eventSubscriber_(eventSubscriber)
{}

void TimeZoneUpdater::SystemAbilityStatusChangeListener::OnAddSystemAbility(
    int32_t systemAbilityId, const std::string &deviceId)
{
    if (systemAbilityId != COMMON_EVENT_SERVICE_ID) {
        TELEPHONY_LOGE("systemAbilityId is not COMMON_EVENT_SERVICE_ID");
        return;
    }
    if (eventSubscriber_ == nullptr) {
        TELEPHONY_LOGE("OnAddSystemAbility COMMON_EVENT_SERVICE_ID eventSubscriber is nullptr");
        return;
    }
    bool subscribeResult = EventFwk::CommonEventManager::SubscribeCommonEvent(eventSubscriber_);
    TELEPHONY_LOGI("TimeZoneUpdater::OnAddSystemAbility subscribeResult = %{public}d", subscribeResult);
}

void TimeZoneUpdater::SystemAbilityStatusChangeListener::OnRemoveSystemAbility(
    int32_t systemAbilityId, const std::string &deviceId)
{
    if (systemAbilityId != COMMON_EVENT_SERVICE_ID) {
        TELEPHONY_LOGE("systemAbilityId is not COMMON_EVENT_SERVICE_ID");
        return;
    }
    if (eventSubscriber_ == nullptr) {
        TELEPHONY_LOGE("OnRemoveSystemAbility COMMON_EVENT_SERVICE_ID opName_ is nullptr");
        return;
    }
    bool subscribeResult = CommonEventManager::UnSubscribeCommonEvent(eventSubscriber_);
    TELEPHONY_LOGI("TimeZoneUpdater::OnRemoveSystemAbility subscribeResult = %{public}d", subscribeResult);
}
} // namespace Telephony
} // namespace OHOS
