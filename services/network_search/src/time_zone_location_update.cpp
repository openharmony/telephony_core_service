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
#include "time_zone_location_update.h"

#include "telephony_errors.h"
#include "telephony_log_wrapper.h"
#include "time_zone_manager.h"

namespace OHOS {
namespace Telephony {
constexpr float TIME_ZONE_MAX_ACCURACY = 500.0;
constexpr int TIME_ZONE_FIX_NUMBER_ONCE = 1;

TimeZoneLocationUpdate::TimeZoneLocationUpdate(std::shared_ptr<TimeZoneLocationSuggester> locationSuggester)
    : locationSuggester_(locationSuggester)
{
    locatorImpl_ = Location::Locator::GetInstance();
    if (locatorImpl_ == nullptr) {
        TELEPHONY_LOGE("locatorImpl is null");
    }
    locationEnabled_ = locatorImpl_->IsLocationEnabled();
}

TimeZoneLocationUpdate::~TimeZoneLocationUpdate()
{
    UnregisterSwitchCallback();
    UnregisterLocationChange();
    locatorImpl_ = nullptr;
    locatorCallback_ = nullptr;
    registerCallback_ = nullptr;
    switchCallback_ = nullptr;
}

bool TimeZoneLocationUpdate::IsLocationEnabled()
{
    if (locatorImpl_ == nullptr) {
        TELEPHONY_LOGE("locatorImpl is null");
        return false;
    }
    return locatorImpl_->IsLocationEnabled();
}

void TimeZoneLocationUpdate::StartPassiveUpdate()
{
    needUpdate_ = true;
    RegisterSwitchCallback();
    RegisterLocationChange();
}

void TimeZoneLocationUpdate::StopPassiveUpdate()
{
    needUpdate_ = false;
    UnregisterSwitchCallback();
    UnregisterLocationChange();
}

void TimeZoneLocationUpdate::RequestUpdate()
{
    if (locatorImpl_ == nullptr || !locatorImpl_->IsLocationEnabled()) {
        TELEPHONY_LOGE("location disabled");
        return;
    }
    if (locatorCallback_ == nullptr) {
        locatorCallback_ = sptr<TimeZoneLocationUpdate::LocationCallback>(
            new (std::nothrow) TimeZoneLocationUpdate::LocationCallback(shared_from_this()));
        if (locatorCallback_ == nullptr) {
            TELEPHONY_LOGE("callback is null");
            return;
        }
    }
    auto callback = sptr<Location::ILocatorCallback>(locatorCallback_);
    auto requestConfig = std::make_unique<Location::RequestConfig>();
    requestConfig->SetPriority(Location::PRIORITY_FAST_FIRST_FIX);
    requestConfig->SetMaxAccuracy(TIME_ZONE_MAX_ACCURACY);
    requestConfig->SetFixNumber(TIME_ZONE_FIX_NUMBER_ONCE);
    TELEPHONY_LOGI("RequestLocation: StartLocating");
    locatorImpl_->StartLocating(requestConfig, callback);
}

void TimeZoneLocationUpdate::CancelUpdate()
{
    if (locatorImpl_ == nullptr) {
        TELEPHONY_LOGE("locatorImpl is null");
        return;
    }
    if (locatorCallback_ != nullptr) {
        auto callback = sptr<Location::ILocatorCallback>(locatorCallback_);
        TELEPHONY_LOGI("CancelUpdate: StopLocating");
        locatorImpl_->StopLocating(callback);
    }
}

std::string TimeZoneLocationUpdate::GetIsoCountryCode()
{
    if (locatorImpl_ == nullptr) {
        TELEPHONY_LOGE("locatorImpl is null");
        return "";
    }
    std::shared_ptr<Location::CountryCode> countryCode = locatorImpl_->GetIsoCountryCode();
    if (countryCode == nullptr) {
        TELEPHONY_LOGE("countryCode is null");
        return "";
    }
    if (countryCode->GetCountryCodeType() != Location::COUNTRY_CODE_FROM_LOCATION) {
        TELEPHONY_LOGW("countryCode is not from location");
        return "";
    }
    return countryCode->GetCountryCodeStr();
}

void TimeZoneLocationUpdate::RegisterLocationChange()
{
    if (locatorImpl_ == nullptr || !locatorImpl_->IsLocationEnabled()) {
        TELEPHONY_LOGE("location disabled");
        return;
    }
    if (registerCallback_ == nullptr) {
        registerCallback_ = sptr<TimeZoneLocationUpdate::LocationCallback>(
            new (std::nothrow) TimeZoneLocationUpdate::LocationCallback(shared_from_this()));
        if (registerCallback_ == nullptr) {
            TELEPHONY_LOGE("callback is null");
            return;
        }
    }

    auto callback = sptr<Location::ILocatorCallback>(registerCallback_);
    auto requestConfig = std::make_unique<Location::RequestConfig>(Location::SCENE_NO_POWER);
    TELEPHONY_LOGI("RegisterLocationChange: StartLocating");
    locatorImpl_->StartLocating(requestConfig, callback);
}

void TimeZoneLocationUpdate::UnregisterLocationChange()
{
    if (locatorImpl_ == nullptr) {
        TELEPHONY_LOGE("locatorImpl is null");
        return;
    }
    if (registerCallback_ != nullptr) {
        auto callback = sptr<Location::ILocatorCallback>(registerCallback_);
        TELEPHONY_LOGI("UnregisterLocationChange: StopLocating");
        locatorImpl_->StopLocating(callback);
    }
}

void TimeZoneLocationUpdate::RegisterSwitchCallback()
{
    if (locatorImpl_ == nullptr) {
        TELEPHONY_LOGE("locatorImpl is null");
        return;
    }
    if (switchCallback_ == nullptr) {
        switchCallback_ = sptr<TimeZoneLocationUpdate::SwitchCallback>(
            new (std::nothrow) TimeZoneLocationUpdate::SwitchCallback(shared_from_this()));
        if (switchCallback_ == nullptr) {
            TELEPHONY_LOGE("callback is null");
            return;
        }
    }
    TELEPHONY_LOGI("RegisterSwitchCallback");
    locatorImpl_->RegisterSwitchCallback(switchCallback_->AsObject(), Location::DEFAULT_UID);
}

void TimeZoneLocationUpdate::UnregisterSwitchCallback()
{
    if (locatorImpl_ == nullptr) {
        TELEPHONY_LOGE("locatorImpl is null");
        return;
    }
    if (switchCallback_ != nullptr) {
        TELEPHONY_LOGI("UnregisterSwitchCallback");
        locatorImpl_->UnregisterSwitchCallback(switchCallback_->AsObject());
    }
}

void TimeZoneLocationUpdate::LocationSwitchChange()
{
    if (!needUpdate_) {
        return;
    }
    if (locatorImpl_ == nullptr) {
        TELEPHONY_LOGE("locatorImpl is null");
        return;
    }
    bool locationEnabled = locationEnabled_;
    locationEnabled_ = locatorImpl_->IsLocationEnabled();
    if (!locationEnabled && locationEnabled_) {
        TELEPHONY_LOGI("Enable location");
        RegisterLocationChange();
        DelayedSingleton<TimeZoneManager>::GetInstance()->SendUpdateLocationRequest();
    } else if (locationEnabled && !locationEnabled_) {
        TELEPHONY_LOGI("Disable location");
        UnregisterLocationChange();
    } else {
        TELEPHONY_LOGI("Location switch not change[%{public}d]", locationEnabled_);
    }
}

void TimeZoneLocationUpdate::LocationReport(const std::unique_ptr<Location::Location> &location)
{
    if (location == nullptr) {
        TELEPHONY_LOGE("location is null");
        return;
    }
    if (location->GetIsFromMock() || location->GetAccuracy() > TIME_ZONE_MAX_ACCURACY) {
        TELEPHONY_LOGE("location is invalid: IsFromMock[%{public}d], Accuracy[%{public}f]", location->GetIsFromMock(),
            location->GetAccuracy());
        return;
    }
    if (locationSuggester_ == nullptr) {
        TELEPHONY_LOGE("locationSuggester is null");
        return;
    }
    locationSuggester_->LocationUpdate(location);
}

TimeZoneLocationUpdate::LocationCallback::LocationCallback(std::shared_ptr<TimeZoneLocationUpdate> locationUpdate)
    : locationUpdate_(locationUpdate)
{}

void TimeZoneLocationUpdate::LocationCallback::OnLocationReport(const std::unique_ptr<Location::Location> &location)
{
    TELEPHONY_LOGI("OnLocationReport");
    if (locationUpdate_ != nullptr) {
        locationUpdate_->LocationReport(location);
    }
}

void TimeZoneLocationUpdate::LocationCallback::OnLocatingStatusChange(const int status) {}

void TimeZoneLocationUpdate::LocationCallback::OnErrorReport(const int errorCode) {}

int TimeZoneLocationUpdate::LocationCallback::OnRemoteRequest(
    uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    if (data.ReadInterfaceToken() != GetDescriptor()) {
        TELEPHONY_LOGE("LocationCallback invalid token.");
        return -1;
    }
    switch (code) {
        case RECEIVE_LOCATION_INFO_EVENT: {
            std::unique_ptr<OHOS::Location::Location> location = OHOS::Location::Location::Unmarshalling(data);
            OnLocationReport(location);
            break;
        }
        case RECEIVE_ERROR_INFO_EVENT: {
            int32_t errorCode = data.ReadInt32();
            OnErrorReport(errorCode);
            break;
        }
        case RECEIVE_LOCATION_STATUS_EVENT: {
            int32_t status = data.ReadInt32();
            OnLocatingStatusChange(status);
            break;
        }
        default: {
            TELEPHONY_LOGE("LocationCallback receive error code:%{public}u", code);
            break;
        }
    }
    return 0;
}

TimeZoneLocationUpdate::SwitchCallback::SwitchCallback(std::shared_ptr<TimeZoneLocationUpdate> locationUpdate)
    : locationUpdate_(locationUpdate)
{}

void TimeZoneLocationUpdate::SwitchCallback::OnSwitchChange(const int state)
{
    if (locationUpdate_) {
        locationUpdate_->LocationSwitchChange();
    }
}

int TimeZoneLocationUpdate::SwitchCallback::OnRemoteRequest(
    uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    if (data.ReadInterfaceToken() != GetDescriptor()) {
        TELEPHONY_LOGE("SwitchCallback invalid token.");
        return -1;
    }
    switch (code) {
        case RECEIVE_SWITCH_STATE_EVENT: {
            int32_t status = data.ReadInt32();
            OnSwitchChange(status);
            break;
        }
        default: {
            TELEPHONY_LOGE("SwitchCallback receive error code:%{public}u", code);
            break;
        }
    }
    return 0;
}
} // namespace Telephony
} // namespace OHOS
