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

#include "nitz_update.h"

#include <securec.h>

#include "common_event.h"
#include "common_event_manager.h"
#include "common_event_support.h"
#include "core_manager_inner.h"
#include "network_search_manager.h"
#include "power_mgr_client.h"
#include "setting_utils.h"
#include "string_ex.h"
#include "telephony_log_wrapper.h"
#include "time_service_client.h"
#include "zone_util.h"

using namespace OHOS::PowerMgr;
using namespace OHOS::AppExecFwk;
using namespace OHOS::EventFwk;
namespace OHOS {
namespace Telephony {
const int32_t MILLI_TO_BASE = 1000;
const int32_t MAX_UPDATE_TIME = 5;
const uint32_t TIME_SPLIT_NUM = 3;
const uint32_t TIMEZONE_SPLIT_NUM = 2;
const uint32_t YEAR_LENGTH_TWO = 2;
const uint32_t YEAR_LENGTH_FOUR = 4;
const uint32_t CST_YEAR = 1900;
const uint32_t ONE_HOUR_TO_SECOND = 3600;
const uint32_t ONE_SECOND_TO_MILLISECOND = 1000;
const uint32_t LOCATION_DAY_OR_SEC = 2;
const uint32_t TIME_THRESHOLD = 3; // seconds
int64_t NitzUpdate::lastSystemTime_ = 0;
int32_t NitzUpdate::offset_ = 0;
int64_t NitzUpdate::lastNetworkTime_ = 0;
std::string NitzUpdate::timeZone_;

NitzUpdate::NitzUpdate(const std::weak_ptr<NetworkSearchManager> &networkSearchManager, int32_t slotId)
    : networkSearchManager_(networkSearchManager), slotId_(slotId)
{}

void NitzUpdate::ProcessNitzUpdate(const AppExecFwk::InnerEvent::Pointer &event)
{
    if (event == nullptr) {
        TELEPHONY_LOGE("NitzUpdate::ProcessNitzUpdate event is nullptr slotId:%{public}d", slotId_);
        return;
    }
    std::shared_ptr<std::string> strTime = event->GetSharedObject<std::string>();
    if (strTime->empty()) {
        TELEPHONY_LOGE("NitzUpdate::ProcessNitzUpdate is nullptr slotId:%{public}d", slotId_);
        return;
    }

    int64_t now = OHOS::MiscServices::TimeServiceClient::GetInstance()->GetBootTimeMs();
    if ((now / MILLI_TO_BASE - lastSystemTime_) < MAX_UPDATE_TIME) {
        TELEPHONY_LOGI("NitzUpdate::ProcessNitzUpdate update time slotId:%{public}d", slotId_);
        return;
    }

    TELEPHONY_LOGI(
        "NitzUpdate::ProcessNitzUpdate get time:%{public}s slotId:%{public}d", strTime.get()->c_str(), slotId_);
    NetworkTime networkTime = {0};
    if (NitzParse(*strTime, networkTime)) {
        ProcessTime(networkTime);
        offset_ = networkTime.offset;
        ProcessTimeZone();
    }
}

bool NitzUpdate::NitzParse(std::string &nitzStr, NetworkTime &networkTime)
{
    std::string strSep = ",";
    std::vector<std::string> strsRet;
    SplitStr(nitzStr, strSep, strsRet);
    if (static_cast<uint32_t>(strsRet.size()) < static_cast<uint32_t>(TIMEZONE_SPLIT_NUM)) {
        TELEPHONY_LOGE("NitzUpdate::NitzParse nitz string error slotId:%{public}d", slotId_);
        return false;
    }
    std::string strDateSubs = strsRet[0];
    strsRet.clear();
    strSep = "/";
    SplitStr(strDateSubs, strSep, strsRet);
    if (static_cast<uint32_t>(strsRet.size()) != static_cast<uint32_t>(TIME_SPLIT_NUM)) {
        TELEPHONY_LOGE("NitzUpdate::NitzParse date string error slotId:%{public}d", slotId_);
        return false;
    }
    std::string strYear = strsRet[0];
    if (strYear.length() != YEAR_LENGTH_TWO && strYear.length() != YEAR_LENGTH_FOUR) {
        TELEPHONY_LOGE("NitzUpdate::NitzParse year string length error slotId:%{public}d", slotId_);
        return false;
    }
    if (strYear.length() == YEAR_LENGTH_TWO) {
        strYear = "20" + strYear;
    }
    StrToInt(strYear, networkTime.year);
    StrToInt(strsRet[1], networkTime.month);
    StrToInt(strsRet[LOCATION_DAY_OR_SEC], networkTime.day);
     std::string strTimeSubs = strsRet[1];
    if (!NitzTimeParse(strTimeSubs, networkTime)) {
        return false;
    }
    return true;
}

bool NitzUpdate::NitzTimeParse(std::string &strTimeSubs, NetworkTime &networkTime)
{
    int32_t flag = 1;
    std::string strSep = "+";
    std::string::size_type posPositive = strTimeSubs.find(strSep);
    strSep = "-";
    std::string::size_type posNegative = strTimeSubs.find(strSep);
    if (posPositive != std::string::npos) {
        strSep = "+";
    } else if (posNegative != std::string::npos) {
        strSep = "-";
        flag = -1;
    } else {
        TELEPHONY_LOGE("NitzUpdate::NitzParse timezone string error %{public}s slotId:%{public}d",
            strTimeSubs.c_str(), slotId_);
        return false;
    }

    std::vector<std::string> strsRet;
    SplitStr(strTimeSubs, strSep, strsRet);
    if (strsRet.size() != TIMEZONE_SPLIT_NUM) {
        TELEPHONY_LOGE("NitzUpdate::NitzParse timezone error slotId:%{public}d", slotId_);
        return false;
    }
    strTimeSubs = strsRet[0];
    StrToInt(strsRet[1], networkTime.offset);
    networkTime.offset = networkTime.offset * flag;

    strSep = ":";
    strsRet.clear();
    SplitStr(strTimeSubs, strSep, strsRet);
    if (strsRet.size() != TIME_SPLIT_NUM) {
        TELEPHONY_LOGE("NitzUpdate::NitzParse timezone vector error slotId:%{public}d", slotId_);
        return false;
    }
    StrToInt(strsRet[0], networkTime.hour);
    StrToInt(strsRet[1], networkTime.minute);
    StrToInt(strsRet[LOCATION_DAY_OR_SEC], networkTime.second);

    return true;
}

void NitzUpdate::ProcessTime(NetworkTime &networkTime)
{
    bool autoTime = IsAutoTime();
    if (!autoTime) {
        TELEPHONY_LOGI("NitzUpdate::ProcessTime not auto udpate time slotId:%{public}d", slotId_);
    }
    if (networkTime.year < static_cast<int32_t>(CST_YEAR) || networkTime.month < 1) {
        TELEPHONY_LOGE("NitzUpdate::ProcessTime time error slotId:%{public}d", slotId_);
        return;
    }

    auto &powerMgrClient = PowerMgrClient::GetInstance();
    auto runningLock = powerMgrClient.CreateRunningLock("runninglock", RunningLockType::RUNNINGLOCK_BACKGROUND);
    if (runningLock != nullptr) {
        runningLock->Lock();
    }

    struct tm t;
    (void)memset_s(&t, sizeof(t), 0, sizeof(t));
    t.tm_year = networkTime.year - CST_YEAR;
    t.tm_mon = networkTime.month - 1;
    t.tm_mday = networkTime.day;
    t.tm_hour = networkTime.hour;
    t.tm_min = networkTime.minute;
    t.tm_sec = networkTime.second;

    if (!IsValidTime(static_cast<int64_t>(timegm(&t)))) {
        TELEPHONY_LOGE("NitzUpdate::ProcessTime invalid time, slotId:%{public}d", slotId_);
        return;
    }

    SaveTime(static_cast<int64_t>(timegm(&t)));
    if (runningLock != nullptr) {
        runningLock->UnLock();
    }
}

bool NitzUpdate::IsValidTime(int64_t networkTime)
{
    int64_t currentSystemTime = OHOS::MiscServices::TimeServiceClient::GetInstance()->GetBootTimeMs();
    if (currentSystemTime <= 0) {
        TELEPHONY_LOGE("NitzUpdate::IsInvalidTime current system time is invalid");
        return false;
    }
    currentSystemTime = currentSystemTime / MILLI_TO_BASE;
    if (lastSystemTime_ == 0 && lastNetworkTime_ == 0) {
        lastSystemTime_ = currentSystemTime;
        lastNetworkTime_ = networkTime;
        return true;
    }

    // The difference between the two NITZ times and the elapsed time should be within the threshold
    int64_t networkTimeInterval = networkTime - lastNetworkTime_;
    int64_t systemElapsedTime = currentSystemTime - lastSystemTime_;
    if (abs(networkTimeInterval - systemElapsedTime) > TIME_THRESHOLD) {
        TELEPHONY_LOGE(
            "NitzUpdate::IsInvalidTime The gap between the network time interval and the system elapsed time interval "
            "is large and will not be processed, slotId:%{public}d",
            slotId_);
        return false;
    }

    lastSystemTime_ = currentSystemTime;
    lastNetworkTime_ = networkTime;

    return true;
}

void NitzUpdate::ProcessTimeZone()
{
    bool autoTimezone = IsAutoTimeZone();
    if (!autoTimezone) {
        TELEPHONY_LOGI("NitzUpdate::ProcessTimeZone not auto udpate timezone slotId:%{public}d", slotId_);
    }
    std::shared_ptr<NetworkSearchManager> nsm = networkSearchManager_.lock();
    if (nsm == nullptr) {
        TELEPHONY_LOGE("failed to get NetworkSearchManager slotId:%{public}d", slotId_);
        return;
    }
    int32_t primarySlotId = INVALID_VALUE;
    CoreManagerInner::GetInstance().GetPrimarySlotId(primarySlotId);
    if (primarySlotId == INVALID_VALUE) {
        TELEPHONY_LOGI("primarySlotId %{public}d is invalid slotId:%{public}d", primarySlotId, slotId_);
        return;
    }
    std::u16string iso;
    nsm->GetIsoCountryCodeForNetwork(primarySlotId, iso);
    std::string countryCode = Str16ToStr8(iso);
    if (countryCode.empty()) {
        TELEPHONY_LOGE("NitzUpdate::ProcessCountryCode countryCode is null slotId:%{public}d", slotId_);
        return;
    }

    OHOS::Global::I18n::ZoneUtil util;
    std::string timeZone = util.GetDefaultZone(countryCode.c_str());
    if (timeZone.empty()) {
        int32_t offset = ONE_HOUR_TO_SECOND * ONE_SECOND_TO_MILLISECOND * offset_;
        timeZone = util.GetDefaultZone(countryCode.c_str(), offset);
    }
    if (timeZone.empty()) {
        TELEPHONY_LOGE("failed to get zone slotId:%{public}d", slotId_);
        return;
    }

    SaveTimeZone(timeZone);
}

void NitzUpdate::SaveTimeZone(std::string &timeZone)
{
    std::string lastTimeZone = OHOS::MiscServices::TimeServiceClient::GetInstance()->GetTimeZone();
    if (timeZone == lastTimeZone) {
        TELEPHONY_LOGI("NitzUpdate::SaveTimeZone timezone[%{public}s] is the same as lastTimeZone slotId:%{public}d",
            timeZone.c_str(), slotId_);
        return;
    }

    timeZone_ = timeZone;
    bool result = OHOS::MiscServices::TimeServiceClient::GetInstance()->SetTimeZone(timeZone);
    TELEPHONY_LOGI("NitzUpdate::ProcessTimeZone result:%{public}d timezone:%{public}s slotId:%{public}d",
        result, timeZone.c_str(), slotId_);

    std::string param = "time-zone";
    AAFwk::Want want;
    want.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_NITZ_TIMEZONE_CHANGED);
    want.SetParam(param, timeZone);
    PublishCommonEvent(want);
}

void NitzUpdate::SaveTime(int64_t networkTime)
{
    TELEPHONY_LOGI("NitzUpdate::SaveTime networkTime:(%{public}" PRId64 ") slotId:%{public}d", networkTime, slotId_);
    auto &powerMgrClient = PowerMgrClient::GetInstance();
    auto runningLock = powerMgrClient.CreateRunningLock("runninglock", RunningLockType::RUNNINGLOCK_BACKGROUND);
    if (runningLock != nullptr) {
        runningLock->Lock();
    }

    bool result = OHOS::MiscServices::TimeServiceClient::GetInstance()->SetTime(networkTime * MILLI_TO_BASE);
    TELEPHONY_LOGI("NitzUpdate::ProcessTime result:%{public}d slotId:%{public}d", result, slotId_);
    if (runningLock != nullptr) {
        runningLock->UnLock();
    }
    std::string param = "time";
    AAFwk::Want want;
    want.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_NITZ_TIME_CHANGED);
    want.SetParam(param, static_cast<int64_t>(networkTime));
    PublishCommonEvent(want);
}

bool NitzUpdate::IsAutoTimeZone()
{
    std::shared_ptr<SettingUtils> settingHelper = SettingUtils::GetInstance();
    if (settingHelper == nullptr) {
        TELEPHONY_LOGI("settingHelper is null");
        return false;
    }
    Uri uri(SettingUtils::NETWORK_SEARCH_SETTING_AUTO_TIMEZONE_URI);
    std::string key = SettingUtils::SETTINGS_NETWORK_SEARCH_AUTO_TIMEZONE;
    std::string value;
    if (!settingHelper->Query(uri, key, value)) {
        TELEPHONY_LOGI("Query %{public}s fail", key.c_str());
        return false;
    }
    bool autoTimezone = value == "1";
    TELEPHONY_LOGI("NitzUpdate::IsAutoTimeZone autoTimezone:%{public}d slotId:%{public}d", autoTimezone, slotId_);
    return autoTimezone;
}

bool NitzUpdate::IsAutoTime()
{
    std::shared_ptr<SettingUtils> settingHelper = SettingUtils::GetInstance();
    if (settingHelper == nullptr) {
        TELEPHONY_LOGI("settingHelper is null");
        return false;
    }
    Uri uri(SettingUtils::NETWORK_SEARCH_SETTING_AUTO_TIME_URI);
    std::string key = SettingUtils::SETTINGS_NETWORK_SEARCH_AUTO_TIME;
    std::string value = "";
    if (!settingHelper->Query(uri, key, value)) {
        TELEPHONY_LOGI("Query %{public}s fail", key.c_str());
        return false;
    }
    bool autoTime = value == "1";
    TELEPHONY_LOGI("NitzUpdate::IsAutoTime autoTime:%{public}d slotId:%{public}d", autoTime, slotId_);
    return autoTime;
}

void NitzUpdate::PublishCommonEvent(AAFwk::Want &want)
{
    CommonEventData data;
    data.SetWant(want);

    bool stickty = true;
    CommonEventPublishInfo publishInfo;
    publishInfo.SetSticky(stickty);
    bool publishResult = CommonEventManager::PublishCommonEvent(data, publishInfo, nullptr);
    if (!publishResult) {
        TELEPHONY_LOGE("NitzUpdate::PublishCommonEvent result:%{public}d slotId:%{public}d", publishResult, slotId_);
    }
}

void NitzUpdate::AutoTimeChange()
{
    bool autoTime = IsAutoTime();
    if (!autoTime) {
        return;
    }
    TELEPHONY_LOGI("now update autoTime:%{public}d slotId:%{public}d", autoTime, slotId_);
    int64_t time = OHOS::MiscServices::TimeServiceClient::GetInstance()->GetBootTimeMs();
    if (lastNetworkTime_ == 0 || lastSystemTime_ == 0 || time < lastSystemTime_) {
        return;
    }
    SaveTime(lastNetworkTime_ + (time - lastSystemTime_));
}

void NitzUpdate::AutoTimeZoneChange()
{
    bool autoTimezone = IsAutoTimeZone();
    if (!autoTimezone) {
        return;
    }
    TELEPHONY_LOGI("now update autoTimezone slotId:%{public}d, timeZone_:%{public}s", slotId_, timeZone_.c_str());
    if (timeZone_.empty()) {
        return;
    }
    SaveTimeZone(timeZone_);
}
} // namespace Telephony
} // namespace OHOS
