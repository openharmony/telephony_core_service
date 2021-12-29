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

#include "string_ex.h"
#include "power_mgr_client.h"
#include "time_service_client.h"
#include "zone_util.h"
#include "common_event.h"
#include "common_event_manager.h"
#include "common_event_support.h"

#include "core_manager.h"
#include "tel_profile_util.h"
#include "telephony_log_wrapper.h"
#include "network_search_manager.h"

using namespace OHOS::PowerMgr;
using namespace OHOS::AppExecFwk;
using namespace OHOS::EventFwk;
namespace OHOS {
namespace Telephony {
static const int32_t MILLI_TO_BASE = 1000;
NitzUpdate::NitzUpdate(std::weak_ptr<NetworkSearchManager> networkSearchManager)
    : networkSearchManager_(networkSearchManager)
{}

void NitzUpdate::ProcessNitzUpdate(const AppExecFwk::InnerEvent::Pointer &event)
{
    if (event == nullptr) {
        TELEPHONY_LOGE("NitzUpdate::ProcessNitzUpdate event is nullptr");
        return;
    }
    std::shared_ptr<std::string> strTime = event->GetSharedObject<std::string>();
    if (strTime->empty()) {
        TELEPHONY_LOGE("NitzUpdate::ProcessNitzUpdate is nullptr");
        return;
    }

    int64_t now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    if ((now - lastUpdateTime_) < MAX_UPDATE_TIME) {
        TELEPHONY_LOGI("NitzUpdate::ProcessNitzUpdate update time");
        return;
    }

    NetworkTime networkTime;
    (void)memset_s(&networkTime, sizeof(NetworkTime), 0, sizeof(NetworkTime));
    if (NitzParse(*strTime, networkTime)) {
        ProcessTime(networkTime);
        ProcessTimeZone(networkTime);
    }
}

bool NitzUpdate::NitzParse(std::string &nitzStr, NetworkTime &networkTime)
{
    std::string strSep = ",";
    std::string strDateSubs = "";
    std::string strTimeSubs = "";
    std::vector<std::string> strsRet;
    SplitStr(nitzStr, strSep, strsRet);
    if (static_cast<uint32_t>(strsRet.size()) != static_cast<uint32_t>(TIMEZONE_SPLIT_NUM)) {
        TELEPHONY_LOGE("NitzUpdate::NitzParse nitz string error");
        return false;
    }
    strDateSubs = strsRet[0];
    strTimeSubs = strsRet[1];

    strsRet.clear();
    strSep = "/";
    SplitStr(strDateSubs, strSep, strsRet);
    if (static_cast<uint32_t>(strsRet.size()) != static_cast<uint32_t>(TIME_SPLIT_NUM)) {
        TELEPHONY_LOGE("NitzUpdate::NitzParse date string error");
        return false;
    }
    StrToInt(strsRet[0], networkTime.year);
    StrToInt(strsRet[1], networkTime.month);
    StrToInt(strsRet[LOCATION_DAY_OR_SEC], networkTime.day);

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
        TELEPHONY_LOGE("NitzUpdate::NitzTimeParse timezone string error %{public}s", strTimeSubs.c_str());
        return false;
    }

    std::vector<std::string> strsRet;
    SplitStr(strTimeSubs, strSep, strsRet);
    if (strsRet.size() != TIMEZONE_SPLIT_NUM) {
        TELEPHONY_LOGE("NitzUpdate::NitzTimeParse timezone error");
        return false;
    }
    strTimeSubs = strsRet[0];
    StrToInt(strsRet[1], networkTime.offset);
    networkTime.offset = networkTime.offset * flag;

    strSep = ":";
    strsRet.clear();
    SplitStr(strTimeSubs, strSep, strsRet);
    if (strsRet.size() != TIME_SPLIT_NUM) {
        TELEPHONY_LOGE("NitzUpdate::NitzTimeParse time vector error");
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
        TELEPHONY_LOGI("NitzUpdate::ProcessTime not auto udpate time");
    }
    if (networkTime.year < static_cast<int32_t>(CST_YEAR) || networkTime.month < 1) {
        TELEPHONY_LOGE("NitzUpdate::ProcessTime time error");
        return;
    }
    
#ifdef IS_SUPPORT_POWERMGR
    auto &powerMgrClient = PowerMgrClient::GetInstance();
    auto runningLock = powerMgrClient.CreateRunningLock("runninglock", RunningLockType::RUNNINGLOCK_BACKGROUND);
    runningLock->Lock();
#endif

    struct tm t;
    (void)memset_s(&t, sizeof(t), 0, sizeof(t));
    t.tm_year = networkTime.year - CST_YEAR;
    t.tm_mon = networkTime.month - 1;
    t.tm_mday = networkTime.day;
    t.tm_hour = networkTime.hour;
    t.tm_min = networkTime.minute;
    t.tm_sec = networkTime.second;
    int64_t time = (int64_t)mktime(&t) + networkTime.offset * ONE_QUARTER_TO_MINUTE * ONE_HOUR_TO_MINUTE;
    bool result = OHOS::MiscServices::TimeServiceClient::GetInstance()->SetTime(time * MILLI_TO_BASE);
    TELEPHONY_LOGI("NitzUpdate::ProcessTime result:%{public}d", result);

    std::string strDate(std::to_string(networkTime.year) + "/" + std::to_string(networkTime.month) + "/" +
        std::to_string(networkTime.day) + " " + std::to_string(networkTime.hour) + ":" +
        std::to_string(networkTime.minute) + ":" + std::to_string(networkTime.second));
    SaveTime(strDate);

#ifdef IS_SUPPORT_POWERMGR
    runningLock->UnLock();
#endif

    std::string action = "usual.event.NITZ_TIME_UPDATED";
    std::string param = "time";
    AAFwk::Want want;
    want.SetAction(action);
    want.SetParam(param, static_cast<long>(time));
    PublishCommonEvent(want);
}

void NitzUpdate::ProcessTimeZone(NetworkTime &networkTime)
{
    bool autoTimezone = IsAutoTimeZone();
    if (!autoTimezone) {
        TELEPHONY_LOGI("NitzUpdate::ProcessTimeZone not auto udpate timezone");
    }
    std::shared_ptr<NetworkSearchManager> nsm = networkSearchManager_.lock();
    if (nsm == nullptr) {
        TELEPHONY_LOGE("failed to get NetworkSearchManager");
        return;
    }

    std::u16string iso = nsm->GetIsoCountryCodeForNetwork(CoreManager::DEFAULT_SLOT_ID);
    std::string countryCode = Str16ToStr8(iso);
    if (!countryCode.empty()) {
        OHOS::Global::I18n::ZoneUtil util;
        std::string timeZone = util.GetDefaultZone(countryCode.c_str());
        if (timeZone.empty()) {
            int32_t offset = ONE_HOUR_TO_SECOND * ONE_SECOND_TO_MILLISECOND * networkTime.offset;
            timeZone = util.GetDefaultZone(countryCode.c_str(), offset);
        }
        if (timeZone.empty()) {
            TELEPHONY_LOGE("failed to get zone");
            return;
        }

        bool result = OHOS::MiscServices::TimeServiceClient::GetInstance()->SetTimeZone(timeZone);
        TELEPHONY_LOGI("NitzUpdate::ProcessTimeZone result:%{public}d", result);
        SaveTimeZone(timeZone);

        std::string action = "usual.event.NITZ_TIMEZONE_UPDATED";
        std::string param = "time-zone";
        AAFwk::Want want;
        want.SetAction(action);
        want.SetParam(param, timeZone);
        PublishCommonEvent(want);
    } else {
        TELEPHONY_LOGI("NitzUpdate::ProcessTimeZone countryCode is null, do nothing");
    }
}

void NitzUpdate::SaveTimeZone(std::string &timeZone)
{
    TELEPHONY_LOGI("NitzUpdate::SaveTime system timezone:%{public}s", timeZone.c_str());
    TelProfileUtil *utils = DelayedSingleton<TelProfileUtil>::GetInstance().get();
    std::string str_key = KEY_SYSTEM_TIMEZONE;
    int32_t result = utils->SaveString(str_key, timeZone);
    if (result == NativePreferences::E_OK) {
        utils->Refresh();
    }
}

void NitzUpdate::SaveTime(std::string &time)
{
    TELEPHONY_LOGI("NitzUpdate::SaveTime system time:%{public}s", time.c_str());
    TelProfileUtil *utils = DelayedSingleton<TelProfileUtil>::GetInstance().get();
    std::string str_key = KEY_SYSTEM_TIME;
    int32_t result = utils->SaveString(str_key, time);
    if (result == NativePreferences::E_OK) {
        utils->Refresh();
    }
}

bool NitzUpdate::IsAutoTimeZone()
{
    TelProfileUtil *utils = DelayedSingleton<TelProfileUtil>::GetInstance().get();
    std::string str_key = KEY_AUTO_TIME_ZONE;
    bool autoTimezone = utils->ObtainBool(str_key, true);
    TELEPHONY_LOGI("NitzUpdate::IsAutoTimeZone autoTimezone:%{public}d", autoTimezone);
    return autoTimezone;
}

bool NitzUpdate::IsAutoTime()
{
    TelProfileUtil *utils = DelayedSingleton<TelProfileUtil>::GetInstance().get();
    std::string str_key = KEY_AUTO_TIME;
    bool autoTime = utils->ObtainBool(str_key, true);
    TELEPHONY_LOGI("NitzUpdate::IsAutoTimeZone autoTime:%{public}d", autoTime);
    return autoTime;
}

void NitzUpdate::PublishCommonEvent(AAFwk::Want& want)
{
    CommonEventData data;
    data.SetWant(want);

    bool stickty = true;
    CommonEventPublishInfo publishInfo;
    publishInfo.SetSticky(stickty);
    bool publishResult = CommonEventManager::PublishCommonEvent(data, publishInfo, nullptr);
    if (!publishResult) {
        TELEPHONY_LOGE("NitzUpdate::PublishCommonEvent result : %{public}d", publishResult);
    }
}
} // namespace Telephony
} // namespace OHOS