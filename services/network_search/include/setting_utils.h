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

#ifndef NETWORK_SEARCH_SETTINGS_RDB_HELPER_H
#define NETWORK_SEARCH_SETTINGS_RDB_HELPER_H

#include <singleton.h>
#include <memory>
#include <utility>

#include "datashare_helper.h"
#include "datashare_predicates.h"
#include "datashare_result_set.h"
#include "datashare_values_bucket.h"
#include "data_ability_observer_stub.h"
#include "iservice_registry.h"
#include "result_set.h"
#include "system_ability_definition.h"
#include "uri.h"
#include "system_ability_status_change_stub.h"
#include "common_event_subscriber.h"
#include <ffrt.h>

#include "network_search_handler.h"

namespace OHOS {
namespace Telephony {
class SettingUtils : public DelayedSingleton<SettingUtils> {
    DECLARE_DELAYED_SINGLETON(SettingUtils);

public:
    static const std::string NETWORK_SEARCH_SETTING_URI;
    static const std::string NETWORK_SEARCH_SETTING_AUTO_TIME_URI;
    static const std::string NETWORK_SEARCH_SETTING_AUTO_TIMEZONE_URI;
    static const std::string NETWORK_SEARCH_SETTING_AIRPLANE_MODE_URI;
    static const std::string NETWORK_SEARCH_SETTING_PREFERRED_NETWORK_MODE_URI;
    static const std::string SETTINGS_NETWORK_SEARCH_AUTO_TIME;
    static const std::string SETTINGS_NETWORK_SEARCH_AUTO_TIMEZONE;
    static const std::string SETTINGS_NETWORK_SEARCH_AIRPLANE_MODE;
    static const std::string SETTINGS_NETWORK_SEARCH_PREFERRED_NETWORK_MODE;
    static const std::string COMMON_EVENT_DATA_SHARE_READY;

    bool RegisterSettingsObserver(const Uri &uri, const sptr<AAFwk::IDataAbilityObserver> &dataObserver);
    bool UnRegisterSettingsObserver(const Uri &uri, const sptr<AAFwk::IDataAbilityObserver> &dataObserver);
    void RegisterSettingsObserver();
    void SetCommonEventSubscribeInfo(const EventFwk::CommonEventSubscribeInfo &subscribeInfo);
    std::shared_ptr<EventFwk::CommonEventSubscriber> GetCommonEventSubscriber();
    int32_t Query(Uri uri, const std::string &key, std::string &value);
    int32_t Insert(Uri uri, const std::string &key, const std::string &value);
    int32_t Update(Uri uri, const std::string &key, const std::string &value);
    void UpdateDdsState(bool isReady);

private:
    std::shared_ptr<DataShare::DataShareHelper> CreateDataShareHelper();
    std::shared_ptr<DataShare::DataShareHelper> CreateNonBlockDataShareHelper();
    bool RegisterToDataShare(const Uri &uri, const sptr<AAFwk::IDataAbilityObserver> &dataObserver);

private:
    const std::string SETTING_KEY = "KEYWORD";
    const std::string SETTING_VALUE = "VALUE";
    const int32_t RDB_INVALID_VALUE = -1;
    ffrt::mutex mtx_;
    std::vector<std::pair<Uri, sptr<AAFwk::IDataAbilityObserver>>> registerInfos_;
    std::shared_ptr<EventFwk::CommonEventSubscriber> commonEventSubscriber_ = nullptr;
    std::atomic<bool> isDdsReady_ = false;

private:
    class BroadcastSubscriber : public EventFwk::CommonEventSubscriber {
    public:
        BroadcastSubscriber(const EventFwk::CommonEventSubscribeInfo &sp);
        ~BroadcastSubscriber() = default;
        void OnReceiveEvent(const EventFwk::CommonEventData &data) override;
    };
};

class SettingEventCode {
public:
    static const int32_t BASE = 0x00050000;
    static const int32_t MSG_AUTO_TIME = BASE + 0;
    static const int32_t MSG_AUTO_TIMEZONE = BASE + 1;
    static const int32_t MSG_AUTO_AIRPLANE_MODE = BASE + 2;
};

class AutoTimeObserver : public AAFwk::DataAbilityObserverStub {
public:
    explicit AutoTimeObserver(std::shared_ptr<NetworkSearchHandler> &networkSearchHandler);
    ~AutoTimeObserver() = default;
    void OnChange() override;

private:
    std::shared_ptr<NetworkSearchHandler> networkSearchHandler_;
};

class AutoTimezoneObserver : public AAFwk::DataAbilityObserverStub {
public:
    explicit AutoTimezoneObserver(std::shared_ptr<NetworkSearchHandler> &networkSearchHandler);
    ~AutoTimezoneObserver() = default;
    void OnChange() override;

private:
    std::shared_ptr<NetworkSearchHandler> networkSearchHandler_;
};

class AirplaneModeObserver : public AAFwk::DataAbilityObserverStub {
public:
    explicit AirplaneModeObserver(std::shared_ptr<NetworkSearchHandler> &networkSearchHandler);
    ~AirplaneModeObserver() = default;
    void OnChange() override;

private:
    std::shared_ptr<NetworkSearchHandler> networkSearchHandler_;
};
} // namespace Telephony
} // namespace OHOS
#endif // NETWORK_SEARCH_SETTINGS_RDB_HELPER_H
