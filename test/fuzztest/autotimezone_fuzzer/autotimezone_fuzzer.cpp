/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "autotimezone_fuzzer.h"

#include <cstddef>
#include <cstdint>

#define private public
#define protected public
#include "addcoreservicetoken_fuzzer.h"
#include "event_runner.h"
#include "sim_manager.h"
#include "tel_ril_manager.h"
#include "time_zone_manager.h"

using namespace OHOS::Telephony;
namespace OHOS {
static bool g_isInited = false;
constexpr int32_t SLOT_NUM = 2;

bool IsServiceInited()
{
    if (!g_isInited) {
        auto telRilManager = std::make_shared<TelRilManager>();
        auto simManager = std::make_shared<SimManager>(telRilManager);
        auto networkSearchManager = std::make_shared<NetworkSearchManager>(telRilManager, simManager);
        auto inner = std::make_shared<NetworkSearchManagerInner>();
        networkSearchManager->AddManagerInner(DEFAULT_SIM_SLOT_ID, inner);
        inner->eventLoop_ = AppExecFwk::EventRunner::Create("test");
        TimeZoneManager::GetInstance().Init(networkSearchManager);
        g_isInited = true;
    }
    return g_isInited;
}

void TestTimeZoneManager(const uint8_t *data, size_t size)
{
    if (!IsServiceInited()) {
        return;
    }

    int32_t slotId = static_cast<int32_t>(size % SLOT_NUM);
    int32_t offset = static_cast<int32_t>(size);
    std::string countryCode(reinterpret_cast<const char *>(data), size);
    std::string timeZone(reinterpret_cast<const char *>(data), size);

    TimeZoneManager::GetInstance().UpdateLocationTimeZone(timeZone);
    TimeZoneManager::GetInstance().UpdateCountryCode(countryCode, slotId);
    TimeZoneManager::GetInstance().UpdateTimeZoneOffset(offset, slotId);
}

void TestTimeZoneUpdater(const uint8_t *data, size_t size)
{
    if (!IsServiceInited()) {
        return;
    }

    auto timeZoneUpdater = TimeZoneManager::GetInstance().timeZoneUpdater_;
    if (timeZoneUpdater == nullptr) {
        return;
    }

    int32_t slotId = static_cast<int32_t>(size % SLOT_NUM);
    int32_t offset = static_cast<int32_t>(size);
    std::string countryCode(reinterpret_cast<const char *>(data), size);
    std::string timeZone(reinterpret_cast<const char *>(data), size);

    timeZoneUpdater->UpdateCountryCode(countryCode, slotId);
    timeZoneUpdater->UpdateTimeZoneOffset(offset, slotId);
    timeZoneUpdater->UpdateLocationTimeZone(timeZone);
    timeZoneUpdater->StringToLower(countryCode);
    timeZoneUpdater->IsMultiTimeZoneCountry(countryCode);
    timeZoneUpdater->UpdateTelephonyTimeZone(countryCode);
    timeZoneUpdater->UpdateTelephonyTimeZone(offset);
    timeZoneUpdater->NeedUpdateLocationTimeZone(timeZone);
    timeZoneUpdater->IsTimeZoneMatchCountryCode(timeZone);
    timeZoneUpdater->SaveTimeZone(timeZone);
}

void TestTimeZoneLocationSuggester(const uint8_t *data, size_t size)
{
    if (!IsServiceInited()) {
        return;
    }

    auto timeZoneUpdater = TimeZoneManager::GetInstance().timeZoneUpdater_;
    if (timeZoneUpdater == nullptr) {
        return;
    }
    auto suggester = timeZoneUpdater->locationSuggester_;
    if (suggester == nullptr) {
        return;
    }
#ifdef ABILITY_LOCATION_SUPPORT
    Parcel parcel;
    parcel.WriteBuffer(data, size);
    std::unique_ptr<Location::Location> location = Location::Location::Unmarshalling(parcel);
    suggester->LocationUpdate(location);
#endif
}

void TestTimeZoneLocationUpdate(const uint8_t *data, size_t size)
{
    if (!IsServiceInited()) {
        return;
    }

    auto timeZoneUpdater = TimeZoneManager::GetInstance().timeZoneUpdater_;
    if (timeZoneUpdater == nullptr) {
        return;
    }
    auto update = timeZoneUpdater->locationUpdate_;
    if (update == nullptr) {
        return;
    }
#ifdef ABILITY_LOCATION_SUPPORT
    Parcel parcel;
    parcel.WriteBuffer(data, size);
    std::unique_ptr<Location::Location> location = Location::Location::Unmarshalling(parcel);
    update->LocationReport(location);
#endif
}

void DoSomethingInterestingWithMyAPI(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }
    TestTimeZoneUpdater(data, size);
    TestTimeZoneLocationSuggester(data, size);
    TestTimeZoneLocationUpdate(data, size);
    TestTimeZoneManager(data, size);
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    OHOS::AddCoreServiceTokenFuzzer token;
    /* Run your code on data */
    OHOS::DoSomethingInterestingWithMyAPI(data, size);
    return 0;
}
