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

#include "time_zone_manager.h"

#include "telephony_log_wrapper.h"

using namespace OHOS::EventFwk;
namespace OHOS {
namespace Telephony {
TimeZoneManager::TimeZoneManager() {}

TimeZoneManager &TimeZoneManager::GetInstance()
{
    static TimeZoneManager instance;
    return instance;
}

void TimeZoneManager::Init(std::weak_ptr<NetworkSearchManager> networkSearchManager)
{
    if (timeZoneUpdater_ != nullptr) {
        TELEPHONY_LOGE("TimeZoneManager already initialized");
        return;
    }
    networkSearchManager_ = networkSearchManager;
    auto nsm = networkSearchManager_.lock();
    if (nsm == nullptr) {
        TELEPHONY_LOGE("NetworkSearchManager is null");
        return;
    }
    auto inner = nsm->FindManagerInner(DEFAULT_SIM_SLOT_ID);
    if (inner == nullptr || inner->eventLoop_ == nullptr) {
        TELEPHONY_LOGE("Eventloop is null");
        return;
    }
    timeZoneUpdater_ = std::make_shared<TimeZoneUpdater>(inner->eventLoop_);
    if (timeZoneUpdater_ == nullptr) {
        TELEPHONY_LOGE("failed to create new TimeZoneUpdater");
        return;
    }
    timeZoneUpdater_->Init();
}

void TimeZoneManager::UpdateCountryCode(std::string &countryCode, int32_t slotId)
{
    if (timeZoneUpdater_ == nullptr) {
        TELEPHONY_LOGE("timeZoneUpdater is null");
        return;
    }
    timeZoneUpdater_->UpdateCountryCode(countryCode, slotId);
}

void TimeZoneManager::UpdateTimeZoneOffset(int32_t offset, int32_t slotId)
{
    if (timeZoneUpdater_ == nullptr) {
        TELEPHONY_LOGE("timeZoneUpdater is null");
        return;
    }
    slotId_ = slotId;
    timeZoneUpdater_->UpdateTimeZoneOffset(offset, slotId);
}

void TimeZoneManager::SendUpdateLocationRequest()
{
    if (timeZoneUpdater_ == nullptr) {
        TELEPHONY_LOGE("timeZoneUpdater is null");
        return;
    }
    timeZoneUpdater_->SendUpdateLocationRequest();
}

void TimeZoneManager::SendUpdateLocationCountryCodeRequest()
{
    if (timeZoneUpdater_ == nullptr) {
        TELEPHONY_LOGE("timeZoneUpdater is null");
        return;
    }
    timeZoneUpdater_->SendUpdateLocationCountryCodeRequest();
}

bool TimeZoneManager::UpdateLocationTimeZone(std::string &timeZone)
{
    if (timeZoneUpdater_ == nullptr) {
        TELEPHONY_LOGE("timeZoneUpdater is null");
        return false;
    }
    return timeZoneUpdater_->UpdateLocationTimeZone(timeZone);
}

bool TimeZoneManager::IsRoaming()
{
    auto networkSearchManager = networkSearchManager_.lock();
    if (networkSearchManager == nullptr) {
        TELEPHONY_LOGE("IsRoaming networkSearchManager is null");
        return false;
    }
    sptr<NetworkState> networkState = nullptr;
    for (int32_t slotId = 0; slotId < SIM_SLOT_COUNT; slotId++) {
        networkSearchManager->GetNetworkStatus(slotId, networkState);
        if (networkState != nullptr && networkState->IsRoaming()) {
            return true;
        }
    }
    return false;
}

bool TimeZoneManager::HasSimCard()
{
    auto networkSearchManager = networkSearchManager_.lock();
    if (networkSearchManager == nullptr) {
        TELEPHONY_LOGE("HasSimCard networkSearchManager is null");
        return false;
    }
    auto simManager = networkSearchManager->GetSimManager();
    if (simManager == nullptr) {
        TELEPHONY_LOGE("HasSimCard SimManager is null");
        return false;
    }
    bool hasSim = false;
    for (int32_t slotId = 0; slotId < SIM_SLOT_COUNT; slotId++) {
        simManager->HasSimCard(slotId, hasSim);
        if (hasSim) {
            return true;
        }
    }
    return false;
}

int32_t TimeZoneManager::GetCurrentLac()
{
    auto networkSearchManager = networkSearchManager_.lock();
    if (networkSearchManager == nullptr) {
        TELEPHONY_LOGE("GetCurrentLac networkSearchManager is null slotId:%{public}d", slotId_);
        return 0;
    }
    sptr<CellLocation> location = networkSearchManager->GetCellLocation(slotId_);
    if (location == nullptr) {
        TELEPHONY_LOGE("GetCurrentLac location is null slotId:%{public}d", slotId_);
        return 0;
    }
    if (location->GetCellLocationType() != CellLocation::CellType::CELL_TYPE_GSM) {
        TELEPHONY_LOGE("GetCurrentLac location type isn't GSM slotId:%{public}d", slotId_);
        return 0;
    }
    sptr<GsmCellLocation> gsmLocation = sptr<GsmCellLocation>(static_cast<GsmCellLocation *>(location.GetRefPtr()));
    if (gsmLocation == nullptr) {
        TELEPHONY_LOGE("GetCurrentLac gsmLocation is null slotId:%{public}d", slotId_);
        return 0;
    }
    return gsmLocation->GetLac();
}
} // namespace Telephony
} // namespace OHOS