/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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

#ifndef TELEPHONY_SIM_CACHE_SYNC_MANAGER_H
#define TELEPHONY_SIM_CACHE_SYNC_MANAGER_H

#include <atomic>
#include <memory>
#include <set>
#include <unordered_map>
#include <vector>

#include "datashare_values_bucket.h"
#include "multi_sim_controller.h"
#include "sim_rdb_helper.h"
#include "sim_rdb_info.h"
#include "telephony_errors.h"
#include "telephony_log_wrapper.h"

namespace OHOS {
namespace Telephony {
const std::string PROP_FIRST_SWITCH_100_TO_101 = "persist.telephony.first_switch_100_to_101";

class SimCacheSyncManager {
public:
    explicit SimCacheSyncManager(std::weak_ptr<MultiSimController> multiSimController,
        std::shared_ptr<SimRdbHelper> simRdbHelper);
    ~SimCacheSyncManager();

    int32_t SyncCacheOnUserSwitch(int32_t currentUserId, int32_t lastUserId);

private:
    bool ValidateSyncParams(int32_t currentUserId, int32_t lastUserId);
    bool CheckPreconditions();
    bool CheckFirstSwitch100To101(int32_t currentUserId, int32_t lastUserId);
    bool DetermineSyncStrategy(bool isFirstTime, bool &needFullSync);
    int32_t ExecuteSyncProcess(int32_t currentUserId, bool needFullSync,
        std::shared_ptr<MultiSimController> controller);
    int32_t PerformSync(bool needFullSync, std::vector<SimRdbInfo> &localCache);
    int32_t QueryTargetUserData(int32_t userId, std::vector<SimRdbInfo> &targetData);
    int32_t GetLocalCache(std::vector<SimRdbInfo> &localCache);
    int32_t SyncToDatabase(const std::vector<SimRdbInfo> &data);
    int32_t SyncSingleRecord(const SimRdbInfo &record);
    void BuildDataShareValues(const SimRdbInfo &record, DataShare::DataShareValuesBucket &values);
    int32_t SyncModifiedRecordsToDatabase(
        const std::unordered_map<std::string, std::set<std::string>> &modifiedRecords);
    int32_t SyncSingleModifiedRecord(const std::vector<SimRdbInfo> &localCache,
        const std::pair<const std::string, std::set<std::string>> &entry);
    void BuildPartialDataShareValues(const SimRdbInfo &record, const std::set<std::string> &modifiedFields,
        DataShare::DataShareValuesBucket &values);
    bool IsFieldEmptyOrDefault(const std::string &value);
    bool IsFieldEmptyOrDefault(int value);

private:
    std::weak_ptr<MultiSimController> multiSimController_;
    std::shared_ptr<SimRdbHelper> simRdbHelper_;
    std::atomic<bool> isSyncing_ = false;
    std::atomic<bool> lastSyncFailed_ = false;
};
} // namespace Telephony
} // namespace OHOS
#endif // TELEPHONY_SIM_CACHE_SYNC_MANAGER_H