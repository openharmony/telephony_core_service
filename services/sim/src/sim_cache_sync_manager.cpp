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

#include "sim_cache_sync_manager.h"

#include <cstring>
#include "datashare_values_bucket.h"
#include "ffrt.h"
#include "parameter.h"
#include "sim_data.h"
#include "sim_constant.h"
#include "telephony_log_wrapper.h"
#include "telephony_types.h"

namespace OHOS {
namespace Telephony {

#undef TELEPHONY_LOG_TAG
#define TELEPHONY_LOG_TAG "SimCacheSync"

SimCacheSyncManager::SimCacheSyncManager(std::weak_ptr<MultiSimController> multiSimController,
    std::shared_ptr<SimRdbHelper> simRdbHelper)
    : multiSimController_(multiSimController), simRdbHelper_(simRdbHelper)
{
    TELEPHONY_LOGI("SimCacheSyncManager constructor");
}

SimCacheSyncManager::~SimCacheSyncManager()
{
    TELEPHONY_LOGI("SimCacheSyncManager destructor");
}

int32_t SimCacheSyncManager::SyncCacheOnUserSwitch(int32_t currentUserId, int32_t lastUserId)
{
    TELEPHONY_LOGI("SyncCacheOnUserSwitch: currentUserId=%{public}d, lastUserId=%{public}d",
        currentUserId, lastUserId);
    
    if (!ValidateSyncParams(currentUserId, lastUserId)) {
        return TELEPHONY_SUCCESS;
    }
    
    if (!CheckPreconditions()) {
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    
    auto controller = multiSimController_.lock();
    if (controller == nullptr) {
        TELEPHONY_LOGE("MultiSimController is null");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    
    bool isFirstTime = CheckFirstSwitch100To101(currentUserId, lastUserId);
    bool needFullSync = false;
    if (!DetermineSyncStrategy(isFirstTime, needFullSync)) {
        return TELEPHONY_SUCCESS;
    }
    
    return ExecuteSyncProcess(currentUserId, needFullSync, controller);
}

bool SimCacheSyncManager::CheckFirstSwitch100To101(int32_t currentUserId, int32_t lastUserId)
{
    bool isSwitching100To101 = (currentUserId == PRIVATE_USER_ID && lastUserId == ACTIVE_USER_ID);
    if (!isSwitching100To101) {
        return false;
    }
    
    char firstSwitchProp[SYSPARA_SIZE] = {0};
    GetParameter(PROP_FIRST_SWITCH_100_TO_101.c_str(), "", firstSwitchProp, SYSPARA_SIZE);
    bool isFirstTime = (firstSwitchProp[0] == '\0');
    if (isFirstTime) {
        TELEPHONY_LOGI("First switch from 100 to 101, set prop and force sync");
        SetParameter(PROP_FIRST_SWITCH_100_TO_101.c_str(), "true");
    }
    return isFirstTime;
}

bool SimCacheSyncManager::DetermineSyncStrategy(bool isFirstTime, bool &needFullSync)
{
    if (isFirstTime) {
        TELEPHONY_LOGI("First switch from 100 to 101, force full sync");
        needFullSync = true;
        return true;
    }
    
    if (lastSyncFailed_.load()) {
        TELEPHONY_LOGI("Last sync failed, force full sync");
        needFullSync = true;
        return true;
    }
    
    TELEPHONY_LOGI("Cache not modified and last sync succeeded, skip sync");
    return false;
}

int32_t SimCacheSyncManager::ExecuteSyncProcess(int32_t currentUserId, bool needFullSync,
    std::shared_ptr<MultiSimController> controller)
{
    if (isSyncing_.exchange(true)) {
        TELEPHONY_LOGW("Sync is already in progress, skip this sync request");
        return TELEPHONY_SUCCESS;
    }
    
    std::vector<SimRdbInfo> targetData;
    if (QueryTargetUserData(currentUserId, targetData) != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("Query target user data failed");
        isSyncing_ = false;
        return TELEPHONY_ERR_DATABASE_READ_FAIL;
    }
    
    std::vector<SimRdbInfo> localCache;
    
    int32_t syncResult = PerformSync(needFullSync, localCache);
    if (syncResult != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("Sync to database failed");
        lastSyncFailed_ = true;
        isSyncing_ = false;
        return TELEPHONY_ERR_DATABASE_WRITE_FAIL;
    }

    lastSyncFailed_ = false;
    isSyncing_ = false;
    TELEPHONY_LOGI("Sync cache on user switch success");
    return TELEPHONY_SUCCESS;
}

int32_t SimCacheSyncManager::PerformSync(bool needFullSync, std::vector<SimRdbInfo> &localCache)
{
    if (needFullSync) {
        TELEPHONY_LOGI("Performing full sync");
        return SyncToDatabase(localCache);
    }
    
    TELEPHONY_LOGI("Performing incremental sync");
    auto controller = multiSimController_.lock();
    if (controller == nullptr) {
        TELEPHONY_LOGE("MultiSimController is null");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    
    auto modifiedRecords = controller->GetModifiedRecords();
    return SyncModifiedRecordsToDatabase(modifiedRecords);
}

bool SimCacheSyncManager::ValidateSyncParams(int32_t currentUserId, int32_t lastUserId)
{
    if (currentUserId == lastUserId) {
        TELEPHONY_LOGI("User not switched, skip sync");
        return false;
    }
    
    if (currentUserId != ACTIVE_USER_ID && currentUserId != PRIVATE_USER_ID) {
        TELEPHONY_LOGI("Current userId is not 100 or 101, skip sync");
        return false;
    }
    
    if (lastUserId != ACTIVE_USER_ID && lastUserId != PRIVATE_USER_ID) {
        TELEPHONY_LOGI("Last userId is not 100 or 101, skip sync");
        return false;
    }
    
    return true;
}

bool SimCacheSyncManager::CheckPreconditions()
{
    if (simRdbHelper_ == nullptr) {
        TELEPHONY_LOGE("SimRdbHelper is null");
        return false;
    }
    
    return true;
}

int32_t SimCacheSyncManager::QueryTargetUserData(int32_t userId, std::vector<SimRdbInfo> &targetData)
{
    if (simRdbHelper_ == nullptr) {
        TELEPHONY_LOGE("SimRdbHelper is null");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    
    if (simRdbHelper_->QueryAllData(targetData) != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("Query all data failed");
        return TELEPHONY_ERR_DATABASE_READ_FAIL;
    }
    
    TELEPHONY_LOGI("Query target user data success, size=%{public}zu", targetData.size());
    return TELEPHONY_SUCCESS;
}

int32_t SimCacheSyncManager::SyncToDatabase(const std::vector<SimRdbInfo> &data)
{
    if (simRdbHelper_ == nullptr) {
        TELEPHONY_LOGE("SimRdbHelper is null");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    
    for (const auto &record : data) {
        int32_t result = SyncSingleRecord(record);
        if (result != TELEPHONY_SUCCESS) {
            TELEPHONY_LOGE("Sync single record failed, simId=%{public}d", record.simId);
            return result;
        }
    }
    
    TELEPHONY_LOGI("Sync to database success, record count: %{public}zu", data.size());
    return TELEPHONY_SUCCESS;
}

int32_t SimCacheSyncManager::SyncSingleRecord(const SimRdbInfo &record)
{
    SimRdbInfo existingRecord;
    int32_t queryResult = simRdbHelper_->QueryDataByIccId(record.iccId, existingRecord);
    
    DataShare::DataShareValuesBucket values;
    BuildDataShareValues(record, values);
    
    int32_t result;
    if (queryResult == TELEPHONY_SUCCESS && record.iccId == existingRecord.iccId) {
        TELEPHONY_LOGI("Record exists in database, update it, simId=%{public}d", record.simId);
        result = simRdbHelper_->UpdateDataByIccId(record.iccId, values);
        if (result == INVALID_VALUE) {
            TELEPHONY_LOGE(
                "Update data by iccId failed, simId=%{public}d, result=%{public}d", record.simId, result);
            return TELEPHONY_ERR_DATABASE_WRITE_FAIL;
        }
        TELEPHONY_LOGI(
            "Update data by iccId success, simId=%{public}d, result=%{public}d", record.simId, result);
    } else {
        TELEPHONY_LOGI("Record not exists in database, insert it, simId=%{public}d", record.simId);
        int64_t id = 0;
        result = simRdbHelper_->InsertData(id, values);
        if (result == INVALID_VALUE) {
            TELEPHONY_LOGE("Insert data failed, simId=%{public}d, result=%{public}d", record.simId, result);
            return TELEPHONY_ERR_DATABASE_WRITE_FAIL;
        }
        TELEPHONY_LOGI("Insert data success, simId=%{public}d, result=%{public}d", record.simId, result);
    }
    
    return TELEPHONY_SUCCESS;
}

void SimCacheSyncManager::BuildDataShareValues(const SimRdbInfo &record, DataShare::DataShareValuesBucket &values)
{
    // Only insert necessary fields, refer to MultiSimController::SimDataBuilder
    DataShare::DataShareValueObject slotObj(record.slotIndex);
    values.Put(SimData::SLOT_INDEX, slotObj);
    
    DataShare::DataShareValueObject iccidObj(record.iccId);
    values.Put(SimData::ICC_ID, iccidObj);
    
    DataShare::DataShareValueObject cardIdObj(record.cardId);
    values.Put(SimData::CARD_ID, cardIdObj);
    
    DataShare::DataShareValueObject isActiveObj(record.isActive);
    values.Put(SimData::IS_ACTIVE, isActiveObj);
    
    DataShare::DataShareValueObject isEsimObj(record.isEsim);
    values.Put(SimData::IS_ESIM, isEsimObj);
    
    DataShare::DataShareValueObject simLabelIndexObj(record.simLabelIndex);
    values.Put(SimData::SIM_LABEL_INDEX, simLabelIndexObj);
    
    DataShare::DataShareValueObject isMainCardObj(record.isMainCard);
    values.Put(SimData::IS_MAIN_CARD, isMainCardObj);
    
    DataShare::DataShareValueObject isVoiceCardObj(record.isVoiceCard);
    values.Put(SimData::IS_VOICE_CARD, isVoiceCardObj);
    
    DataShare::DataShareValueObject isMessageCardObj(record.isMessageCard);
    values.Put(SimData::IS_MESSAGE_CARD, isMessageCardObj);
    
    DataShare::DataShareValueObject isCellularDataCardObj(record.isCellularDataCard);
    values.Put(SimData::IS_CELLULAR_DATA_CARD, isCellularDataCardObj);

    DataShare::DataShareValueObject operatorNameObj(record.operatorName);
    values.Put(SimData::OPERATOR_NAME, operatorNameObj);

    DataShare::DataShareValueObject showNameObj(record.showName);
    values.Put(SimData::SHOW_NAME, showNameObj);
}

int32_t SimCacheSyncManager::SyncModifiedRecordsToDatabase(
    const std::unordered_map<std::string, std::set<std::string>> &modifiedRecords)
{
    if (simRdbHelper_ == nullptr) {
        TELEPHONY_LOGE("SimRdbHelper is null");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    
    std::vector<SimRdbInfo> localCache;
    
    for (const auto &entry : modifiedRecords) {
        if (SyncSingleModifiedRecord(localCache, entry) != TELEPHONY_SUCCESS) {
            return TELEPHONY_ERR_DATABASE_WRITE_FAIL;
        }
    }
    
    return TELEPHONY_SUCCESS;
}

int32_t SimCacheSyncManager::SyncSingleModifiedRecord(
    const std::vector<SimRdbInfo> &localCache,
    const std::pair<const std::string, std::set<std::string>> &entry)
{
    const std::string &iccId = entry.first;
    const std::set<std::string> &modifiedFields = entry.second;
    
    SimRdbInfo record;
    bool found = false;
    for (const auto &cacheRecord : localCache) {
        if (cacheRecord.iccId == iccId) {
            record = cacheRecord;
            found = true;
            break;
        }
    }
    
    if (!found) {
        TELEPHONY_LOGW("Record not found in local cache, iccId=%{public}s", iccId.c_str());
        return TELEPHONY_SUCCESS;
    }
    
    DataShare::DataShareValuesBucket values;
    BuildPartialDataShareValues(record, modifiedFields, values);
    
    int32_t result = simRdbHelper_->UpdateDataByIccId(iccId, values);
    if (result == INVALID_VALUE) {
        TELEPHONY_LOGE("Update data by iccId failed, iccId=%{public}s", iccId.c_str());
        return TELEPHONY_ERR_DATABASE_WRITE_FAIL;
    }
    TELEPHONY_LOGI("Update modified fields success, iccId=%{public}s, fields=%{public}zu",
        iccId.c_str(), modifiedFields.size());
    return TELEPHONY_SUCCESS;
}

void SimCacheSyncManager::BuildPartialDataShareValues(const SimRdbInfo &record,
    const std::set<std::string> &modifiedFields, DataShare::DataShareValuesBucket &values)
{
    if (modifiedFields.find("all_fields") != modifiedFields.end()) {
        BuildDataShareValues(record, values);
        return;
    }
    for (const auto &field : modifiedFields) {
        if (field == "showName") {
            DataShare::DataShareValueObject showNameObj(record.showName);
            values.Put(SimData::SHOW_NAME, showNameObj);
        } else if (field == "phoneNumber") {
            DataShare::DataShareValueObject phoneObj(record.phoneNumber);
            values.Put(SimData::PHONE_NUMBER, phoneObj);
        } else if (field == "simLabelIndex") {
            DataShare::DataShareValueObject labelObj(record.simLabelIndex);
            values.Put(SimData::SIM_LABEL_INDEX, labelObj);
        } else if (field == "operatorName") {
            DataShare::DataShareValueObject opNameObj(record.operatorName);
            values.Put(SimData::OPERATOR_NAME, opNameObj);
        } else if (field == "isMainCard") {
            DataShare::DataShareValueObject mainCardObj(record.isMainCard);
            values.Put(SimData::IS_MAIN_CARD, mainCardObj);
        } else if (field == "isVoiceCard") {
            DataShare::DataShareValueObject voiceCardObj(record.isVoiceCard);
            values.Put(SimData::IS_VOICE_CARD, voiceCardObj);
        } else if (field == "isMessageCard") {
            DataShare::DataShareValueObject msgCardObj(record.isMessageCard);
            values.Put(SimData::IS_MESSAGE_CARD, msgCardObj);
        } else if (field == "isCellularDataCard") {
            DataShare::DataShareValueObject dataCardObj(record.isCellularDataCard);
            values.Put(SimData::IS_CELLULAR_DATA_CARD, dataCardObj);
        } else if (field == "isActive") {
            DataShare::DataShareValueObject activeObj(record.isActive);
            values.Put(SimData::IS_ACTIVE, activeObj);
        } else if (field == "isEsim") {
            DataShare::DataShareValueObject esimObj(record.isEsim);
            values.Put(SimData::IS_ESIM, esimObj);
        }
    }
}

bool SimCacheSyncManager::IsFieldEmptyOrDefault(const std::string &value)
{
    return value.empty();
}

bool SimCacheSyncManager::IsFieldEmptyOrDefault(int value)
{
    return value == 0 || value == INVALID_VALUE;
}
} // namespace Telephony
} // namespace OHOS