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

#include "multi_sim_controller.h"

#include "common_event_manager.h"
#include "common_event_support.h"
#include "string_ex.h"

namespace OHOS {
namespace Telephony {
using namespace OHOS::EventFwk;
std::mutex MultiSimController::mutex_;
std::vector<SimRdbInfo> MultiSimController::localCacheInfo_;
bool MultiSimController::ready_ = false;

MultiSimController::MultiSimController(std::shared_ptr<Telephony::ITelRilManager> telRilManager,
    std::shared_ptr<SimStateManager> simStateManager, std::shared_ptr<SimFileManager> simFileManager,
    const std::shared_ptr<AppExecFwk::EventRunner> &runner, int32_t slotId)
    : telRilManager_(telRilManager), simStateManager_(simStateManager), simFileManager_(simFileManager)
{
    TELEPHONY_LOGI("MultiSimController::MultiSimController");
    slotId_ = slotId;
    radioCapController_ = std::make_shared<RadioCapController>(telRilManager_, runner);
}

MultiSimController::~MultiSimController() {}

// set all data to invalid wait for InitData to rebuild
void MultiSimController::Init()
{
    if (simDbHelper_ == nullptr) {
        simDbHelper_ = std::make_unique<SimRdbHelper>();
    }
    maxCount_ = SIM_SLOT_COUNT;
    TELEPHONY_LOGI("MultiSimController::Init Create SimRdbHelper count = %{public}d", maxCount_);
}

bool MultiSimController::ForgetAllData()
{
    if (simDbHelper_ == nullptr) {
        TELEPHONY_LOGE("MultiSimController::Init simDbHelper_ is nullptr failed");
        return false;
    }
    ready_ = false;
    int32_t result = INVALID_VALUE;
    for (uint32_t i = 0; i <= RETRY_COUNT; i++) { // if we can not do ForgetAllData right,then nothing will be right
        if (ready_) {
            TELEPHONY_LOGI("MultiSimController::already ForgetAllData");
            return true;
        }
        result = simDbHelper_->ForgetAllData();
        std::this_thread::sleep_for(std::chrono::milliseconds(RETRY_TIME));
        if (result != INVALID_VALUE) {
            TELEPHONY_LOGI("MultiSimController::ForgetAllData complete");
            ready_ = true;
            return true;
        }
    }
    TELEPHONY_LOGE("MultiSimController::get dataAbility error, is over");
    return false;
}

void MultiSimController::SetNetworkSearchManager(std::shared_ptr<INetworkSearch> networkSearchManager)
{
    networkSearchManager_ = networkSearchManager;
}

bool MultiSimController::InitData(int32_t slotId)
{
    TELEPHONY_LOGI("MultiSimController::InitData");
    bool result = true;
    if (!IsValidData()) {
        TELEPHONY_LOGI("MultiSimController::InitData has no sim card, abandon");
        return false;
    }
    if (!InitIccId(slotId)) { // check if we insert or reactive a data
        TELEPHONY_LOGI("MultiSimController::InitData can not init IccId");
        result = false;
    }
    if (!GetListFromDataBase()) { // init data base to local cache
        TELEPHONY_LOGE("MultiSimController::InitData can not get dataBase");
        result = false;
    }
    if (localCacheInfo_.size() <= 0) {
        TELEPHONY_LOGE("MultiSimController::we get nothing from init");
        return false;
    }
    if (!InitActive(slotId)) {
        TELEPHONY_LOGE("MultiSimController::InitData InitActive failed");
        result = false;
    }
    if (!InitShowName(slotId)) {
        TELEPHONY_LOGE("MultiSimController::InitData InitShowName failed");
        result = false;
    }
    if (!InitShowNumber(slotId)) {
        TELEPHONY_LOGE("MultiSimController::InitData InitShowNumber failed");
        result = false;
    }
    return result;
}

bool MultiSimController::InitActive(int slotId)
{
    if (simStateManager_ == nullptr) {
        TELEPHONY_LOGE("MultiSimController::InitActive can not get simStateManager");
        return false;
    }
    bool result = true;
    if (!IsSimActive(slotId) && simStateManager_->HasSimCard()) {
        result = SetActiveSim(slotId, ACTIVE, true); // force set to database ACTIVE and avoid duplicate
    }
    if (IsSimActive(slotId) && !simStateManager_->HasSimCard()) {
        if (result && SetActiveSim(slotId, DEACTIVE, true)) {
            result = true;
        } else {
            result = false;
        } // force set to database DEACTIVE and avoid duplicate
    }
    return result;
}

bool MultiSimController::InitIccId(int slotId)
{
    TELEPHONY_LOGI("MultiSimController::InitIccId slotId = %{public}d", slotId);
    std::lock_guard<std::mutex> lock(mutex_);
    if (simFileManager_ == nullptr) {
        TELEPHONY_LOGE("MultiSimController::InitIccId can not get simFileManager");
        return false;
    }
    std::string newIccId = Str16ToStr8(simFileManager_->GetSimIccId());
    if (newIccId.empty()) {
        TELEPHONY_LOGE("MultiSimController::InitIccId can not get iccId");
        return false;
    }
    if (simDbHelper_ == nullptr) {
        TELEPHONY_LOGE("MultiSimController::InitIccId failed by nullptr");
        return false;
    }
    int32_t result;
    SimRdbInfo simRdbInfo;
    simDbHelper_->QueryDataByIccId(newIccId, simRdbInfo);
    if (!simRdbInfo.iccId.empty()) { // already have this card, reactive it
        result = UpdateDataByIccId(slotId, newIccId);
    } else { // insert a new data for new IccId
        result = InsertData(slotId, newIccId);
    }
    if (result == INVALID_VALUE) {
        TELEPHONY_LOGE("MultiSimController::InitIccId failed to init data");
        return false;
    } else {
        return true;
    }
}

int32_t MultiSimController::UpdateDataByIccId(int slotId, std::string newIccId)
{
    TELEPHONY_LOGI("MultiSimController::InitIccId UpdateDataByIccId");
    if (simDbHelper_ == nullptr) {
        TELEPHONY_LOGE("MultiSimController::UpdateDataByIccId failed by nullptr");
        return INVALID_VALUE;
    }
    SimRdbInfo simRdbInfo;
    simDbHelper_->QueryDataByIccId(newIccId, simRdbInfo);
    NativeRdb::ValuesBucket values;
    values.PutInt(SimRdbInfo::SLOT_INDEX, slotId);
    const int32_t slotSingle = 1;
    if (SIM_SLOT_COUNT == slotSingle) {
        values.PutInt(SimData::IS_MAIN_CARD, MAIN_CARD);
        values.PutInt(SimData::IS_VOICE_CARD, MAIN_CARD);
        values.PutInt(SimData::IS_MESSAGE_CARD, MAIN_CARD);
        values.PutInt(SimData::IS_CELLULAR_DATA_CARD, MAIN_CARD);
    }
    return simDbHelper_->UpdateDataByIccId(newIccId, values); // finish re active
}

int32_t MultiSimController::InsertData(int slotId, std::string newIccId)
{
    TELEPHONY_LOGI("MultiSimController::InitIccId InsertData");
    if (simDbHelper_ == nullptr) {
        TELEPHONY_LOGE("MultiSimController::InsertData failed by nullptr");
        return INVALID_VALUE;
    }
    SimRdbInfo simRdbInfo;
    simDbHelper_->QueryDataByIccId(newIccId, simRdbInfo);
    NativeRdb::ValuesBucket values;
    values.PutInt(SimRdbInfo::SLOT_INDEX, slotId);
    values.PutString(SimRdbInfo::ICC_ID, newIccId);
    values.PutString(SimRdbInfo::CARD_ID, newIccId); // iccId == cardId by now
    const int32_t slotSingle = 1;
    if (SIM_SLOT_COUNT == slotSingle) {
        values.PutInt(SimData::IS_MAIN_CARD, MAIN_CARD);
        values.PutInt(SimData::IS_VOICE_CARD, MAIN_CARD);
        values.PutInt(SimData::IS_MESSAGE_CARD, MAIN_CARD);
        values.PutInt(SimData::IS_CELLULAR_DATA_CARD, MAIN_CARD);
    } else {
        values.PutInt(SimData::IS_MAIN_CARD, NOT_MAIN);
        values.PutInt(SimData::IS_VOICE_CARD, NOT_MAIN);
        values.PutInt(SimData::IS_MESSAGE_CARD, NOT_MAIN);
        values.PutInt(SimData::IS_CELLULAR_DATA_CARD, NOT_MAIN);
    }
    int64_t id;
    return simDbHelper_->InsertData(id, values);
}

bool MultiSimController::InitShowName(int slotId)
{
    TELEPHONY_LOGI("MultiSimController::InitShowName slotId = %{public}d", slotId);
    std::u16string showName = GetShowName(slotId);
    if (!showName.empty() && showName != IccAccountInfo::DEFAULT_SHOW_NAME) {
        TELEPHONY_LOGI("MultiSimController::InitShowName no need to Init again");
        return true;
    }
    if (networkSearchManager_ == nullptr) {
        TELEPHONY_LOGE("MultiSimController::InitShowName failed by nullptr");
        return false;
    }
    showName = networkSearchManager_->GetOperatorName(slotId);
    bool result = false;
    if (!showName.empty()) {
        result = SetShowName(slotId, showName, true);
    } else {
        result = SetShowName(slotId, IccAccountInfo::DEFAULT_SHOW_NAME, true);
    }
    return result;
}

bool MultiSimController::InitShowNumber(int slotId)
{
    TELEPHONY_LOGI("MultiSimController::InitShowNumber slotId = %{public}d", slotId);
    std::u16string showNumber = GetShowNumber(slotId);
    if (!showNumber.empty() && showNumber != IccAccountInfo::DEFAULT_SHOW_NUMBER) {
        TELEPHONY_LOGI("MultiSimController::InitShowName no need to Init again");
        return true;
    }
    if (simFileManager_ == nullptr) {
        TELEPHONY_LOGE("can not get simFileManager");
        return false;
    }
    showNumber = simFileManager_->GetSimTelephoneNumber();
    bool result = false;
    if (!showNumber.empty()) {
        result = SetShowNumber(slotId, showNumber, true);
    } else {
        result = SetShowNumber(slotId, IccAccountInfo::DEFAULT_SHOW_NUMBER, true);
    }
    return result;
}

bool MultiSimController::GetListFromDataBase()
{
    TELEPHONY_LOGI("MultiSimController::GetListFromDataBase");
    std::lock_guard<std::mutex> lock(mutex_);
    if (localCacheInfo_.size() > 0) {
        localCacheInfo_.clear();
    }
    if (simDbHelper_ == nullptr) {
        TELEPHONY_LOGE("MultiSimController::GetListFromDataBase failed by nullptr");
        return false;
    }
    int32_t result = simDbHelper_->QueryAllValidData(localCacheInfo_);
    SortCache();
    return (result != INVALID_VALUE) ? true : false;
}

void MultiSimController::SortCache()
{
    size_t count = localCacheInfo_.size();
    TELEPHONY_LOGI("MultiSimController::SortCache count = %{public}lu", (unsigned long)count);
    if (count <= 0) {
        TELEPHONY_LOGE("MultiSimController::Sort empty");
        return;
    }
    std::vector<SimRdbInfo> sortCache;
    SimRdbInfo emptyUnit;
    emptyUnit.isActive = DEACTIVE;
    emptyUnit.iccId = "";
    for (int i = 0; i < maxCount_; i++) {
        emptyUnit.slotIndex = i;
        sortCache.emplace_back(emptyUnit);
    }
    for (size_t j = 0; j < count; j++) {
        TELEPHONY_LOGI(
            "MultiSimController::index = %{public}d j = %{public}lu", localCacheInfo_[j].slotIndex, (unsigned long)j);
        sortCache[localCacheInfo_[j].slotIndex] = localCacheInfo_[j];
    }
    localCacheInfo_ = sortCache;
}

/*
 * check the data is valid, if we don't have SimCard the data is not valid
 */
bool MultiSimController::IsValidData()
{
    if (simStateManager_ == nullptr) {
        TELEPHONY_LOGE("MultiSimController::InitActive can not get simStateManager");
        return false;
    }
    return simStateManager_->HasSimCard();
}

bool MultiSimController::RefreshActiveIccAccountInfoList()
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (localCacheInfo_.size() <= EMPTY_VECTOR) {
        TELEPHONY_LOGE("MultiSimController::RefreshActiveIccAccountInfoList failed by invalid data");
        return false;
    }
    std::vector<SimRdbInfo>::iterator it = localCacheInfo_.begin();
    if (iccAccountInfoList_.size() > 0) {
        iccAccountInfoList_.clear();
    }
    while (it != localCacheInfo_.end()) { // loop data list
        if (it->isActive == ACTIVE) { // pick Active item
            iccAccountInfo_.Init(it->simId, it->slotIndex);
            iccAccountInfo_.showName = Str8ToStr16(it->showName);
            iccAccountInfo_.showNumber = Str8ToStr16(it->phoneNumber);
            iccAccountInfo_.iccId = Str8ToStr16(it->iccId);
            iccAccountInfo_.isActive = it->isActive;
            iccAccountInfoList_.emplace_back(iccAccountInfo_);
        }
        it++;
    }
    return true;
}

int32_t MultiSimController::GetSlotId(int32_t simId)
{
    if (localCacheInfo_.size() <= EMPTY_VECTOR) {
        TELEPHONY_LOGE("MultiSimController::GetSlotId failed by nullptr");
        return INVALID_VALUE;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<SimRdbInfo>::iterator it = localCacheInfo_.begin();

    while (it != localCacheInfo_.end()) { // loop data list
        if (it->isActive == ACTIVE && it->simId == simId) { // pick Active item
            return it->slotIndex;
        }
        it++;
    }
    return INVALID_VALUE;
}

bool MultiSimController::IsSimActive(int32_t slotId)
{
    TELEPHONY_LOGI("MultiSimController::IsSimActive slotId = %{public}d", slotId);
    std::lock_guard<std::mutex> lock(mutex_);
    if (!IsValidData()) {
        TELEPHONY_LOGE("MultiSimController::IsSimActive InValidData");
        return false;
    }
    if ((uint32_t)slotId >= localCacheInfo_.size()) {
        TELEPHONY_LOGE("MultiSimController::IsSimActive failed by out of range");
        return false;
    }
    return localCacheInfo_[slotId].isActive == ACTIVE ? true : false;
}

bool MultiSimController::IsSimActivatable(int32_t slotId)
{
    TELEPHONY_LOGI("MultiSimController::IsSimActivatable slotId = %{public}d", slotId);
    std::lock_guard<std::mutex> lock(mutex_);
    if ((uint32_t)slotId >= localCacheInfo_.size()) {
        TELEPHONY_LOGE("MultiSimController::IsSimActivatable failed by out of range");
        return false;
    }
    return localCacheInfo_[slotId].isActive == ACTIVATABLE ? true : false;
}

bool MultiSimController::SetActiveSim(int32_t slotId, int32_t enable, bool force)
{
    TELEPHONY_LOGI("MultiSimController::SetActiveSim enable = %{public}d slotId = %{public}d", enable, slotId);
    if (!force && GetIccId(slotId).empty() && enable != ACTIVE) { // force is used for init data
        TELEPHONY_LOGE("MultiSimController::SetActiveSim empty sim operation set failed");
        return false;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    if ((uint32_t)slotId >= localCacheInfo_.size() && enable != ACTIVE) {
        TELEPHONY_LOGE("MultiSimController::SetActiveSim failed by out of range");
        return false;
    }
    if (!force && !SetActiveSimToRil(slotId, ENTITY_CARD, enable)) {
        TELEPHONY_LOGE("MultiSimController::SetActiveSim SetActiveSimToRil failed");
        return false;
    }
    if (simDbHelper_ == nullptr) {
        TELEPHONY_LOGE("MultiSimController::SetActiveSim failed by nullptr");
        return false;
    }
    NativeRdb::ValuesBucket values;
    values.PutInt(SimRdbInfo::IS_ACTIVE, enable);
    int32_t result = simDbHelper_->UpdateDataBySlotId(slotId, values);
    if (result != INVALID_VALUE) { // save to cache
        if (enable == ACTIVE) {
            localCacheInfo_[slotId].isActive = enable;
        } else {
            localCacheInfo_[slotId].isActive = ACTIVATABLE;
        }
    }
    return (result != INVALID_VALUE) ? true : false;
}

bool MultiSimController::SetActiveSimToRil(int32_t slotId, int32_t type, int32_t enable)
{
    TELEPHONY_LOGI("MultiSimController::SetActiveSimToRil enable = %{public}d slotId = %{public}d", enable, slotId);
    int32_t ret = ACTIVE_INIT;
    if (radioCapController_ == nullptr) {
        TELEPHONY_LOGE("MultiSimController::SetActiveSim failed by nullptr");
        return false;
    }
    std::unique_lock<std::mutex> lck(radioCapController_->ctx_);
    radioCapController_->RadioCapControllerWait();
    if (!radioCapController_->SetActiveSimToRil(slotId, type, enable)) {
        TELEPHONY_LOGE("MultiSimController::SetActiveSimToRil failed");
        return false;
    }
    while (!radioCapController_->RadioCapControllerPoll()) {
        TELEPHONY_LOGI("MultiSimController SetActiveSimToRil::wait()");
        radioCapController_->cv_.wait(lck);
    }
    ret = radioCapController_->GetActiveSimToRilResult();
    return (ret != SUCCESS) ? false : true;
}

bool MultiSimController::GetSimAccountInfo(int32_t slotId, IccAccountInfo &info)
{
    TELEPHONY_LOGI("MultiSimController::GetSimAccountInfo slotId = %{public}d", slotId);
    std::lock_guard<std::mutex> lock(mutex_);
    if (!IsValidData()) {
        TELEPHONY_LOGE("MultiSimController::GetSimAccountInfo InValidData");
        return false;
    }
    if ((uint32_t)slotId >= localCacheInfo_.size()) {
        TELEPHONY_LOGE("MultiSimController::GetSimAccountInfo failed by out of range");
        return false;
    }
    if (localCacheInfo_[slotId].iccId.empty()) {
        TELEPHONY_LOGE("MultiSimController::GetSimAccountInfo failed by no data");
        return false;
    }
    info.slotIndex = localCacheInfo_[slotId].slotIndex;
    info.simId = localCacheInfo_[slotId].simId;
    info.isActive = localCacheInfo_[slotId].isActive;
    info.showName = Str8ToStr16(localCacheInfo_[slotId].showName);
    info.showNumber = Str8ToStr16(localCacheInfo_[slotId].phoneNumber);
    info.iccId = Str8ToStr16(localCacheInfo_[slotId].iccId);
    info.isEsim = false;
    return true;
}

int32_t MultiSimController::GetDefaultVoiceSlotId()
{
    TELEPHONY_LOGI("MultiSimController::GetDefaultVoiceSlotId");
    std::lock_guard<std::mutex> lock(mutex_);
    if (localCacheInfo_.size() <= EMPTY_VECTOR) {
        TELEPHONY_LOGE("MultiSimController::GetDefaultVoiceSlotId failed by nullptr");
        return INVALID_VALUE;
    }
    int32_t i = DEFAULT_SIM_SLOT_ID;
    for (; i < maxCount_; i++) {
        if (localCacheInfo_[i].isVoiceCard == MAIN_CARD) {
            return i;
        }
    }
    return GetFirstActivedSlotId();
}

int32_t MultiSimController::GetFirstActivedSlotId()
{
    TELEPHONY_LOGI("MultiSimController::GetFirstActivedSlotId");
    int32_t i = DEFAULT_SIM_SLOT_ID;
    for (; i < maxCount_; i++) {
        if (localCacheInfo_[i].isActive == ACTIVE) {
            return localCacheInfo_[i].slotIndex;
        }
    }
    return INVALID_VALUE;
}

bool MultiSimController::SetDefaultVoiceSlotId(int32_t slotId)
{
    TELEPHONY_LOGI("MultiSimController::SetDefaultVoiceSlotId slotId = %{public}d", slotId);
    std::lock_guard<std::mutex> lock(mutex_);
    TELEPHONY_LOGI("MultiSimController::SetDefaultVoiceSlotId slotId = %{public}d", slotId);
    if (simDbHelper_ == nullptr) {
        TELEPHONY_LOGE("MultiSimController::SetDefaultVoiceSlotId failed by nullptr");
        return false;
    }
    if (slotId >= (int32_t)localCacheInfo_.size() || slotId < DEFAULT_SIM_SLOT_ID_REMOVE) {
        TELEPHONY_LOGE("MultiSimController::SetDefaultVoiceSlotId failed by out of range");
        return false;
    }
    int32_t result = simDbHelper_->SetDefaultVoiceCard(slotId);
    if (result == INVALID_VALUE) {
        TELEPHONY_LOGE("MultiSimController::SetDefaultVoiceSlotId get Data Base failed");
        return false;
    }
    int32_t i = DEFAULT_SIM_SLOT_ID;
    for (; i < maxCount_; i++) { // save to cache
        if (slotId == i) {
            localCacheInfo_[i].isVoiceCard = MAIN_CARD;
            continue;
        }
        localCacheInfo_[i].isVoiceCard = NOT_MAIN;
    }
    return AnnounceDefaultVoiceSlotIdChanged(slotId);
}

int32_t MultiSimController::GetDefaultSmsSlotId()
{
    TELEPHONY_LOGI("MultiSimController::GetDefaultSmsSlotId");
    std::lock_guard<std::mutex> lock(mutex_);
    if (localCacheInfo_.size() <= EMPTY_VECTOR) {
        TELEPHONY_LOGE("MultiSimController::GetDefaultSmsSlotId failed by nullptr");
        return INVALID_VALUE;
    }
    int32_t i = DEFAULT_SIM_SLOT_ID;
    for (; i < maxCount_; i++) {
        if (localCacheInfo_[i].isMessageCard == MAIN_CARD) {
            return i;
        }
    }
    return GetFirstActivedSlotId();
}

bool MultiSimController::SetDefaultSmsSlotId(int32_t slotId)
{
    TELEPHONY_LOGI("MultiSimController::SetDefaultSmsSlotId slotId = %{public}d", slotId);
    std::lock_guard<std::mutex> lock(mutex_);
    if (simDbHelper_ == nullptr) {
        TELEPHONY_LOGE("MultiSimController::SetDefaultSmsSlotId failed by nullptr");
        return false;
    }
    if (slotId >= (int32_t)localCacheInfo_.size() || slotId < DEFAULT_SIM_SLOT_ID_REMOVE) {
        TELEPHONY_LOGE("MultiSimController::SetDefaultSmsSlotId failed by out of range");
        return false;
    }
    int32_t result = simDbHelper_->SetDefaultMessageCard(slotId);
    if (result == INVALID_VALUE) {
        TELEPHONY_LOGE("MultiSimController::SetDefaultSmsSlotId get Data Base failed");
        return false;
    }
    int32_t i = DEFAULT_SIM_SLOT_ID;
    for (; i < maxCount_; i++) { // save to cache
        if (slotId == i) {
            localCacheInfo_[i].isMessageCard = MAIN_CARD;
            continue;
        }
        localCacheInfo_[i].isMessageCard = NOT_MAIN;
    }
    return AnnounceDefaultSmsSlotIdChanged(slotId);
}

int32_t MultiSimController::GetDefaultCellularDataSlotId()
{
    TELEPHONY_LOGI("MultiSimController::GetDefaultCellularDataSlotId");
    std::lock_guard<std::mutex> lock(mutex_);
    return GetDefaultCellularDataSlotIdUnit();
}

bool MultiSimController::SetDefaultCellularDataSlotId(int32_t slotId)
{
    TELEPHONY_LOGI("MultiSimController::SetDefaultCellularDataSlotId slotId = %{public}d", slotId);
    std::lock_guard<std::mutex> lock(mutex_);
    TELEPHONY_LOGI("MultiSimController::SetDefaultCellularDataSlotId slotId = %{public}d", slotId);
    if (simDbHelper_ == nullptr) {
        TELEPHONY_LOGE("MultiSimController::SetDefaultCellularDataSlotId failed by nullptr");
        return false;
    }
    if (slotId >= (int32_t)localCacheInfo_.size() || slotId < DEFAULT_SIM_SLOT_ID_REMOVE) {
        TELEPHONY_LOGE("MultiSimController::SetDefaultCellularDataSlotId failed by out of range");
        return false;
    }
    int32_t result = simDbHelper_->SetDefaultCellularData(slotId);
    if (result == INVALID_VALUE) {
        TELEPHONY_LOGE("MultiSimController::SetDefaultCellularDataSlotId get Data Base failed");
        return false;
    }
    int32_t i = DEFAULT_SIM_SLOT_ID;
    for (; i < maxCount_; i++) { // save to cache
        if (slotId == i) {
            localCacheInfo_[i].isCellularDataCard = MAIN_CARD;
            continue;
        }
        localCacheInfo_[i].isCellularDataCard = NOT_MAIN;
    }
    return AnnounceDefaultCellularDataSlotIdChanged(slotId);
}

int32_t MultiSimController::GetDefaultCellularDataSlotIdUnit()
{
    TELEPHONY_LOGI("MultiSimController::GetDefaultCellularDataSlotId");
    if (localCacheInfo_.size() <= EMPTY_VECTOR) {
        TELEPHONY_LOGE("MultiSimController::GetDefaultCellularDataSlotId failed by nullptr");
        return INVALID_VALUE;
    }
    int32_t i = DEFAULT_SIM_SLOT_ID;
    for (; i < maxCount_; i++) {
        if (localCacheInfo_[i].isCellularDataCard == MAIN_CARD) {
            return i;
        }
    }
    return GetFirstActivedSlotId();
}

int32_t MultiSimController::GetPrimarySlotId()
{
    TELEPHONY_LOGI("MultiSimController::GetPrimarySlotId");
    std::lock_guard<std::mutex> lock(mutex_);
    if (localCacheInfo_.size() <= EMPTY_VECTOR) {
        TELEPHONY_LOGE("MultiSimController::GetPrimarySlotId failed by nullptr");
        return INVALID_VALUE;
    }
    int32_t i = DEFAULT_SIM_SLOT_ID;
    for (; i < maxCount_; i++) {
        if (localCacheInfo_[i].isMainCard == MAIN_CARD) {
            return i;
        }
    }
    return GetDefaultCellularDataSlotIdUnit();
}

bool MultiSimController::SetPrimarySlotId(int32_t slotId)
{
    TELEPHONY_LOGI("MultiSimController::SetPrimarySlotId slotId = %{public}d", slotId);
    std::lock_guard<std::mutex> lock(mutex_);
    if ((uint32_t)slotId >= localCacheInfo_.size()) {
        TELEPHONY_LOGE("MultiSimController::SetPrimarySlotId failed by out of range");
        return false;
    }
    if (simDbHelper_ == nullptr) {
        TELEPHONY_LOGE("MultiSimController::SetPrimarySlotId failed by nullptr");
        return false;
    }
    // change protocol for default cellulardata slotId
    if (!SetRadioProtocol(slotId, MAX_PROTOCOL)) {
        TELEPHONY_LOGE("MultiSimController::SetPrimarySlotId failed by SetRadioProtocol failed");
        return false;
    }
    int32_t result = simDbHelper_->SetDefaultMainCard(slotId);
    if (result == INVALID_VALUE) {
        TELEPHONY_LOGE("MultiSimController::SetPrimarySlotId get Data Base failed");
        return false;
    }
    int32_t i = DEFAULT_SIM_SLOT_ID;
    for (; i < maxCount_; i++) { // save to cache
        if (slotId == i) {
            localCacheInfo_[i].isMainCard = MAIN_CARD;
            continue;
        }
        localCacheInfo_[i].isMainCard = NOT_MAIN;
    }
    return AnnounceDefaultMainSlotIdChanged(slotId);
}

std::u16string MultiSimController::GetShowNumber(int32_t slotId)
{
    TELEPHONY_LOGI("MultiSimController::GetShowNumber");
    std::lock_guard<std::mutex> lock(mutex_);
    if (!IsValidData()) {
        TELEPHONY_LOGE("MultiSimController::GetShowNumber InValidData");
        return u"";
    }
    if ((uint32_t)slotId >= localCacheInfo_.size()) {
        TELEPHONY_LOGE("MultiSimController::GetShowNumber failed by nullptr");
        return u"";
    }
    return Str8ToStr16(localCacheInfo_[slotId].phoneNumber);
}

bool MultiSimController::SetShowNumber(int32_t slotId, std::u16string number, bool force)
{
    TELEPHONY_LOGI("MultiSimController::SetShowNumber number");
    if (!force && GetIccId(slotId).empty()) {
        TELEPHONY_LOGE("MultiSimController::SetShowNumber empty sim operation set failed");
        return false;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    if (!force && !IsValidData()) {
        TELEPHONY_LOGE("MultiSimController::SetShowNumber InValidData");
        return false;
    }
    if ((uint32_t)slotId >= localCacheInfo_.size()) {
        TELEPHONY_LOGE("MultiSimController::SetShowNumber failed by out of range");
        return false;
    }
    if (simDbHelper_ == nullptr) {
        TELEPHONY_LOGE("MultiSimController::SetShowNumber failed by nullptr");
        return false;
    }
    NativeRdb::ValuesBucket values;
    values.PutString(SimRdbInfo::PHONE_NUMBER, Str16ToStr8(number));
    int32_t result = simDbHelper_->UpdateDataBySlotId(slotId, values);
    if (result == INVALID_VALUE) {
        TELEPHONY_LOGE("MultiSimController::SetShowNumber set Data Base failed");
        return false;
    }
    localCacheInfo_[slotId].phoneNumber = Str16ToStr8(number); // save to cache
    return true;
}

std::u16string MultiSimController::GetShowName(int32_t slotId)
{
    TELEPHONY_LOGI("MultiSimController::GetShowName");
    std::lock_guard<std::mutex> lock(mutex_);
    if (!IsValidData()) {
        TELEPHONY_LOGE("MultiSimController::GetShowNumber InValidData");
        return u"";
    }
    if ((uint32_t)slotId >= localCacheInfo_.size()) {
        TELEPHONY_LOGE("MultiSimController::GetShowName failed by nullptr");
        return u"";
    }
    return Str8ToStr16(localCacheInfo_[slotId].showName);
}

bool MultiSimController::SetShowName(int32_t slotId, std::u16string name, bool force)
{
    TELEPHONY_LOGI("MultiSimController::SetShowName name = %{public}s", Str16ToStr8(name).c_str());
    if (!force && GetIccId(slotId).empty()) {
        TELEPHONY_LOGE("MultiSimController::SetShowName empty sim operation set failed");
        return false;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    if (!force && !IsValidData()) {
        TELEPHONY_LOGE("MultiSimController::SetShowNumber InValidData");
        return false;
    }
    if ((uint32_t)slotId >= localCacheInfo_.size()) {
        TELEPHONY_LOGE("MultiSimController::SetShowName failed by out of range");
        return false;
    }
    if (simDbHelper_ == nullptr) {
        TELEPHONY_LOGE("MultiSimController::SetShowName get Data Base failed");
        return false;
    }
    NativeRdb::ValuesBucket values;
    values.PutString(SimRdbInfo::SHOW_NAME, Str16ToStr8(name));
    int32_t result = simDbHelper_->UpdateDataBySlotId(slotId, values);
    if (result == INVALID_VALUE) {
        TELEPHONY_LOGE("MultiSimController::SetShowName set Data Base failed");
        return false;
    }
    localCacheInfo_[slotId].showName = Str16ToStr8(name); // save to cache
    return true;
}

std::u16string MultiSimController::GetIccId(int32_t slotId)
{
    TELEPHONY_LOGI("MultiSimController::GetIccId");
    std::lock_guard<std::mutex> lock(mutex_);
    if ((uint32_t)slotId >= localCacheInfo_.size()) {
        TELEPHONY_LOGE("MultiSimController::GetIccId failed by nullptr");
        return u"";
    }
    return Str8ToStr16(localCacheInfo_[slotId].iccId);
}

bool MultiSimController::SetIccId(int32_t slotId, std::u16string iccId)
{
    TELEPHONY_LOGI("MultiSimController::SetIccId");
    std::lock_guard<std::mutex> lock(mutex_);
    if ((uint32_t)slotId >= localCacheInfo_.size()) {
        TELEPHONY_LOGE("MultiSimController::SetIccId failed by out of range");
        return false;
    }
    if (simDbHelper_ == nullptr) {
        TELEPHONY_LOGE("MultiSimController::SetIccId failed by nullptr");
        return false;
    }
    NativeRdb::ValuesBucket values;
    values.PutString(SimRdbInfo::ICC_ID, Str16ToStr8(iccId));
    values.PutString(SimRdbInfo::CARD_ID, Str16ToStr8(iccId)); // iccId == cardId by now
    int32_t result = simDbHelper_->UpdateDataBySlotId(slotId, values);
    if (result == INVALID_VALUE) {
        TELEPHONY_LOGE("MultiSimController::SetIccId set Data Base failed");
        return false;
    }
    localCacheInfo_[slotId].iccId = Str16ToStr8(iccId); // save to cache
    localCacheInfo_[slotId].cardId = Str16ToStr8(iccId);
    return true;
}

bool MultiSimController::SetRadioProtocol(int32_t slotId, int32_t protocol)
{
    TELEPHONY_LOGI("MultiSimController::SetRadioProtocol slotId = %{public}d protocol = %{public}d", slotId, protocol);
    if (radioCapController_ == nullptr) {
        TELEPHONY_LOGE("MultiSimController::SetRadioProtocol failed by nullptr");
        return false;
    }
    std::unique_lock<std::mutex> lck(radioCapController_->ctx_);
    radioCapController_->RadioCapControllerWait();
    if (!radioCapController_->SetRadioProtocol(slotId, protocol)) {
        TELEPHONY_LOGE("MultiSimController::SetRadioProtocol failed");
        return false;
    }
    while (!radioCapController_->RadioCapControllerPoll()) {
        radioCapController_->cv_.wait(lck);
    }
    bool response = radioCapController_->GetRadioProtocolResponse();
    radioCapController_->ResetResponse();
    TELEPHONY_LOGI("MultiSimController::%{public}d ", response);
    return response;
}

bool MultiSimController::AnnounceDefaultVoiceSlotIdChanged(int32_t slotId)
{
    AAFwk::Want want;
    want.SetParam(PARAM_SLOTID, slotId);
    want.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_SIM_CARD_DEFAULT_VOICE_SUBSCRIPTION_CHANGED);
    int32_t eventCode = EVENT_CODE;
    std::string eventData(DEFAULT_VOICE_SLOT_CHANGED);
    return PublishSimFileEvent(want, eventCode, eventData);
}

bool MultiSimController::AnnounceDefaultSmsSlotIdChanged(int32_t slotId)
{
    AAFwk::Want want;
    want.SetParam(PARAM_SLOTID, slotId);
    want.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_SIM_CARD_DEFAULT_SMS_SUBSCRIPTION_CHANGED);
    int32_t eventCode = EVENT_CODE;
    std::string eventData(DEFAULT_SMS_SLOT_CHANGED);
    return PublishSimFileEvent(want, eventCode, eventData);
}

bool MultiSimController::AnnounceDefaultCellularDataSlotIdChanged(int32_t slotId)
{
    AAFwk::Want want;
    want.SetParam(PARAM_SLOTID, slotId);
    want.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_SIM_CARD_DEFAULT_DATA_SUBSCRIPTION_CHANGED);
    int32_t eventCode = EVENT_CODE;
    std::string eventData(DEFAULT_CELLULAR_DATA_SLOT_CHANGED);
    return PublishSimFileEvent(want, eventCode, eventData);
}

bool MultiSimController::AnnounceDefaultMainSlotIdChanged(int32_t slotId)
{
    AAFwk::Want want;
    want.SetParam(PARAM_SLOTID, slotId);
    want.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_SIM_CARD_DEFAULT_MAIN_SUBSCRIPTION_CHANGED);
    int32_t eventCode = EVENT_CODE;
    std::string eventData(DEFAULT_MAIN_SLOT_CHANGED);
    return PublishSimFileEvent(want, eventCode, eventData);
}

bool MultiSimController::PublishSimFileEvent(const AAFwk::Want &want, int eventCode, const std::string &eventData)
{
    EventFwk::CommonEventData data;
    data.SetWant(want);
    data.SetCode(eventCode);
    data.SetData(eventData);
    EventFwk::CommonEventPublishInfo publishInfo;
    publishInfo.SetOrdered(true);
    bool publishResult = EventFwk::CommonEventManager::PublishCommonEvent(data, publishInfo, nullptr);
    TELEPHONY_LOGI("MultiSimController::PublishSimFileEvent end###publishResult = %{public}d\n", publishResult);
    return publishResult;
}
} // namespace Telephony
} // namespace OHOS
