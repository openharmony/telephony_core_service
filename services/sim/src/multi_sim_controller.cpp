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
#include "string_ex.h"

namespace OHOS {
namespace Telephony {
std::mutex MultiSimController::mutex_;
std::vector<SimRdbInfo> MultiSimController::localCacheInfo_;

MultiSimController::MultiSimController(std::shared_ptr<ISimStateManager> simStateManager,
    std::shared_ptr<ISimFileManager> simFileManager,
    std::shared_ptr<INetworkSearch> networkSearchManager,
    int32_t slotId)
    : simStateManager_(simStateManager), simFileManager_(simFileManager), netWorkSearchManager_(networkSearchManager)
{
    TELEPHONY_LOGI("MultiSimController::MultiSimController");
    lackSim_ = false;
    slotId_ = slotId;
}

MultiSimController::~MultiSimController() {}

void MultiSimController::Init()
{
    if (simDbHelper_ == nullptr) {
        simDbHelper_ = std::make_unique<SimRdbHelper>();
    }
    maxCount_ = CoreManager::GetInstance().getCore(CoreManager::DEFAULT_SLOT_ID)->GetMaxSimCount();
    TELEPHONY_LOGI("MultiSimController::Init Create SimRdbHelper count = %{public}d", maxCount_);
    if (simDbHelper_ == nullptr) {
        TELEPHONY_LOGE("MultiSimController::Init simDbHelper_ is nullptr failed");
        return;
    }
    // if there is not a main card the database must be empty,to be init
    if (simDbHelper_->GetDefaultMainCardSlotId() != INVALID_VALUE) {
        TELEPHONY_LOGE("MultiSimController::Init data base is already exist");
        return;
    }
    TELEPHONY_LOGI("MultiSimController::Init Create SimRdbHelper table");
    int result = 0;
    for (int i = CoreManager::DEFAULT_SLOT_ID; i < maxCount_; i++) { // insert default to database
        int64_t id;
        NativeRdb::ValuesBucket values;
        values.PutInt(SimRdbInfo::SIM_ID, i);
        values.PutInt(SimRdbInfo::SLOT_INDEX, i);
        values.PutString(SimRdbInfo::ICC_ID, Str16ToStr8(IccAccountInfo::DEFAULT_ICC_ID));
        values.PutString(SimRdbInfo::CARD_ID, Str16ToStr8(IccAccountInfo::DEFAULT_ICC_ID)); // iccId == cardId by now
        values.PutString(SimRdbInfo::PHONE_NUMBER, Str16ToStr8(IccAccountInfo::DEFAULT_SHOW_NUMBER));
        result = simDbHelper_->InsertData(id, values);
        if (result == INVALID_VALUE) {
            // if insert data failed, we do not stop the process, just mark it
            TELEPHONY_LOGE("MultiSimController::Init insert data failed %{public}d", i);
        }
    }
    int32_t slotId = CoreManager::DEFAULT_SLOT_ID;
    result = simDbHelper_->SetDefaultMainCard(slotId);
    if (result == INVALID_VALUE) {
        // if set default, we do not stop the process, just mark it
        TELEPHONY_LOGE("MultiSimController::Init SetDefaultMainCard data failed");
        return;
    }
    result = simDbHelper_->SetDefaultMessageCard(slotId);
    if (result == INVALID_VALUE) {
        // if set default, we do not stop the process, just mark it
        TELEPHONY_LOGE("MultiSimController::Init SetDefaultMessageCard data failed");
        return;
    }
    result = simDbHelper_->SetDefaultCellularData(slotId);
    if (result == INVALID_VALUE) {
        // if set default, we do not stop the process, just mark it
        TELEPHONY_LOGE("MultiSimController::Init SetDefaultCellularData data failed");
        return;
    }
}

void MultiSimController::InitData()
{
    TELEPHONY_LOGI("MultiSimController::InitData");
    if (!GetListFromDataBase()) { // init data base to local cache
        TELEPHONY_LOGE("MultiSimController::InitData can not get dataBase");
        return;
    }
    if (!InitActive(slotId_)) {
        TELEPHONY_LOGE("MultiSimController::InitData InitActive failed");
    }
    if (!InitIccId(slotId_)) { // if IccId is same, no need to init other data
        TELEPHONY_LOGI("MultiSimController::InitData same data not need to init again");
        return;
    }
    if (!InitShowName(slotId_)) {
        TELEPHONY_LOGE("MultiSimController::InitData InitShowName failed");
    }
    if (!InitShowNumber(slotId_)) {
        TELEPHONY_LOGE("MultiSimController::InitData InitShowNumber failed");
    }
}

bool MultiSimController::InitActive(int slotId)
{
    if (simStateManager_ == nullptr) {
        TELEPHONY_LOGE("MultiSimController::InitActive can not get simStateManager");
        return false;
    }
    bool result = true;
    if (!IsSimActive(slotId) && simStateManager_->HasSimCard(slotId)) {
        result = SetActiveSim(slotId, ACTIVE, true); // force set to database ACTIVE and avoid duplicate
    }
    if (IsSimActive(slotId) && !simStateManager_->HasSimCard(slotId)) {
        result &= SetActiveSim(slotId, DEACTIVE, true); // force set to database DEACTIVE and avoid duplicate
    }
    return result;
}

bool MultiSimController::InitIccId(int slotId)
{
    TELEPHONY_LOGI("MultiSimController::InitIccId slotId = %{public}d", slotId);
    std::u16string oldIccId = GetIccId(slotId);
    if (simFileManager_ == nullptr) {
        TELEPHONY_LOGE("MultiSimController::InitIccId can not get simFileManager");
        return false;
    }
    std::u16string newIccId = simFileManager_->GetSimIccId(slotId);
    if (!newIccId.empty()) {
        lackSim_ = false;
    } else {
        lackSim_ = true;
    }
    if (!lackSim_ && (oldIccId == newIccId)) {
        TELEPHONY_LOGI("MultiSimController::same IccId, no need to init");
        return false;
    }
    bool result = true;
    if (!newIccId.empty()) {
        result = SetIccId(slotId, newIccId);
    } else {
        result &= SetIccId(slotId, IccAccountInfo::DEFAULT_ICC_ID);
    }
    return result;
}

bool MultiSimController::InitShowName(int slotId)
{
    TELEPHONY_LOGI("MultiSimController::InitShowName slotId = %{public}d", slotId);
    std::u16string showName = GetShowName(slotId);
    if (netWorkSearchManager_ == nullptr) {
        TELEPHONY_LOGE("can not get netWorkSearchManager");
        return false;
    }
    showName = netWorkSearchManager_->GetOperatorName(slotId);
    bool result = false;
    if (lackSim_) {
        result = SetShowName(slotId, u"", true);
    } else if (!showName.empty()) {
        result = SetShowName(slotId, showName, true);
    } else {
        result = SetShowName(slotId, IccAccountInfo::DEFAULT_SHOW_NAME + Str8ToStr16(std::to_string(slotId)), true);
    }
    return result;
}

bool MultiSimController::InitShowNumber(int slotId)
{
    TELEPHONY_LOGI("MultiSimController::InitShowNumber slotId = %{public}d", slotId);
    std::u16string showNumber = GetShowNumber(slotId);
    if (simFileManager_ == nullptr) {
        TELEPHONY_LOGE("can not get simFileManager");
        return false;
    }
    showNumber = simFileManager_->GetSimTelephoneNumber(slotId);
    bool result = false;
    if (lackSim_) {
        result = SetShowNumber(slotId, u"", true);
    } else if (!showNumber.empty()) {
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
    int32_t result = simDbHelper_->QueryAllData(localCacheInfo_);
    return (result != INVALID_VALUE) ? true : false;
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
    return simStateManager_->HasSimCard(slotId_);
}

bool MultiSimController::RefreshActiveIccAccountInfoList()
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (!IsValidData()) {
        TELEPHONY_LOGE("MultiSimController::RefreshActiveIccAccountInfoList InValidData");
        return false;
    }
    std::vector<SimRdbInfo>::iterator it = localCacheInfo_.begin();
    if (iccAccountInfoList_.size() > 0) {
        iccAccountInfoList_.clear();
    }
    while (it != localCacheInfo_.end()) { // loop data list
        if (it->isActive != DEACTIVE) { // pick Active item
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

bool MultiSimController::IsSimActive(int32_t slotId)
{
    TELEPHONY_LOGI("MultiSimController::IsSimActive slotId = %{public}d", slotId);
    std::lock_guard<std::mutex> lock(mutex_);
    if (!IsValidData()) {
        TELEPHONY_LOGE("MultiSimController::IsSimActive InValidData");
        return false;
    }
    if (localCacheInfo_.size() <= slotId) {
        TELEPHONY_LOGE("MultiSimController::IsSimActive failed by out of range");
        return false;
    }
    return localCacheInfo_[slotId].isActive == ACTIVE ? true : false;
}

bool MultiSimController::SetActiveSim(int32_t slotId, int32_t enable, bool force)
{
    TELEPHONY_LOGI("MultiSimController::SetActiveSim enable = %{public}d slotId = %{public}d", enable, slotId);
    if (!force && GetIccId(slotId).empty()) { // force is used for init data
        TELEPHONY_LOGE("MultiSimController::SetActiveSim empty sim operation set failed");
        return false;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    if (localCacheInfo_.size() <= slotId) {
        TELEPHONY_LOGE("MultiSimController::SetActiveSim failed by out of range");
        return false;
    }
    if (simStateManager_ == nullptr) {
        TELEPHONY_LOGE("MultiSimController::SetActiveSim can not call simStateManager_");
        return false;
    }
    if (!simStateManager_->SetActiveSim(slotId, ENTITY_CARD, enable)) {
        TELEPHONY_LOGE("MultiSimController::SetActiveSim do simStateManager.SetActiveSim failed");
        return false;
    }
    if (simDbHelper_ == nullptr) {
        TELEPHONY_LOGE("MultiSimController::SetActiveSim failed by nullptr");
        return false;
    }
    NativeRdb::ValuesBucket values;
    values.PutInt(SimRdbInfo::IS_ACTIVE, enable);
    int32_t result = simDbHelper_->UpdateDateBySlotId(slotId, values);
    if (result != INVALID_VALUE) { // save to cache
        localCacheInfo_[slotId].isActive = enable;
    }
    return (result != INVALID_VALUE) ? true : false;
}

bool MultiSimController::GetSimAccountInfo(int32_t slotId, IccAccountInfo &info)
{
    TELEPHONY_LOGI("MultiSimController::GetSimAccountInfo slotId = %{public}d", slotId);
    std::lock_guard<std::mutex> lock(mutex_);
    if (!IsValidData()) {
        TELEPHONY_LOGE("MultiSimController::GetSimAccountInfo InValidData");
        return false;
    }
    if (localCacheInfo_.size() <= slotId) {
        TELEPHONY_LOGE("MultiSimController::GetSimAccountInfo failed by out of range");
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
    if (!IsValidData()) {
        TELEPHONY_LOGE("MultiSimController::GetDefaultVoiceSlotId InValidData");
        return INVALID_VALUE;
    }
    if (localCacheInfo_.size() <= EMPTY_VECTOR) {
        TELEPHONY_LOGE("MultiSimController::GetDefaultVoiceSlotId failed by nullptr");
        return INVALID_VALUE;
    }
    int32_t i = CoreManager::DEFAULT_SLOT_ID;
    for (; i < maxCount_; i++) {
        if (localCacheInfo_[i].isMainCard == MAIN_CARD) {
            return i;
        }
    }
    return INVALID_VALUE;
}

bool MultiSimController::SetDefaultVoiceSlotId(int32_t slotId)
{
    TELEPHONY_LOGI("MultiSimController::SetDefaultVoiceSlotId slotId = %{public}d", slotId);
    if (GetIccId(slotId).empty()) {
        TELEPHONY_LOGE("MultiSimController::SetDefaultVoiceSlotId empty sim operation set failed");
        return false;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    if (!IsValidData()) {
        TELEPHONY_LOGE("MultiSimController::SetDefaultVoiceSlotId InValidData");
        return false;
    }
    if (localCacheInfo_.size() <= slotId) {
        TELEPHONY_LOGE("MultiSimController::SetDefaultVoiceSlotId failed by out of range");
        return false;
    }
    if (simDbHelper_ == nullptr) {
        TELEPHONY_LOGE("MultiSimController::SetDefaultVoiceSlotId failed by nullptr");
        return false;
    }
    int32_t result = simDbHelper_->SetDefaultMainCard(slotId);
    if (result == INVALID_VALUE) {
        TELEPHONY_LOGE("MultiSimController::SetDefaultVoiceSlotId get Data Base failed");
        return false;
    }
    int32_t i = CoreManager::DEFAULT_SLOT_ID;
    for (; i < maxCount_; i++) { // save to cache
        if (slotId == i) {
            localCacheInfo_[i].isMainCard = MAIN_CARD;
            continue;
        }
        localCacheInfo_[i].isMainCard = NOT_MAIN;
    }
    return AnnounceDefaultVoiceSlotIdChanged(slotId);
}

int32_t MultiSimController::GetDefaultSmsSlotId()
{
    TELEPHONY_LOGI("MultiSimController::GetDefaultSmsSlotId");
    std::lock_guard<std::mutex> lock(mutex_);
    if (!IsValidData()) {
        TELEPHONY_LOGE("MultiSimController::GetDefaultSmsSlotId InValidData");
        return INVALID_VALUE;
    }
    if (localCacheInfo_.size() <= EMPTY_VECTOR) {
        TELEPHONY_LOGE("MultiSimController::GetDefaultSmsSlotId failed by nullptr");
        return INVALID_VALUE;
    }
    int32_t i = CoreManager::DEFAULT_SLOT_ID;
    for (; i < maxCount_; i++) {
        if (localCacheInfo_[i].isMessageCard == MAIN_CARD) {
            return i;
        }
    }
    return INVALID_VALUE;
}

bool MultiSimController::SetDefaultSmsSlotId(int32_t slotId)
{
    TELEPHONY_LOGI("MultiSimController::SetDefaultSmsSlotId slotId = %{public}d", slotId);
    if (GetIccId(slotId).empty()) {
        TELEPHONY_LOGE("MultiSimController::SetDefaultSmsSlotId empty sim operation set failed");
        return false;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    if (!IsValidData()) {
        TELEPHONY_LOGE("MultiSimController::SetDefaultSmsSlotId InValidData");
        return false;
    }
    if (localCacheInfo_.size() <= slotId) {
        TELEPHONY_LOGE("MultiSimController::SetDefaultSmsSlotId failed by out of range");
        return false;
    }
    if (simDbHelper_ == nullptr) {
        TELEPHONY_LOGE("MultiSimController::SetDefaultSmsSlotId failed by nullptr");
        return false;
    }
    int32_t result = simDbHelper_->SetDefaultMessageCard(slotId);
    if (result == INVALID_VALUE) {
        TELEPHONY_LOGE("MultiSimController::SetDefaultSmsSlotId get Data Base failed");
        return false;
    }
    int32_t i = CoreManager::DEFAULT_SLOT_ID;
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
    if (!IsValidData()) {
        TELEPHONY_LOGE("MultiSimController::GetDefaultCellularDataSlotId InValidData");
        return INVALID_VALUE;
    }
    if (localCacheInfo_.size() <= EMPTY_VECTOR) {
        TELEPHONY_LOGE("MultiSimController::GetDefaultCellularDataSlotId failed by nullptr");
        return INVALID_VALUE;
    }
    int32_t i = CoreManager::DEFAULT_SLOT_ID;
    for (; i < maxCount_; i++) {
        if (localCacheInfo_[i].isCellularDataCard == MAIN_CARD) {
            return i;
        }
    }
    return INVALID_VALUE;
}

bool MultiSimController::SetDefaultCellularDataSlotId(int32_t slotId)
{
    TELEPHONY_LOGI("MultiSimController::SetDefaultCellularDataSlotId slotId = %{public}d", slotId);
    if (GetIccId(slotId).empty()) {
        TELEPHONY_LOGE("MultiSimController::SetDefaultCellularDataSlotId empty sim operation set failed");
        return false;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    if (!IsValidData()) {
        TELEPHONY_LOGE("MultiSimController::SetDefaultCellularDataSlotId InValidData");
        return false;
    }
    if (localCacheInfo_.size() <= slotId) {
        TELEPHONY_LOGE("MultiSimController::SetDefaultCellularDataSlotId failed by out of range");
        return false;
    }
    if (simDbHelper_ == nullptr) {
        TELEPHONY_LOGE("MultiSimController::SetDefaultVoiceSlotId failed by nullptr");
        return false;
    }
    int32_t result = simDbHelper_->SetDefaultCellularData(slotId);
    if (result == INVALID_VALUE) {
        TELEPHONY_LOGE("MultiSimController::SetDefaultCellularDataSlotId get Data Base failed");
        return false;
    }
    int32_t i = CoreManager::DEFAULT_SLOT_ID;
    for (; i < maxCount_; i++) { // save to cache
        if (slotId == i) {
            localCacheInfo_[i].isCellularDataCard = MAIN_CARD;
            continue;
        }
        localCacheInfo_[i].isCellularDataCard = NOT_MAIN;
    }
    return AnnounceDefaultCellularDataSlotIdChanged(slotId);
}

std::u16string MultiSimController::GetShowNumber(int32_t slotId)
{
    TELEPHONY_LOGI("MultiSimController::GetShowNumber");
    std::lock_guard<std::mutex> lock(mutex_);
    if (!IsValidData()) {
        TELEPHONY_LOGE("MultiSimController::GetShowNumber InValidData");
        return u"";
    }
    if (localCacheInfo_.size() <= slotId) {
        TELEPHONY_LOGE("MultiSimController::GetShowNumber failed by nullptr");
        return u"";
    }
    return Str8ToStr16(localCacheInfo_[slotId].phoneNumber);
}

bool MultiSimController::SetShowNumber(int32_t slotId, std::u16string number, bool force)
{
    TELEPHONY_LOGI("MultiSimController::SetShowNumber number = %{public}s ", Str16ToStr8(number).c_str());
    if (!force && GetIccId(slotId).empty()) {
        TELEPHONY_LOGE("MultiSimController::SetShowNumber empty sim operation set failed");
        return false;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    if (!force && !IsValidData()) {
        TELEPHONY_LOGE("MultiSimController::SetShowNumber InValidData");
        return false;
    }
    if (localCacheInfo_.size() <= slotId) {
        TELEPHONY_LOGE("MultiSimController::SetShowNumber failed by out of range");
        return false;
    }
    if (simDbHelper_ == nullptr) {
        TELEPHONY_LOGE("MultiSimController::SetShowNumber failed by nullptr");
        return false;
    }
    NativeRdb::ValuesBucket values;
    values.PutString(SimRdbInfo::PHONE_NUMBER, Str16ToStr8(number));
    int32_t result = simDbHelper_->UpdateDateBySlotId(slotId, values);
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
    if (localCacheInfo_.size() <= slotId) {
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
    if (localCacheInfo_.size() <= slotId) {
        TELEPHONY_LOGE("MultiSimController::SetShowName failed by out of range");
        return false;
    }
    if (simDbHelper_ == nullptr) {
        TELEPHONY_LOGE("MultiSimController::SetShowName get Data Base failed");
        return false;
    }
    NativeRdb::ValuesBucket values;
    values.PutString(SimRdbInfo::SHOW_NAME, Str16ToStr8(name));
    int32_t result = simDbHelper_->UpdateDateBySlotId(slotId, values);
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
    if (localCacheInfo_.size() <= slotId) {
        TELEPHONY_LOGE("MultiSimController::GetIccId failed by nullptr");
        return u"";
    }
    return Str8ToStr16(localCacheInfo_[slotId].iccId);
}

bool MultiSimController::SetIccId(int32_t slotId, std::u16string iccId)
{
    TELEPHONY_LOGI("MultiSimController::SetIccId iccId = %{public}s", Str16ToStr8(iccId).c_str());
    std::lock_guard<std::mutex> lock(mutex_);
    if (localCacheInfo_.size() <= slotId) {
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
    int32_t result = simDbHelper_->UpdateDateBySlotId(slotId, values);
    if (result == INVALID_VALUE) {
        TELEPHONY_LOGE("MultiSimController::SetIccId set Data Base failed");
        return false;
    }
    localCacheInfo_[slotId].iccId = Str16ToStr8(iccId); // save to cache
    localCacheInfo_[slotId].cardId = Str16ToStr8(iccId);
    return true;
}

bool MultiSimController::AnnounceDefaultVoiceSlotIdChanged(int32_t slotId)
{
    AAFwk::Want want;
    want.SetParam(PARAM_SLOTID, slotId);
    want.SetAction(DEFAULT_VOICE_SLOTID_CHANGE_ACTION);
    int32_t eventCode = EVENT_CODE;
    std::string eventData(DEFAULT_VOICE_SLOT_CHANGED);
    return PublishSimFileEvent(want, eventCode, eventData);
}

bool MultiSimController::AnnounceDefaultSmsSlotIdChanged(int32_t slotId)
{
    AAFwk::Want want;
    want.SetParam(PARAM_SLOTID, slotId);
    want.SetAction(DEFAULT_SMS_SLOTID_CHANGE_ACTION);
    int32_t eventCode = EVENT_CODE;
    std::string eventData(DEFAULT_SMS_SLOT_CHANGED);
    return PublishSimFileEvent(want, eventCode, eventData);
}

bool MultiSimController::AnnounceDefaultCellularDataSlotIdChanged(int32_t slotId)
{
    AAFwk::Want want;
    want.SetParam(PARAM_SLOTID, slotId);
    want.SetAction(DEFAULT_DATA_SLOTID_CHANGE_ACTION);
    int32_t eventCode = EVENT_CODE;
    std::string eventData(DEFAULT_CELLULAR_DATA_SLOT_CHANGED);
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
