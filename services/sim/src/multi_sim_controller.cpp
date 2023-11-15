/*
 * Copyright (C) 2021-2022 Huawei Device Co., Ltd.
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
#include "core_service_errors.h"
#include "core_service_hisysevent.h"
#include "parameters.h"
#include "sim_data.h"
#include "string_ex.h"

namespace OHOS {
namespace Telephony {
static const int32_t EVENT_CODE = 1;
static const int32_t ACTIVATABLE = 2;
static const int32_t IMS_SWITCH_VALUE_UNKNOWN = -1;
static const std::string PARAM_SIMID = "simId";
static const std::string DEFAULT_VOICE_SIMID_CHANGED = "defaultVoiceSimIdChanged";
static const std::string DEFAULT_SMS_SIMID_CHANGED = "defaultSmsSimIdChanged";
static const std::string DEFAULT_CELLULAR_DATA_SIMID_CHANGED = "defaultCellularDataSimIdChanged";
static const std::string DEFAULT_MAIN_SIMID_CHANGED = "defaultMainSimIdChanged";

MultiSimController::MultiSimController(std::shared_ptr<Telephony::ITelRilManager> telRilManager,
    std::vector<std::shared_ptr<Telephony::SimStateManager>> simStateManager,
    std::vector<std::shared_ptr<Telephony::SimFileManager>> simFileManager,
    const std::shared_ptr<AppExecFwk::EventRunner> &runner)
    : simStateManager_(simStateManager), simFileManager_(simFileManager)
{
    TELEPHONY_LOGI("MultiSimController::MultiSimController");
    radioProtocolController_ =
        std::make_shared<RadioProtocolController>(std::weak_ptr<ITelRilManager>(telRilManager), runner);
}

MultiSimController::~MultiSimController()
{
    if (radioProtocolController_ != nullptr) {
        radioProtocolController_->UnRegisterEvents();
    }
}

// set all data to invalid wait for InitData to rebuild
void MultiSimController::Init()
{
    if (simDbHelper_ == nullptr) {
        simDbHelper_ = std::make_unique<SimRdbHelper>();
    }
    if (radioProtocolController_ != nullptr) {
        radioProtocolController_->Init();
    }
    maxCount_ = SIM_SLOT_COUNT;
    TELEPHONY_LOGI("Create SimRdbHelper count = %{public}d", maxCount_);
}

bool MultiSimController::ForgetAllData()
{
    if (simDbHelper_ == nullptr) {
        TELEPHONY_LOGE("simDbHelper_ is nullptr failed");
        return false;
    }
    return simDbHelper_->ForgetAllData();
}

bool MultiSimController::ForgetAllData(int32_t slotId)
{
    if (simDbHelper_ == nullptr) {
        TELEPHONY_LOGE("simDbHelper_ is nullptr");
        return false;
    }
    return simDbHelper_->ForgetAllData(slotId) != INVALID_VALUE;
}

void MultiSimController::SetNetworkSearchManager(std::shared_ptr<INetworkSearch> networkSearchManager)
{
    networkSearchManager_ = networkSearchManager;
}

bool MultiSimController::InitData(int32_t slotId)
{
    TELEPHONY_LOGI("start to initData slotId is %{public}d", slotId);
    bool result = true;
    if (!IsValidData(slotId)) {
        TELEPHONY_LOGE("has no sim card, abandon");
        return false;
    }
    if (!InitIccId(slotId)) { // check if we insert or reactive a data
        TELEPHONY_LOGE("can not init IccId");
        result = false;
    }
    if (!GetListFromDataBase()) { // init data base to local cache
        TELEPHONY_LOGE("can not get dataBase");
        result = false;
    }
    if (localCacheInfo_.size() <= 0) {
        TELEPHONY_LOGE("MultiSimController::we get nothing from init");
        return false;
    }
    if (!InitActive(slotId)) {
        TELEPHONY_LOGE("InitActive failed");
        result = false;
    }
    if (!InitShowNumber(slotId)) {
        TELEPHONY_LOGE("InitShowNumber failed");
        result = false;
    }
    return result;
}

bool MultiSimController::InitActive(int slotId)
{
    bool result = true;
    if (!IsSimActive(slotId) && simStateManager_[slotId]->HasSimCard()) {
        // force set to database ACTIVE and avoid duplicate
        result = (SetActiveSim(slotId, ACTIVE, true) == TELEPHONY_ERR_SUCCESS);
    }
    if (IsSimActive(slotId) && !simStateManager_[slotId]->HasSimCard()) {
        if (result && (SetActiveSim(slotId, DEACTIVE, true) == TELEPHONY_ERR_SUCCESS)) {
            result = true;
        } else {
            result = false;
        } // force set to database DEACTIVE and avoid duplicate
    }
    return result;
}

bool MultiSimController::InitIccId(int slotId)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (simFileManager_[slotId] == nullptr) {
        TELEPHONY_LOGE("can not get simFileManager");
        return false;
    }
    std::string newIccId = Str16ToStr8(simFileManager_[slotId]->GetSimIccId());
    if (newIccId.empty()) {
        TELEPHONY_LOGE("can not get iccId");
        return false;
    }
    if (simDbHelper_ == nullptr) {
        TELEPHONY_LOGE("failed by nullptr");
        return false;
    }
    int32_t result;
    SimRdbInfo simRdbInfo;
    simDbHelper_->QueryDataByIccId(newIccId, simRdbInfo);
    if (!simRdbInfo.iccId.empty()) { // already have this card, reactive it
        TELEPHONY_LOGI("old sim insert");
        result = UpdateDataByIccId(slotId, newIccId);
    } else { // insert a new data for new IccId
        TELEPHONY_LOGI("new sim insert");
        result = InsertData(slotId, newIccId);
    }
    if (result == INVALID_VALUE) {
        TELEPHONY_LOGE("failed to init data");
        return false;
    }
    TELEPHONY_LOGI("result is %{public}d", result);
    return true;
}

int32_t MultiSimController::UpdateDataByIccId(int slotId, const std::string &newIccId)
{
    if (simDbHelper_ == nullptr) {
        TELEPHONY_LOGE("failed by nullptr");
        return INVALID_VALUE;
    }
    SimRdbInfo simRdbInfo;
    simDbHelper_->QueryDataByIccId(newIccId, simRdbInfo);
    DataShare::DataShareValuesBucket values;
    DataShare::DataShareValueObject slotObj(slotId);
    DataShare::DataShareValueObject valueObj(ACTIVE);
    values.Put(SimData::SLOT_INDEX, slotObj);
    values.Put(SimData::IS_ACTIVE, valueObj);
    const int32_t slotSingle = 1;
    if (SIM_SLOT_COUNT == slotSingle) {
        DataShare::DataShareValueObject mainCardObj(MAIN_CARD);
        values.Put(SimData::IS_MAIN_CARD, mainCardObj);
        values.Put(SimData::IS_VOICE_CARD, mainCardObj);
        values.Put(SimData::IS_MESSAGE_CARD, mainCardObj);
        values.Put(SimData::IS_CELLULAR_DATA_CARD, mainCardObj);
    }
    return simDbHelper_->UpdateDataByIccId(newIccId, values); // finish re active
}

int32_t MultiSimController::InsertData(int slotId, const std::string &newIccId)
{
    if (simDbHelper_ == nullptr) {
        TELEPHONY_LOGE("failed by nullptr");
        return INVALID_VALUE;
    }
    SimRdbInfo simRdbInfo;
    simDbHelper_->QueryDataByIccId(newIccId, simRdbInfo);
    DataShare::DataShareValuesBucket values;
    DataShare::DataShareValueObject slotObj(slotId);
    DataShare::DataShareValueObject iccidObj(newIccId);
    DataShare::DataShareValueObject valueObj(ACTIVE);
    values.Put(SimData::SLOT_INDEX, slotObj);
    values.Put(SimData::ICC_ID, iccidObj);
    values.Put(SimData::CARD_ID, iccidObj); // iccId == cardId by now
    values.Put(SimData::IS_ACTIVE, valueObj);
    const int32_t slotSingle = 1;
    if (SIM_SLOT_COUNT == slotSingle) {
        DataShare::DataShareValueObject mainCardObj(MAIN_CARD);
        values.Put(SimData::IS_MAIN_CARD, mainCardObj);
        values.Put(SimData::IS_VOICE_CARD, mainCardObj);
        values.Put(SimData::IS_MESSAGE_CARD, mainCardObj);
        values.Put(SimData::IS_CELLULAR_DATA_CARD, mainCardObj);
    } else {
        DataShare::DataShareValueObject notMainCardObj(NOT_MAIN);
        values.Put(SimData::IS_MAIN_CARD, notMainCardObj);
        values.Put(SimData::IS_VOICE_CARD, notMainCardObj);
        values.Put(SimData::IS_MESSAGE_CARD, notMainCardObj);
        values.Put(SimData::IS_CELLULAR_DATA_CARD, notMainCardObj);
    }
    int64_t id;
    return simDbHelper_->InsertData(id, values);
}

bool MultiSimController::InitShowNumber(int slotId)
{
    std::u16string showNumber;
    GetShowNumber(slotId, showNumber);
    if (!showNumber.empty() && showNumber != IccAccountInfo::DEFAULT_SHOW_NUMBER) {
        TELEPHONY_LOGD("no need to Init again");
        return true;
    }
    if (simFileManager_[slotId] == nullptr) {
        TELEPHONY_LOGE("can not get simFileManager");
        return false;
    }
    showNumber = simFileManager_[slotId]->GetSimTelephoneNumber();
    int32_t result = TELEPHONY_ERROR;
    if (!showNumber.empty()) {
        result = SetShowNumber(slotId, showNumber, true);
    } else {
        result = SetShowNumber(slotId, IccAccountInfo::DEFAULT_SHOW_NUMBER, true);
    }
    return result == TELEPHONY_ERR_SUCCESS;
}

bool MultiSimController::GetListFromDataBase()
{
    TELEPHONY_LOGD("start");
    std::lock_guard<std::mutex> lock(mutex_);
    if (localCacheInfo_.size() > 0) {
        localCacheInfo_.clear();
    }
    if (simDbHelper_ == nullptr) {
        TELEPHONY_LOGE("failed by nullptr");
        return false;
    }
    int32_t result = simDbHelper_->QueryAllValidData(localCacheInfo_);
    TELEPHONY_LOGI("QueryAllValidData result is %{public}d", result);
    SortCache();
    return (result != INVALID_VALUE) ? true : false;
}

void MultiSimController::SortCache()
{
    size_t count = localCacheInfo_.size();
    TELEPHONY_LOGI("count = %{public}lu", static_cast<unsigned long>(count));
    if (count <= 0) {
        TELEPHONY_LOGE("empty");
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
        TELEPHONY_LOGD(
            "index = %{public}d j = %{public}lu", localCacheInfo_[j].slotIndex, static_cast<unsigned long>(j));
        sortCache[localCacheInfo_[j].slotIndex] = localCacheInfo_[j];
    }
    localCacheInfo_ = sortCache;
}

/*
 * check the data is valid, if we don't have SimCard the data is not valid
 */
bool MultiSimController::IsValidData(int32_t slotId)
{
    if (((slotId < DEFAULT_SIM_SLOT_ID) || (slotId >= SIM_SLOT_COUNT)) || simStateManager_[slotId] == nullptr) {
        TELEPHONY_LOGE("can not get simStateManager");
        return false;
    }
    return simStateManager_[slotId]->HasSimCard();
}

bool MultiSimController::RefreshActiveIccAccountInfoList()
{
    if (localCacheInfo_.empty()) {
        TELEPHONY_LOGE("failed by invalid data");
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
        ++it;
    }
    return true;
}

int32_t MultiSimController::GetSlotId(int32_t simId)
{
    if (localCacheInfo_.empty()) {
        TELEPHONY_LOGE("failed by nullptr");
        return INVALID_VALUE;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<SimRdbInfo>::iterator it = localCacheInfo_.begin();

    while (it != localCacheInfo_.end()) { // loop data list
        if (it->isActive == ACTIVE && it->simId == simId) { // pick Active item
            return it->slotIndex;
        }
        ++it;
    }
    return INVALID_VALUE;
}

bool MultiSimController::IsSimActive(int32_t slotId)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (!IsValidData(slotId)) {
        TELEPHONY_LOGE("InValidData");
        return false;
    }
    if (static_cast<uint32_t>(slotId) >= localCacheInfo_.size()) {
        TELEPHONY_LOGE("failed by out of range");
        return false;
    }
    return localCacheInfo_[slotId].isActive == ACTIVE ? true : false;
}

bool MultiSimController::IsSimActivatable(int32_t slotId)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (static_cast<uint32_t>(slotId) >= localCacheInfo_.size()) {
        TELEPHONY_LOGD("out of range");
        return false;
    }
    return localCacheInfo_[slotId].isActive == ACTIVATABLE ? true : false;
}

int32_t MultiSimController::SetActiveSim(int32_t slotId, int32_t enable, bool force)
{
    TELEPHONY_LOGI("enable = %{public}d slotId = %{public}d", enable, slotId);
    if (!IsValidData(slotId)) {
        TELEPHONY_LOGE("invalid slotid or sim card absent.");
        return TELEPHONY_ERR_NO_SIM_CARD;
    }
    if (!force && GetIccId(slotId).empty() && enable != ACTIVE) { // force is used for init data
        TELEPHONY_LOGE("empty sim operation set failed");
        return TELEPHONY_ERR_ARGUMENT_INVALID;
    }
    if (static_cast<uint32_t>(slotId) >= localCacheInfo_.size() && enable != ACTIVE) {
        TELEPHONY_LOGE("failed by out of range");
        return TELEPHONY_ERR_ARGUMENT_INVALID;
    }
    if (!force && !SetActiveSimToRil(slotId, ENTITY_CARD, enable)) {
        TELEPHONY_LOGE("SetActiveSimToRil failed");
        return TELEPHONY_ERR_RIL_CMD_FAIL;
    }
    if (static_cast<uint32_t>(slotId) >= localCacheInfo_.size()) {
        TELEPHONY_LOGE("failed by out of range");
        return TELEPHONY_ERR_ARGUMENT_INVALID;
    }
    if (simDbHelper_ == nullptr) {
        TELEPHONY_LOGE("failed by nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    DataShare::DataShareValuesBucket values;
    DataShare::DataShareValueObject valueObj(enable);
    values.Put(SimData::IS_ACTIVE, valueObj);
    int32_t result = simDbHelper_->UpdateDataBySimId(localCacheInfo_[slotId].simId, values);
    if (result == INVALID_VALUE) {
        TELEPHONY_LOGE("failed by database");
        return TELEPHONY_ERR_DATABASE_WRITE_FAIL;
    }
    if (enable == ACTIVE) {
        localCacheInfo_[slotId].isActive = enable;
    } else {
        localCacheInfo_[slotId].isActive = ACTIVATABLE;
    }
    return TELEPHONY_ERR_SUCCESS;
}

bool MultiSimController::SetActiveSimToRil(int32_t slotId, int32_t type, int32_t enable)
{
    if (radioProtocolController_ == nullptr) {
        TELEPHONY_LOGE("radioProtocolController_ is nullptr");
        return false;
    }
    std::unique_lock<std::mutex> lck(radioProtocolController_->ctx_);
    radioProtocolController_->RadioProtocolControllerWait();
    if (!radioProtocolController_->SetActiveSimToRil(slotId, type, enable)) {
        TELEPHONY_LOGE("MultiSimController::SetActiveSimToRil failed");
        return false;
    }
    while (!radioProtocolController_->RadioProtocolControllerPoll()) {
        TELEPHONY_LOGI("MultiSimController SetActiveSimToRil wait");
        radioProtocolController_->cv_.wait(lck);
    }
    return radioProtocolController_->GetActiveSimToRilResult() == static_cast<int32_t>(HRilErrType::NONE);
}

int32_t MultiSimController::GetSimAccountInfo(int32_t slotId, bool denied, IccAccountInfo &info)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (!IsValidData(slotId)) {
        TELEPHONY_LOGE("MultiSimController::GetSimAccountInfo InValidData");
        return TELEPHONY_ERR_NO_SIM_CARD;
    }
    if (static_cast<uint32_t>(slotId) >= localCacheInfo_.size()) {
        TELEPHONY_LOGE("MultiSimController::GetSimAccountInfo failed by out of range");
        return TELEPHONY_ERR_SLOTID_INVALID;
    }
    if (localCacheInfo_[slotId].iccId.empty()) {
        TELEPHONY_LOGE("MultiSimController::GetSimAccountInfo failed by no data");
        return CORE_ERR_SIM_CARD_LOAD_FAILED;
    }
    info.slotIndex = localCacheInfo_[slotId].slotIndex;
    info.simId = localCacheInfo_[slotId].simId;
    info.isActive = localCacheInfo_[slotId].isActive;
    info.showName = Str8ToStr16(localCacheInfo_[slotId].showName);
    info.isEsim = false;
    if (!denied) {
        info.showNumber = Str8ToStr16(localCacheInfo_[slotId].phoneNumber);
        info.iccId = Str8ToStr16(localCacheInfo_[slotId].iccId);
    }
    return TELEPHONY_ERR_SUCCESS;
}

int32_t MultiSimController::GetDefaultVoiceSlotId()
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (localCacheInfo_.empty()) {
        TELEPHONY_LOGE("failed by nullptr");
        if (simDbHelper_ == nullptr) {
            TELEPHONY_LOGE("simDbHelper is nullptr");
            return INVALID_VALUE;
        }
        return simDbHelper_->GetDefaultVoiceCardSlotId();
    }
    int32_t i = DEFAULT_SIM_SLOT_ID;
    for (; i < maxCount_; i++) {
        if (localCacheInfo_[i].isVoiceCard == MAIN_CARD && localCacheInfo_[i].isActive == ACTIVE) {
            return i;
        }
    }
    return INVALID_VALUE;
}

int32_t MultiSimController::GetFirstActivedSlotId()
{
    int32_t i = DEFAULT_SIM_SLOT_ID;
    for (; i < maxCount_; i++) {
        if (localCacheInfo_[i].isActive == ACTIVE) {
            return localCacheInfo_[i].slotIndex;
        }
    }
    return INVALID_VALUE;
}

int32_t MultiSimController::SetDefaultVoiceSlotId(int32_t slotId)
{
    TELEPHONY_LOGD("slotId = %{public}d", slotId);
    if ((slotId == DEFAULT_SIM_SLOT_ID_REMOVE && localCacheInfo_.empty()) ||
        (slotId != DEFAULT_SIM_SLOT_ID_REMOVE && !IsValidData(slotId))) {
        TELEPHONY_LOGE("no sim card");
        return TELEPHONY_ERR_NO_SIM_CARD;
    }
    if (slotId != DEFAULT_SIM_SLOT_ID_REMOVE && !IsSimActive(slotId)) {
        TELEPHONY_LOGE("slotId is not active");
        return CORE_SERVICE_SIM_CARD_IS_NOT_ACTIVE;
    }
    if (slotId >= (int32_t)localCacheInfo_.size() || slotId < DEFAULT_SIM_SLOT_ID_REMOVE) {
        TELEPHONY_LOGE("failed by out of range");
        return TELEPHONY_ERR_SLOTID_INVALID;
    }
    if (simDbHelper_ == nullptr) {
        TELEPHONY_LOGE("failed by nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    int32_t result = simDbHelper_->SetDefaultVoiceCard(localCacheInfo_[slotId].simId);
    if (result == INVALID_VALUE) {
        TELEPHONY_LOGE("get Data Base failed");
        return TELEPHONY_ERR_DATABASE_WRITE_FAIL;
    }
    int32_t i = DEFAULT_SIM_SLOT_ID;
    for (; i < maxCount_; i++) { // save to cache
        if (slotId == i) {
            localCacheInfo_[i].isVoiceCard = MAIN_CARD;
            continue;
        }
        localCacheInfo_[i].isVoiceCard = NOT_MAIN;
    }
    if (localCacheInfo_[slotId].simId == defaultVoiceSimId_) {
        TELEPHONY_LOGE("no need to AnnounceDefaultVoiceSimIdChanged");
        return TELEPHONY_ERR_SUCCESS;
    }
    defaultVoiceSimId_ = localCacheInfo_[slotId].simId;
    if (!AnnounceDefaultVoiceSimIdChanged(slotId)) {
        return TELEPHONY_ERR_PUBLISH_BROADCAST_FAIL;
    }
    return TELEPHONY_ERR_SUCCESS;
}

int32_t MultiSimController::GetDefaultSmsSlotId()
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (localCacheInfo_.empty()) {
        TELEPHONY_LOGE("failed by nullptr");
        if (simDbHelper_ == nullptr) {
            TELEPHONY_LOGE("simDbHelper is nullptr");
            return INVALID_VALUE;
        }
        return simDbHelper_->GetDefaultMessageCardSlotId();
    }
    int32_t i = DEFAULT_SIM_SLOT_ID;
    for (; i < maxCount_; i++) {
        if (localCacheInfo_[i].isMessageCard == MAIN_CARD && localCacheInfo_[i].isActive == ACTIVE) {
            return i;
        }
    }
    return GetFirstActivedSlotId();
}

int32_t MultiSimController::SetDefaultSmsSlotId(int32_t slotId)
{
    if (slotId == DEFAULT_SIM_SLOT_ID_REMOVE && localCacheInfo_.empty()) {
        TELEPHONY_LOGE("no sim card");
        return TELEPHONY_ERR_NO_SIM_CARD;
    }
    if (slotId != DEFAULT_SIM_SLOT_ID_REMOVE && !IsSimActive(slotId)) {
        TELEPHONY_LOGE("slotId is not active!");
        return CORE_SERVICE_SIM_CARD_IS_NOT_ACTIVE;
    }
    if (slotId >= (int32_t)localCacheInfo_.size() || slotId < DEFAULT_SIM_SLOT_ID_REMOVE) {
        TELEPHONY_LOGE("failed by out of range");
        return TELEPHONY_ERR_SLOTID_INVALID;
    }
    if (simDbHelper_ == nullptr) {
        TELEPHONY_LOGE("failed by nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    int32_t result = simDbHelper_->SetDefaultMessageCard(localCacheInfo_[slotId].simId);
    if (result == INVALID_VALUE) {
        TELEPHONY_LOGE("get Data Base failed");
        return TELEPHONY_ERR_DATABASE_WRITE_FAIL;
    }
    int32_t i = DEFAULT_SIM_SLOT_ID;
    for (; i < maxCount_; i++) { // save to cache
        if (slotId == i) {
            localCacheInfo_[i].isMessageCard = MAIN_CARD;
            continue;
        }
        localCacheInfo_[i].isMessageCard = NOT_MAIN;
    }
    if (localCacheInfo_[slotId].simId == defaultSmsSimId_) {
        TELEPHONY_LOGE("no need to AnnounceDefaultSmsSimIdChanged");
        return TELEPHONY_ERR_SUCCESS;
    }
    defaultSmsSimId_ = localCacheInfo_[slotId].simId;
    if (!AnnounceDefaultSmsSimIdChanged(slotId)) {
        return TELEPHONY_ERR_PUBLISH_BROADCAST_FAIL;
    }
    return TELEPHONY_ERR_SUCCESS;
}

int32_t MultiSimController::GetDefaultCellularDataSlotId()
{
    return GetDefaultCellularDataSlotIdUnit();
}

int32_t MultiSimController::SetDefaultCellularDataSlotId(int32_t slotId)
{
    TELEPHONY_LOGD("slotId = %{public}d", slotId);
    if ((slotId == DEFAULT_SIM_SLOT_ID_REMOVE && localCacheInfo_.empty()) ||
        (slotId != DEFAULT_SIM_SLOT_ID_REMOVE && !IsValidData(slotId))) {
        TELEPHONY_LOGE("no sim card");
        return TELEPHONY_ERR_NO_SIM_CARD;
    }
    if (slotId != DEFAULT_SIM_SLOT_ID_REMOVE && !IsSimActive(slotId)) {
        TELEPHONY_LOGE("slotId is not active");
        return CORE_SERVICE_SIM_CARD_IS_NOT_ACTIVE;
    }
    if (slotId >= (int32_t)localCacheInfo_.size() || slotId < DEFAULT_SIM_SLOT_ID_REMOVE) {
        TELEPHONY_LOGE("failed by out of range");
        return TELEPHONY_ERR_SLOTID_INVALID;
    }
    if (simDbHelper_ == nullptr) {
        TELEPHONY_LOGE("failed by nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    int32_t result = simDbHelper_->SetDefaultCellularData(localCacheInfo_[slotId].simId);
    if (result == INVALID_VALUE) {
        TELEPHONY_LOGE("get Data Base failed");
        return TELEPHONY_ERR_DATABASE_WRITE_FAIL;
    }
    int32_t i = DEFAULT_SIM_SLOT_ID;
    for (; i < maxCount_; i++) { // save to cache
        if (slotId == i) {
            localCacheInfo_[i].isCellularDataCard = MAIN_CARD;
            continue;
        }
        localCacheInfo_[i].isCellularDataCard = NOT_MAIN;
    }
    CoreServiceHiSysEvent::WriteDefaultDataSlotIdBehaviorEvent(slotId);
    if (localCacheInfo_[slotId].simId == defaultCellularSimId_) {
        TELEPHONY_LOGE("no need to defaultCellularSimId_");
        return TELEPHONY_ERR_SUCCESS;
    }
    defaultCellularSimId_ = localCacheInfo_[slotId].simId;
    if (!AnnounceDefaultCellularDataSimIdChanged(defaultCellularSimId_)) {
        TELEPHONY_LOGE("publish broadcast failed");
        return TELEPHONY_ERR_PUBLISH_BROADCAST_FAIL;
    }
    return TELEPHONY_ERR_SUCCESS;
}

int32_t MultiSimController::GetDefaultCellularDataSlotIdUnit()
{
    if (localCacheInfo_.empty()) {
        TELEPHONY_LOGE("failed by nullptr");
        if (simDbHelper_ == nullptr) {
            TELEPHONY_LOGE("simDbHelper is nullptr");
            return INVALID_VALUE;
        }
        return simDbHelper_->GetDefaultCellularDataCardSlotId();
    }
    int32_t i = DEFAULT_SIM_SLOT_ID;
    for (; i < maxCount_; i++) {
        if (localCacheInfo_[i].isCellularDataCard == MAIN_CARD && localCacheInfo_[i].isActive == ACTIVE) {
            return i;
        }
    }
    return GetFirstActivedSlotId();
}

int32_t MultiSimController::GetPrimarySlotId()
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (localCacheInfo_.empty()) {
        if (simDbHelper_ == nullptr) {
            TELEPHONY_LOGE("failed by nullptr");
            return INVALID_VALUE;
        }
        return simDbHelper_->GetDefaultMainCardSlotId();
    }
    int32_t i = DEFAULT_SIM_SLOT_ID;
    for (; i < maxCount_; i++) {
        if (localCacheInfo_[i].isMainCard == MAIN_CARD && localCacheInfo_[i].isActive == ACTIVE) {
            return i;
        }
    }
    return GetFirstActivedSlotId();
}

int32_t MultiSimController::SetPrimarySlotId(int32_t slotId)
{
    if (localCacheInfo_.empty() || !IsValidData(slotId)) {
        TELEPHONY_LOGE("no sim card");
        return TELEPHONY_ERR_NO_SIM_CARD;
    }
    if (static_cast<uint32_t>(slotId) >= localCacheInfo_.size()) {
        TELEPHONY_LOGE("failed by out of range");
        return TELEPHONY_ERR_SLOTID_INVALID;
    }
    if (!IsSimActive(slotId)) {
        TELEPHONY_LOGE("slotId is not active");
        return CORE_SERVICE_SIM_CARD_IS_NOT_ACTIVE;
    }
    // change protocol for default cellulardata slotId
    if (radioProtocolController_ == nullptr || !radioProtocolController_->SetRadioProtocol(slotId)) {
        TELEPHONY_LOGE("SetRadioProtocol failed");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    if (simDbHelper_ == nullptr) {
        TELEPHONY_LOGE("failed by nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    int32_t setMainResult = simDbHelper_->SetDefaultMainCard(localCacheInfo_[slotId].simId);
    int32_t setDataResult = simDbHelper_->SetDefaultCellularData(localCacheInfo_[slotId].simId);
    if (setMainResult == INVALID_VALUE || setDataResult == INVALID_VALUE) {
        TELEPHONY_LOGE("failed by invalid result");
        return TELEPHONY_ERR_DATABASE_WRITE_FAIL;
    }
    int32_t i = DEFAULT_SIM_SLOT_ID;
    for (; i < maxCount_; i++) { // save to cache
        if (slotId == i) {
            localCacheInfo_[i].isMainCard = MAIN_CARD;
            localCacheInfo_[i].isCellularDataCard = MAIN_CARD;
            continue;
        }
        localCacheInfo_[i].isMainCard = NOT_MAIN;
        localCacheInfo_[i].isCellularDataCard = NOT_MAIN;
    }
    if (localCacheInfo_[slotId].simId == primarySimId_) {
        TELEPHONY_LOGE("no need to AnnounceDefaultMainSimIdChanged");
        return TELEPHONY_ERR_SUCCESS;
    }
    primarySimId_ = localCacheInfo_[slotId].simId;
    if (!AnnounceDefaultMainSimIdChanged(slotId)) {
        TELEPHONY_LOGE("publish broadcast failed");
        return TELEPHONY_ERR_PUBLISH_BROADCAST_FAIL;
    }
    return TELEPHONY_ERR_SUCCESS;
}

int32_t MultiSimController::GetShowNumber(int32_t slotId, std::u16string &showNumber)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (!IsValidData(slotId)) {
        TELEPHONY_LOGE("InValidData");
        return TELEPHONY_ERR_NO_SIM_CARD;
    }
    if (static_cast<uint32_t>(slotId) >= localCacheInfo_.size()) {
        TELEPHONY_LOGE("failed by nullptr");
        return TELEPHONY_ERR_ARGUMENT_INVALID;
    }
    showNumber = Str8ToStr16(localCacheInfo_[slotId].phoneNumber);
    return TELEPHONY_ERR_SUCCESS;
}

int32_t MultiSimController::SetShowNumber(int32_t slotId, std::u16string number, bool force)
{
    TELEPHONY_LOGI("MultiSimController::SetShowNumber slotId = %{public}d", slotId);
    if (!force && !IsValidData(slotId)) {
        TELEPHONY_LOGE("MultiSimController::SetShowNumber InValidData");
        return TELEPHONY_ERR_NO_SIM_CARD;
    }
    if ((static_cast<uint32_t>(slotId) >= localCacheInfo_.size()) || (!force && GetIccId(slotId).empty())) {
        TELEPHONY_LOGE("MultiSimController::SetShowNumber failed by out of range");
        return TELEPHONY_ERR_ARGUMENT_INVALID;
    }
    if (simDbHelper_ == nullptr) {
        TELEPHONY_LOGE("MultiSimController::SetShowNumber failed by nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    DataShare::DataShareValuesBucket values;
    DataShare::DataShareValueObject valueObj(Str16ToStr8(number));
    values.Put(SimData::PHONE_NUMBER, valueObj);
    int32_t result = simDbHelper_->UpdateDataBySimId(localCacheInfo_[slotId].simId, values);
    if (result == INVALID_VALUE) {
        TELEPHONY_LOGE("MultiSimController::SetShowNumber set Data Base failed");
        return TELEPHONY_ERR_DATABASE_WRITE_FAIL;
    }
    localCacheInfo_[slotId].phoneNumber = Str16ToStr8(number); // save to cache
    return TELEPHONY_ERR_SUCCESS;
}

int32_t MultiSimController::GetShowName(int32_t slotId, std::u16string &showName)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (!IsValidData(slotId)) {
        TELEPHONY_LOGE("InValidData");
        return TELEPHONY_ERR_NO_SIM_CARD;
    }
    if (static_cast<uint32_t>(slotId) >= localCacheInfo_.size()) {
        TELEPHONY_LOGE("failed by nullptr");
        return TELEPHONY_ERR_ARGUMENT_INVALID;
    }
    showName = Str8ToStr16(localCacheInfo_[slotId].showName);
    if (showName.empty() && networkSearchManager_ != nullptr) {
        TELEPHONY_LOGI("GetOperatorName");
        networkSearchManager_->GetOperatorName(slotId, showName);
        return TELEPHONY_ERR_SUCCESS;
    }
    TELEPHONY_LOGI("name is empty");
    return TELEPHONY_ERR_SUCCESS;
}

int32_t MultiSimController::SetShowName(int32_t slotId, std::u16string name, bool force)
{
    if (!force && !IsValidData(slotId)) {
        TELEPHONY_LOGE("MultiSimController::SetShowNumber InValidData");
        return TELEPHONY_ERR_NO_SIM_CARD;
    }
    if ((static_cast<uint32_t>(slotId) >= localCacheInfo_.size()) || (!force && GetIccId(slotId).empty())) {
        TELEPHONY_LOGE("MultiSimController::SetShowName failed by out of range");
        return TELEPHONY_ERR_ARGUMENT_INVALID;
    }
    if (simDbHelper_ == nullptr) {
        TELEPHONY_LOGE("MultiSimController::SetShowName get Data Base failed");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    DataShare::DataShareValuesBucket values;
    DataShare::DataShareValueObject valueObj(Str16ToStr8(name));
    values.Put(SimData::SHOW_NAME, valueObj);
    int32_t result = simDbHelper_->UpdateDataBySimId(localCacheInfo_[slotId].simId, values);
    if (result == INVALID_VALUE) {
        TELEPHONY_LOGE("MultiSimController::SetShowName set Data Base failed");
        return TELEPHONY_ERR_DATABASE_WRITE_FAIL;
    }
    localCacheInfo_[slotId].showName = Str16ToStr8(name); // save to cache
    return TELEPHONY_ERR_SUCCESS;
}

std::u16string MultiSimController::GetIccId(int32_t slotId)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (static_cast<uint32_t>(slotId) >= localCacheInfo_.size()) {
        TELEPHONY_LOGE("MultiSimController::GetIccId failed by nullptr");
        return u"";
    }
    return Str8ToStr16(localCacheInfo_[slotId].iccId);
}

bool MultiSimController::AnnounceDefaultVoiceSimIdChanged(int32_t simId)
{
    AAFwk::Want want;
    want.SetParam(PARAM_SIMID, simId);
    want.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_SIM_CARD_DEFAULT_VOICE_SUBSCRIPTION_CHANGED);
    int32_t eventCode = EVENT_CODE;
    std::string eventData(DEFAULT_VOICE_SIMID_CHANGED);
    return PublishSimFileEvent(want, eventCode, eventData);
}

bool MultiSimController::AnnounceDefaultSmsSimIdChanged(int32_t simId)
{
    AAFwk::Want want;
    want.SetParam(PARAM_SIMID, simId);
    want.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_SIM_CARD_DEFAULT_SMS_SUBSCRIPTION_CHANGED);
    int32_t eventCode = EVENT_CODE;
    std::string eventData(DEFAULT_SMS_SIMID_CHANGED);
    return PublishSimFileEvent(want, eventCode, eventData);
}

bool MultiSimController::AnnounceDefaultCellularDataSimIdChanged(int32_t simId)
{
    AAFwk::Want want;
    want.SetParam(PARAM_SIMID, simId);
    want.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_SIM_CARD_DEFAULT_DATA_SUBSCRIPTION_CHANGED);
    int32_t eventCode = EVENT_CODE;
    std::string eventData(DEFAULT_CELLULAR_DATA_SIMID_CHANGED);
    return PublishSimFileEvent(want, eventCode, eventData);
}

bool MultiSimController::AnnounceDefaultMainSimIdChanged(int32_t simId)
{
    AAFwk::Want want;
    want.SetParam(PARAM_SIMID, simId);
    want.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_SIM_CARD_DEFAULT_MAIN_SUBSCRIPTION_CHANGED);
    int32_t eventCode = EVENT_CODE;
    std::string eventData(DEFAULT_MAIN_SIMID_CHANGED);
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
    TELEPHONY_LOGD("MultiSimController::PublishSimFileEvent end###publishResult = %{public}d", publishResult);
    return publishResult;
}

int32_t MultiSimController::SaveImsSwitch(int32_t slotId, int32_t imsSwitchValue)
{
    if (static_cast<std::size_t>(slotId) >= localCacheInfo_.size() || simDbHelper_ == nullptr) {
        TELEPHONY_LOGE(
            "failed by out of range or simDbHelper is nullptr, slotId = %{public}d localCacheInfo size = %{public}zu",
            slotId, localCacheInfo_.size());
        return TELEPHONY_ERROR;
    }
    DataShare::DataShareValuesBucket values;
    DataShare::DataShareValueObject valueObj(imsSwitchValue);
    values.Put(SimData::IMS_SWITCH, valueObj);
    return simDbHelper_->UpdateDataByIccId(localCacheInfo_[slotId].iccId, values);
}

int32_t MultiSimController::QueryImsSwitch(int32_t slotId, int32_t &imsSwitchValue)
{
    if (static_cast<std::size_t>(slotId) >= localCacheInfo_.size() || simDbHelper_ == nullptr) {
        TELEPHONY_LOGE(
            "failed by out of range or simDbHelper is nullptr, slotId = %{public}d localCacheInfo size = %{public}zu",
            slotId, localCacheInfo_.size());
        imsSwitchValue = IMS_SWITCH_VALUE_UNKNOWN;
        return TELEPHONY_ERROR;
    }
    SimRdbInfo simRdbInfo;
    simDbHelper_->QueryDataByIccId(localCacheInfo_[slotId].iccId, simRdbInfo);
    imsSwitchValue = simRdbInfo.imsSwitch;
    return TELEPHONY_SUCCESS;
}

int32_t MultiSimController::GetActiveSimAccountInfoList(bool denied, std::vector<IccAccountInfo> &iccAccountInfoList)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (!RefreshActiveIccAccountInfoList()) {
        TELEPHONY_LOGE("refresh failed");
        return TELEPHONY_ERR_NO_SIM_CARD;
    }
    iccAccountInfoList.clear();
    std::vector<IccAccountInfo>::iterator it = iccAccountInfoList_.begin();
    while (it != iccAccountInfoList_.end()) {
        TELEPHONY_LOGI("slotIndex=%{public}d", it->slotIndex);
        if (denied) {
            it->iccId = u"";
            it->showNumber = u"";
        }
        iccAccountInfoList.emplace_back(*it);
        ++it;
    }
    return iccAccountInfoList.size() > 0 ? TELEPHONY_ERR_SUCCESS : TELEPHONY_ERR_NO_SIM_CARD;
}

int32_t MultiSimController::GetRadioProtocolTech(int32_t slotId)
{
    if (radioProtocolController_ == nullptr) {
        TELEPHONY_LOGE("radioProtocolController_ is nullptr");
        return static_cast<int32_t>(RadioProtocolTech::RADIO_PROTOCOL_TECH_UNKNOWN);
    }
    return radioProtocolController_->GetRadioProtocolTech(slotId);
}

void MultiSimController::GetRadioProtocol(int32_t slotId)
{
    if (radioProtocolController_ == nullptr) {
        TELEPHONY_LOGE("radioProtocolController_ is nullptr");
        return;
    }
    radioProtocolController_->GetRadioProtocol(slotId);
}
} // namespace Telephony
} // namespace OHOS
