/*
 * Copyright (C) 2021-2024 Huawei Device Co., Ltd.
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

#include <openssl/sha.h>

#include "common_event_manager.h"
#include "common_event_support.h"
#include "core_manager_inner.h"
#include "core_service_errors.h"
#include "core_service_hisysevent.h"
#include "ims_core_service_client.h"
#include "tel_aes_crypto_util.h"
#include "parameters.h"
#include "sim_data.h"
#include "sim_utils.h"
#include "string_ex.h"
#include "telephony_ext_wrapper.h"

namespace OHOS {
namespace Telephony {
static const int32_t EVENT_CODE = 1;
static const int32_t IMS_SWITCH_VALUE_UNKNOWN = -1;
static const int32_t MAIN_MODEM_ID = 0;
const int32_t SYSTEM_PARAMETER_LENGTH = 128;
static const std::string PARAM_SIMID = "simId";
static const std::string PARAM_SET_PRIMARY_STATUS = "setDone";
static const std::string DEFAULT_VOICE_SIMID_CHANGED = "defaultVoiceSimIdChanged";
static const std::string DEFAULT_SMS_SIMID_CHANGED = "defaultSmsSimIdChanged";
static const std::string DEFAULT_CELLULAR_DATA_SIMID_CHANGED = "defaultCellularDataSimIdChanged";
static const std::string DEFAULT_MAIN_SIMID_CHANGED = "defaultMainSimIdChanged";
static const std::string MAIN_CARD_ICCID_KEY = "persist.telephony.MainCard.Iccid";
static const std::string PRIMARY_SLOTID_KEY = "persist.telephony.MainSlotId";
static const std::string MAIN_CELLULAR_DATA_SLOTID_KEY = "persist.telephony.MainCellularDataSlotId";
static const std::string PRIMARY_SLOTID = "0";

MultiSimController::MultiSimController(std::shared_ptr<Telephony::ITelRilManager> telRilManager,
    std::vector<std::shared_ptr<Telephony::SimStateManager>> simStateManager,
    std::vector<std::shared_ptr<Telephony::SimFileManager>> simFileManager)
    : simStateManager_(simStateManager), simFileManager_(simFileManager)
{
    TELEPHONY_LOGI("MultiSimController::MultiSimController");
    radioProtocolController_ = std::make_shared<RadioProtocolController>(std::weak_ptr<ITelRilManager>(telRilManager));
    InitMainCardSlotId();
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
    isSetActiveSimInProgress_.resize(maxCount_, 0);
    TELEPHONY_LOGI("Create SimRdbHelper count = %{public}d", maxCount_);
}

bool MultiSimController::ForgetAllData()
{
    if (simDbHelper_ == nullptr) {
        TELEPHONY_LOGE("simDbHelper_ is nullptr failed");
        return false;
    }
    return (simDbHelper_->ForgetAllData() != INVALID_VALUE);
}

bool MultiSimController::ForgetAllData(int32_t slotId)
{
    if (simDbHelper_ == nullptr) {
        TELEPHONY_LOGE("simDbHelper_ is nullptr");
        return false;
    }
    return simDbHelper_->ForgetAllData(slotId) != INVALID_VALUE;
}

void MultiSimController::AddExtraManagers(std::shared_ptr<Telephony::SimStateManager> simStateManager,
    std::shared_ptr<Telephony::SimFileManager> simFileManager)
{
    if (static_cast<int>(simStateManager_.size()) == SIM_SLOT_COUNT) {
        simStateManager_.push_back(simStateManager);
        simFileManager_.push_back(simFileManager);
        isSetActiveSimInProgress_.push_back(0);
        maxCount_ = MAX_SLOT_COUNT;
        size_t count = localCacheInfo_.size();
        TELEPHONY_LOGI("localCacheInfo_.size() = %{public}lu, maxCount_ = %{public}d",
            static_cast<unsigned long>(count), maxCount_);
    }
}

bool MultiSimController::InitData(int32_t slotId)
{
    TELEPHONY_LOGI("start to initData slotId is %{public}d", slotId);
    if (!IsValidData(slotId)) {
        TELEPHONY_LOGE("has no sim card, abandon");
        return false;
    }
    if (!InitIccId(slotId)) { // check if we insert or reactive a data
        TELEPHONY_LOGE("can not init IccId");
        return false;
    }
    if (!GetListFromDataBase()) { // init data base to local cache
        TELEPHONY_LOGE("can not get dataBase");
        return false;
    }
    if (localCacheInfo_.size() <= 0) {
        TELEPHONY_LOGE("MultiSimController::we get nothing from init");
        return false;
    }
    if (!InitActive(slotId)) {
        TELEPHONY_LOGE("InitActive failed");
        return false;
    }
    if (!InitShowNumber(slotId)) {
        TELEPHONY_LOGE("InitShowNumber failed");
    }
    if (InitPrimary()) {
        TELEPHONY_LOGI("InitPrimary start");
        CheckIfNeedSwitchMainSlotId();
    }
    TELEPHONY_LOGI("sim account loaded, slotId is %{public}d, simId is %{public}d", slotId,
        localCacheInfo_[slotId].simId);
    return true;
}

bool MultiSimController::InitActive(int slotId)
{
    bool result = true;
    if (!simStateManager_[slotId]->HasSimCard()) {
        TELEPHONY_LOGI("has no sim and not need to active");
        return result;
    }
    if (!IsSimActive(slotId)) {
        result = (SetActiveSim(slotId, DEACTIVE, true) == TELEPHONY_ERR_SUCCESS);
    }
    if (IsSimActive(slotId)) {
        result = (SetActiveSim(slotId, ACTIVE, true) == TELEPHONY_ERR_SUCCESS);
    }
    return result;
}

bool MultiSimController::InitPrimary()
{
    if (maxCount_ <= 1) {
        TELEPHONY_LOGI("no need to init");
        return false;
    }
    if (!IsAllModemInitDone()) {
        TELEPHONY_LOGI("wait for the other modem init");
        return false;
    }
    unInitModemSlotId_ = INVALID_VALUE;
    if (IsAllCardsReady() && !IsAllCardsLoaded()) {
        TELEPHONY_LOGI("wait for the other card ready");
        return false;
    }
    return true;
}

void MultiSimController::ReCheckPrimary()
{
    if (InitPrimary()) {
        TELEPHONY_LOGI("ReCheckPrimary start");
        CheckIfNeedSwitchMainSlotId();
    }
}

bool MultiSimController::IsAllCardsReady()
{
    for (int32_t i = 0; i < SIM_SLOT_COUNT; i++) {
        if (simStateManager_[i] != nullptr && (simStateManager_[i]->GetSimState() == SimState::SIM_STATE_UNKNOWN
            || simStateManager_[i]->GetSimState() == SimState::SIM_STATE_NOT_PRESENT)) {
            TELEPHONY_LOGI("slot:%{public}d not ready", i);
            return false;
        }
    }
    return true;
}

bool MultiSimController::IsAllModemInitDone()
{
    for (int32_t i = 0; i < SIM_SLOT_COUNT; i++) {
        if (simStateManager_[i] != nullptr && !(simStateManager_[i]->IfModemInitDone())) {
            TELEPHONY_LOGI("slot:%{public}d modem init not done", i);
            unInitModemSlotId_ = i;
            return false;
        }
    }
    return true;
}

bool MultiSimController::IsDataShareError()
{
    return simDbHelper_ != nullptr && simDbHelper_->IsDataShareError();
}

void MultiSimController::ResetDataShareError()
{
    if (simDbHelper_ != nullptr) {
        simDbHelper_->ResetDataShareError();
    }
}

int32_t MultiSimController::UpdateOpKeyInfo()
{
    if (simDbHelper_ == nullptr) {
        TELEPHONY_LOGE("simDbHelper is nullptr");
        return TELEPHONY_ERROR;
    }
    return simDbHelper_->UpdateOpKeyInfo();
}

bool MultiSimController::IsAllCardsLoaded()
{
    if (localCacheInfo_.empty()) {
        TELEPHONY_LOGI("there is no card loaded");
        return false;
    }
    for (int32_t i = 0; i < SIM_SLOT_COUNT; i++) {
        if (localCacheInfo_[i].iccId.empty()) {
            TELEPHONY_LOGI("slot:%{public}d not loaded", i);
            return false;
        }
    }
    return true;
}

bool MultiSimController::InitIccId(int slotId)
{
    if (simFileManager_[slotId] == nullptr) {
        TELEPHONY_LOGE("can not get simFileManager");
        return false;
    }
    std::string newIccId = Str16ToStr8(simFileManager_[slotId]->GetSimIccId());
    if (newIccId.empty()) {
        TELEPHONY_LOGI("iccid is empty.");
        newIccId = "emptyiccid" + std::to_string(slotId);
    }
    if (simDbHelper_ == nullptr) {
        TELEPHONY_LOGE("failed by nullptr");
        return false;
    }
    int32_t result;
    SimRdbInfo simRdbInfo;
    if (simDbHelper_->QueryDataByIccId(newIccId, simRdbInfo) == INVALID_VALUE) {
        TELEPHONY_LOGE("query fail");
        return false;
    }
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
    DataShare::DataShareValuesBucket values;
    DataShare::DataShareValueObject slotObj(slotId);
    values.Put(SimData::SLOT_INDEX, slotObj);
    const int32_t slotSingle = 1;
    if (SIM_SLOT_COUNT == slotSingle) {
        DataShare::DataShareValueObject mainCardObj(MAIN_CARD);
        values.Put(SimData::IS_MAIN_CARD, mainCardObj);
        values.Put(SimData::IS_VOICE_CARD, mainCardObj);
        values.Put(SimData::IS_MESSAGE_CARD, mainCardObj);
        values.Put(SimData::IS_CELLULAR_DATA_CARD, mainCardObj);
    }
    return simDbHelper_->UpdateDataByIccId(newIccId, values);
}

int32_t MultiSimController::InsertData(int slotId, const std::string &newIccId)
{
    if (simDbHelper_ == nullptr) {
        TELEPHONY_LOGE("failed by nullptr");
        return INVALID_VALUE;
    }
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
    if (!IsValidData(slotId)) {
        TELEPHONY_LOGE("InValidData");
        return false;
    }
    if (simFileManager_[slotId] == nullptr) {
        TELEPHONY_LOGE("can not get simFileManager");
        return false;
    }
    showNumber = simFileManager_[slotId]->GetSimTelephoneNumber();
    int32_t result = TELEPHONY_ERROR;
    result = SetShowNumberToDB(slotId, showNumber);
    return result == TELEPHONY_ERR_SUCCESS;
}

bool MultiSimController::GetListFromDataBase()
{
    TELEPHONY_LOGD("start");
    std::vector<SimRdbInfo> newCache;
    if (simDbHelper_ == nullptr) {
        TELEPHONY_LOGE("failed by nullptr");
        return false;
    }
    int32_t result = simDbHelper_->QueryAllValidData(newCache);
    TELEPHONY_LOGI("QueryAllValidData result is %{public}d", result);
    std::unique_lock<std::mutex> lock(mutex_);
    if (localCacheInfo_.size() > 0) {
        localCacheInfo_.clear();
    }
    localCacheInfo_ = newCache;
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
    count = localCacheInfo_.size();
    TELEPHONY_LOGI("localCacheInfo_.size() = %{public}lu, maxCount_ = %{public}d",
        static_cast<unsigned long>(count), maxCount_);
}

/*
 * check the data is valid, if we don't have SimCard the data is not valid
 */
bool MultiSimController::IsValidData(int32_t slotId)
{
    if ((slotId < DEFAULT_SIM_SLOT_ID) || (static_cast<uint32_t>(slotId) >= simStateManager_.size())) {
        TELEPHONY_LOGE("can not get simStateManager");
        return false;
    }
    if (simStateManager_.empty() || static_cast<uint32_t>(slotId) >= simStateManager_.size() ||
        simStateManager_[slotId] == nullptr) {
        TELEPHONY_LOGE("can not get simStateManager");
        return false;
    }
    return simStateManager_[slotId]->HasSimCard();
}

bool MultiSimController::RefreshActiveIccAccountInfoList()
{
    std::unique_lock<std::mutex> lock(mutex_);
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
    std::unique_lock<std::mutex> lock(mutex_);
    if (localCacheInfo_.empty()) {
        TELEPHONY_LOGE("failed by nullptr");
        return INVALID_VALUE;
    }
    std::vector<SimRdbInfo>::iterator it = localCacheInfo_.begin();

    while (it != localCacheInfo_.end()) { // loop data list
        if (it->isActive == ACTIVE && it->simId == simId) { // pick Active item
            return it->slotIndex;
        }
        ++it;
    }
    return INVALID_VALUE;
}

int32_t MultiSimController::GetSimId(int32_t slotId)
{
    IccAccountInfo iccAccountInfo;
    if (GetSimAccountInfo(slotId, true, iccAccountInfo) == TELEPHONY_ERR_SUCCESS) {
        return iccAccountInfo.simId;
    }
    return INVALID_VALUE;
}

bool MultiSimController::IsSimActive(int32_t slotId)
{
    if (!IsValidData(slotId)) {
        return false;
    }
    if (static_cast<uint32_t>(slotId) >= localCacheInfo_.size()) {
        TELEPHONY_LOGD("failed by out of range");
        return false;
    }
    return localCacheInfo_[slotId].isActive == ACTIVE ? true : false;
}

void MultiSimController::UpdateSubState(int32_t slotId, int32_t enable)
{
    if (TELEPHONY_EXT_WRAPPER.updateSubState_) {
        TELEPHONY_LOGI("TELEPHONY_EXT_WRAPPER UpdateSubState slotId: %{public}d enable: %{public}d", slotId, enable);
        TELEPHONY_EXT_WRAPPER.updateSubState_(slotId, enable);
    }
    isSetActiveSimInProgress_[slotId] = 0;
}

int32_t MultiSimController::SetActiveSim(int32_t slotId, int32_t enable, bool force)
{
    TELEPHONY_LOGI("enable = %{public}d slotId = %{public}d", enable, slotId);
    if (!IsValidData(slotId)) {
        TELEPHONY_LOGE("invalid slotid or sim card absent.");
        return TELEPHONY_ERR_NO_SIM_CARD;
    }
    int curSimId = 0;
    if (GetTargetSimId(slotId, curSimId) != TELEPHONY_ERR_SUCCESS) {
        TELEPHONY_LOGE("failed by out of range");
        return TELEPHONY_ERR_ARGUMENT_INVALID;
    }
    isSetActiveSimInProgress_[slotId] = 1;
    if (!SetActiveSimToRil(slotId, ENTITY_CARD, enable)) {
        CoreServiceHiSysEvent::WriteSetActiveSimFaultEvent(
            slotId, SimCardErrorCode::SET_ACTIVESIM_ERROR, "SetActiveSimToRil failure");
        TELEPHONY_LOGE("SetActiveSimToRil failed");
        isSetActiveSimInProgress_[slotId] = 0;
        return TELEPHONY_ERR_RIL_CMD_FAIL;
    }
    if (force) {
        TELEPHONY_LOGD("no need to update cache");
        UpdateSubState(slotId, enable);
        return TELEPHONY_ERR_SUCCESS;
    }
    if (simDbHelper_ == nullptr) {
        TELEPHONY_LOGE("failed by nullptr");
        isSetActiveSimInProgress_[slotId] = 0;
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    DataShare::DataShareValuesBucket values;
    DataShare::DataShareValueObject valueObj(enable);
    values.Put(SimData::IS_ACTIVE, valueObj);
    int32_t result = simDbHelper_->UpdateDataBySimId(curSimId, values);
    if (result == INVALID_VALUE) {
        TELEPHONY_LOGE("failed by database");
        isSetActiveSimInProgress_[slotId] = 0;
        return TELEPHONY_ERR_DATABASE_WRITE_FAIL;
    }
    std::unique_lock<std::mutex> lock(mutex_);
    if (static_cast<uint32_t>(slotId) >= localCacheInfo_.size()) {
        TELEPHONY_LOGE("failed by out of range");
        isSetActiveSimInProgress_[slotId] = 0;
        return TELEPHONY_ERR_ARGUMENT_INVALID;
    }
    localCacheInfo_[slotId].isActive = enable;
    lock.unlock();
    UpdateSubState(slotId, enable);
    CheckIfNeedSwitchMainSlotId();
    return TELEPHONY_ERR_SUCCESS;
}

void MultiSimController::CheckIfNeedSwitchMainSlotId()
{
    TELEPHONY_LOGD("start");
    bool satelliteStatusOn = CoreManagerInner::GetInstance().IsSatelliteEnabled();
    if (IsSatelliteSupported() == static_cast<int32_t>(SatelliteValue::SATELLITE_SUPPORTED) && satelliteStatusOn) {
        TELEPHONY_LOGI("CheckIfNeedSwitchMainSlotId satelliteStatusOn");
        return;
    }
    int32_t defaultSlotId = getDefaultMainSlotByIccId();
    if (IsSimActive(defaultSlotId)) {
        if (IsAllCardsReady() && defaultSlotId != lastPrimarySlotId_) {
            TELEPHONY_LOGI("defaultSlotId changed, need to set slot%{public}d primary", defaultSlotId);
            std::thread initDataTask([&, defaultSlotId = defaultSlotId]() {
                pthread_setname_np(pthread_self(), "SetPrimarySlotId");
                CoreManagerInner::GetInstance().SetPrimarySlotId(defaultSlotId);
            });
            initDataTask.detach();
        } else if (radioProtocolController_->GetRadioProtocolModemId(defaultSlotId) != MAIN_MODEM_ID) {
            TELEPHONY_LOGI("main slot is different with modemid, need to set slot%{public}d primary", defaultSlotId);
            std::thread initDataTask([&, defaultSlotId = defaultSlotId]() {
                pthread_setname_np(pthread_self(), "SetPrimarySlotId");
                CoreManagerInner::GetInstance().SetPrimarySlotId(defaultSlotId);
            });
            initDataTask.detach();
        } else {
            TELEPHONY_LOGI("no need set main slot, defaultslot same main slot");
            SavePrimarySlotIdInfo(defaultSlotId);
        }
    } else {
        int32_t firstActivedSlotId = GetFirstActivedSlotId();
        if (!IsValidSlotId(firstActivedSlotId)) {
            TELEPHONY_LOGE("active slotId is invalid");
            return;
        }
        TELEPHONY_LOGI("single card active, need to set slot%{public}d primary", firstActivedSlotId);
        std::thread initDataTask([&, firstActivedSlotId = firstActivedSlotId]() {
            pthread_setname_np(pthread_self(), "SetPrimarySlotId");
            CoreManagerInner::GetInstance().SetPrimarySlotId(firstActivedSlotId);
        });
        initDataTask.detach();
    }
}

int32_t MultiSimController::getDefaultMainSlotByIccId()
{
    if (SIM_SLOT_COUNT == std::atoi(DEFAULT_SLOT_COUNT)) {
        TELEPHONY_LOGI("default slotId is 0 for single card version");
        return DEFAULT_SIM_SLOT_ID;
    }
    int mainSlot = lastPrimarySlotId_;
    if (simFileManager_[SIM_SLOT_0] == nullptr || simFileManager_[SIM_SLOT_1] == nullptr) {
        TELEPHONY_LOGE("simFileManager_ is null");
        return mainSlot;
    }
    std::string iccIdSub1 = Str16ToStr8(simFileManager_[SIM_SLOT_0]->GetSimIccId());
    std::string iccIdSub2 = Str16ToStr8(simFileManager_[SIM_SLOT_1]->GetSimIccId());
    if (iccIdSub1.empty() || iccIdSub2.empty()) {
        TELEPHONY_LOGD("iccid is null");
        return mainSlot;
    }
    std::string encryptIccIdSub1 = EncryptIccId(iccIdSub1);
    std::string encryptIccIdSub2 = EncryptIccId(iccIdSub2);
    char lastMainCardIccId[SYSTEM_PARAMETER_LENGTH] = { 0 };
    GetParameter(MAIN_CARD_ICCID_KEY.c_str(), "", lastMainCardIccId, SYSTEM_PARAMETER_LENGTH);
    if (lastMainCardIccId == encryptIccIdSub1) {
        mainSlot = SIM_SLOT_0;
    } else if (lastMainCardIccId == encryptIccIdSub2) {
        mainSlot = SIM_SLOT_1;
    }
    TELEPHONY_LOGI("getDefaultMainSlotByIccId is %{public}d", mainSlot);
    return mainSlot;
}

bool MultiSimController::IsValidSlotId(int32_t slotId)
{
    return ((slotId >= DEFAULT_SIM_SLOT_ID) && (slotId < SIM_SLOT_COUNT));
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
    return radioProtocolController_->GetActiveSimToRilResult() == static_cast<int32_t>(ErrType::NONE);
}

int32_t MultiSimController::GetSimAccountInfo(int32_t slotId, bool denied, IccAccountInfo &info)
{
    if (!IsValidData(slotId)) {
        TELEPHONY_LOGE("MultiSimController::GetSimAccountInfo InValidData");
        return TELEPHONY_ERR_NO_SIM_CARD;
    }
    std::unique_lock<std::mutex> lock(mutex_);
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
    std::unique_lock<std::mutex> lock(mutex_);
    if (localCacheInfo_.size() <= 0) {
        TELEPHONY_LOGE("failed by nullptr");
        return INVALID_VALUE;
    }
    int32_t i = DEFAULT_SIM_SLOT_ID;
    for (; i < static_cast<int32_t>(localCacheInfo_.size()); i++) {
        if (localCacheInfo_[i].isVoiceCard == MAIN_CARD && localCacheInfo_[i].isActive == ACTIVE) {
            return i;
        }
    }
    return INVALID_VALUE;
}

size_t MultiSimController::GetLocalCacheSize()
{
    std::unique_lock<std::mutex> lock(mutex_);
    return localCacheInfo_.size();
}

int32_t MultiSimController::GetTargetSimId(int32_t slotId, int &simId)
{
    std::unique_lock<std::mutex> lock(mutex_);
    simId = 0;
    if (static_cast<uint32_t>(slotId) >= localCacheInfo_.size()) {
        return TELEPHONY_ERR_ARGUMENT_INVALID;
    }
    simId = localCacheInfo_[slotId].simId;
    return TELEPHONY_ERR_SUCCESS;
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
    int curSimId = 0;
    int32_t ret = GetTargetDefaultSimId(slotId, curSimId);
    if (ret != TELEPHONY_ERR_SUCCESS) {
        TELEPHONY_LOGE("ret is %{public}d", ret);
        return ret;
    }
    if (simDbHelper_ == nullptr) {
        TELEPHONY_LOGE("failed by nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    int32_t result = simDbHelper_->SetDefaultVoiceCard(curSimId);
    if (result == INVALID_VALUE) {
        TELEPHONY_LOGE("get Data Base failed");
        return TELEPHONY_ERR_DATABASE_WRITE_FAIL;
    }
    int32_t i = DEFAULT_SIM_SLOT_ID;
    std::unique_lock<std::mutex> lock(mutex_);
    if (localCacheInfo_.size() <= 0) {
        TELEPHONY_LOGE("failed by nullptr");
        return TELEPHONY_ERR_NO_SIM_CARD;
    }
    for (; i < static_cast<int32_t>(localCacheInfo_.size()); i++) { // save to cache
        if (slotId == i) {
            localCacheInfo_[i].isVoiceCard = MAIN_CARD;
            curSimId = localCacheInfo_[i].simId;
            continue;
        }
        localCacheInfo_[i].isVoiceCard = NOT_MAIN;
    }
    lock.unlock();
    if (curSimId == defaultVoiceSimId_) {
        TELEPHONY_LOGE("no need to AnnounceDefaultVoiceSimIdChanged");
        return TELEPHONY_ERR_SUCCESS;
    }
    defaultVoiceSimId_ = curSimId;
    if (!AnnounceDefaultVoiceSimIdChanged(defaultVoiceSimId_)) {
        return TELEPHONY_ERR_PUBLISH_BROADCAST_FAIL;
    }
    return TELEPHONY_ERR_SUCCESS;
}

int32_t MultiSimController::GetDefaultSmsSlotId()
{
    std::unique_lock<std::mutex> lock(mutex_);
    if (localCacheInfo_.size() <= 0) {
        TELEPHONY_LOGE("failed by nullptr");
        return INVALID_VALUE;
    }
    int32_t i = DEFAULT_SIM_SLOT_ID;
    for (; i < static_cast<int32_t>(localCacheInfo_.size()); i++) {
        if (localCacheInfo_[i].isMessageCard == MAIN_CARD && localCacheInfo_[i].isActive == ACTIVE) {
            return i;
        }
    }
    return GetFirstActivedSlotId();
}

int32_t MultiSimController::SetDefaultSmsSlotId(int32_t slotId)
{
    TELEPHONY_LOGD("slotId = %{public}d", slotId);
    int curSimId = 0;
    int32_t ret = GetTargetDefaultSimId(slotId, curSimId);
    if (ret != TELEPHONY_ERR_SUCCESS) {
        TELEPHONY_LOGE("ret is %{public}d", ret);
        return ret;
    }
    if (simDbHelper_ == nullptr) {
        TELEPHONY_LOGE("failed by nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    int32_t result = simDbHelper_->SetDefaultMessageCard(curSimId);
    if (result == INVALID_VALUE) {
        TELEPHONY_LOGE("get Data Base failed");
        return TELEPHONY_ERR_DATABASE_WRITE_FAIL;
    }
    int32_t i = DEFAULT_SIM_SLOT_ID;
    std::unique_lock<std::mutex> lock(mutex_);
    if (localCacheInfo_.size() <= 0) {
        TELEPHONY_LOGE("failed by nullptr");
        return TELEPHONY_ERR_NO_SIM_CARD;
    }
    for (; i < static_cast<int32_t>(localCacheInfo_.size()); i++) { // save to cache
        if (slotId == i) {
            localCacheInfo_[i].isMessageCard = MAIN_CARD;
            curSimId = localCacheInfo_[slotId].simId;
            continue;
        }
        localCacheInfo_[i].isMessageCard = NOT_MAIN;
    }
    lock.unlock();
    if (curSimId == defaultSmsSimId_) {
        TELEPHONY_LOGE("no need to AnnounceDefaultSmsSimIdChanged");
        return TELEPHONY_ERR_SUCCESS;
    }
    defaultSmsSimId_ = curSimId;
    if (!AnnounceDefaultSmsSimIdChanged(defaultSmsSimId_)) {
        return TELEPHONY_ERR_PUBLISH_BROADCAST_FAIL;
    }
    return TELEPHONY_ERR_SUCCESS;
}

int32_t MultiSimController::GetTargetDefaultSimId(int32_t slotId, int &simId)
{
    std::unique_lock<std::mutex> lock(mutex_);
    simId = 0;
    if ((slotId == DEFAULT_SIM_SLOT_ID_REMOVE && localCacheInfo_.empty()) ||
        (slotId != DEFAULT_SIM_SLOT_ID_REMOVE && !IsValidData(slotId))) {
        TELEPHONY_LOGE("no sim card");
        return TELEPHONY_ERR_NO_SIM_CARD;
    }
    if (slotId != DEFAULT_SIM_SLOT_ID_REMOVE && !IsSimActive(slotId)) {
        TELEPHONY_LOGE("slotId is not active!");
        return CORE_SERVICE_SIM_CARD_IS_NOT_ACTIVE;
    }
    if (slotId != DEFAULT_SIM_SLOT_ID_REMOVE) {
        simId = localCacheInfo_[slotId].simId;
    }
    return TELEPHONY_ERR_SUCCESS;
}

int32_t MultiSimController::GetDefaultCellularDataSlotId()
{
    TELEPHONY_LOGD("start lastCellularDataSlotId_ is %{public}d", lastCellularDataSlotId_);
    return lastCellularDataSlotId_;
}

int32_t MultiSimController::SetDefaultCellularDataSlotId(int32_t slotId)
{
    SaveDefaultCellularDataSlotIdInfo(slotId);
    CoreServiceHiSysEvent::WriteDefaultDataSlotIdBehaviorEvent(slotId);
    return TELEPHONY_ERR_SUCCESS;
}

int32_t MultiSimController::GetPrimarySlotId()
{
    TELEPHONY_LOGD("start lastPrimarySlotId_ is %{public}d", lastPrimarySlotId_);
    return lastPrimarySlotId_;
}

int32_t MultiSimController::SetPrimarySlotId(int32_t slotId)
{
    TELEPHONY_LOGD("slotId = %{public}d", slotId);
    if (TELEPHONY_EXT_WRAPPER.isHandleVSim_ && TELEPHONY_EXT_WRAPPER.isHandleVSim_()) {
        TELEPHONY_LOGE("in vsim handle, not allowed switch card");
        return TELEPHONY_ERR_FAIL;
    }

    if (!IsValidData(slotId)) {
        TELEPHONY_LOGE("no sim card");
        return TELEPHONY_ERR_NO_SIM_CARD;
    }
    if (radioProtocolController_->GetRadioProtocolModemId(slotId) == MAIN_MODEM_ID) {
        TELEPHONY_LOGI("The current slot is the main slot, no need to set primary slot");
        SavePrimarySlotIdInfo(slotId);
        return TELEPHONY_ERR_SUCCESS;
    }
    // change protocol for default cellulardata slotId
    isSetPrimarySlotIdInProgress_ = true;
    PublishSetPrimaryEvent(false);
    if (radioProtocolController_ == nullptr || !radioProtocolController_->SetRadioProtocol(slotId)) {
        TELEPHONY_LOGE("SetRadioProtocol failed");
        isSetPrimarySlotIdInProgress_ = false;
        PublishSetPrimaryEvent(true);
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    SavePrimarySlotIdInfo(slotId);
    isSetPrimarySlotIdInProgress_ = false;
    PublishSetPrimaryEvent(true);
    return TELEPHONY_ERR_SUCCESS;
}

void MultiSimController::PublishSetPrimaryEvent(bool setDone)
{
    AAFwk::Want want;
    want.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_SET_PRIMARY_SLOT_STATUS);
    want.SetParam(PARAM_SET_PRIMARY_STATUS, setDone);
    EventFwk::CommonEventData data;
    data.SetWant(want);

    EventFwk::CommonEventPublishInfo publishInfo;
    publishInfo.SetSticky(true);
    bool publishResult = EventFwk::CommonEventManager::PublishCommonEvent(data, publishInfo, nullptr);
    TELEPHONY_LOGI("result : %{public}d", publishResult);
}

void MultiSimController::SendMainCardBroadCast(int32_t slotId)
{
    std::unique_lock<std::mutex> lock(mutex_);
    if (localCacheInfo_.empty() || static_cast<uint32_t>(slotId) >= localCacheInfo_.size()) {
        TELEPHONY_LOGE("no need to update cache");
        return;
    }
    if (localCacheInfo_[slotId].simId == primarySimId_) {
        TELEPHONY_LOGE("no need to AnnouncePrimarySimIdChanged");
        return;
    }
    primarySimId_ = localCacheInfo_[slotId].simId;
    lock.unlock();
    TELEPHONY_LOGI("Announce main simId %{public}d", primarySimId_);
    AnnouncePrimarySimIdChanged(primarySimId_);
}

void MultiSimController::SendDefaultCellularDataBroadCast(int32_t slotId)
{
    if (localCacheInfo_.empty() || static_cast<uint32_t>(slotId) >= localCacheInfo_.size()) {
        TELEPHONY_LOGE("no need to update cache");
        return;
    }
    if (localCacheInfo_[slotId].simId == defaultCellularSimId_) {
        TELEPHONY_LOGE("no need to AnnouncePrimarySimIdChanged");
        return;
    }
    defaultCellularSimId_ = localCacheInfo_[slotId].simId;
    TELEPHONY_LOGI("Announce default cellular data simId %{public}d", defaultCellularSimId_);
    AnnounceDefaultCellularDataSimIdChanged(defaultCellularSimId_);
}

std::string MultiSimController::EncryptIccId(const std::string iccid)
{
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, iccid.c_str(), iccid.size());
    SHA256_Final(hash, &sha256);
    std::string encryptIccId = SIMUtils::BytesConvertToHexString(hash, SHA256_DIGEST_LENGTH);
    return encryptIccId;
}

void MultiSimController::SavePrimarySlotIdInfo(int32_t slotId)
{
    lastPrimarySlotId_ = slotId;
    SetParameter(PRIMARY_SLOTID_KEY.c_str(), std::to_string(slotId).c_str());
    if (simFileManager_[slotId] == nullptr) {
        TELEPHONY_LOGE("simFileManager_ is null slotId is %{public}d", slotId);
        return;
    }
    std::string iccId = Str16ToStr8(simFileManager_[slotId]->GetSimIccId());
    TELEPHONY_LOGI("save data is empty %{public}d", iccId.empty());
    if (!iccId.empty()) {
        std::string encryptIccId = EncryptIccId(iccId);
        SetParameter(MAIN_CARD_ICCID_KEY.c_str(), encryptIccId.c_str());
    }
    SendMainCardBroadCast(slotId);
    SetDefaultCellularDataSlotId(slotId);
}

void MultiSimController::SaveDefaultCellularDataSlotIdInfo(int32_t slotId)
{
    SetParameter(MAIN_CELLULAR_DATA_SLOTID_KEY.c_str(), std::to_string(slotId).c_str());
    lastCellularDataSlotId_ = slotId;
    SendDefaultCellularDataBroadCast(slotId);
}

void MultiSimController::InitMainCardSlotId()
{
    char lastPrimarySlotId[SYSTEM_PARAMETER_LENGTH] = { 0 };
    GetParameter(PRIMARY_SLOTID_KEY.c_str(), PRIMARY_SLOTID.c_str(), lastPrimarySlotId, SYSTEM_PARAMETER_LENGTH);
    lastPrimarySlotId_ = std::atoi(lastPrimarySlotId);

    char lastCellularDataSlotId[SYSTEM_PARAMETER_LENGTH] = { 0 };
    GetParameter(
        MAIN_CELLULAR_DATA_SLOTID_KEY.c_str(), PRIMARY_SLOTID.c_str(), lastCellularDataSlotId, SYSTEM_PARAMETER_LENGTH);
    lastCellularDataSlotId_ = std::atoi(lastCellularDataSlotId);
}

int32_t MultiSimController::GetShowNumber(int32_t slotId, std::u16string &showNumber)
{
    if (!IsValidData(slotId)) {
        TELEPHONY_LOGE("InValidData");
        return TELEPHONY_ERR_NO_SIM_CARD;
    }
    if (simFileManager_[slotId] == nullptr) {
        TELEPHONY_LOGE("can not get simFileManager");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    showNumber = simFileManager_[slotId]->GetSimTelephoneNumber();
    if (!showNumber.empty()) {
        TELEPHONY_LOGI("get phone number from sim");
        return TELEPHONY_ERR_SUCCESS;
    }
    int curSimId;
    if (GetTargetSimId(slotId, curSimId) != TELEPHONY_ERR_SUCCESS) {
        TELEPHONY_LOGE("failed by out of range");
        return TELEPHONY_ERR_ARGUMENT_INVALID;
    }
    showNumber = Str8ToStr16(localCacheInfo_[slotId].phoneNumber);
    if (!showNumber.empty()) {
        return TELEPHONY_ERR_SUCCESS;
    }
    return GetSimTelephoneNumber(slotId, showNumber);
}

int32_t MultiSimController::SetShowNumber(int32_t slotId, std::u16string number, bool force)
{
    TELEPHONY_LOGI("MultiSimController::SetShowNumber slotId = %{public}d", slotId);
    if (!force && !IsValidData(slotId)) {
        TELEPHONY_LOGE("MultiSimController::SetShowNumber InValidData");
        return TELEPHONY_ERR_NO_SIM_CARD;
    }
    if (simFileManager_[slotId] == nullptr) {
        TELEPHONY_LOGE("can not get simFileManager");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    std::u16string alphaTag = simFileManager_[slotId]->GetSimTeleNumberIdentifier();
    if (!simFileManager_[slotId]->SetSimTelephoneNumber(alphaTag, number)) {
        return TELEPHONY_ERR_FAIL;
    }
    return SetShowNumberToDB(slotId, number);
}

int32_t MultiSimController::SetShowNumberToDB(int32_t slotId, std::u16string number)
{
    if (static_cast<uint32_t>(slotId) >= localCacheInfo_.size()) {
        TELEPHONY_LOGE("failed by nullptr");
        return false;
    }
    int curSimId;
    if (GetTargetSimId(slotId, curSimId) != TELEPHONY_ERR_SUCCESS) {
        TELEPHONY_LOGE("MultiSimController::SetShowNumber failed by out of range");
        return TELEPHONY_ERR_ARGUMENT_INVALID;
    }
    if (simDbHelper_ == nullptr) {
        TELEPHONY_LOGE("MultiSimController::SetShowNumber failed by nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    DataShare::DataShareValuesBucket values;
    DataShare::DataShareValueObject valueObj(Str16ToStr8(number));
    values.Put(SimData::PHONE_NUMBER, valueObj);
    int32_t result = simDbHelper_->UpdateDataBySimId(curSimId, values);
    if (result == INVALID_VALUE) {
        TELEPHONY_LOGE("MultiSimController::SetShowNumber set Data Base failed");
        return TELEPHONY_ERR_DATABASE_WRITE_FAIL;
    }
    std::unique_lock<std::mutex> lock(mutex_);
    if ((static_cast<uint32_t>(slotId) >= localCacheInfo_.size())) {
        TELEPHONY_LOGE("localCacheInfo_ is empty");
        return TELEPHONY_ERR_NO_SIM_CARD;
    }
    localCacheInfo_[slotId].phoneNumber = Str16ToStr8(number); // save to cache
    return TELEPHONY_ERR_SUCCESS;
}

int32_t MultiSimController::GetShowName(int32_t slotId, std::u16string &showName)
{
    if (!IsValidData(slotId)) {
        TELEPHONY_LOGE("InValidData");
        return TELEPHONY_ERR_NO_SIM_CARD;
    }
    std::unique_lock<std::mutex> lock(mutex_);
    if (static_cast<uint32_t>(slotId) >= localCacheInfo_.size()) {
        TELEPHONY_LOGE("failed by nullptr");
        return TELEPHONY_ERR_ARGUMENT_INVALID;
    }
    showName = Str8ToStr16(localCacheInfo_[slotId].showName);
    lock.unlock();
    TELEPHONY_LOGD("Get the SIM name set by the user");
    return TELEPHONY_ERR_SUCCESS;
}

int32_t MultiSimController::SetShowName(int32_t slotId, std::u16string name, bool force)
{
    if (!force && !IsValidData(slotId)) {
        TELEPHONY_LOGE("MultiSimController::SetShowNumber InValidData");
        return TELEPHONY_ERR_NO_SIM_CARD;
    }
    int curSimId;
    if (GetTargetSimId(slotId, curSimId) != TELEPHONY_ERR_SUCCESS) {
        TELEPHONY_LOGE("MultiSimController::SetShowName failed by out of range");
        return TELEPHONY_ERR_ARGUMENT_INVALID;
    }
    if (simDbHelper_ == nullptr) {
        TELEPHONY_LOGE("MultiSimController::SetShowName get Data Base failed");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    DataShare::DataShareValuesBucket values;
    DataShare::DataShareValueObject valueObj(Str16ToStr8(name));
    values.Put(SimData::SHOW_NAME, valueObj);
    int32_t result = simDbHelper_->UpdateDataBySimId(curSimId, values);
    if (result == INVALID_VALUE) {
        TELEPHONY_LOGE("MultiSimController::SetShowName set Data Base failed");
        return TELEPHONY_ERR_DATABASE_WRITE_FAIL;
    }
    std::unique_lock<std::mutex> lock(mutex_);
    if ((static_cast<uint32_t>(slotId) >= localCacheInfo_.size())) {
        TELEPHONY_LOGE("failed by out of range");
        return TELEPHONY_ERR_ARGUMENT_INVALID;
    }
    localCacheInfo_[slotId].showName = Str16ToStr8(name); // save to cache
    return TELEPHONY_ERR_SUCCESS;
}

int32_t MultiSimController::GetSimTelephoneNumber(int32_t slotId, std::u16string &telephoneNumber)
{
    if (!IsValidData(slotId)) {
        TELEPHONY_LOGE("InValidData");
        return TELEPHONY_ERR_NO_SIM_CARD;
    }
    std::shared_ptr<ImsCoreServiceClient> imsCoreServiceClient = DelayedSingleton<ImsCoreServiceClient>::GetInstance();
    if (imsCoreServiceClient == nullptr) {
        TELEPHONY_LOGE("can not get imsCoreServiceClient");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    std::string result = "";
    imsCoreServiceClient->GetPhoneNumberFromIMPU(slotId, result);
    telephoneNumber = Str8ToStr16(result);
    TELEPHONY_LOGI("impu result is empty:%{public}s, slotId:%{public}d", (telephoneNumber.empty() ? "true" : "false"),
        slotId);
    return TELEPHONY_ERR_SUCCESS;
}

int32_t MultiSimController::GetTargetIccId(int32_t slotId, std::string &iccId)
{
    std::unique_lock<std::mutex> lock(mutex_);
    iccId = "";
    if (static_cast<uint32_t>(slotId) >= localCacheInfo_.size()) {
        TELEPHONY_LOGE("failed by out of range");
        return TELEPHONY_ERROR;
    }
    iccId = localCacheInfo_[slotId].iccId;
    return TELEPHONY_ERR_SUCCESS;
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

bool MultiSimController::AnnouncePrimarySimIdChanged(int32_t simId)
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
    publishInfo.SetOrdered(false);
    bool publishResult = EventFwk::CommonEventManager::PublishCommonEvent(data, publishInfo, nullptr);
    TELEPHONY_LOGD("MultiSimController::PublishSimFileEvent end###publishResult = %{public}d", publishResult);
    return publishResult;
}

int32_t MultiSimController::SaveImsSwitch(int32_t slotId, int32_t imsSwitchValue)
{
    std::string curIccid = "";
    if (GetTargetIccId(slotId, curIccid) != TELEPHONY_SUCCESS || simDbHelper_ == nullptr) {
        TELEPHONY_LOGE("failed by out of range or simDbHelper is nullptr");
        imsSwitchValue = IMS_SWITCH_VALUE_UNKNOWN;
        return TELEPHONY_ERROR;
    }
    DataShare::DataShareValuesBucket values;
    DataShare::DataShareValueObject valueObj(imsSwitchValue);
    values.Put(SimData::IMS_SWITCH, valueObj);
    return simDbHelper_->UpdateDataByIccId(curIccid, values);
}

int32_t MultiSimController::QueryImsSwitch(int32_t slotId, int32_t &imsSwitchValue)
{
    std::string curIccid = "";
    if (GetTargetIccId(slotId, curIccid) != TELEPHONY_SUCCESS || simDbHelper_ == nullptr) {
        TELEPHONY_LOGE("failed by out of range or simDbHelper is nullptr");
        imsSwitchValue = IMS_SWITCH_VALUE_UNKNOWN;
        return TELEPHONY_ERROR;
    }
    SimRdbInfo simRdbInfo;
    simRdbInfo.imsSwitch = IMS_SWITCH_STATUS_UNKNOWN;
    simDbHelper_->QueryDataByIccId(curIccid, simRdbInfo);
    imsSwitchValue = simRdbInfo.imsSwitch;
    return TELEPHONY_SUCCESS;
}

int32_t MultiSimController::GetActiveSimAccountInfoList(bool denied, std::vector<IccAccountInfo> &iccAccountInfoList)
{
    if (!RefreshActiveIccAccountInfoList()) {
        TELEPHONY_LOGE("refresh failed");
        return TELEPHONY_ERR_NO_SIM_CARD;
    }
    iccAccountInfoList.clear();
    std::unique_lock<std::mutex> lock(mutex_);
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
int32_t MultiSimController::IsSatelliteSupported()
{
    char satelliteSupported[SYSPARA_SIZE] = { 0 };
    GetParameter(TEL_SATELLITE_SUPPORTED, SATELLITE_DEFAULT_VALUE, satelliteSupported, SYSPARA_SIZE);
    TELEPHONY_LOGI("satelliteSupported is %{public}s", satelliteSupported);
    return std::atoi(satelliteSupported);
}

bool MultiSimController::IsSetActiveSimInProgress(int32_t slotId)
{
    if (static_cast<uint32_t>(slotId) >= isSetActiveSimInProgress_.size()) {
        TELEPHONY_LOGE("IsSetActiveSimInProgress invalid slotId: %{public}d", slotId);
        return false;
    }
    TELEPHONY_LOGD("isSetActiveSimInProgress_ %{public}d, is %{public}d", slotId, isSetActiveSimInProgress_[slotId]);
    return static_cast<bool>(isSetActiveSimInProgress_[slotId]);
}

bool MultiSimController::IsSetPrimarySlotIdInProgress()
{
    TELEPHONY_LOGD("isSetPrimarySlotIdInProgress_ is %{public}d", isSetPrimarySlotIdInProgress_);
    return isSetPrimarySlotIdInProgress_;
}

int32_t MultiSimController::SavePrimarySlotId(int32_t slotId)
{
    if (!IsValidSlotId(slotId)) {
        TELEPHONY_LOGE("SavePrimarySlotId invalid slotId: %{public}d", slotId);
        return TELEPHONY_ERR_ARGUMENT_INVALID;
    }

    TELEPHONY_LOGI("SavePrimarySlotId: %{public}d", slotId);
    SavePrimarySlotIdInfo(slotId);
    return TELEPHONY_ERR_SUCCESS;
}

} // namespace Telephony
} // namespace OHOS
