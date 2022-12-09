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

#include "sim_rdb_helper.h"

#include "telephony_errors.h"
#include "telephony_types.h"

namespace OHOS {
namespace Telephony {
SimRdbHelper::SimRdbHelper()
{
    helper_ = CreateDataAHelper();
}

SimRdbHelper::~SimRdbHelper() {}

std::shared_ptr<AppExecFwk::DataAbilityHelper> SimRdbHelper::CreateDataAHelper()
{
    TELEPHONY_LOGI("SimRdbHelper::CreateDataAHelper");
    auto saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (saManager == nullptr) {
        TELEPHONY_LOGE("SimRdbHelper Get system ability mgr failed.");
        return nullptr;
    }
    auto remoteObj = saManager->GetSystemAbility(TELEPHONY_CORE_SERVICE_SYS_ABILITY_ID);
    if (remoteObj == nullptr) {
        TELEPHONY_LOGE("SimRdbHelper GetSystemAbility Service Failed.");
        return nullptr;
    }
    return AppExecFwk::DataAbilityHelper::Creator(remoteObj);
}

int SimRdbHelper::Insert(const NativeRdb::ValuesBucket &values)
{
    if (helper_ == nullptr) {
        TELEPHONY_LOGE("SimRdbHelper::Insert failed by nullptr");
        return INVALID_VALUE;
    }
    Uri simUri(SimRdbInfo::SIM_RDB_URI);
    TELEPHONY_LOGI("SimRdbHelper::Insert");
    return helper_->Insert(simUri, values);
}

std::shared_ptr<NativeRdb::AbsSharedResultSet> SimRdbHelper::Query(
    std::vector<std::string> &columns, const NativeRdb::DataAbilityPredicates &predicates)
{
    if (helper_ == nullptr) {
        TELEPHONY_LOGE("SimRdbHelper::Query failed by nullptr");
        return nullptr;
    }
    Uri simUri(SimRdbInfo::SIM_RDB_URI);
    TELEPHONY_LOGI("SimRdbHelper::Query");
    std::shared_ptr<NativeRdb::AbsSharedResultSet> ret = helper_->Query(simUri, columns, predicates);
    return ret;
}

int SimRdbHelper::Update(const NativeRdb::ValuesBucket &value, const NativeRdb::DataAbilityPredicates &predicates)
{
    if (helper_ == nullptr) {
        TELEPHONY_LOGE("SimRdbHelper::Update failed by nullptr");
        return INVALID_VALUE;
    }
    Uri simUri(SimRdbInfo::SIM_RDB_URI);
    TELEPHONY_LOGI("SimRdbHelper::Update");
    return helper_->Update(simUri, value, predicates);
}

int SimRdbHelper::Delete(const NativeRdb::DataAbilityPredicates &predicates)
{
    if (helper_ == nullptr) {
        TELEPHONY_LOGE("SimRdbHelper::Delete failed by nullptr");
        return INVALID_VALUE;
    }
    Uri simUri(SimRdbInfo::SIM_RDB_URI);
    TELEPHONY_LOGI("SimRdbHelper::Delete");
    return helper_->Delete(simUri, predicates);
}

int32_t SimRdbHelper::GetDefaultMainCardSlotId()
{
    TELEPHONY_LOGI("SimRdbHelper::GetDefaultMainCardSlotId");
    int32_t mainCardSlotId = 0;
    std::vector<std::string> colume;
    NativeRdb::DataAbilityPredicates predicates;
    predicates.EqualTo(SimRdbInfo::IS_MAIN_CARD, std::to_string(static_cast<int32_t>(MAIN_CARD)));
    std::shared_ptr<NativeRdb::AbsSharedResultSet> result = Query(colume, predicates);
    if (result == nullptr) {
        TELEPHONY_LOGE("SimRdbHelper::get nothing");
        return mainCardSlotId;
    }
    int resultSetNum = result->GoToFirstRow();
    if (resultSetNum != 0) {
        TELEPHONY_LOGI("SimRdbHelper::GetDefaultMainCardSlotId not found main card");
        return mainCardSlotId;
    }
    int index = 0;
    result->GetColumnIndex(SimRdbInfo::SLOT_INDEX, index);
    result->GetInt(index, mainCardSlotId);
    result->Close();
    return mainCardSlotId;
}

int32_t SimRdbHelper::GetDefaultMessageCardSlotId()
{
    TELEPHONY_LOGI("SimRdbHelper::GetDefaultMessageCardSlotId");
    int32_t messageCardSlotId = 0;
    std::vector<std::string> colume;
    NativeRdb::DataAbilityPredicates predicates;
    predicates.EqualTo(SimRdbInfo::IS_MESSAGE_CARD, std::to_string(static_cast<int32_t>(MAIN_CARD)));
    std::shared_ptr<NativeRdb::AbsSharedResultSet> result = Query(colume, predicates);
    if (result == nullptr) {
        TELEPHONY_LOGE("SimRdbHelper::get nothing");
        return messageCardSlotId;
    }
    int resultSetNum = result->GoToFirstRow();
    if (resultSetNum != 0) {
        TELEPHONY_LOGI("SimRdbHelper::GetDefaultMessageCardSlotId not found default sms card");
        return cellularDataCardSlotId;
    }
    int index = 0;
    result->GetColumnIndex(SimRdbInfo::SLOT_INDEX, index);
    result->GetInt(index, messageCardSlotId);
    result->Close();
    return messageCardSlotId;
}

int32_t SimRdbHelper::GetDefaultCellularDataCardSlotId()
{
    TELEPHONY_LOGI("SimRdbHelper::GetDefaultCellularDataCardSlotId");
    int32_t cellularDataCardSlotId = 0;
    std::vector<std::string> colume;
    NativeRdb::DataAbilityPredicates predicates;
    predicates.EqualTo(SimRdbInfo::IS_CELLULAR_DATA_CARD, std::to_string(static_cast<int32_t>(MAIN_CARD)));
    std::shared_ptr<NativeRdb::AbsSharedResultSet> result = Query(colume, predicates);
    if (result == nullptr) {
        TELEPHONY_LOGE("SimRdbHelper::get nothing");
        return cellularDataCardSlotId;
    }
    int resultSetNum = result->GoToFirstRow();
    if (resultSetNum != 0) {
        TELEPHONY_LOGI("SimRdbHelper::GetDefaultCellularDataCardSlotId not found default data card");
        return cellularDataCardSlotId;
    }
    int index = 0;
    result->GetColumnIndex(SimRdbInfo::SLOT_INDEX, index);
    result->GetInt(index, cellularDataCardSlotId);
    result->Close();
    return cellularDataCardSlotId;
}

int32_t SimRdbHelper::GetDefaultVoiceCardSlotId()
{
    TELEPHONY_LOGI("SimRdbHelper::GetDefaultVoiceCardSlotId");
    int32_t voiceCardSlotId = 0;
    std::vector<std::string> colume;
    NativeRdb::DataAbilityPredicates predicates;
    predicates.EqualTo(SimRdbInfo::IS_VOICE_CARD, std::to_string(static_cast<int32_t>(MAIN_CARD)));
    std::shared_ptr<NativeRdb::AbsSharedResultSet> result = Query(colume, predicates);
    if (result == nullptr) {
        TELEPHONY_LOGE("SimRdbHelper::get nothing");
        return voiceCardSlotId;
    }
    int resultSetNum = result->GoToFirstRow();
    if (resultSetNum != 0) {
        TELEPHONY_LOGI("SimRdbHelper::GetDefaultVoiceCardSlotId not found default voice card");
        return voiceCardSlotId;
    }
    int index = 0;
    result->GetColumnIndex(SimRdbInfo::SLOT_INDEX, index);
    result->GetInt(index, voiceCardSlotId);
    result->Close();
    return voiceCardSlotId;
}

int32_t SimRdbHelper::SetDefaultMainCard(int32_t slotId)
{
    TELEPHONY_LOGI("SimRdbHelper::SetDefaultMainCard = %{public}d", slotId);
    NativeRdb::DataAbilityPredicates predicates;
    NativeRdb::ValuesBucket value;
    value.PutInt(SimRdbInfo::SLOT_INDEX, slotId);
    value.PutInt(SimRdbInfo::CARD_TYPE, static_cast<int>(DefaultCardType::MAIN));
    if (helper_ == nullptr) {
        TELEPHONY_LOGE("SimRdbHelper::SetDefaultMainCard failed by nullptr");
        return INVALID_VALUE;
    }
    Uri defaultUri(SimRdbInfo::SIM_RDB_DEFAULT_SET_URI);
    return helper_->Update(defaultUri, value, predicates);
}

int32_t SimRdbHelper::SetDefaultVoiceCard(int32_t slotId)
{
    TELEPHONY_LOGI("SimRdbHelper::SetDefaultVoiceCard = %{public}d", slotId);
    NativeRdb::DataAbilityPredicates predicates;
    NativeRdb::ValuesBucket value;
    value.PutInt(SimRdbInfo::SLOT_INDEX, slotId);
    value.PutInt(SimRdbInfo::CARD_TYPE, static_cast<int>(DefaultCardType::VOICE));
    if (helper_ == nullptr) {
        TELEPHONY_LOGE("SimRdbHelper::SetDefaultVoiceCard failed by nullptr");
        return INVALID_VALUE;
    }
    Uri defaultUri(SimRdbInfo::SIM_RDB_DEFAULT_SET_URI);
    return helper_->Update(defaultUri, value, predicates);
}

int32_t SimRdbHelper::SetDefaultMessageCard(int32_t slotId)
{
    TELEPHONY_LOGI("SimRdbHelper::SetDefaultMessageCard = %{public}d", slotId);
    NativeRdb::DataAbilityPredicates predicates;
    NativeRdb::ValuesBucket value;
    value.PutInt(SimRdbInfo::SLOT_INDEX, slotId);
    value.PutInt(SimRdbInfo::CARD_TYPE, static_cast<int>(DefaultCardType::SMS));
    if (helper_ == nullptr) {
        TELEPHONY_LOGE("SimRdbHelper::SetDefaultMessageCard failed by nullptr");
        return INVALID_VALUE;
    }
    Uri defaultUri(SimRdbInfo::SIM_RDB_DEFAULT_SET_URI);
    return helper_->Update(defaultUri, value, predicates);
}

int32_t SimRdbHelper::SetDefaultCellularData(int32_t slotId)
{
    TELEPHONY_LOGI("SimRdbHelper::SetDefaultCellularData = %{public}d", slotId);
    NativeRdb::DataAbilityPredicates predicates;
    NativeRdb::ValuesBucket value;
    value.PutInt(SimRdbInfo::SLOT_INDEX, slotId);
    value.PutInt(SimRdbInfo::CARD_TYPE, static_cast<int>(DefaultCardType::DATA));
    if (helper_ == nullptr) {
        TELEPHONY_LOGE("SimRdbHelper::SetDefaultCellularData failed by nullptr");
        return INVALID_VALUE;
    }
    Uri defaultUri(SimRdbInfo::SIM_RDB_DEFAULT_SET_URI);
    return helper_->Update(defaultUri, value, predicates);
}

int32_t SimRdbHelper::InsertData(int64_t &id, const NativeRdb::ValuesBucket &values)
{
    TELEPHONY_LOGI("SimRdbHelper::InsertData");
    return Insert(values);
}

void SimRdbHelper::SaveDataToBean(std::shared_ptr<NativeRdb::AbsSharedResultSet> result, SimRdbInfo &simBean)
{
    TELEPHONY_LOGI("SimRdbHelper::SaveDataToBean");
    int index = 0;
    result->GetColumnIndex(SimRdbInfo::SIM_ID, index);
    result->GetInt(index, simBean.simId);
    result->GetColumnIndex(SimRdbInfo::ICC_ID, index);
    result->GetString(index, simBean.iccId);
    result->GetColumnIndex(SimRdbInfo::CARD_ID, index);
    result->GetString(index, simBean.cardId);
    result->GetColumnIndex(SimRdbInfo::IMS_SWITCH, index);
    result->GetInt(index, simBean.imsSwitch);
    result->GetColumnIndex(SimRdbInfo::SLOT_INDEX, index);
    result->GetInt(index, simBean.slotIndex);
    result->GetColumnIndex(SimRdbInfo::CARD_TYPE, index);
    result->GetInt(index, simBean.cardType);
    result->GetColumnIndex(SimRdbInfo::SHOW_NAME, index);
    result->GetString(index, simBean.showName);
    result->GetColumnIndex(SimRdbInfo::PHONE_NUMBER, index);
    result->GetString(index, simBean.phoneNumber);
    result->GetColumnIndex(SimRdbInfo::COUNTRY_CODE, index);
    result->GetString(index, simBean.countryCode);
    result->GetColumnIndex(SimRdbInfo::LANGUAGE, index);
    result->GetString(index, simBean.language);
    result->GetColumnIndex(SimRdbInfo::IMSI, index);
    result->GetString(index, simBean.imsi);
    result->GetColumnIndex(SimRdbInfo::IS_MAIN_CARD, index);
    result->GetInt(index, simBean.isMainCard);
    result->GetColumnIndex(SimRdbInfo::IS_VOICE_CARD, index);
    result->GetInt(index, simBean.isVoiceCard);
    result->GetColumnIndex(SimRdbInfo::IS_MESSAGE_CARD, index);
    result->GetInt(index, simBean.isMessageCard);
    result->GetColumnIndex(SimRdbInfo::IS_CELLULAR_DATA_CARD, index);
    result->GetInt(index, simBean.isCellularDataCard);
    result->GetColumnIndex(SimRdbInfo::IS_ACTIVE, index);
    result->GetInt(index, simBean.isActive);
}

int32_t SimRdbHelper::QueryDataBySlotId(int32_t slotId, SimRdbInfo &simBean)
{
    TELEPHONY_LOGI("SimRdbHelper::QueryDataBySlotId = %{public}d", slotId);
    std::string slot = std::to_string(slotId);
    std::vector<std::string> colume;
    NativeRdb::DataAbilityPredicates predicates;
    predicates.EqualTo(SimRdbInfo::SLOT_INDEX, slot);
    std::shared_ptr<NativeRdb::AbsSharedResultSet> result = Query(colume, predicates);
    if (result == nullptr) {
        TELEPHONY_LOGE("SimRdbHelper::QueryDataBySlotId get nothing");
        return INVALID_VALUE;
    }
    int resultSetNum = result->GoToFirstRow();
    while (resultSetNum == 0) {
        SaveDataToBean(result, simBean);
        resultSetNum = result->GoToNextRow();
    }
    result->Close();
    return TELEPHONY_SUCCESS;
}

int32_t SimRdbHelper::QueryDataByIccId(std::string iccId, SimRdbInfo &simBean)
{
    TELEPHONY_LOGI("SimRdbHelper::QueryDataByIccId");
    std::vector<std::string> colume;
    NativeRdb::DataAbilityPredicates predicates;
    predicates.EqualTo(SimRdbInfo::ICC_ID, iccId);
    std::shared_ptr<NativeRdb::AbsSharedResultSet> result = Query(colume, predicates);
    if (result == nullptr) {
        TELEPHONY_LOGE("SimRdbHelper::QueryDataByIccId get nothing");
        return INVALID_VALUE;
    }
    int resultSetNum = result->GoToFirstRow();
    while (resultSetNum == 0) {
        SaveDataToBean(result, simBean);
        resultSetNum = result->GoToNextRow();
    }
    result->Close();
    return TELEPHONY_SUCCESS;
}

int32_t SimRdbHelper::QueryAllData(std::vector<SimRdbInfo> &vec)
{
    TELEPHONY_LOGI("SimRdbHelper::QueryAllData");
    std::vector<std::string> colume;
    NativeRdb::DataAbilityPredicates predicates;
    std::shared_ptr<NativeRdb::AbsSharedResultSet> result = Query(colume, predicates);
    if (result == nullptr) {
        TELEPHONY_LOGE("SimRdbHelper::QueryAllData get nothing");
        return INVALID_VALUE;
    }
    int resultSetNum = result->GoToFirstRow();
    while (resultSetNum == 0) {
        SimRdbInfo simBean;
        SaveDataToBean(result, simBean);
        vec.push_back(simBean);
        resultSetNum = result->GoToNextRow();
    }
    result->Close();
    return TELEPHONY_SUCCESS;
}

int32_t SimRdbHelper::QueryAllValidData(std::vector<SimRdbInfo> &vec)
{
    TELEPHONY_LOGI("SimRdbHelper::QueryAllValidData");
    std::vector<std::string> colume;
    std::string id = std::to_string(INVALID_VALUE);
    NativeRdb::DataAbilityPredicates predicates;
    predicates.GreaterThan(SimRdbInfo::SLOT_INDEX, id);
    std::shared_ptr<NativeRdb::AbsSharedResultSet> result = Query(colume, predicates);
    if (result == nullptr) {
        TELEPHONY_LOGE("SimRdbHelper::QueryAllValidData get nothing");
        return INVALID_VALUE;
    }
    int resultSetNum = result->GoToFirstRow();
    while (resultSetNum == 0) {
        SimRdbInfo simBean;
        SaveDataToBean(result, simBean);
        vec.push_back(simBean);
        resultSetNum = result->GoToNextRow();
    }
    result->Close();
    return TELEPHONY_SUCCESS;
}

int32_t SimRdbHelper::UpdateDataBySlotId(int32_t slotId, const NativeRdb::ValuesBucket &values)
{
    TELEPHONY_LOGI("SimRdbHelper::UpdateDataBySlotId = %{public}d", slotId);
    std::string slot = std::to_string(slotId);
    NativeRdb::DataAbilityPredicates predicates;
    predicates.EqualTo(SimRdbInfo::SLOT_INDEX, slot);
    return Update(values, predicates);
}

int32_t SimRdbHelper::UpdateDataByIccId(std::string iccId, const NativeRdb::ValuesBucket &values)
{
    TELEPHONY_LOGI("SimRdbHelper::UpdateDataByIccId");
    NativeRdb::DataAbilityPredicates predicates;
    predicates.EqualTo(SimRdbInfo::ICC_ID, iccId);
    return Update(values, predicates);
}

int32_t SimRdbHelper::ForgetAllData()
{
    TELEPHONY_LOGI("SimRdbHelper::ForgetAllData");
    NativeRdb::DataAbilityPredicates predicates;
    NativeRdb::ValuesBucket values;
    values.PutInt(SimRdbInfo::SLOT_INDEX, INVALID_VALUE);
    return Update(values, predicates);
}

int32_t SimRdbHelper::ForgetAllData(int32_t slotId)
{
    TELEPHONY_LOGI("SimRdbHelper::ForgetAllData slotId = %{public}d", slotId);
    NativeRdb::DataAbilityPredicates predicates;
    predicates.EqualTo(SimRdbInfo::SLOT_INDEX, std::to_string(slotId));
    NativeRdb::ValuesBucket values;
    values.PutInt(SimRdbInfo::SLOT_INDEX, INVALID_VALUE);
    return Update(values, predicates);
}

int32_t SimRdbHelper::ClearData()
{
    std::string id = std::to_string(INVALID_VALUE);
    NativeRdb::DataAbilityPredicates predicates;
    predicates.GreaterThan(SimRdbInfo::SIM_ID, id);
    return Delete(predicates);
}
} // namespace Telephony
} // namespace OHOS
