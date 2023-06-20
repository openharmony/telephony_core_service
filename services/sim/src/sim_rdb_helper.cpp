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

#include "sim_data.h"
#include "telephony_errors.h"
#include "telephony_types.h"

namespace OHOS {
namespace Telephony {
SimRdbHelper::SimRdbHelper() {}

SimRdbHelper::~SimRdbHelper() {}

std::shared_ptr<DataShare::DataShareHelper> SimRdbHelper::CreateDataHelper()
{
    TELEPHONY_LOGD("start");
    auto saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (saManager == nullptr) {
        TELEPHONY_LOGE("Get system ability mgr failed.");
        return nullptr;
    }
    auto remoteObj = saManager->GetSystemAbility(TELEPHONY_CORE_SERVICE_SYS_ABILITY_ID);
    if (remoteObj == nullptr) {
        TELEPHONY_LOGE("GetSystemAbility Service Failed.");
        return nullptr;
    }
    return DataShare::DataShareHelper::Creator(remoteObj, SIM_URI);
}

int SimRdbHelper::Insert(
    std::shared_ptr<DataShare::DataShareHelper> dataShareHelper, const DataShare::DataShareValuesBucket &values)
{
    if (dataShareHelper == nullptr) {
        TELEPHONY_LOGE("failed by nullptr");
        return INVALID_VALUE;
    }
    Uri simUri(SimRdbInfo::SIM_RDB_SELECTION);
    TELEPHONY_LOGD("SimRdbHelper::Insert");
    return dataShareHelper->Insert(simUri, values);
}

std::shared_ptr<DataShare::DataShareResultSet> SimRdbHelper::Query(
    std::shared_ptr<DataShare::DataShareHelper> dataShareHelper, std::vector<std::string> &columns,
    const DataShare::DataSharePredicates &predicates)
{
    if (dataShareHelper == nullptr) {
        TELEPHONY_LOGE("failed by nullptr");
        return nullptr;
    }
    Uri simUri(SimRdbInfo::SIM_RDB_SELECTION);
    return dataShareHelper->Query(simUri, predicates, columns);
}

int SimRdbHelper::Update(std::shared_ptr<DataShare::DataShareHelper> dataShareHelper,
    const DataShare::DataShareValuesBucket &value, const DataShare::DataSharePredicates &predicates)
{
    if (dataShareHelper == nullptr) {
        TELEPHONY_LOGE("failed by nullptr");
        return INVALID_VALUE;
    }
    Uri simUri(SimRdbInfo::SIM_RDB_SELECTION);
    TELEPHONY_LOGD("SimRdbHelper::Update");
    return dataShareHelper->Update(simUri, predicates, value);
}

int SimRdbHelper::Delete(
    std::shared_ptr<DataShare::DataShareHelper> dataShareHelper, const DataShare::DataSharePredicates &predicates)
{
    if (dataShareHelper == nullptr) {
        TELEPHONY_LOGE("failed by nullptr");
        return INVALID_VALUE;
    }
    Uri simUri(SimRdbInfo::SIM_RDB_SELECTION);
    TELEPHONY_LOGD("SimRdbHelper::Delete");
    return dataShareHelper->Delete(simUri, predicates);
}

int32_t SimRdbHelper::GetDefaultMainCardSlotId()
{
    TELEPHONY_LOGD("start");
    int32_t mainCardSlotId = INVALID_VALUE;
    std::vector<std::string> colume;
    DataShare::DataSharePredicates predicates;
    predicates.EqualTo(SimData::IS_MAIN_CARD, std::to_string(static_cast<int32_t>(MAIN_CARD)));
    predicates.EqualTo(SimData::IS_ACTIVE, std::to_string(static_cast<int32_t>(ACTIVE)));
    std::shared_ptr<DataShare::DataShareHelper> dataShareHelper = CreateDataHelper();
    if (dataShareHelper == nullptr) {
        TELEPHONY_LOGE("SimRdbHelper::GetDefaultMainCardSlotId failed by nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    std::shared_ptr<DataShare::DataShareResultSet> result = Query(dataShareHelper, colume, predicates);
    if (result == nullptr) {
        TELEPHONY_LOGE("nothing");
        return mainCardSlotId;
    }
    int resultSetNum = result->GoToFirstRow();
    if (resultSetNum != 0) {
        TELEPHONY_LOGD("not found main card");
        return mainCardSlotId;
    }
    int index = 0;
    result->GetColumnIndex(SimData::SLOT_INDEX, index);
    result->GetInt(index, mainCardSlotId);
    result->Close();
    dataShareHelper->Release();
    dataShareHelper = nullptr;
    return mainCardSlotId;
}

int32_t SimRdbHelper::GetDefaultMessageCardSlotId()
{
    TELEPHONY_LOGD("start");
    int32_t messageCardSlotId = INVALID_VALUE;
    std::vector<std::string> colume;
    DataShare::DataSharePredicates predicates;
    predicates.EqualTo(SimData::IS_MESSAGE_CARD, std::to_string(static_cast<int32_t>(MAIN_CARD)));
    predicates.EqualTo(SimData::IS_ACTIVE, std::to_string(static_cast<int32_t>(ACTIVE)));
    std::shared_ptr<DataShare::DataShareHelper> dataShareHelper = CreateDataHelper();
    if (dataShareHelper == nullptr) {
        TELEPHONY_LOGE("SimRdbHelper::GetDefaultMessageCardSlotId failed by nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    std::shared_ptr<DataShare::DataShareResultSet> result = Query(dataShareHelper, colume, predicates);
    if (result == nullptr) {
        TELEPHONY_LOGE("SimRdbHelper::get nothing");
        return messageCardSlotId;
    }
    int resultSetNum = result->GoToFirstRow();
    if (resultSetNum != 0) {
        TELEPHONY_LOGD("not found default sms card");
        return messageCardSlotId;
    }
    int index = 0;
    result->GetColumnIndex(SimData::SLOT_INDEX, index);
    result->GetInt(index, messageCardSlotId);
    result->Close();
    dataShareHelper->Release();
    dataShareHelper = nullptr;
    return messageCardSlotId;
}

int32_t SimRdbHelper::GetDefaultCellularDataCardSlotId()
{
    TELEPHONY_LOGD("start");
    int32_t cellularDataCardSlotId = INVALID_VALUE;
    std::vector<std::string> colume;
    DataShare::DataSharePredicates predicates;
    predicates.EqualTo(SimData::IS_CELLULAR_DATA_CARD, std::to_string(static_cast<int32_t>(MAIN_CARD)));
    predicates.EqualTo(SimData::IS_ACTIVE, std::to_string(static_cast<int32_t>(ACTIVE)));
    std::shared_ptr<DataShare::DataShareHelper> dataShareHelper = CreateDataHelper();
    if (dataShareHelper == nullptr) {
        TELEPHONY_LOGE("SimRdbHelper::GetDefaultCellularDataCardSlotId failed by nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    std::shared_ptr<DataShare::DataShareResultSet> result = Query(dataShareHelper, colume, predicates);
    if (result == nullptr) {
        TELEPHONY_LOGE("SimRdbHelper::get nothing");
        return cellularDataCardSlotId;
    }
    int resultSetNum = result->GoToFirstRow();
    if (resultSetNum != 0) {
        TELEPHONY_LOGD("not found default data card");
        return cellularDataCardSlotId;
    }
    int index = 0;
    result->GetColumnIndex(SimData::SLOT_INDEX, index);
    result->GetInt(index, cellularDataCardSlotId);
    result->Close();
    dataShareHelper->Release();
    dataShareHelper = nullptr;
    return cellularDataCardSlotId;
}

int32_t SimRdbHelper::GetDefaultVoiceCardSlotId()
{
    int32_t voiceCardSlotId = INVALID_VALUE;
    std::vector<std::string> colume;
    DataShare::DataSharePredicates predicates;
    predicates.EqualTo(SimData::IS_VOICE_CARD, std::to_string(static_cast<int32_t>(MAIN_CARD)));
    predicates.EqualTo(SimData::IS_ACTIVE, std::to_string(static_cast<int32_t>(ACTIVE)));
    std::shared_ptr<DataShare::DataShareHelper> dataShareHelper = CreateDataHelper();
    if (dataShareHelper == nullptr) {
        TELEPHONY_LOGE("SimRdbHelper::GetDefaultVoiceCardSlotId failed by nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    std::shared_ptr<DataShare::DataShareResultSet> result = Query(dataShareHelper, colume, predicates);
    if (result == nullptr) {
        TELEPHONY_LOGE("get nothing");
        return voiceCardSlotId;
    }
    int resultSetNum = result->GoToFirstRow();
    if (resultSetNum != 0) {
        TELEPHONY_LOGD("not found default voice card");
        return voiceCardSlotId;
    }
    int index = 0;
    result->GetColumnIndex(SimData::SLOT_INDEX, index);
    result->GetInt(index, voiceCardSlotId);
    result->Close();
    dataShareHelper->Release();
    dataShareHelper = nullptr;
    TELEPHONY_LOGD("voiceCardSlotId = %{public}d", voiceCardSlotId);
    return voiceCardSlotId;
}

int32_t SimRdbHelper::SetDefaultMainCard(int32_t simId)
{
    TELEPHONY_LOGI("simId = %{public}d", simId);
    DataShare::DataSharePredicates predicates;
    DataShare::DataShareValuesBucket value;
    DataShare::DataShareValueObject slotObj(simId);
    DataShare::DataShareValueObject valueObj(static_cast<int>(DefaultCardType::MAIN));
    value.Put(SimData::SIM_ID, slotObj);
    value.Put(SimData::CARD_TYPE, valueObj);
    std::shared_ptr<DataShare::DataShareHelper> dataShareHelper = CreateDataHelper();
    if (dataShareHelper == nullptr) {
        TELEPHONY_LOGE("failed by nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    Uri defaultUri(SimRdbInfo::SIM_RDB_DEFAULT_SET_URI);
    int result = dataShareHelper->Update(defaultUri, predicates, value);
    dataShareHelper->Release();
    dataShareHelper = nullptr;
    return result;
}

int32_t SimRdbHelper::SetDefaultVoiceCard(int32_t simId)
{
    TELEPHONY_LOGI("simId = %{public}d", simId);
    DataShare::DataSharePredicates predicates;
    DataShare::DataShareValuesBucket value;
    DataShare::DataShareValueObject slotObj(simId);
    DataShare::DataShareValueObject valueObj(static_cast<int>(DefaultCardType::VOICE));
    value.Put(SimData::SIM_ID, slotObj);
    value.Put(SimData::CARD_TYPE, valueObj);
    std::shared_ptr<DataShare::DataShareHelper> dataShareHelper = CreateDataHelper();
    if (dataShareHelper == nullptr) {
        TELEPHONY_LOGE("failed by nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    Uri defaultUri(SimRdbInfo::SIM_RDB_DEFAULT_SET_URI);
    int result = dataShareHelper->Update(defaultUri, predicates, value);
    dataShareHelper->Release();
    dataShareHelper = nullptr;
    return result;
}

int32_t SimRdbHelper::SetDefaultMessageCard(int32_t simId)
{
    TELEPHONY_LOGI("simId = %{public}d", simId);
    DataShare::DataSharePredicates predicates;
    DataShare::DataShareValuesBucket value;
    DataShare::DataShareValueObject slotObj(simId);
    DataShare::DataShareValueObject valueObj(static_cast<int>(DefaultCardType::SMS));
    value.Put(SimData::SIM_ID, slotObj);
    value.Put(SimData::CARD_TYPE, valueObj);
    std::shared_ptr<DataShare::DataShareHelper> dataShareHelper = CreateDataHelper();
    if (dataShareHelper == nullptr) {
        TELEPHONY_LOGE("failed by nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    Uri defaultUri(SimRdbInfo::SIM_RDB_DEFAULT_SET_URI);
    int result = dataShareHelper->Update(defaultUri, predicates, value);
    dataShareHelper->Release();
    dataShareHelper = nullptr;
    return result;
}

int32_t SimRdbHelper::SetDefaultCellularData(int32_t slotId)
{
    TELEPHONY_LOGI("slotId = %{public}d", slotId);
    DataShare::DataSharePredicates predicates;
    DataShare::DataShareValuesBucket value;
    DataShare::DataShareValueObject slotObj(slotId);
    DataShare::DataShareValueObject valueObj(static_cast<int>(DefaultCardType::DATA));
    value.Put(SimData::SLOT_INDEX, slotObj);
    value.Put(SimData::CARD_TYPE, valueObj);
    std::shared_ptr<DataShare::DataShareHelper> dataShareHelper = CreateDataHelper();
    if (dataShareHelper == nullptr) {
        TELEPHONY_LOGE("failed by nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    Uri defaultUri(SimRdbInfo::SIM_RDB_DEFAULT_SET_URI);
    int result = dataShareHelper->Update(defaultUri, predicates, value);
    dataShareHelper->Release();
    dataShareHelper = nullptr;
    return result;
}

int32_t SimRdbHelper::InsertData(int64_t &id, const DataShare::DataShareValuesBucket &values)
{
    TELEPHONY_LOGD("start");
    std::shared_ptr<DataShare::DataShareHelper> dataShareHelper = CreateDataHelper();
    if (dataShareHelper == nullptr) {
        TELEPHONY_LOGE("SimRdbHelper::InsertData failed by nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    int result = Insert(dataShareHelper, values);
    dataShareHelper->Release();
    dataShareHelper = nullptr;
    return result;
}

void SimRdbHelper::SaveDataToBean(std::shared_ptr<DataShare::DataShareResultSet> result, SimRdbInfo &simBean)
{
    TELEPHONY_LOGD("start");
    int index = 0;
    result->GetColumnIndex(SimData::SIM_ID, index);
    result->GetInt(index, simBean.simId);
    result->GetColumnIndex(SimData::ICC_ID, index);
    result->GetString(index, simBean.iccId);
    result->GetColumnIndex(SimData::CARD_ID, index);
    result->GetString(index, simBean.cardId);
    result->GetColumnIndex(SimData::IMS_SWITCH, index);
    result->GetInt(index, simBean.imsSwitch);
    result->GetColumnIndex(SimData::SLOT_INDEX, index);
    result->GetInt(index, simBean.slotIndex);
    result->GetColumnIndex(SimData::CARD_TYPE, index);
    result->GetInt(index, simBean.cardType);
    result->GetColumnIndex(SimData::SHOW_NAME, index);
    result->GetString(index, simBean.showName);
    result->GetColumnIndex(SimData::PHONE_NUMBER, index);
    result->GetString(index, simBean.phoneNumber);
    result->GetColumnIndex(SimData::COUNTRY_CODE, index);
    result->GetString(index, simBean.countryCode);
    result->GetColumnIndex(SimData::LANGUAGE, index);
    result->GetString(index, simBean.language);
    result->GetColumnIndex(SimData::IMSI, index);
    result->GetString(index, simBean.imsi);
    result->GetColumnIndex(SimData::IS_MAIN_CARD, index);
    result->GetInt(index, simBean.isMainCard);
    result->GetColumnIndex(SimData::IS_VOICE_CARD, index);
    result->GetInt(index, simBean.isVoiceCard);
    result->GetColumnIndex(SimData::IS_MESSAGE_CARD, index);
    result->GetInt(index, simBean.isMessageCard);
    result->GetColumnIndex(SimData::IS_CELLULAR_DATA_CARD, index);
    result->GetInt(index, simBean.isCellularDataCard);
    result->GetColumnIndex(SimData::IS_ACTIVE, index);
    result->GetInt(index, simBean.isActive);
}

int32_t SimRdbHelper::QueryDataByIccId(std::string iccId, SimRdbInfo &simBean)
{
    TELEPHONY_LOGD("start");
    std::vector<std::string> colume;
    DataShare::DataSharePredicates predicates;
    predicates.EqualTo(SimData::ICC_ID, iccId);
    std::shared_ptr<DataShare::DataShareHelper> dataShareHelper = CreateDataHelper();
    if (dataShareHelper == nullptr) {
        TELEPHONY_LOGE("failed by nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    std::shared_ptr<DataShare::DataShareResultSet> result = Query(dataShareHelper, colume, predicates);
    if (result == nullptr) {
        TELEPHONY_LOGE("get nothing");
        return INVALID_VALUE;
    }
    int resultSetNum = result->GoToFirstRow();
    while (resultSetNum == 0) {
        SaveDataToBean(result, simBean);
        resultSetNum = result->GoToNextRow();
    }
    result->Close();
    dataShareHelper->Release();
    dataShareHelper = nullptr;
    return TELEPHONY_SUCCESS;
}

int32_t SimRdbHelper::QueryAllData(std::vector<SimRdbInfo> &vec)
{
    TELEPHONY_LOGD("start");
    std::vector<std::string> colume;
    DataShare::DataSharePredicates predicates;
    std::shared_ptr<DataShare::DataShareHelper> dataShareHelper = CreateDataHelper();
    if (dataShareHelper == nullptr) {
        TELEPHONY_LOGE("failed by nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    std::shared_ptr<DataShare::DataShareResultSet> result = Query(dataShareHelper, colume, predicates);
    if (result == nullptr) {
        TELEPHONY_LOGE("get nothing");
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
    dataShareHelper->Release();
    dataShareHelper = nullptr;
    return TELEPHONY_SUCCESS;
}

int32_t SimRdbHelper::QueryAllValidData(std::vector<SimRdbInfo> &vec)
{
    TELEPHONY_LOGD("start");
    std::vector<std::string> colume;
    std::string id = std::to_string(DEACTIVE);
    DataShare::DataSharePredicates predicates;
    predicates.GreaterThan(SimData::IS_ACTIVE, id);
    std::shared_ptr<DataShare::DataShareHelper> dataShareHelper = CreateDataHelper();
    if (dataShareHelper == nullptr) {
        TELEPHONY_LOGE("failed by nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    std::shared_ptr<DataShare::DataShareResultSet> result = Query(dataShareHelper, colume, predicates);
    if (result == nullptr) {
        TELEPHONY_LOGE("get nothing");
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
    dataShareHelper->Release();
    dataShareHelper = nullptr;
    return TELEPHONY_SUCCESS;
}

int32_t SimRdbHelper::UpdateDataBySimId(int32_t simId, const DataShare::DataShareValuesBucket &values)
{
    TELEPHONY_LOGD("simId = %{public}d", simId);
    std::string sim = std::to_string(simId);
    DataShare::DataSharePredicates predicates;
    predicates.EqualTo(SimData::SIM_ID, sim);
    std::shared_ptr<DataShare::DataShareHelper> dataShareHelper = CreateDataHelper();
    if (dataShareHelper == nullptr) {
        TELEPHONY_LOGE("failed by nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    int result = Update(dataShareHelper, values, predicates);
    dataShareHelper->Release();
    dataShareHelper = nullptr;
    return result;
}

int32_t SimRdbHelper::UpdateDataByIccId(std::string iccId, const DataShare::DataShareValuesBucket &values)
{
    TELEPHONY_LOGI("start");
    DataShare::DataSharePredicates predicates;
    predicates.EqualTo(SimData::ICC_ID, iccId);
    std::shared_ptr<DataShare::DataShareHelper> dataShareHelper = CreateDataHelper();
    if (dataShareHelper == nullptr) {
        TELEPHONY_LOGE("failed by nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    int result = Update(dataShareHelper, values, predicates);
    dataShareHelper->Release();
    dataShareHelper = nullptr;
    return result;
}

int32_t SimRdbHelper::ForgetAllData()
{
    TELEPHONY_LOGD("start");
    DataShare::DataSharePredicates predicates;
    DataShare::DataShareValuesBucket value;
    DataShare::DataShareValueObject valueObj(DEACTIVE);
    value.Put(SimData::IS_ACTIVE, valueObj);
    std::shared_ptr<DataShare::DataShareHelper> dataShareHelper = CreateDataHelper();
    if (dataShareHelper == nullptr) {
        TELEPHONY_LOGE("failed by nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    int result = Update(dataShareHelper, value, predicates);
    dataShareHelper->Release();
    dataShareHelper = nullptr;
    return result;
}

int32_t SimRdbHelper::ForgetAllData(int32_t slotId)
{
    TELEPHONY_LOGD("slotId = %{public}d", slotId);
    DataShare::DataSharePredicates predicates;
    predicates.EqualTo(SimData::SLOT_INDEX, std::to_string(slotId));
    DataShare::DataShareValuesBucket value;
    DataShare::DataShareValueObject valueObj(DEACTIVE);
    value.Put(SimData::IS_ACTIVE, valueObj);
    std::shared_ptr<DataShare::DataShareHelper> dataShareHelper = CreateDataHelper();
    if (dataShareHelper == nullptr) {
        TELEPHONY_LOGE("failed by nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    int result = Update(dataShareHelper, value, predicates);
    dataShareHelper->Release();
    dataShareHelper = nullptr;
    return result;
}

int32_t SimRdbHelper::ClearData()
{
    std::string id = std::to_string(INVALID_VALUE);
    DataShare::DataSharePredicates predicates;
    predicates.GreaterThan(SimData::SIM_ID, id);
    std::shared_ptr<DataShare::DataShareHelper> dataShareHelper = CreateDataHelper();
    if (dataShareHelper == nullptr) {
        TELEPHONY_LOGE("failed by nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    int result = Delete(dataShareHelper, predicates);
    dataShareHelper->Release();
    dataShareHelper = nullptr;
    return result;
}
} // namespace Telephony
} // namespace OHOS
