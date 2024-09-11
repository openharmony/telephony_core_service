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
#include "telephony_ext_wrapper.h"
#include "telephony_types.h"

namespace OHOS {
namespace Telephony {
const int WAIT_TIME = 10;
SimRdbHelper::SimRdbHelper() {}

SimRdbHelper::~SimRdbHelper() {}

std::shared_ptr<DataShare::DataShareHelper> SimRdbHelper::CreateDataHelper()
{
    TELEPHONY_LOGD("start");
    if (mTelephonyDatahelper == nullptr) {
        TELEPHONY_LOGE("get CreateDataHelper Failed");
        return nullptr;
    }
    return mTelephonyDatahelper->CreateSimHelper();
}

std::shared_ptr<DataShare::DataShareHelper> SimRdbHelper::CreateDataHelper(const int waitTime)
{
    TELEPHONY_LOGD("start");
    if (mTelephonyDatahelper == nullptr) {
        TELEPHONY_LOGE("get CreateDataHelper Failed");
        return nullptr;
    }
    return mTelephonyDatahelper->CreateSimHelper(waitTime);
}

std::shared_ptr<DataShare::DataShareHelper> SimRdbHelper::CreateOpKeyHelper()
{
    TELEPHONY_LOGI("SimRdbHelper::CreateOpKeyHelper");
    if (mTelephonyDatahelper == nullptr) {
        TELEPHONY_LOGE("get CreateOpKeyHelper Failed");
        return nullptr;
    }
    return mTelephonyDatahelper->CreateOpKeyHelper();
}

int SimRdbHelper::UpdateOpKeyInfo()
{
    TELEPHONY_LOGI("InitOpKeyData start");
    std::shared_ptr<DataShare::DataShareHelper> helper = CreateOpKeyHelper();
    if (helper == nullptr) {
        TELEPHONY_LOGE("OpKey helper is nullptr");
        return TELEPHONY_ERROR;
    }
    Uri uri(SimRdbInfo::OPKEY_INIT_URI);
    std::vector<DataShare::DataShareValuesBucket> values;
    int result = helper->BatchInsert(uri, values);
    helper->Release();
    helper = nullptr;
    if (result <= 0) {
        TELEPHONY_LOGI("InitOpKeyInfo opkey not change");
        return result;
    }
    helper = CreateDataHelper();
    if (helper == nullptr) {
        TELEPHONY_LOGE("Sim helper is nullptr");
        return TELEPHONY_ERROR;
    }
    TELEPHONY_LOGI("InitOpKeyInfo Opkey changed. clear opkey cache");
    DataShare::DataShareValuesBucket valuesBucket;
    DataShare::DataShareValueObject valueObj("");
    valuesBucket.Put(SimData::OPKEY, valueObj);
    DataShare::DataSharePredicates predicates;
    result = Update(helper, valuesBucket, predicates);
    helper->Release();
    helper = nullptr;
    TELEPHONY_LOGI("InitOpKeyInfo end");
    return TELEPHONY_SUCCESS;
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
    int32_t mainCardSlotId = 0;
    std::vector<std::string> colume;
    DataShare::DataSharePredicates predicates;
    predicates.EqualTo(SimData::IS_MAIN_CARD, std::to_string(static_cast<int32_t>(MAIN_CARD)));
    predicates.EqualTo(SimData::IS_ACTIVE, std::to_string(static_cast<int32_t>(ACTIVE)));
    std::shared_ptr<DataShare::DataShareHelper> dataShareHelper = CreateDataHelper();
    if (dataShareHelper == nullptr) {
        TELEPHONY_LOGE("SimRdbHelper::GetDefaultMainCardSlotId failed by nullptr");
        return mainCardSlotId;
    }
    std::shared_ptr<DataShare::DataShareResultSet> result = Query(dataShareHelper, colume, predicates);
    if (result == nullptr) {
        TELEPHONY_LOGE("nothing");
        dataShareHelper->Release();
        return mainCardSlotId;
    }
    int resultSetNum = result->GoToFirstRow();
    if (resultSetNum != 0) {
        TELEPHONY_LOGD("not found main card");
        result->Close();
        dataShareHelper->Release();
        return mainCardSlotId;
    }
    int index = 0;
    result->GetColumnIndex(SimData::SLOT_INDEX, index);
    result->GetInt(index, mainCardSlotId);
    result->Close();
    dataShareHelper->Release();
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
        return messageCardSlotId;
    }
    std::shared_ptr<DataShare::DataShareResultSet> result = Query(dataShareHelper, colume, predicates);
    if (result == nullptr) {
        TELEPHONY_LOGE("SimRdbHelper::get nothing");
        dataShareHelper->Release();
        return messageCardSlotId;
    }
    int resultSetNum = result->GoToFirstRow();
    if (resultSetNum != 0) {
        TELEPHONY_LOGD("not found default sms card");
        result->Close();
        dataShareHelper->Release();
        return messageCardSlotId;
    }
    int index = 0;
    result->GetColumnIndex(SimData::SLOT_INDEX, index);
    result->GetInt(index, messageCardSlotId);
    result->Close();
    dataShareHelper->Release();
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
        return cellularDataCardSlotId;
    }
    std::shared_ptr<DataShare::DataShareResultSet> result = Query(dataShareHelper, colume, predicates);
    if (result == nullptr) {
        TELEPHONY_LOGE("SimRdbHelper::get nothing");
        dataShareHelper->Release();
        return cellularDataCardSlotId;
    }
    int resultSetNum = result->GoToFirstRow();
    if (resultSetNum != 0) {
        TELEPHONY_LOGD("not found default data card");
        result->Close();
        dataShareHelper->Release();
        return cellularDataCardSlotId;
    }
    int index = 0;
    result->GetColumnIndex(SimData::SLOT_INDEX, index);
    result->GetInt(index, cellularDataCardSlotId);
    result->Close();
    dataShareHelper->Release();
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
        return voiceCardSlotId;
    }
    std::shared_ptr<DataShare::DataShareResultSet> result = Query(dataShareHelper, colume, predicates);
    if (result == nullptr) {
        TELEPHONY_LOGE("get nothing");
        dataShareHelper->Release();
        return voiceCardSlotId;
    }
    int resultSetNum = result->GoToFirstRow();
    if (resultSetNum != 0) {
        TELEPHONY_LOGD("not found default voice card");
        result->Close();
        dataShareHelper->Release();
        return voiceCardSlotId;
    }
    int index = 0;
    result->GetColumnIndex(SimData::SLOT_INDEX, index);
    result->GetInt(index, voiceCardSlotId);
    result->Close();
    dataShareHelper->Release();
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
        return INVALID_VALUE;
    }
    Uri defaultUri(SimRdbInfo::SIM_RDB_DEFAULT_SET_URI);
    int result = dataShareHelper->Update(defaultUri, predicates, value);
    dataShareHelper->Release();
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
        return INVALID_VALUE;
    }
    Uri defaultUri(SimRdbInfo::SIM_RDB_DEFAULT_SET_URI);
    int result = dataShareHelper->Update(defaultUri, predicates, value);
    dataShareHelper->Release();
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
        return INVALID_VALUE;
    }
    Uri defaultUri(SimRdbInfo::SIM_RDB_DEFAULT_SET_URI);
    int result = dataShareHelper->Update(defaultUri, predicates, value);
    dataShareHelper->Release();
    return result;
}

int32_t SimRdbHelper::SetDefaultCellularData(int32_t simId)
{
    TELEPHONY_LOGI("simId = %{public}d", simId);
    DataShare::DataSharePredicates predicates;
    DataShare::DataShareValuesBucket value;
    DataShare::DataShareValueObject slotObj(simId);
    DataShare::DataShareValueObject valueObj(static_cast<int>(DefaultCardType::DATA));
    value.Put(SimData::SIM_ID, slotObj);
    value.Put(SimData::CARD_TYPE, valueObj);
    std::shared_ptr<DataShare::DataShareHelper> dataShareHelper = CreateDataHelper();
    if (dataShareHelper == nullptr) {
        TELEPHONY_LOGE("failed by nullptr");
        return INVALID_VALUE;
    }
    Uri defaultUri(SimRdbInfo::SIM_RDB_DEFAULT_SET_URI);
    int result = dataShareHelper->Update(defaultUri, predicates, value);
    dataShareHelper->Release();
    return result;
}

int32_t SimRdbHelper::InsertData(int64_t &id, const DataShare::DataShareValuesBucket &values)
{
    TELEPHONY_LOGD("start");
    std::shared_ptr<DataShare::DataShareHelper> dataShareHelper = CreateDataHelper(WAIT_TIME);
    if (dataShareHelper == nullptr) {
        TELEPHONY_LOGE("need to retry CreateDataHelper");
        dataShareHelper = CreateDataHelper();
    }
    if (dataShareHelper == nullptr) {
        TELEPHONY_LOGE("SimRdbHelper::InsertData failed by nullptr");
        return INVALID_VALUE;
    }
    int result = Insert(dataShareHelper, values);
    dataShareHelper->Release();
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
    std::shared_ptr<DataShare::DataShareHelper> dataShareHelper = CreateDataHelper(WAIT_TIME);
    if (dataShareHelper == nullptr) {
        TELEPHONY_LOGE("failed by nullptr");
        return INVALID_VALUE;
    }
    std::shared_ptr<DataShare::DataShareResultSet> result = Query(dataShareHelper, colume, predicates);
    if (result == nullptr) {
        TELEPHONY_LOGE("get nothing");
        dataShareHelper->Release();
        return TELEPHONY_SUCCESS;
    }
    int rowCount = 0;
    result->GetRowCount(rowCount);
    if (rowCount <= 0) {
        TELEPHONY_LOGE("dont query the iccid record in db");
        result->Close();
        dataShareHelper->Release();
        return TELEPHONY_SUCCESS;
    }
    int resultSetNum = result->GoToFirstRow();
    while (resultSetNum == 0) {
        SaveDataToBean(result, simBean);
        resultSetNum = result->GoToNextRow();
    }
    result->Close();
    dataShareHelper->Release();
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
        return INVALID_VALUE;
    }
    std::shared_ptr<DataShare::DataShareResultSet> result = Query(dataShareHelper, colume, predicates);
    if (result == nullptr) {
        TELEPHONY_LOGE("get nothing");
        dataShareHelper->Release();
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
    return TELEPHONY_SUCCESS;
}

int32_t SimRdbHelper::QueryAllValidData(std::vector<SimRdbInfo> &vec)
{
    TELEPHONY_LOGD("start");
    std::vector<std::string> colume;
    std::string id = std::to_string(INVALID_VALUE);
    DataShare::DataSharePredicates predicates;
    predicates.GreaterThan(SimData::SLOT_INDEX, id);
    std::shared_ptr<DataShare::DataShareHelper> dataShareHelper = CreateDataHelper(WAIT_TIME);
    if (dataShareHelper == nullptr) {
        TELEPHONY_LOGI("retry CreateDataHelper");
        dataShareHelper = CreateDataHelper();
    }
    if (dataShareHelper == nullptr) {
        TELEPHONY_LOGE("failed by nullptr");
        return INVALID_VALUE;
    }
    std::shared_ptr<DataShare::DataShareResultSet> result = Query(dataShareHelper, colume, predicates);
    if (result == nullptr) {
        TELEPHONY_LOGE("get nothing");
        dataShareHelper->Release();
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
        return INVALID_VALUE;
    }
    int result = Update(dataShareHelper, values, predicates);
    dataShareHelper->Release();
    return result;
}

int32_t SimRdbHelper::UpdateDataByIccId(std::string iccId, const DataShare::DataShareValuesBucket &values)
{
    TELEPHONY_LOGI("start");
    DataShare::DataSharePredicates predicates;
    predicates.EqualTo(SimData::ICC_ID, iccId);
    std::shared_ptr<DataShare::DataShareHelper> dataShareHelper = CreateDataHelper(WAIT_TIME);
    if (dataShareHelper == nullptr) {
        TELEPHONY_LOGE("failed by nullptr");
        return INVALID_VALUE;
    }
    int result = Update(dataShareHelper, values, predicates);
    dataShareHelper->Release();
    return result;
}

int32_t SimRdbHelper::ForgetAllData()
{
    TELEPHONY_LOGD("start");
    DataShare::DataSharePredicates predicates;
    DataShare::DataShareValuesBucket value;
    DataShare::DataShareValueObject valueObj(INVALID_VALUE);
    value.Put(SimData::SLOT_INDEX, valueObj);
    std::shared_ptr<DataShare::DataShareHelper> dataShareHelper = CreateDataHelper(WAIT_TIME);
    if (dataShareHelper == nullptr) {
        TELEPHONY_LOGE("failed by nullptr");
        return INVALID_VALUE;
    }
    int result = Update(dataShareHelper, value, predicates);
    dataShareHelper->Release();
    TELEPHONY_LOGD("result = %{public}d", result);
    return result;
}

int32_t SimRdbHelper::ForgetAllData(int32_t slotId)
{
    TELEPHONY_LOGD("slotId = %{public}d", slotId);
    DataShare::DataSharePredicates predicates;
    predicates.EqualTo(SimData::SLOT_INDEX, std::to_string(slotId));
    DataShare::DataShareValuesBucket value;
    if (TELEPHONY_EXT_WRAPPER.isVSimEnabled_ && TELEPHONY_EXT_WRAPPER.isVSimEnabled_() &&
        slotId != static_cast<int32_t>(SimSlotType::VSIM_SLOT_ID)) {
        TELEPHONY_LOGI("vsim enabled, not change slotId: %{public}d IS_ACTIVE state", slotId);
    } else {
        DataShare::DataShareValueObject valueObj(ACTIVE);
        value.Put(SimData::IS_ACTIVE, valueObj);
    }
    DataShare::DataShareValueObject valueIndex(INVALID_VALUE);
    value.Put(SimData::SLOT_INDEX, valueIndex);
    std::shared_ptr<DataShare::DataShareHelper> dataShareHelper = CreateDataHelper();
    if (dataShareHelper == nullptr) {
        TELEPHONY_LOGE("failed by nullptr");
        return INVALID_VALUE;
    }
    int result = Update(dataShareHelper, value, predicates);
    dataShareHelper->Release();
    TELEPHONY_LOGD("result = %{public}d", result);
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
        return INVALID_VALUE;
    }
    int result = Delete(dataShareHelper, predicates);
    dataShareHelper->Release();
    return result;
}

bool SimRdbHelper::IsDataShareError()
{
    return mTelephonyDatahelper != nullptr && mTelephonyDatahelper->IsDataShareError();
}

void SimRdbHelper::ResetDataShareError()
{
    if (mTelephonyDatahelper != nullptr) {
        mTelephonyDatahelper->ResetDataShareError();
    }
}
} // namespace Telephony
} // namespace OHOS
