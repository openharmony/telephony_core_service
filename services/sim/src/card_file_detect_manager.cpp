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

#include "card_file_detect_manager.h"

#include "sim_data.h"
#include "telephony_errors.h"

namespace OHOS {
namespace Telephony {
#undef TELEPHONY_LOG_TAG
#define TELEPHONY_LOG_TAG "CardFileDetectManager"

CardFileDetectManager::CardFileDetectManager()
{
    simRdbHelper_ = std::make_shared<SimRdbHelper>();
}

CardFileDetectManager::~CardFileDetectManager() {}

bool CardFileDetectManager::IsIccIdExists(const std::string &iccId)
{
    if (iccId.empty()) {
        TELEPHONY_LOGE("IsIccIdExists: iccId is empty");
        return false;
    }
    SimRdbInfo simInfo;
    int32_t result = simRdbHelper_->QueryDataByIccId(iccId, simInfo);
    if (result != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("IsIccIdExists: QueryDataByIccId failed, result=%{public}d", result);
        return false;
    }
    return !simInfo.iccId.empty();
}

void CardFileDetectManager::BuildDataShareValues(
    const CardFileDetectData &data, DataShare::DataShareValuesBucket &values)
{
    auto PutString = [&](const std::string &key, const std::string &value) {
        if (!value.empty()) {
            values.Put(key, DataShare::DataShareValueObject(value));
        }
    };

    values.Put(SimData::PHY_CARD, DataShare::DataShareValueObject(data.phyCard));
    values.Put(SimData::LSI, DataShare::DataShareValueObject(data.lsi));

    if (data.phyCard == 0 || data.phyCard == 1) {
        values.Put(SimData::SIM_LABEL_INDEX, DataShare::DataShareValueObject(data.phyCard + 1));
        values.Put(SimData::IS_ESIM, DataShare::DataShareValueObject(0));
    } else {
        values.Put(SimData::IS_ESIM, DataShare::DataShareValueObject(1));
    }

    if (data.mncLen != 0) {
        values.Put(SimData::MNC_LEN, DataShare::DataShareValueObject(data.mncLen));
    }

    PutString(SimData::ICC_ID, data.iccId);
    PutString(SimData::EFUST, data.efust);
    PutString(SimData::IMSI, data.imsi);
    PutString(SimData::GID1, data.gid1);
    PutString(SimData::GID2, data.gid2);
    PutString(SimData::SPN, data.spn);
    PutString(SimData::EHPLMN, data.ehplmn);
}

int32_t CardFileDetectManager::InsertCardFileDetectData(const CardFileDetectData &data)
{
    DataShare::DataShareValuesBucket values;
    BuildDataShareValues(data, values);
    int64_t id = 0;
    int32_t result = simRdbHelper_->InsertData(id, values);
    if (result == INVALID_VALUE) {
        TELEPHONY_LOGE("InsertCardFileDetectData: InsertData failed");
        return TELEPHONY_ERR_DATABASE_WRITE_FAIL;
    }
    TELEPHONY_LOGI("InsertCardFileDetectData: success, iccId=%{public}s", data.iccId.c_str());
    return TELEPHONY_SUCCESS;
}

int32_t CardFileDetectManager::UpdateCardFileDetectData(const CardFileDetectData &data)
{
    DataShare::DataShareValuesBucket values;
    BuildDataShareValues(data, values);
    int32_t result = simRdbHelper_->UpdateDataByIccId(data.iccId, values);
    if (result == INVALID_VALUE) {
        TELEPHONY_LOGE("UpdateCardFileDetectData: UpdateDataByIccId failed");
        return TELEPHONY_ERR_DATABASE_WRITE_FAIL;
    }
    TELEPHONY_LOGI("UpdateCardFileDetectData: success, iccId=%{public}s", data.iccId.c_str());
    return TELEPHONY_SUCCESS;
}

int32_t CardFileDetectManager::SaveCardFileDetectData(const CardFileDetectData &data)
{
    if (data.iccId.empty()) {
        TELEPHONY_LOGE("SaveCardFileDetectData: iccId is empty");
        return TELEPHONY_ERR_ARGUMENT_INVALID;
    }
    if (IsIccIdExists(data.iccId)) {
        return UpdateCardFileDetectData(data);
    }
    return InsertCardFileDetectData(data);
}

int32_t CardFileDetectManager::GetAllSimCardInfo(std::vector<SimCardInfo> &results)
{
    std::vector<SimRdbInfo> rdbResult;
    int32_t ret = simRdbHelper_->QueryAllData(rdbResult);
    if (ret != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("GetAllSimCardInfo: QueryAllData failed, ret=%{public}d", ret);
        return ret;
    }
    for (const auto &info : rdbResult) {
        SimCardInfo simCardInfo;
        simCardInfo.iccId = info.iccId;
        simCardInfo.efust = info.efust;
        simCardInfo.imsi = info.imsi;
        simCardInfo.gid1 = info.gid1;
        simCardInfo.gid2 = info.gid2;
        simCardInfo.spn = info.spn;
        simCardInfo.ehplmn = info.ehplmn;
        simCardInfo.plmnLength = info.mncLen;
        simCardInfo.phyCard = info.phyCard;
        simCardInfo.simlabel.simType = info.isEsim ? SimType::ESIM : SimType::PSIM;
        simCardInfo.simlabel.index = info.simLabelIndex;
        results.push_back(simCardInfo);
    }
    TELEPHONY_LOGI("GetAllSimCardInfo: results size=%{public}zu", results.size());
    return TELEPHONY_SUCCESS;
}
} // namespace Telephony
} // namespace OHOS