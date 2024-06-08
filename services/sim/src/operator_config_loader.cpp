/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#include "operator_config_loader.h"

#include <string_ex.h>
#include "sim_data.h"
#include "telephony_data_helper.h"
#include "core_manager_inner.h"
#include "operator_matching_rule.h"
#include "sim_state_type.h"
#include "telephony_types.h"
#include "telephony_errors.h"
#include "telephony_ext_wrapper.h"

namespace OHOS {
namespace Telephony {
OperatorConfigLoader::OperatorConfigLoader(
    std::weak_ptr<SimFileManager> simFileManager, std::shared_ptr<OperatorConfigCache> operatorConfigCache)
    : simFileManager_(simFileManager), operatorConfigCache_(operatorConfigCache)
{
    TELEPHONY_LOGI("OperatorConfigLoader construct");
}

OperatorConfigLoader::~OperatorConfigLoader() {}

OperatorConfig OperatorConfigLoader::LoadOperatorConfig(int32_t slotId)
{
    OperatorConfig opc;
    if (operatorConfigCache_ == nullptr) {
        TELEPHONY_LOGE("operatorConfigCache_ is nullptr");
        return opc;
    }
    bool isNeedLoad = operatorConfigCache_->IsNeedOperatorLoad(slotId);
    TELEPHONY_LOGI("LoadOperatorConfig slotId: %{public}d isNeedLoad: %{public}d", slotId, isNeedLoad);
    if (!isNeedLoad) {
        return opc;
    }
    TELEPHONY_LOGI("LoadOperatorConfig slotId %{public}d", slotId);
    std::string opkey = LoadOpKeyOnMccMnc(slotId);
    operatorConfigCache_->LoadOperatorConfig(slotId, opc);
    TELEPHONY_LOGI("LoadOperatorConfig %{public}zu", opc.configValue.size());
    return opc;
}

std::string OperatorConfigLoader::LoadOpKeyOnMccMnc(int32_t slotId)
{
    SimState simState = SimState::SIM_STATE_UNKNOWN;
    CoreManagerInner::GetInstance().GetSimState(slotId, simState);
    std::shared_ptr<SimFileManager> simFileManager = simFileManager_.lock();
    if (simFileManager == nullptr || simState != SimState::SIM_STATE_READY) {
        TELEPHONY_LOGE("LoadOpKeyOnMccMnc simState not ready");
        return DEFAULT_OPERATOR_KEY;
    }
    Uri uri(OPKEY_INFO_URI);
    std::vector<std::string> colume;
    DataShare::DataSharePredicates predicates;
    std::shared_ptr<DataShare::DataShareResultSet> resultSet;
    std::shared_ptr<DataShare::DataShareHelper> helper = CreateOpKeyHelper();
    if (helper == nullptr) {
        TELEPHONY_LOGE("helper is nullptr");
        return DEFAULT_OPERATOR_KEY;
    }
    std::string mccmncFromSim = Str16ToStr8(simFileManager->GetSimOperatorNumeric());
    if (TELEPHONY_EXT_WRAPPER.getRoamingBrokerNumeric_) {
        TELEPHONY_EXT_WRAPPER.getRoamingBrokerNumeric_(slotId, mccmncFromSim);
    }
    predicates.EqualTo(MCCMNC, mccmncFromSim);
    resultSet = helper->Query(uri, predicates, colume);
    if (resultSet != nullptr) {
        std::string opkey = GetOpKey(resultSet, slotId);
        helper->Release();
        return opkey;
    }
    helper->Release();
    return DEFAULT_OPERATOR_KEY;
}

int OperatorConfigLoader::InsertOpkeyToSimDb(std::string opKeyValue)
{
    if (opKeyValue.empty() || iccidFromSim_.empty()) {
        TELEPHONY_LOGE("opKeyValue or imsi is null");
        return Telephony::TELEPHONY_ERR_ARGUMENT_NULL;
    }
    std::shared_ptr<DataShare::DataShareHelper> helper = CreateSimHelper();
    if (helper == nullptr) {
        TELEPHONY_LOGE("helper is nullptr");
        return Telephony::TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    DataShare::DataShareValuesBucket values;
    DataShare::DataShareValueObject valueObj(opKeyValue);
    values.Put(SimData::OPKEY, valueObj);
    DataShare::DataSharePredicates predicates;
    predicates.EqualTo(SimData::ICC_ID, iccidFromSim_);
    predicates.And();
    predicates.EqualTo(SimData::IMSI, imsiFromSim_);
    Uri simUri(SIM_INFO_URI);
    std::vector<std::string> colume;
    auto resultSet = helper->Query(simUri, predicates, colume);
    int rowCount = 0;
    if (resultSet != nullptr) {
        resultSet->GetRowCount(rowCount);
    }
    int result = 0;
    if (rowCount > 0) {
        result = helper->Update(simUri, predicates, values);
    }
    helper->Release();
    return result;
}

std::string OperatorConfigLoader::GetOpKey(std::shared_ptr<DataShare::DataShareResultSet> resultSet, int32_t slotId)
{
    if (resultSet == nullptr) {
        TELEPHONY_LOGE("GetOpKey resultSet is nullptr");
        return DEFAULT_OPERATOR_KEY;
    }
    std::shared_ptr<SimFileManager> simFileManager = simFileManager_.lock();
    if (simFileManager == nullptr) {
        TELEPHONY_LOGE("GetOpKey simFileManager is nullptr");
        return DEFAULT_OPERATOR_KEY;
    }
    iccidFromSim_ = Str16ToStr8(simFileManager->GetSimDecIccId());
    imsiFromSim_ = Str16ToStr8(simFileManager->GetIMSI());
    spnFromSim_ = Str16ToStr8(simFileManager->GetSimSpn());
    gid1FromSim_ = Str16ToStr8(simFileManager->GetSimGid1());
    gid2FromSim_ = Str16ToStr8(simFileManager->GetSimGid2());
    mccmncFromSim_ = Str16ToStr8(simFileManager->GetSimOperatorNumeric());
    if (TELEPHONY_EXT_WRAPPER.getRoamingBrokerNumeric_ && TELEPHONY_EXT_WRAPPER.getRoamingBrokerImsi_) {
        TELEPHONY_EXT_WRAPPER.getRoamingBrokerNumeric_(slotId, mccmncFromSim_);
        TELEPHONY_EXT_WRAPPER.getRoamingBrokerImsi_(slotId, imsiFromSim_);
    }
    std::string opKeyVal = mccmncFromSim_;
    std::string opNameVal = "COMMON";
    std::string opKeyExtVal = "";
    int count;
    resultSet->GetRowCount(count);
    TELEPHONY_LOGI("GetOpKey count: %{public}d", count);
    if (count <= 0) {
        TELEPHONY_LOGE("GetOpKey count: %{public}d, use MccMnc as opkey, COMMON as opname", count);
        resultSet->Close();
        SetMatchResultToSimFileManager(opKeyVal, opNameVal, opKeyExtVal, slotId, simFileManager);
        return opKeyVal;
    }
    int columnIndex;
    for (int row = 0; row < count; row++) {
        if (MatchOperatorRule(resultSet, row)) {
            resultSet->GetColumnIndex(OPKEY, columnIndex);
            resultSet->GetString(columnIndex, opKeyVal);
            resultSet->GetColumnIndex(OPNAME, columnIndex);
            resultSet->GetString(columnIndex, opNameVal);
            resultSet->GetColumnIndex(OPKEY_EXT, columnIndex);
            resultSet->GetString(columnIndex, opKeyExtVal);
        }
    }
    resultSet->Close();
    SetMatchResultToSimFileManager(opKeyVal, opNameVal, opKeyExtVal, slotId, simFileManager);
    InsertOpkeyToSimDb(opKeyVal);
    return opKeyVal;
}

void OperatorConfigLoader::SetMatchResultToSimFileManager(std::string opKeyVal, std::string opNameVal,
    std::string opKeyExtVal, int32_t slotId, std::shared_ptr<SimFileManager> simFileManager)
{
    std::string key;
    SetParameter(key.append(OPKEY_PROP_PREFIX).append(std::to_string(slotId)).c_str(), opKeyVal.c_str());
    key.shrink_to_fit();
    simFileManager->SetOpKey(opKeyVal);
    simFileManager->SetOpName(opNameVal);
    simFileManager->SetOpKeyExt(opKeyExtVal);
}

bool OperatorConfigLoader::MatchOperatorRule(std::shared_ptr<DataShare::DataShareResultSet> &resultSet, int row)
{
    if (resultSet == nullptr) {
        TELEPHONY_LOGE("resultSet is nullptr");
        return false;
    }
    bool isAllRuleMatch = true;
    int columnIndex;
    std::string strVal;
    resultSet->GoToRow(row);
    resultSet->GetColumnIndex(ICCID, columnIndex);
    resultSet->GetString(columnIndex, strVal);
    if (!strVal.empty()) {
        isAllRuleMatch = OperatorMatchingRule::IccidRegexMatch(iccidFromSim_, strVal);
    }
    if (!isAllRuleMatch) {
        return false;
    }
    resultSet->GetColumnIndex(IMSI, columnIndex);
    resultSet->GetString(columnIndex, strVal);
    if (!strVal.empty()) {
        isAllRuleMatch = OperatorMatchingRule::ImsiRegexMatch(imsiFromSim_, strVal);
    }
    if (!isAllRuleMatch) {
        return false;
    }
    resultSet->GetColumnIndex(SPN, columnIndex);
    resultSet->GetString(columnIndex, strVal);
    if (!strVal.empty()) {
        isAllRuleMatch = OperatorMatchingRule::SpnRegexMatch(spnFromSim_, strVal);
    }
    if (!isAllRuleMatch) {
        return false;
    }
    resultSet->GetColumnIndex(GID1, columnIndex);
    resultSet->GetString(columnIndex, strVal);
    if (!strVal.empty()) {
        isAllRuleMatch = OperatorMatchingRule::PrefixMatch(gid1FromSim_, strVal);
    }
    if (!isAllRuleMatch) {
        return false;
    }
    resultSet->GetColumnIndex(GID2, columnIndex);
    resultSet->GetString(columnIndex, strVal);
    if (!strVal.empty()) {
        isAllRuleMatch = OperatorMatchingRule::PrefixMatch(gid2FromSim_, strVal);
    }
    return isAllRuleMatch;
}

std::shared_ptr<DataShare::DataShareHelper> OperatorConfigLoader::CreateOpKeyHelper() const
{
    TELEPHONY_LOGI("OperatorConfigLoader::CreateOpKeyHelper");
    auto helper = TelephonyDataHelper::GetInstance();
    if (helper == nullptr) {
        TELEPHONY_LOGE("get CreateOpKeyHelper Failed.");
    }
    return helper->CreateOpKeyHelper();
}

std::shared_ptr<DataShare::DataShareHelper> OperatorConfigLoader::CreateSimHelper() const
{
    TELEPHONY_LOGI("OperatorConfigLoader::CreateSimHelper");
    auto helper = TelephonyDataHelper::GetInstance();
    if (helper == nullptr) {
        TELEPHONY_LOGE("get CreateSimHelper Failed.");
    }
    return helper->CreateSimHelper();
}
} // namespace Telephony
} // namespace OHOS
