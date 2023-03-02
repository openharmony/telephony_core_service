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

#include "core_manager_inner.h"
#include "operator_matching_rule.h"
#include "sim_state_type.h"
#include "telephony_types.h"

namespace OHOS {
namespace Telephony {
OperatorConfigLoader::OperatorConfigLoader(
    std::shared_ptr<SimFileManager> simFileManager, std::shared_ptr<OperatorConfigCache> operatorConfigCache)
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
    if (simState != SimState::SIM_STATE_READY) {
        TELEPHONY_LOGE("LoadOpKeyOnMccMnc simState not ready");
        return DEFAULT_OPERATOR_KEY;
    }
    Uri uri(OPKEY_INFO_URI);
    std::vector<std::string> colume;
    DataShare::DataSharePredicates predicates;
    std::shared_ptr<DataShare::DataShareResultSet> resultSet;
    std::shared_ptr<DataShare::DataShareHelper> helper = CreateOpKeyHelper();
    if (helper == nullptr || simFileManager_ == nullptr) {
        TELEPHONY_LOGE("helper or simFileManager_ is nullptr");
        return DEFAULT_OPERATOR_KEY;
    }
    std::string mccmncFromSim = Str16ToStr8(simFileManager_->GetSimOperatorNumeric());
    predicates.EqualTo(MCCMNC, mccmncFromSim);
    resultSet = helper->Query(uri, predicates, colume);
    if (resultSet != nullptr) {
        return GetOpKey(resultSet, slotId);
    }
    return DEFAULT_OPERATOR_KEY;
}

std::string OperatorConfigLoader::GetOpKey(std::shared_ptr<DataShare::DataShareResultSet> resultSet, int32_t slotId)
{
    if (resultSet == nullptr) {
        TELEPHONY_LOGE("GetOpKey resultSet is nullptr");
        return DEFAULT_OPERATOR_KEY;
    }
    if (simFileManager_ == nullptr) {
        TELEPHONY_LOGE("GetOpKey simFileManager_ is nullptr");
        return DEFAULT_OPERATOR_KEY;
    }
    iccidFromSim_ = Str16ToStr8(simFileManager_->GetSimIccId());
    imsiFromSim_ = Str16ToStr8(simFileManager_->GetIMSI());
    spnFromSim_ = Str16ToStr8(simFileManager_->GetSimSpn());
    gid1FromSim_ = Str16ToStr8(simFileManager_->GetSimGid1());
    gid2FromSim_ = Str16ToStr8(simFileManager_->GetSimGid2());
    int count;
    resultSet->GetRowCount(count);
    TELEPHONY_LOGI("GetOpKey count: %{public}d", count);
    if (count <= 0) {
        TELEPHONY_LOGE("GetOpKey count: %{public}d null return", count);
        return DEFAULT_OPERATOR_KEY;
    }
    int columnIndex;
    std::string opKeyVal = DEFAULT_OPERATOR_KEY;
    std::string opNameVal;
    std::string opKeyExtVal;
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
    std::string key;
    SetParameter(key.append(OPKEY_PROP_PREFIX).append(std::to_string(slotId)).c_str(), opKeyVal.c_str());
    key.shrink_to_fit();
    simFileManager_->SetOpKey(opKeyVal);
    simFileManager_->SetOpName(opNameVal);
    simFileManager_->SetOpKeyExt(opKeyExtVal);
    return opKeyVal;
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

std::shared_ptr<DataShare::DataShareHelper> OperatorConfigLoader::CreateOpKeyHelper()
{
    if (opKeyDataAbilityHelper_ == nullptr) {
        opKeyDataAbilityHelper_ = CreateDataAHelper();
    }
    return opKeyDataAbilityHelper_;
}

std::shared_ptr<DataShare::DataShareHelper> OperatorConfigLoader::CreateDataAHelper() const
{
    TELEPHONY_LOGI("OperatorConfigLoader::CreateDataAHelper");
    auto saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (saManager == nullptr) {
        TELEPHONY_LOGE("OperatorConfigLoader Get system ability mgr failed");
        return nullptr;
    }
    auto remoteObj = saManager->GetSystemAbility(TELEPHONY_CORE_SERVICE_SYS_ABILITY_ID);
    if (remoteObj == nullptr) {
        TELEPHONY_LOGE("OperatorConfigLoader GetSystemAbility Service Failed");
        return nullptr;
    }
    return DataShare::DataShareHelper::Creator(remoteObj, OPKEY_URI);
}
} // namespace Telephony
} // namespace OHOS
