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
#include "operator_config_cache.h"

#include <fstream>
#include <openssl/sha.h>
#include <string_ex.h>
#include <telephony_types.h>

#include "cJSON.h"
#include "common_event_manager.h"
#include "common_event_support.h"
#include "core_manager_inner.h"
#include "pdp_profile_rdb_helper.h"
#include "radio_event.h"
#include "parameters.h"

namespace OHOS {
namespace Telephony {
OperatorConfigCache::OperatorConfigCache(std::weak_ptr<SimFileManager> simFileManager, int32_t slotId)
    : TelEventHandler("OperatorConfigCache"), simFileManager_(simFileManager), slotId_(slotId)
{
    TELEPHONY_LOGI("OperatorConfigCache create");
}

void OperatorConfigCache::ClearAllCache(int32_t slotId)
{
    std::unique_lock<std::mutex> lock(mutex_);
    ClearOperatorValue(slotId);
    ClearMemoryCache(slotId);
    OperatorFileParser::ClearFilesCache();
    lock.unlock();
}

void OperatorConfigCache::ClearMemoryAndOpkey(int32_t slotId)
{
    std::unique_lock<std::mutex> lock(mutex_);
    ClearOperatorValue(slotId);
    ClearMemoryCache(slotId);
    lock.unlock();
}

void OperatorConfigCache::ClearOperatorValue(int32_t slotId)
{
    auto simFileManager = simFileManager_.lock();
    if (simFileManager == nullptr) {
        TELEPHONY_LOGE("simFileManager is nullptr");
        return;
    }
    std::string key;
    std::string initialOpkey = INITIAL_OPKEY;
    SetParameter(key.append(OPKEY_PROP_PREFIX).append(std::to_string(slotId)).c_str(), initialOpkey.c_str());
    simFileManager->SetOpKey("");
    simFileManager->SetOpName("");
    simFileManager->SetOpKeyExt("");
}

void OperatorConfigCache::ClearMemoryCache(int32_t slotId)
{
    opc_.stringValue.clear();
    opc_.stringArrayValue.clear();
    opc_.intValue.clear();
    opc_.intArrayValue.clear();
    opc_.longValue.clear();
    opc_.longArrayValue.clear();
    opc_.boolValue.clear();
    opc_.configValue.clear();
}

void OperatorConfigCache::UpdateCurrentOpc(
    int32_t slotId, OperatorConfig &poc, int32_t state, bool needUpdateLoading)
{
    bool isUseCloudImsNV = system::GetBoolParameter(KEY_CONST_TELEPHONY_IS_USE_CLOUD_IMS_NV, true);
    TELEPHONY_LOGI("[slot%{public}d], isUseCloudImsNV = %{public}d", slotId, isUseCloudImsNV);
    if (isUseCloudImsNV) {
        UpdatevolteCap(slotId, poc);
    }
    std::unique_lock<std::mutex> lock(mutex_);
    CopyOperatorConfig(poc, opc_);
    lock.unlock();
    AnnounceOperatorConfigChanged(slotId, state);
    if (needUpdateLoading) {
        isLoadingConfig = false;
    }
}

void OperatorConfigCache::UpdateOpcBoolValue(OperatorConfig &opc, const std::string &key, const bool value)
{
    std::map<std::string, bool>::iterator it = opc.boolValue.find(key);
    bool result;
    if (it != opc.boolValue.end()) {
        result = it->second && value;
        it->second = result;
    } else {
        TELEPHONY_LOGI("Not find in opc");
        result = value;
        opc.boolValue.emplace(key, value);
    }

    std::string sResult = result ? "true" : "false";
    opc.configValue[Str8ToStr16(key)] = Str8ToStr16(sResult);
}

void OperatorConfigCache::UpdatevolteCap(int32_t slotId, OperatorConfig &opc)
{
    std::string volteCapKey = KEY_PERSIST_TELEPHONY_VOLTE_CAP_IN_CHIP + std::to_string(slotId);
    int32_t volteCapInChip = GetIntParameter(volteCapKey.c_str(), -1);
    TELEPHONY_LOGI("volteCapInChip = %{public}d", volteCapInChip);

    std::unique_lock<std::mutex> lock(mutex_);
    switch (volteCapInChip) {
        case IMS_SWITCH_OFF:
            UpdateOpcBoolValue(opc, "volte_supported_bool", false);
            break;
        case IMS_SWITCH_ON:
            UpdateOpcBoolValue(opc, "volte_supported_bool", true);
            break;
        case IMS_SWITCH_DEFAULT:
            opc.boolValue["volte_supported_bool"] = true;
            opc.boolValue["hide_ims_switch_bool"] = false;
            opc.boolValue["ims_switch_on_by_default_bool"] = false;
            opc.configValue[Str8ToStr16("volte_supported_bool")] = Str8ToStr16("true");
            opc.configValue[Str8ToStr16("hide_ims_switch_bool")] = Str8ToStr16("false");
            opc.configValue[Str8ToStr16("ims_switch_on_by_default_bool")] = Str8ToStr16("false");
            break;
        default:
            TELEPHONY_LOGE("Invalid volte para!");
            break;
    }
    lock.unlock();
}

int32_t OperatorConfigCache::LoadOperatorConfig(int32_t slotId, OperatorConfig &poc, int32_t state)
{
    auto simFileManager = simFileManager_.lock();
    if (simFileManager == nullptr) {
        TELEPHONY_LOGE("simFileManager is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    std::string iccid = Str16ToStr8(simFileManager->GetSimIccId());
    std::string opkey = GetOpKey(slotId);
    std::string filename = EncryptIccId(iccid + opkey) + ".json";
    if (opkey == std::string(INITIAL_OPKEY)) {
        TELEPHONY_LOGI("load default operator config, slotId = %{public}d", slotId);
        filename = DEFAULT_OPERATOR_CONFIG;
    }
    isLoadingConfig = true;
    TELEPHONY_LOGI("LoadOperatorConfig slotId = %{public}d state = %{public}d, opkey = %{public}s",
        slotId, state, opkey.data());
    cJSON *root = nullptr;
    if (parser_.ParseOperatorConfigFromFile(poc, parser_.GetOperatorConfigFilePath(filename), root)) {
        TELEPHONY_LOGI("load from file success opc size %{public}zu, slotId = %{public}d",
            poc.configValue.size(), slotId);
        if (poc.configValue.size() > 0) {
            // state indicate the case of load operator config
            UpdateCurrentOpc(slotId, poc, state, false);
            root = nullptr;
            return TELEPHONY_ERR_SUCCESS;
        }
    }
    root = cJSON_CreateObject();
    if (parser_.ParseFromCustomSystem(slotId, poc, root)) {
        TELEPHONY_LOGI("load from custom system success, slotId = %{public}d", slotId);
        parser_.WriteOperatorConfigJson(filename, root);

        if (poc.configValue.size() > 0) {
            // state indicate the case of load operator config
            UpdateCurrentOpc(slotId, poc, state, true);
            if (root != nullptr) {
                cJSON_Delete(root);
                root = nullptr;
            }
            return TELEPHONY_ERR_SUCCESS;
        }
    }
    isLoadingConfig = false;
    if (root != nullptr) {
        cJSON_Delete(root);
        root = nullptr;
    }
    return CORE_ERR_OPERATOR_CONF_NOT_EXIT;
}

int32_t OperatorConfigCache::GetOperatorConfigs(int32_t slotId, OperatorConfig &poc)
{
    std::unique_lock<std::mutex> lock(mutex_);
    if (opc_.configValue.size() > 0) {
        TELEPHONY_LOGD("get from memory");
        CopyOperatorConfig(opc_, poc);
        lock.unlock();
        return TELEPHONY_ERR_SUCCESS;
    }
    lock.unlock();
    TELEPHONY_LOGI("reload operator config, slotId = %{public}d", slotId);
    return LoadOperatorConfig(slotId, poc);
}

int32_t OperatorConfigCache::UpdateOperatorConfigs(int32_t slotId)
{
    std::unique_lock<std::mutex> lock(mutex_);
    ClearMemoryCache(slotId);
    lock.unlock();
    if (slotId == 0) {
        TELEPHONY_LOGD("OperatorConfigCache:UpdateOperatorConfigs ClearFilesCache");
        OperatorFileParser::ClearFilesCache();
    }
    OperatorConfig opc;
    int32_t ret = LoadOperatorConfig(slotId_, opc, STATE_PARA_UPDATE);
    return ret;
}

void OperatorConfigCache::CopyOperatorConfig(const OperatorConfig &from, OperatorConfig &to)
{
    for (const auto &it : from.configValue) {
        to.configValue[it.first] = it.second;
    }
    for (const auto &it : from.boolValue) {
        to.boolValue[it.first] = it.second;
    }
    for (const auto &it : from.intValue) {
        to.intValue[it.first] = it.second;
    }
    for (const auto &it : from.longValue) {
        to.longValue[it.first] = it.second;
    }
    for (const auto &it : from.stringValue) {
        to.stringValue[it.first] = it.second;
    }
    for (const auto &it : from.intArrayValue) {
        to.intArrayValue[it.first] = std::vector<int32_t>(it.second);
    }
    for (const auto &it : from.longArrayValue) {
        to.longArrayValue[it.first] = std::vector<int64_t>(it.second);
    }
    for (const auto &it : from.stringArrayValue) {
        to.stringArrayValue[it.first] = std::vector<std::string>(it.second);
    }
}

std::string OperatorConfigCache::GetOpKey(int32_t slotId)
{
    char simOpKey[SYSPARA_SIZE] = { 0 };
    std::string key;
    GetParameter(key.append(OPKEY_PROP_PREFIX).append(std::to_string(slotId)).c_str(), DEFAULT_OPERATOR_KEY,
        simOpKey, SYSPARA_SIZE);
    key.shrink_to_fit();
    return simOpKey;
}

std::string OperatorConfigCache::EncryptIccId(const std::string iccid)
{
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, iccid.c_str(), iccid.size());
    SHA256_Final(hash, &sha256);
    std::string encryptIccId = SIMUtils::BytesConvertToHexString(hash, SHA256_DIGEST_LENGTH);
    return encryptIccId;
}

bool OperatorConfigCache::RegisterForIccChange()
{
    TELEPHONY_LOGI("OperatorConfigCache::RegisterForIccLoaded");
    auto simFileManager = simFileManager_.lock();
    if (simFileManager == nullptr) {
        TELEPHONY_LOGE("OperatorConfigCache::can not get SimFileManager");
        return false;
    }
    simFileManager->RegisterCoreNotify(shared_from_this(), RadioEvent::RADIO_SIM_STATE_CHANGE);
    return true;
}

void OperatorConfigCache::ProcessEvent(const AppExecFwk::InnerEvent::Pointer &event)
{
    if (event == nullptr) {
        TELEPHONY_LOGE("start ProcessEvent but event is null!");
        return;
    }
    SimState simState = SimState::SIM_STATE_UNKNOWN;
    CoreManagerInner::GetInstance().GetSimState(slotId_, simState);
    if (event->GetInnerEventId() == RadioEvent::RADIO_SIM_STATE_CHANGE) {
        TELEPHONY_LOGI("OperatorConfigCache::Sim state change, slotId = %{public}d, simstate = %{public}d",
            slotId_, static_cast<int>(simState));
        if (simState == SimState::SIM_STATE_NOT_PRESENT || simState == SimState::SIM_STATE_LOCKED) {
            std::unique_lock<std::mutex> lock(mutex_);
            ClearOperatorValue(slotId_);
            ClearMemoryCache(slotId_);
            modemSimMatchedOpNameCache_ = "";
            lock.unlock();
            OperatorConfig opc;
            LoadOperatorConfig(slotId_, opc, STATE_PARA_CLEAR);
        }
    }
}

bool OperatorConfigCache::UnRegisterForIccChange()
{
    TELEPHONY_LOGI("OperatorConfigCache::UnRegisterForIccLoaded");
    auto simFileManager = simFileManager_.lock();
    if (simFileManager == nullptr) {
        TELEPHONY_LOGE("OperatorConfigCache::can not get SimFileManager");
        return false;
    }
    simFileManager->UnRegisterCoreNotify(shared_from_this(), RadioEvent::RADIO_SIM_STATE_CHANGE);
    return true;
}

void OperatorConfigCache::SendSimMatchedOperatorInfo(int32_t slotId, int32_t state)
{
    TELEPHONY_LOGI("OperatorConfigCache::SendSimMatchedOperatorInfo, slotId = %{public}d", slotId);
    auto simFileManager = simFileManager_.lock();
    if (simFileManager == nullptr) {
        TELEPHONY_LOGE("OperatorConfigCache::can not get SimFileManager");
        return;
    }
    std::string operName = Str16ToStr8(simFileManager->GetOpName());
    std::string operKey = Str16ToStr8(simFileManager->GetOpKey());
    if (operKey == "") {
        operName = "NULL";
    } else {
        if (modemSimMatchedOpNameCache_ == "") {
            modemSimMatchedOpNameCache_ = operName;
        } else {
            operName = modemSimMatchedOpNameCache_;
        }
    }
    int32_t response = CoreManagerInner::GetInstance().SendSimMatchedOperatorInfo(slotId,
        state, operName, operKey);
    TELEPHONY_LOGI("OperatorConfigCache::SendSimMatchedOperatorInfo slotId[%{public}d], opkey[%{public}s],"
        "opname[%{public}s], response = %{public}d", slotId, operKey.data(), operName.data(), response);
}

void OperatorConfigCache::notifyInitApnConfigs(int32_t slotId)
{
    SimState simState = SimState::SIM_STATE_UNKNOWN;
    CoreManagerInner::GetInstance().GetSimState(slotId, simState);
    if (!(simState == SimState::SIM_STATE_READY || simState == SimState::SIM_STATE_LOADED)) {
        return;
    }
    auto helper = PdpProfileRdbHelper::GetInstance();
    if (helper == nullptr) {
        TELEPHONY_LOGE("get PdpProfileRdbHelper Failed.");
        return;
    }
    TELEPHONY_LOGI("OperatorConfigCache:notifyInitApnConfigs end");
    helper->notifyInitApnConfigs(slotId);
}

bool OperatorConfigCache::AnnounceOperatorConfigChanged(int32_t slotId, int32_t state)
{
    SimState simState = SimState::SIM_STATE_UNKNOWN;
    CoreManagerInner::GetInstance().GetSimState(slotId, simState);
    bool isDataShareError = CoreManagerInner::GetInstance().IsDataShareError();
    TELEPHONY_LOGI("AnnounceOperatorConfigChanged isDataShareError = %{public}d", isDataShareError);
    std::string opkey = GetOpKey(slotId);
    notifyInitApnConfigs(slotId);
    SendSimMatchedOperatorInfo(slotId, state);
    if ((opkey != std::string(INITIAL_OPKEY) && !isDataShareError) ||
        (simState == SimState::SIM_STATE_NOT_PRESENT || simState == SimState::SIM_STATE_NOT_READY ||
            simState == SimState::SIM_STATE_UNKNOWN)) {
        AAFwk::Want want;
        want.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_OPERATOR_CONFIG_CHANGED);
        want.SetParam(KEY_SLOTID, slotId);
        want.SetParam(CHANGE_STATE, state);
        std::string eventData(OPERATOR_CONFIG_CHANGED);
        EventFwk::CommonEventData data;
        data.SetWant(want);
        data.SetData(eventData);
        EventFwk::CommonEventPublishInfo publishInfo;
        publishInfo.SetOrdered(false);
        bool publishResult = EventFwk::CommonEventManager::PublishCommonEvent(data, publishInfo, nullptr);
        TELEPHONY_LOGI("OperatorConfigCache:AnnounceOperatorConfigChanged end. result = %{public}d, opkey: %{public}s,"
            "slotId: %{public}d, state: %{public}d", publishResult, opkey.data(), slotId, state);
        return publishResult;
    }
    TELEPHONY_LOGI("AnnounceOperatorConfigChanged dont publish OPERATOR_CONFIG_CHANGED opkey is %{public}s,"
        "slotId: %{public}d, state: %{public}d", opkey.data(), slotId, state);
    return true;
}

bool OperatorConfigCache::IsNeedOperatorLoad(int32_t slotId)
{
    std::string opkey = GetOpKey(slotId);
    TELEPHONY_LOGI("IsNeedOperatorLoad slotId %{public}d opkey %{public}s isLoadingConfig: %{public}d",
        slotId, opkey.data(), isLoadingConfig);
    if (opkey.empty() || opkey == std::string(INITIAL_OPKEY)) {
        return true;
    }
    if (isLoadingConfig) {
        return false;
    }
    auto simFileManager = simFileManager_.lock();
    if (simFileManager == nullptr) {
        TELEPHONY_LOGI("simFileManager is nullptr");
        return true;
    }
    std::string iccid = Str16ToStr8(simFileManager->GetSimIccId());
    std::string filename = EncryptIccId(iccid + opkey) + ".json";
    std::string path = parser_.GetOperatorConfigFilePath(filename);
    std::ifstream f(path.c_str());
    return !f.good();
}

void OperatorConfigCache::UpdateImsCapFromChip(int32_t slotId, const ImsCapFromChip &imsCapFromChip)
{
    TELEPHONY_LOGI("[slot%{public}d] imsCapFromChip = %{public}d, %{public}d, %{public}d, %{public}d",
        slotId,
        imsCapFromChip.volteCap,
        imsCapFromChip.vowifiCap,
        imsCapFromChip.vonrCap,
        imsCapFromChip.vtCap);

    int32_t volteCap = imsCapFromChip.volteCap;
    std::string volteCapKey = KEY_PERSIST_TELEPHONY_VOLTE_CAP_IN_CHIP + std::to_string(slotId);
    std::string strvolteCap = std::to_string(volteCap);
    SetParameter(volteCapKey.c_str(), strvolteCap.c_str());
    UpdatevolteCap(slotId, opc_);
}
} // namespace Telephony
} // namespace OHOS
