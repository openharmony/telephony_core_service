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
    std::unique_lock<std::mutex> lock(mutex_);
    CopyOperatorConfig(poc, opc_);
    lock.unlock();
    AnnounceOperatorConfigChanged(slotId, state);
    if (needUpdateLoading) {
        isLoadingConfig = false;
    }
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
        TELEPHONY_LOGI("load default operator config");
        filename = DEFAULT_OPERATOR_CONFIG;
    }
    isLoadingConfig = true;
    SimState simState = SimState::SIM_STATE_UNKNOWN;
    CoreManagerInner::GetInstance().GetSimState(slotId, simState);
    TELEPHONY_LOGI("LoadOperatorConfig slotId = %{public}d simState = %{public}d", slotId, simState);
    cJSON *root = nullptr;
    if (parser_.ParseOperatorConfigFromFile(poc, parser_.GetOperatorConfigFilePath(filename), root)) {
        TELEPHONY_LOGI("load from file success opc size %{public}zu", poc.configValue.size());
        if (poc.configValue.size() > 0) {
            // state indicate the case of load operator config
            UpdateCurrentOpc(slotId, poc, state, false);
            root = nullptr;
            return TELEPHONY_ERR_SUCCESS;
        }
    }
    root = cJSON_CreateObject();
    if (parser_.ParseFromCustomSystem(slotId, poc, root)) {
        TELEPHONY_LOGI("load from custom system success");
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
    TELEPHONY_LOGI("reload operator config");
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
        TELEPHONY_LOGI("OperatorConfigCache::Sim state change");
        if (simState == SimState::SIM_STATE_NOT_PRESENT || simState == SimState::SIM_STATE_LOCKED) {
            std::unique_lock<std::mutex> lock(mutex_);
            ClearOperatorValue(slotId_);
            ClearMemoryCache(slotId_);
            modemSimMatchedOpNameCache_ = "";
            lock.unlock();
            OperatorConfig opc;
            LoadOperatorConfig(slotId_, opc);
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

void OperatorConfigCache::SendSimMatchedOperatorInfo(int32_t slotId)
{
    TELEPHONY_LOGI("OperatorConfigCache::SendSimMatchedOperatorInfo");
    auto simFileManager = simFileManager_.lock();
    if (simFileManager == nullptr) {
        TELEPHONY_LOGE("OperatorConfigCache::can not get SimFileManager");
        return;
    }
    SimState simState = SimState::SIM_STATE_UNKNOWN;
    CoreManagerInner::GetInstance().GetSimState(slotId_, simState);
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
        static_cast<int32_t>(simState), operName, operKey);
    TELEPHONY_LOGI("OperatorConfigCache::SendSimMatchedOperatorInfo response = %{public}d", response);
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
    notifyInitApnConfigs(slotId);
    SendSimMatchedOperatorInfo(slotId);
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
    TELEPHONY_LOGI("OperatorConfigCache:AnnounceOperatorConfigChanged end###result = %{public}d", publishResult);
    return publishResult;
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
} // namespace Telephony
} // namespace OHOS
