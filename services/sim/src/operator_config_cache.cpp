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

#include <json/json.h>
#include <openssl/sha.h>
#include <string_ex.h>
#include <telephony_types.h>

#include "common_event_manager.h"
#include "common_event_support.h"
#include "core_manager_inner.h"
#include "radio_event.h"
#include "telephony_ext_wrapper.h"

namespace OHOS {
namespace Telephony {
OperatorConfigCache::OperatorConfigCache(std::weak_ptr<SimFileManager> simFileManager, int32_t slotId)
    : TelEventHandler("OperatorConfigCache"), simFileManager_(simFileManager), slotId_(slotId)
{
    TELEPHONY_LOGI("OperatorConfigCache create");
    if (TELEPHONY_EXT_WRAPPER.checkOpcVersionIsUpdate_ != nullptr &&
        TELEPHONY_EXT_WRAPPER.updateOpcVersion_ != nullptr) {
        if (TELEPHONY_EXT_WRAPPER.checkOpcVersionIsUpdate_()) {
            ClearAllCache(slotId);
            TELEPHONY_LOGI("clear all cache done");
            TELEPHONY_EXT_WRAPPER.updateOpcVersion_();
        }
    }
}

void OperatorConfigCache::ClearAllCache(int32_t slotId)
{
    std::unique_lock<std::mutex> lock(mutex_);
    ClearOperatorValue(slotId);
    ClearMemoryCache(slotId);
    parser_.ClearFilesCache();
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

int32_t OperatorConfigCache::LoadOperatorConfig(int32_t slotId, OperatorConfig &poc)
{
    auto simFileManager = simFileManager_.lock();
    if (simFileManager == nullptr) {
        TELEPHONY_LOGE("simFileManager is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    std::string iccid = Str16ToStr8(simFileManager->GetSimIccId());
    std::string filename = EncryptIccId(iccid) + ".json";
    std::string opkey = GetOpKey(slotId);
    if (opkey == std::string(INITIAL_OPKEY)) {
        TELEPHONY_LOGI("load default operator config");
        filename = DEFAULT_OPERATOR_CONFIG;
    }
    SimState simState = SimState::SIM_STATE_UNKNOWN;
    CoreManagerInner::GetInstance().GetSimState(slotId, simState);
    TELEPHONY_LOGI("LoadOperatorConfig simState = %{public}d", simState);
    bool canAnnounceChanged = (simState == SimState::SIM_STATE_NOT_PRESENT || simState == SimState::SIM_STATE_READY);
    Json::Value opcJson;
    if (parser_.ParseOperatorConfigFromFile(poc, parser_.GetOperatorConfigFilePath(filename), opcJson)) {
        TELEPHONY_LOGI("load from file success opc size %{public}zu", poc.configValue.size());
        if (poc.configValue.size() > 0) {
            std::unique_lock<std::mutex> lock(mutex_);
            CopyOperatorConfig(poc, opc_);
            lock.unlock();
            if (canAnnounceChanged) {
                AnnounceOperatorConfigChanged(slotId);
            }
            return TELEPHONY_ERR_SUCCESS;
        }
    }
    if (parser_.ParseFromCustomSystem(slotId, poc, opcJson)) {
        TELEPHONY_LOGI("load from custom system success");
        parser_.WriteOperatorConfigJson(filename, opcJson);

        if (poc.configValue.size() > 0) {
            std::unique_lock<std::mutex> lock(mutex_);
            CopyOperatorConfig(poc, opc_);
            lock.unlock();
            if (canAnnounceChanged) {
                AnnounceOperatorConfigChanged(slotId);
            }
            return TELEPHONY_ERR_SUCCESS;
        }
    }
    return CORE_ERR_OPERATOR_CONF_NOT_EXIT;
}

int32_t OperatorConfigCache::GetOperatorConfigs(int32_t slotId, OperatorConfig &poc)
{
    if (opc_.configValue.size() > 0) {
        TELEPHONY_LOGI("get from memory");
        std::unique_lock<std::mutex> lock(mutex_);
        CopyOperatorConfig(opc_, poc);
        lock.unlock();
        return TELEPHONY_ERR_SUCCESS;
    }
    TELEPHONY_LOGI("reload operator config");
    return LoadOperatorConfig(slotId, poc);
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
    int32_t response = CoreManagerInner::GetInstance().SendSimMatchedOperatorInfo(slotId,
        static_cast<int32_t>(simState), operName, operKey);
    TELEPHONY_LOGI("OperatorConfigCache::SendSimMatchedOperatorInfo response = %{public}d", response);
}

bool OperatorConfigCache::AnnounceOperatorConfigChanged(int32_t slotId)
{
    SendSimMatchedOperatorInfo(slotId);
    AAFwk::Want want;
    want.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_OPERATOR_CONFIG_CHANGED);
    want.SetParam(KEY_SLOTID, slotId);
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
} // namespace Telephony
} // namespace OHOS
