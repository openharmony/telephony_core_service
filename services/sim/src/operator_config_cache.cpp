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

namespace OHOS {
namespace Telephony {
OperatorConfigCache::OperatorConfigCache(const std::shared_ptr<AppExecFwk::EventRunner> &runner,
    std::shared_ptr<SimFileManager> simFileManager, int32_t slotId)
    : AppExecFwk::EventHandler(runner), simFileManager_(simFileManager), slotId_(slotId)
{
    TELEPHONY_LOGI("OperatorConfigCache create");
}

void OperatorConfigCache::ClearAllCache(int32_t slotId)
{
    ClearMemoryCache(slotId);
    parser_.ClearFilesCache();
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

bool OperatorConfigCache::LoadOperatorConfig(int32_t slotId, OperatorConfig &poc)
{
    if (simFileManager_ == nullptr) {
        TELEPHONY_LOGE("simFileManager_ is nullptr");
        return false;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    std::string iccid = Str16ToStr8(simFileManager_->GetSimIccId());
    std::string filename = EncryptIccId(iccid) + ".json";
    Json::Value opcJson;
    int32_t simState = CoreManagerInner::GetInstance().GetSimState(slotId_);
    bool canReadOrSaveCache = !(iccid.empty()) && simState != static_cast<int32_t>(SimState::SIM_STATE_NOT_PRESENT) &&
        simState != static_cast<int32_t>(SimState::SIM_STATE_LOCKED);
    if (canReadOrSaveCache &&
        parser_.ParseOperatorConfigFromFile(poc, parser_.GetOperatorConfigFilePath(filename), opcJson)) {
        TELEPHONY_LOGI("load from file success opc size %{public}zu", poc.configValue.size());
        if (poc.configValue.size() > 0) {
            CopyOperatorConfig(poc, opc_);
            AnnounceOperatorConfigChanged(slotId);
            return true;
        }
    }
    if (parser_.ParseFromCustomSystem(slotId, poc, opcJson)) {
        TELEPHONY_LOGI("load from custom system success");
        if (canReadOrSaveCache) {
            TELEPHONY_LOGI("save cache");
            parser_.WriteOperatorConfigJson(filename, opcJson);
        }
        if (poc.configValue.size() > 0) {
            CopyOperatorConfig(poc, opc_);
            AnnounceOperatorConfigChanged(slotId);
            return true;
        }
    }
    return false;
}

bool OperatorConfigCache::GetOperatorConfigs(int32_t slotId, OperatorConfig &poc)
{
    if (opc_.configValue.size() > 0) {
        TELEPHONY_LOGI("get from memory");
        CopyOperatorConfig(opc_, poc);
        return true;
    }
    TELEPHONY_LOGI("reload operator config");
    return LoadOperatorConfig(slotId, poc);
}

void OperatorConfigCache::CopyOperatorConfig(const OperatorConfig &from, OperatorConfig &to)
{
    for (auto it : from.configValue) {
        to.configValue[it.first] = it.second;
    }
    for (auto it : from.boolValue) {
        to.boolValue[it.first] = it.second;
    }
    for (auto it : from.intValue) {
        to.intValue[it.first] = it.second;
    }
    for (auto it : from.longValue) {
        to.longValue[it.first] = it.second;
    }
    for (auto it : from.stringValue) {
        to.stringValue[it.first] = it.second;
    }
    for (auto it : from.intArrayValue) {
        to.intArrayValue[it.first] = std::vector<int32_t>(it.second);
    }
    for (auto it : from.longArrayValue) {
        to.longArrayValue[it.first] = std::vector<int64_t>(it.second);
    }
    for (auto it : from.stringArrayValue) {
        to.stringArrayValue[it.first] = std::vector<std::string>(it.second);
    }
}

std::string OperatorConfigCache::GetOpKey(int32_t slotId)
{
    char simOpKey[SYSPARA_SIZE] = { 0 };
    std::string key;
    GetParameter(key.append(OPKEY_PROP_PREFIX).append(std::to_string(slotId)).c_str(), DEFAULT_OPERATOR_KEY.c_str(),
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
    if (simFileManager_ == nullptr) {
        TELEPHONY_LOGE("OperatorConfigCache::can not get SimFileManager");
        return false;
    }
    simFileManager_->RegisterCoreNotify(shared_from_this(), RadioEvent::RADIO_SIM_STATE_CHANGE);
    return true;
}

void OperatorConfigCache::ProcessEvent(const AppExecFwk::InnerEvent::Pointer &event)
{
    if (event == nullptr) {
        TELEPHONY_LOGE("start ProcessEvent but event is null!");
        return;
    }
    int32_t simState = CoreManagerInner::GetInstance().GetSimState(slotId_);
    if (event->GetInnerEventId() == RadioEvent::RADIO_SIM_STATE_CHANGE) {
        TELEPHONY_LOGI("OperatorConfigCache::Sim state change");
        if (simState == static_cast<int32_t>(SimState::SIM_STATE_NOT_PRESENT) ||
            simState == static_cast<int32_t>(SimState::SIM_STATE_LOCKED)) {
            ClearMemoryCache(slotId_);
            OperatorConfig opc;
            LoadOperatorConfig(slotId_, opc);
        }
    }
}

bool OperatorConfigCache::UnRegisterForIccChange()
{
    TELEPHONY_LOGI("OperatorConfigCache::UnRegisterForIccLoaded");
    if (simFileManager_ == nullptr) {
        TELEPHONY_LOGE("OperatorConfigCache::can not get SimFileManager");
        return false;
    }
    simFileManager_->UnRegisterCoreNotify(shared_from_this(), RadioEvent::RADIO_SIM_STATE_CHANGE);
    return true;
}

bool OperatorConfigCache::AnnounceOperatorConfigChanged(int32_t slotId)
{
    AAFwk::Want want;
    want.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_OPERATOR_CONFIG_CHANGED);
    want.SetParam(KEY_SLOTID, slotId);
    std::string eventData(OPERATOR_CONFIG_CHANGED);
    EventFwk::CommonEventData data;
    data.SetWant(want);
    data.SetData(eventData);
    EventFwk::CommonEventPublishInfo publishInfo;
    publishInfo.SetOrdered(true);
    bool publishResult = EventFwk::CommonEventManager::PublishCommonEvent(data, publishInfo, nullptr);
    TELEPHONY_LOGI("OperatorConfigCache:AnnounceOperatorConfigChanged end###result = %{public}d", publishResult);
    return publishResult;
}
} // namespace Telephony
} // namespace OHOS
