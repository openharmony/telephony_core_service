/*
 * Copyright (C) 2026-2026 Huawei Device Co., Ltd.
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

#include "multi_sim_helper.h"
#include "sim_data.h"
#include <openssl/sha.h>

namespace OHOS {
namespace Telephony {
static const std::string PARAM_SIMID = "simId";
static const int32_t EVENT_CODE = 1;
static const std::string DEFAULT_SMS_SIMID_CHANGED = "defaultSmsSimIdChanged";
static const std::string DEFAULT_MAIN_SIMID_CHANGED = "defaultMainSimIdChanged";
static const std::string DEFAULT_VOICE_SIMID_CHANGED = "defaultVoiceSimIdChanged";
static const std::string DEFAULT_CELLULAR_DATA_SIMID_CHANGED = "defaultCellularDataSimIdChanged";
static const std::string PARAM_SET_PRIMARY_STATUS = "setDone";
static const std::string PARAM_SET_PRIMARY_IS_USER_SET = "isUserSet";

MultiSimHelper::MultiSimHelper()
{}

MultiSimHelper::~MultiSimHelper()
{}

bool MultiSimHelper::AnnounceDefaultSmsSimIdChanged(int32_t simId)
{
    AAFwk::Want want;
    want.SetParam(PARAM_SIMID, simId);
    want.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_SIM_CARD_DEFAULT_SMS_SUBSCRIPTION_CHANGED);
    int32_t eventCode = EVENT_CODE;
    std::string eventData(DEFAULT_SMS_SIMID_CHANGED);
    return PublishSimFileEvent(want, eventCode, eventData);
}

bool MultiSimHelper::AnnounceDefaultCellularDataSimIdChanged(int32_t simId)
{
    AAFwk::Want want;
    want.SetParam(PARAM_SIMID, simId);
    want.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_SIM_CARD_DEFAULT_DATA_SUBSCRIPTION_CHANGED);
    int32_t eventCode = EVENT_CODE;
    std::string eventData(DEFAULT_CELLULAR_DATA_SIMID_CHANGED);
    return PublishSimFileEvent(want, eventCode, eventData);
}

bool MultiSimHelper::AnnouncePrimarySimIdChanged(int32_t simId)
{
    AAFwk::Want want;
    want.SetParam(PARAM_SIMID, simId);
    want.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_SIM_CARD_DEFAULT_MAIN_SUBSCRIPTION_CHANGED);
    int32_t eventCode = EVENT_CODE;
    std::string eventData(DEFAULT_MAIN_SIMID_CHANGED);
    return PublishSimFileEvent(want, eventCode, eventData);
}

bool MultiSimHelper::AnnounceDefaultVoiceSimIdChanged(int32_t simId)
{
    AAFwk::Want want;
    want.SetParam(PARAM_SIMID, simId);
    want.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_SIM_CARD_DEFAULT_VOICE_SUBSCRIPTION_CHANGED);
    int32_t eventCode = EVENT_CODE;
    std::string eventData(DEFAULT_VOICE_SIMID_CHANGED);
    return PublishSimFileEvent(want, eventCode, eventData);
}

void MultiSimHelper::PublishSetPrimaryEvent(bool setDone, bool isUserSet)
{
    AAFwk::Want want;
    want.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_SET_PRIMARY_SLOT_STATUS);
    want.SetParam(PARAM_SET_PRIMARY_STATUS, setDone);
    want.SetParam(PARAM_SET_PRIMARY_IS_USER_SET, isUserSet);
    EventFwk::CommonEventData data;
    data.SetWant(want);

    EventFwk::CommonEventPublishInfo publishInfo;
    publishInfo.SetSticky(true);
    bool publishResult = EventFwk::CommonEventManager::PublishCommonEvent(data, publishInfo, nullptr);
    TELEPHONY_LOGI("setDone: %{public}d, isUserSet: %{public}d, result: %{public}d", setDone, isUserSet, publishResult);
}

bool MultiSimHelper::PublishSimFileEvent(const AAFwk::Want &want, int eventCode, const std::string &eventData)
{
    EventFwk::CommonEventData data;
    data.SetWant(want);
    data.SetCode(eventCode);
    data.SetData(eventData);
    EventFwk::CommonEventPublishInfo publishInfo;
    publishInfo.SetOrdered(false);
    bool publishResult = EventFwk::CommonEventManager::PublishCommonEvent(data, publishInfo, nullptr);
    return publishResult;
}

std::string MultiSimHelper::EncryptIccId(const std::string iccid)
{
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, iccid.c_str(), iccid.size());
    SHA256_Final(hash, &sha256);
    std::string encryptIccId = SIMUtils::BytesConvertToHexString(hash, SHA256_DIGEST_LENGTH);
    return encryptIccId;
}

bool MultiSimHelper::PrepareCacheForSync(std::vector<SimRdbInfo> &cache)
{
    TELEPHONY_LOGI("PrepareCacheForSync: cache size=%{public}zu", cache.size());
    return true;
}

void MultiSimHelper::SimDataBuilder(int32_t slotId, DataShare::DataShareValuesBucket &values,
    const std::string &iccId, int32_t simLabel, bool isEsim)
{
    DataShare::DataShareValueObject slotObj(slotId);
    DataShare::DataShareValueObject iccidObj(iccId);
    DataShare::DataShareValueObject valueObj(ACTIVE);
    DataShare::DataShareValueObject simLabelIndexObj(simLabel);
    DataShare::DataShareValueObject isEsimObj(isEsim);
    values.Put(SimData::SLOT_INDEX, slotObj);
    values.Put(SimData::ICC_ID, iccidObj);
    values.Put(SimData::CARD_ID, iccidObj); // iccId == cardId by now
    values.Put(SimData::IS_ACTIVE, valueObj);
    values.Put(SimData::IS_ESIM, isEsimObj);
    values.Put(SimData::SIM_LABEL_INDEX, simLabelIndexObj);
    if (SIM_SLOT_COUNT == 1) {
        DataShare::DataShareValueObject mainCardObj(MAIN_CARD);
        values.Put(SimData::IS_MAIN_CARD, mainCardObj);
        values.Put(SimData::IS_VOICE_CARD, mainCardObj);
        values.Put(SimData::IS_MESSAGE_CARD, mainCardObj);
        values.Put(SimData::IS_CELLULAR_DATA_CARD, mainCardObj);
    } else {
        DataShare::DataShareValueObject notMainCardObj(NOT_MAIN);
        values.Put(SimData::IS_MAIN_CARD, notMainCardObj);
        values.Put(SimData::IS_VOICE_CARD, notMainCardObj);
        values.Put(SimData::IS_MESSAGE_CARD, notMainCardObj);
        values.Put(SimData::IS_CELLULAR_DATA_CARD, notMainCardObj);
    }
}

}
}