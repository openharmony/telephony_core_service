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
#include "telephony_ext_wrapper.h"
#include "core_manager_inner.h"
#include "sim_data.h"
#include <openssl/sha.h>

#ifdef  CORE_SERVICE_SUPPORT_ESIM
#include "reset_response.h"
#endif

namespace OHOS {
namespace Telephony {
static const std::string PARAM_SIMID = "simId";
static const std::string PARAM_SLOTID = "slotId";
static const int32_t EVENT_CODE = 1;
static constexpr int32_t DEC_TYPE = 10;
static const std::string DEFAULT_SMS_SIMID_CHANGED = "defaultSmsSimIdChanged";
static const std::string DEFAULT_MAIN_SIMID_CHANGED = "defaultMainSimIdChanged";
static const std::string DEFAULT_VOICE_SIMID_CHANGED = "defaultVoiceSimIdChanged";
static const std::string DEFAULT_CELLULAR_DATA_SIMID_CHANGED = "defaultCellularDataSimIdChanged";
static const std::string PARAM_SET_PRIMARY_STATUS = "setDone";
static const std::string PARAM_SET_PRIMARY_IS_USER_SET = "isUserSet";
static const std::string SIM_LABEL_STATE_PROP = "persist.ril.sim_switch";
static const int32_t CARD_ATR_LEN = 65;
static constexpr int32_t SLOT_ID_0 = 0;
static constexpr int32_t SLOT_ID_1 = 1;
static constexpr int32_t SLOT_ID_2 = 2;
static constexpr int32_t SLOT_ID_3 = 3;
constexpr int32_t PSIM1 = 1;
constexpr int32_t PSIM2 = 2;
constexpr int32_t PSIM1_PSIM2 = 0;
constexpr int32_t PSIM1_ESIM = 1;
constexpr int32_t PSIM2_ESIM = 2;

#ifdef CORE_SERVICE_SUPPORT_ESIM
static const std::string GSM_SIM_ATR = "gsm.sim.hw_atr";
static const std::string GSM_SIM_ATR1 = "gsm.sim.hw_atr1";
static const std::string GSM_SIM_ATR2 = "gsm.sim.hw_atr2";
static const std::string GSM_SIM_ATR3 = "gsm.sim.hw_atr3";
#endif

MultiSimHelper::MultiSimHelper()
{
tstsMode_ = OHOS::system::GetIntParameter("persist.telephony.tsts_mode", 0);
}

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

bool MultiSimHelper::AnnouncePrimarySimIdChanged(int32_t simId, int32_t slotId)
{
    AAFwk::Want want;
    want.SetParam(PARAM_SIMID, simId);
    want.SetParam(PARAM_SLOTID, slotId);
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

std::string MultiSimHelper::EncryptIccId(const std::string &iccid)
{
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, iccid.c_str(), iccid.size());
    SHA256_Final(hash, &sha256);
    std::string encryptIccId = SIMUtils::BytesConvertToHexString(hash, SHA256_DIGEST_LENGTH);
    return encryptIccId;
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

void MultiSimHelper::BuildSimPresentValues(int32_t slotId, DataShare::DataShareValuesBucket &values,
    const std::string &iccId)
{
    DataShare::DataShareValueObject slotObj(INVALID_VALUE);
    DataShare::DataShareValueObject iccidObj(iccId);
    DataShare::DataShareValueObject valueObj(ACTIVE);
    DataShare::DataShareValueObject simLabelIndexObj(slotId + 1);
    DataShare::DataShareValueObject isEsimObj(false);
    DataShare::DataShareValueObject notMainCardObj(NOT_MAIN);
    values.Put(SimData::SLOT_INDEX, slotObj);
    values.Put(SimData::ICC_ID, iccidObj);
    values.Put(SimData::CARD_ID, iccidObj);
    values.Put(SimData::IS_ACTIVE, valueObj);
    values.Put(SimData::SIM_LABEL_INDEX, simLabelIndexObj);
    values.Put(SimData::IS_ESIM, isEsimObj);
    values.Put(SimData::IS_MAIN_CARD, notMainCardObj);
    values.Put(SimData::IS_VOICE_CARD, notMainCardObj);
    values.Put(SimData::IS_MESSAGE_CARD, notMainCardObj);
    values.Put(SimData::IS_CELLULAR_DATA_CARD, notMainCardObj);
}

bool MultiSimHelper::IsValidSlotString(const char* slotIdStr)
{
    if (slotIdStr == nullptr) {
        return false;
    }
    bool isValid = true;
    for (int i = 0; slotIdStr[i] != '\0'; ++i) {
        if (!std::isdigit(slotIdStr[i])) {
            isValid = false;
            break;
        }
    }
    return isValid;
}

int32_t MultiSimHelper::GetPsimLabelIndex(int slotId)
{
    if (IsEsim(slotId)) {
        TELEPHONY_LOGE("GetPsimLabelIndex error sim type");
        return PSIM1;
    }
    if (tstsMode_) {
        int32_t simLabelindex = PSIM1;
        if (!TELEPHONY_EXT_WRAPPER.GetSimLabelIndexFromLsiCfg(slotId, simLabelindex)) {
            TELEPHONY_LOGE("TELEPHONY_EXT_WRAPPER failed");
        }
        TELEPHONY_LOGI("GetPsimLabelIndex simLabelindex = %{public}d", simLabelindex);
        return simLabelindex;
    }

    int32_t simLabelState = OHOS::system::GetIntParameter(SIM_LABEL_STATE_PROP, PSIM1_PSIM2);
    if (simLabelState == PSIM1_PSIM2) {
        return slotId == 0 ? PSIM1 : PSIM2;
    } else {
        return simLabelState == PSIM1_ESIM ? PSIM1 : PSIM2;
    }
}

bool MultiSimHelper::IsEsim(int32_t slotId)
{
#ifdef CORE_SERVICE_SUPPORT_ESIM
    if (!CoreManagerInner::GetInstance().IsSupported(slotId)) {
        return false;
    }
    std::string propAtr = "";
    propAtr = (slotId == SLOT_ID_0) ? GSM_SIM_ATR : propAtr;
    propAtr = (slotId == SLOT_ID_1) ? GSM_SIM_ATR1 : propAtr;
    propAtr = (slotId == SLOT_ID_2) ? GSM_SIM_ATR2 : propAtr;
    propAtr = (slotId == SLOT_ID_3) ? GSM_SIM_ATR3 : propAtr;
    if (propAtr.empty()) {
        TELEPHONY_LOGE("slotId %{public}d invalid, can't get atr prop.", slotId);
        return false;
    }

    char buf[CARD_ATR_LEN + 1] = {0};
    GetParameter(propAtr.c_str(), "", buf, CARD_ATR_LEN);
    std::string cardAtr(buf);
    if (cardAtr.empty()) {
        TELEPHONY_LOGE("card atr is empty.");
        return false;
    }

    ResetResponse resetResponse;
    resetResponse.AnalysisAtrData(cardAtr);
    TELEPHONY_LOGI("slot%{public}d isEsim: %{public}s", slotId, resetResponse.IsEuiccAvailable() ? "true" : "false");
    return resetResponse.IsEuiccAvailable();
#else
    return false;
#endif
}
}
}
