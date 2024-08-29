/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "voice_mail_constants.h"

#include <unistd.h>

#include "core_manager_inner.h"
#include "string_ex.h"
#include "telephony_ext_wrapper.h"

using namespace std;

namespace OHOS {
namespace Telephony {
VoiceMailConstants::VoiceMailConstants(int32_t slotId)
{
    slotId_ = slotId;
    if (TELEPHONY_EXT_WRAPPER.initVoiceMailManagerExt_ != nullptr) {
        TELEPHONY_EXT_WRAPPER.initVoiceMailManagerExt_(slotId);
    }
}

VoiceMailConstants::~VoiceMailConstants()
{
    if (TELEPHONY_EXT_WRAPPER.deinitVoiceMailManagerExt_ != nullptr) {
        TELEPHONY_EXT_WRAPPER.deinitVoiceMailManagerExt_(slotId_);
    }
}

std::string VoiceMailConstants::GetStringValueFromCust(int32_t slotId, std::string key)
{
    OperatorConfig operatorConfig;
    CoreManagerInner::GetInstance().GetOperatorConfigs(slotId, operatorConfig);
    std::string value = "";
    std::map<std::string, std::string>::iterator it = operatorConfig.stringValue.begin();
    it = operatorConfig.stringValue.find(key);
    if (it != operatorConfig.stringValue.end()) {
        value = it->second;
    }
    return value;
}

void VoiceMailConstants::ResetVoiceMailLoadedFlag()
{
    if (TELEPHONY_EXT_WRAPPER.resetVoiceMailLoadedFlagExt_ != nullptr) {
        TELEPHONY_LOGI("VoiceMailConstants::ResetVoiceMailLoadedFlag, resetVoiceMailLoadedFlagExt_");
        TELEPHONY_EXT_WRAPPER.resetVoiceMailLoadedFlagExt_(slotId_);
        return;
    }
    isVoiceMailFixed_ = false;
}

bool VoiceMailConstants::GetVoiceMailFixed(std::string carrier)
{
    if (TELEPHONY_EXT_WRAPPER.getVoiceMailFixedExt_ != nullptr) {
        TELEPHONY_LOGI("VoiceMailConstants::GetVoiceMailFixed, getVoiceMailFixedExt_");
        return TELEPHONY_EXT_WRAPPER.getVoiceMailFixedExt_(slotId_, carrier.c_str());
    }
    isVoiceMailFixed_ = true;
    return isVoiceMailFixed_;
}

std::string VoiceMailConstants::GetVoiceMailNumber(std::string carrier)
{
    if (TELEPHONY_EXT_WRAPPER.getVoiceMailNumberExt_ != nullptr) {
        TELEPHONY_LOGI("VoiceMailConstants::GetVoiceMailNumber, getVoiceMailNumberExt_");
        std::string number = "";
        TELEPHONY_EXT_WRAPPER.getVoiceMailNumberExt_(slotId_, carrier.c_str(), number);
        return number;
    }
    return GetStringValueFromCust(slotId_, KEY_VOICE_MAIL_NUMBER_STRING);
}

std::string VoiceMailConstants::GetVoiceMailTag(std::string carrier)
{
    if (TELEPHONY_EXT_WRAPPER.getVoiceMailTagExt_ != nullptr) {
        TELEPHONY_LOGI("VoiceMailConstants::GetVoiceMailTag, getVoiceMailTagExt_");
        std::string tag = "";
        TELEPHONY_EXT_WRAPPER.getVoiceMailTagExt_(slotId_, carrier.c_str(), tag);
        return tag;
    }
    return GetStringValueFromCust(slotId_, KEY_VOICE_MAIL_TAG_STRING);
}

std::string VoiceMailConstants::LoadVoiceMailConfigFromCard(std::string configName, std::string carrier)
{
    if (carrier.empty()) {
        return "";
    }
    return GetStringValueFromCust(slotId_, configName);
}

bool VoiceMailConstants::ContainsCarrier(std::string carrier)
{
    std::string carrierName = LoadVoiceMailConfigFromCard(KEY_VOICE_MAIL_CARRIER_STRING, carrier);
    return !carrierName.empty();
}
} // namespace Telephony
} // namespace OHOS
