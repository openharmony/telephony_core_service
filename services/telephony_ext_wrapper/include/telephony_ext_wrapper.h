/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef TELEPHONY_EXT_WRAPPER_H
#define TELEPHONY_EXT_WRAPPER_H

#include "nocopyable.h"
#include "singleton.h"

namespace OHOS {
namespace Telephony {
class TelephonyExtWrapper final {
DECLARE_DELAYED_REF_SINGLETON(TelephonyExtWrapper);

public:
    DISALLOW_COPY_AND_MOVE(TelephonyExtWrapper);
    void InitTelephonyExtWrapper();

    typedef bool (*CHECK_OPC_VERSION_IS_UPDATE)(void);
    typedef void (*UPDATE_OPC_VERSION)(void);
    typedef char* (*GET_VOICE_MAIL_ICCID_PARAMETER)(int32_t, const char*);
    typedef void (*SET_VOICE_MAIL_ICCID_PARAMETER)(int32_t, const char*, const char*);
    typedef void (*INIT_VOICE_MAIL_MANAGER_EXT)(int32_t);
    typedef void (*DEINIT_VOICE_MAIL_MANAGER_EXT)(int32_t);
    typedef void (*RESET_VOICE_MAIL_LOADED_FLAG_EXT)(int32_t);
    typedef void (*SET_VOICE_MAIL_ON_SIM_EXT)(int32_t, const char*, const char*);
    typedef bool (*GET_VOICE_MAIL_FIXED_EXT)(int32_t, const char*);
    typedef char* (*GET_VOICE_MAIL_NUMBER_EXT)(int32_t, const char*);
    typedef char* (*GET_VOICE_MAIL_TAG_EXT)(int32_t, const char*);

    CHECK_OPC_VERSION_IS_UPDATE checkOpcVersionIsUpdate_ = nullptr;
    UPDATE_OPC_VERSION updateOpcVersion_ = nullptr;
    GET_VOICE_MAIL_ICCID_PARAMETER getVoiceMailIccidParameter_ = nullptr;
    SET_VOICE_MAIL_ICCID_PARAMETER setVoiceMailIccidParameter_ = nullptr;
    INIT_VOICE_MAIL_MANAGER_EXT initVoiceMailManagerExt_ = nullptr;
    DEINIT_VOICE_MAIL_MANAGER_EXT deinitVoiceMailManagerExt_ = nullptr;
    RESET_VOICE_MAIL_LOADED_FLAG_EXT resetVoiceMailLoadedFlagExt_ = nullptr;
    SET_VOICE_MAIL_ON_SIM_EXT setVoiceMailOnSimExt_ = nullptr;
    GET_VOICE_MAIL_FIXED_EXT getVoiceMailFixedExt_ = nullptr;
    GET_VOICE_MAIL_NUMBER_EXT getVoiceMailNumberExt_ = nullptr;
    GET_VOICE_MAIL_TAG_EXT getVoiceMailTagExt_ = nullptr;

private:
    void* telephonyExtWrapperHandle_ = nullptr;
};

#define TELEPHONY_EXT_WRAPPER ::OHOS::DelayedRefSingleton<TelephonyExtWrapper>::GetInstance()
} // namespace Telephony
} // namespace OHOS
#endif // TELEPHONY_EXT_WRAPPER_H
