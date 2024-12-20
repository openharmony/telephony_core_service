/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#ifndef IESIM_SERVICE_CALLBACK_H
#define IESIM_SERVICE_CALLBACK_H

#include <iremote_proxy.h>

namespace OHOS {
namespace Telephony {
class IEsimServiceCallback : public IRemoteBroker {
public:
    virtual ~IEsimServiceCallback() = default;
    enum class EsimServiceCallback {
        GET_EUICCINFO_RESULT = 0,
		GET_DOWNLOADABLE_PROFILE_METADATA_RESULT,
		GET_DOWNLOADABLE_PROFILES_RESULT,
		GET_EUICC_PROFILE_INFO_LIST_RESULT,
		GET_DEFAULT_SMDP_ADDRESS_RESULT,
		SET_DEFAULT_SMDP_ADDRESS_RESULT,
		SET_PROFILE_NICKNAME_RESULT,
		CANCEL_SESSION_CALLBACK_RESULT,
		DOWNLOAD_PROFILE_RESULT,
		DELETE_PROFILE_RESULT,
		START_OSU_RESULT,
		SWITCH_PROFILE_RESULT,
		RESET_MEMORY_RESULT,
		GET_EID_RESULT,
    };
    virtual int32_t OnEsimServiceCallback(EsimServiceCallback requestId, MessageParcel &data) = 0;

public:
    DECLARE_INTERFACE_DESCRIPTOR(u"OHOS.Telephony.IEsimServiceCallback");
};
}
}
#endif