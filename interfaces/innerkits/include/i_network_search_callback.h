/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#ifndef I_NETWORK_SEARCH_CALLBACK_H
#define I_NETWORK_SEARCH_CALLBACK_H

#include <iremote_proxy.h>

namespace OHOS {
namespace Telephony {
class INetworkSearchCallback : public IRemoteBroker {
public:
    virtual ~INetworkSearchCallback() = default;
    enum class NetworkSearchCallback {
        GET_AVAILABLE_RESULT = 0,
        GET_NETWORK_MODE_RESULT,
        SET_NETWORK_MODE_RESULT,
        GET_RADIO_STATUS_RESULT,
        SET_RADIO_STATUS_RESULT,
        GET_PREFERRED_NETWORK_MODE_RESULT,
        SET_PREFERRED_NETWORK_MODE_RESULT,
        SET_NR_OPTION_MODE_RESULT,
        GET_NR_OPTION_MODE_RESULT,
    };
    virtual int32_t OnNetworkSearchCallback(NetworkSearchCallback requestId, MessageParcel &data) = 0;

public:
    DECLARE_INTERFACE_DESCRIPTOR(u"OHOS.Telephony.INetworkSearchCallback");
};
} // namespace Telephony
} // namespace OHOS
#endif // I_NETWORK_SEARCH_CALLBACK_H
