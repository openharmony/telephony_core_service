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

#ifndef I_NETWORK_SEARCH_H
#define I_NETWORK_SEARCH_H

#include <vector>

#include "event_handler.h"

#include "i_network_search_callback.h"
#include "network_state.h"
#include "signal_information.h"
#include "network_search_result.h"

namespace OHOS {
namespace Telephony {
class INetworkSearch {
public:
    using HANDLE = const std::shared_ptr<AppExecFwk::EventHandler>;
    virtual void Init();
    virtual int32_t GetPsRadioTech(int32_t slotId) const = 0;
    virtual int32_t GetCsRadioTech(int32_t slotId) const = 0;
    virtual std::u16string GetOperatorNumeric(int32_t slotId) const = 0;
    virtual std::u16string GetOperatorName(int32_t slotId) const = 0;
    virtual sptr<NetworkState> GetNetworkStatus(int32_t slotId) const = 0;
    virtual int32_t GetRadioState() const = 0;
    virtual bool GetRadioState(const sptr<INetworkSearchCallback> &callback) = 0;
    virtual void SetRadioState(bool isOn, int32_t rst) = 0;
    virtual bool SetRadioState(bool isOn, int32_t rst, const sptr<INetworkSearchCallback> &callback) = 0;
    virtual std::vector<sptr<SignalInformation>> GetSignalInfoList(int32_t slotId) const = 0;
    virtual void RegisterPhoneNotify(
        const std::shared_ptr<AppExecFwk::EventHandler> &handler, int what, void *obj) = 0;
    virtual void UnRegisterPhoneNotify(const std::shared_ptr<AppExecFwk::EventHandler> &handler, int what) = 0;
    virtual bool GetNetworkSearchResult(int32_t slotId, const sptr<INetworkSearchCallback> &callback) = 0;
    virtual bool GetNetworkSelectionMode(int32_t slotId, const sptr<INetworkSearchCallback> &callback) = 0;
    virtual bool SetNetworkSelectionMode(int32_t slotId, int32_t selectMode,
        const sptr<NetworkInformation> &networkInformation, bool resumeSelection,
        const sptr<INetworkSearchCallback> &callback) = 0;
    virtual std::u16string GetIsoCountryCodeForNetwork(int32_t slotId) const = 0;
};
} // namespace Telephony
} // namespace OHOS
#endif // I_NETWORK_SEARCH_H
