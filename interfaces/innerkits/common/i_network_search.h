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

#ifndef OHOS_I_NS_MANAGER_H
#define OHOS_I_NS_MANAGER_H

#include <string.h>
#include <unistd.h>
#include <cstdio>
#include <cstring>
#include <memory>
#include <vector>
#include "event_handler.h"
#include "network_state.h"
#include "signal_information.h"

namespace OHOS {
class INetworkSearch {
public:
    using HANDLE = const std::shared_ptr<AppExecFwk::EventHandler>;
    virtual void Init();
    virtual int32_t GetPsRadioTech(int32_t slotId) = 0;
    virtual int32_t GetCsRadioTech(int32_t slotId) = 0;
    virtual std::u16string GetOperatorNumeric(int32_t slotId) = 0;
    virtual std::u16string GetOperatorName(int32_t slotId) = 0;
    virtual sptr<NetworkState> GetNetworkStatus(int32_t slotId) = 0;
    virtual bool GetRadioState(int32_t slotId) = 0;
    virtual void SetHRilRadioState(bool isOn) = 0;
    virtual std::vector<sptr<SignalInformation>> GetSignalInfoList(int32_t slotId) = 0;
    virtual void RegisterForPSConnectionAttached(const HANDLE &handler) = 0;
    virtual void UnregisterForPSConnectionAttached(const HANDLE &handler) = 0;
    virtual void RegisterForPSConnectionDetached(const HANDLE &handler) = 0;
    virtual void UnregisterForPSConnectionDetached(const HANDLE &handler) = 0;
};
} // namespace OHOS
#endif // CORE_SERVICE_IRIL_MANAGER_H
