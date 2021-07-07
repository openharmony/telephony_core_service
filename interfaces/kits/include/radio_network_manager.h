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

#ifndef RADIO_NETWORK_MANAGER_H
#define RADIO_NETWORK_MANAGER_H

#include <cstdint>
#include <string>
#include <vector>
#include "i_core_service.h"
#include "iremote_object.h"
#include "refbase.h"
#include "signal_information.h"

namespace OHOS {
class RadioNetworkManager {
public:
    RadioNetworkManager();
    ~RadioNetworkManager();
    int32_t GetPsRadioTech(int32_t slotId);
    int32_t GetCsRadioTech(int32_t slotId);
    std::vector<sptr<SignalInformation>> GetSignalInfoList(int32_t slotId);
    std::u16string GetOperatorNumeric(int32_t slotId);
    std::u16string GetOperatorName(int32_t slotId);
    sptr<NetworkState> GetNetworkStatus(int32_t slotId);
    bool IsConnect();
    int32_t ConnectService(); 

private:
    sptr<ICoreService> radioNetworkService_;
};
} // namespace OHOS
#endif // RADIO_NETWORK_MANAGER_H
