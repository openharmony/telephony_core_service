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

#ifndef SIM_CARD_MANAGER
#define SIM_CARD_MANAGER

#include <cstdint>
#include <string>
#include "i_core_service.h"
#include "iremote_object.h"
#include "network_state.h"
#include "refbase.h"

namespace OHOS {
namespace Telephony {
class SimCardManager {
public:
    SimCardManager();
    ~SimCardManager();
    bool HasSimCard(int32_t slotId);
    int32_t GetSimState(int32_t slotId);
    std::u16string GetIsoCountryCodeForSim(int32_t slotId);
    std::u16string GetSimOperatorNumeric(int32_t slotId);
    std::u16string GetSimSpn(int32_t slotId);
    std::u16string getLocaleFromDefaultSim();
    std::u16string GetSimGid1(int32_t slotId);
    bool IsConnect();
    int32_t ConnectService();
    bool GetSimAccountInfo(int32_t subId, IccAccountInfo &info);
    bool SetDefaultVoiceSlotId(int32_t subId);
    int32_t GetDefaultVoiceSlotId();
    std::u16string GetSimIccId(int32_t slotId);
    bool UnlockPin(std::u16string pin, LockStatusResponse &response, int32_t phoneId);
    bool UnlockPuk(std::u16string newPin, std::u16string puk, LockStatusResponse &response, int32_t phoneId);
    bool AlterPin(std::u16string newPin, std::u16string oldPin, LockStatusResponse &response, int32_t phoneId);
    bool SetLockState(std::u16string pin, int32_t enable, LockStatusResponse &response, int32_t phoneId);
    int32_t RefreshSimState(int32_t slotId);
    bool IsSimActive(int32_t slotId);
    std::u16string GetIMSI(int32_t slotId);

private:
    sptr<ICoreService> simManagerInterface_;
};
} // namespace Telephony
} // namespace OHOS
#endif // SIM_CARD_MANAGER