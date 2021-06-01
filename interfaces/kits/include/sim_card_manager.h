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
#include "refbase.h"
namespace OHOS {
class SimCardManager {
public:
    SimCardManager();
    ~SimCardManager();
    bool HasSimCard(int32_t slotId);
    int32_t GetSimState(int32_t slotId);
    std::u16string GetIsoCountryCode(int32_t slotId);
    std::u16string GetOperatorNumeric(int32_t slotId);
    std::u16string GetSpn(int32_t slotId);

private:
    int32_t ConnectService();
    sptr<ICoreService> simManagerInterface_;
};
} // namespace OHOS
#endif // SIM_CARD_MANAGER