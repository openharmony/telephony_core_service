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

#ifndef TELEPHONY_SIM_RDB_INFO_H
#define TELEPHONY_SIM_RDB_INFO_H

namespace OHOS {
namespace Telephony {
class SimRdbInfo {
public:
    inline static const std::string SIM_RDB_SELECTION = "datashare:///com.ohos.simability/sim/sim_info";
    inline static const std::string SIM_RDB_DEFAULT_SET_URI =
        "datashare:///com.ohos.simability/sim/sim_info/set_card";
    int simId;
    std::string iccId;
    std::string cardId;
    int slotIndex;
    int cardType;
    int imsSwitch;
    std::string showName;
    std::string phoneNumber;
    std::string countryCode;
    std::string language;
    std::string imsi;
    int isMainCard;
    int isVoiceCard;
    int isMessageCard;
    int isCellularDataCard;
    int isActive;
};

enum class CardSeclectedStatus {
    OFF,
    ON,
};
} // namespace Telephony
} // namespace OHOS
#endif // TELEPHONY_SIM_RDB_INFO_H