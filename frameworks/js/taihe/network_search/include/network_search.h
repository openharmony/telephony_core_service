/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#ifndef BASE_TELEPHONY_ANI_NETWORK_SERACH_H
#define BASE_TELEPHONY_ANI_NETWORK_SERACH_H
#include "ani_radio_types.h"

struct GetNetworkStateContext {
    std::string longOperatorName = "";
    std::string shortOperatorName = "";
    std::string plmnNumeric = "";
    bool isRoaming = false;
    int32_t regStatus = 0;
    int32_t cfgTech = 0;
    int32_t nsaState = 0;
    bool isEmergency = false;
};
#endif // ANI_NETWORK_SERACH_H