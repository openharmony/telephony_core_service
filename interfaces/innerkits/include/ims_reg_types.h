/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#ifndef IMS_REG_TYPES_H
#define IMS_REG_TYPES_H

#include <stdint.h>

namespace OHOS {
namespace Telephony {
const int16_t VALUE_MAXIMUM_LIMIT = 3;
const int16_t INFO_MAXIMUM_LIMIT = 31;
const int16_t DATA_LENGTH_ONE = 1;
const int16_t DATA_LENGTH_TWO = 2;

/**
 * @brief IMS register status
 */
enum ImsRegState {
    IMS_UNREGISTERED,
    IMS_REGISTERED,
};

/**
 * @brief IMS register technology
 */
enum ImsRegTech {
    IMS_REG_TECH_NONE = 0,
    IMS_REG_TECH_LTE = 1,
    IMS_REG_TECH_IWLAN = 2,
    IMS_REG_TECH_NR = 3,
};

/**
 * @brief IMS service type
 */
enum ImsServiceType {
    TYPE_VOICE = 0,
    TYPE_VIDEO = 1,
    TYPE_UT = 2,
    TYPE_SMS = 3,
};

/**
 * @brief IMS register information
 */
struct ImsRegInfo {
    ImsRegState imsRegState = IMS_UNREGISTERED;
    ImsRegTech imsRegTech = IMS_REG_TECH_NONE;
};
} // namespace Telephony
} // namespace OHOS
#endif  // IMS_REG_TYPES_H