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

#ifndef TELEPHONY_IMS_CORE_SERVICE_TYPES_H
#define TELEPHONY_IMS_CORE_SERVICE_TYPES_H

#include <stdint.h>

#include "ims_reg_types.h"

namespace OHOS {
namespace Telephony {
enum ImsErrType {
    IMS_SUCCESS = 0,
    IMS_FAILED = 1,
};

enum RadioTechFamily {
    RADIO_TECH_FAMILY_3GPP = 0,
    RADIO_TECH_FAMILY_3GPP2 = 1,
};

struct ImsResponseInfo {
    int32_t slotId = 0;
    ImsErrType error = ImsErrType::IMS_FAILED;
};

struct ImsServiceStatus {
    bool supportImsVoice = false;
    bool supportImsVideo = false;
    bool supportImsUt = false;
    bool supportImsSms = false;
    ImsRegTech imsRegTech = ImsRegTech::IMS_REG_TECH_NONE;
};

struct ImsRegistrationStatus {
    bool isRegisterd = false;
    RadioTechFamily radioTechFamily = RadioTechFamily::RADIO_TECH_FAMILY_3GPP;
};
} // namespace Telephony
} // namespace OHOS
#endif // TELEPHONY_IMS_CORE_SERVICE_TYPES_H
