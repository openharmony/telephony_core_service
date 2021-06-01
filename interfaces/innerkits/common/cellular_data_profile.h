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

#ifndef HOS_CD_PROFILE_H
#define HOS_CD_PROFILE_H

#include "string"

namespace OHOS {
class CellularDataProfile {
public:
    CellularDataProfile(int profileId, std::string apn, std::string protocol, int verType, std::string userName,
        std::string password, std::string roamingProtocol)
        : profileId(profileId), apn(apn), protocol(protocol), verType(verType), userName(userName),
          password(password), roamingProtocol(roamingProtocol)
    {}

    ~CellularDataProfile() = default;

public:
    int profileId;
    std::string apn; /** (Access Point Name) a string parameter which is a logical name that is used to select the
                      * GGSN or the external packet data network. from 3GPP TS 27.007 10.1 V4.3.0 (2001-12)
                      */
    std::string protocol; /** (Packet Data Protocol type) a string parameter which specifies the type of packet
                           * data protocol from 3GPP TS 27.007 10.1 V4.3.0 (2001-12)
                           */
    int verType;
    std::string userName;
    std::string password;
    std::string roamingProtocol;
};
} // namespace OHOS
#endif // HOS_CD_PROFILE_H
