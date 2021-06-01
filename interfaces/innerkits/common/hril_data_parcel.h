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
#ifndef OHOS_RIL_DATA_PARCEL_H
#define OHOS_RIL_DATA_PARCEL_H

#include <memory>
#include <string>
#include "parcel.h"
#include "string_ex.h"
#include "hril_types.h"

namespace OHOS {
struct SetupDataCallResultInfo : public Parcelable {
    int32_t flag;
    int32_t state; /* from 3GPP TS 27.007 10.1.10 V4.3.0 (2001-12)
                    * indicates the state of PDP context activation
                    * 0 - deactivated
                    * 1 - activated */
    int32_t retryTime; /* if errorCode != 0, suggested retry time */
    int32_t cid; /* from 3GPP TS 27.007 10.1.1 V4.3.0 (2001-12)
                  * specifies a particular PDP context definition. The parameter is local to the TE-MT interface
                  * and is used in other PDP context-related commands. */
    int32_t active; /* 0: inactive, 1: active(physical link down), 2 : 2=active (physical link up) */
    std::string type; /* PDP_type values from 3GPP TS 27.007 V4.3.0 section 10.1.1.
                       * specifies the type of packet data protocol. The default value is manufacturer specific. */
    std::string netPortName; /* Network interface name */
    std::string address; /*  from 3GPP TS 27.007 10.1.1 V4.3.0 (2001-12)
                          *  a string parameter that identifies the MT in the address space applicable to the PDP. */
    std::string dns; /* If the MT indicates more than two IP addresses of P-CSCF servers
                      * or more than two IP addresses of DNS servers,
                      * multiple lines of information per <cid> will be returned.
                      * If the MT has dual stack capabilities,
                      * First one line with the IPv4 parameters followed by one line with the IPv6 parameters. */
    std::string gateway; /* network gateway address */
    int32_t mtu; /* Maximum Transfer Unit. The range of permitted values (minimum value = 1
                  * or if the initial PDP context is supported minimum value = 0)
                  * is returned by the test form of the command. */
    bool ReadFromParcel(Parcel &parcel);
    virtual bool Marshalling(Parcel &parcel) const override;
    std::shared_ptr<SetupDataCallResultInfo> UnMarshalling(Parcel &parcel);
    void Dump(std::string, int32_t);
};

struct DataCallResultList : public Parcelable {
    int32_t size; /* Size of DataCall List */
    std::vector<SetupDataCallResultInfo> dcList; /* DataCall List */

    bool ReadFromParcel(Parcel &parcel);
    virtual bool Marshalling(Parcel &parcel) const override;
    std::shared_ptr<DataCallResultList> UnMarshalling(Parcel &parcel);
    void Dump(std::string, int32_t);
};

/* from 3GPP TS 27.007 10.1 V4.3.0 (2001-12) */
struct DataProfileDataInfo : public Parcelable {
    int32_t serial;
    int32_t profileId; /* Id of data profiles */
    std::string apn; /* (Access Point Name) a string parameter
                      * which is a logical name that is used to select the GGSN or the */
    std::string protocol; /* (Packet Data Protocol type) a string parameter which
                           * specifies the type of packet data protocol */
    std::string roamingProtocol;
    int32_t verType; /* APN verification type */
    std::string userName;
    std::string password;

    bool ReadFromParcel(Parcel &parcel);
    virtual bool Marshalling(Parcel &parcel) const override;
    std::shared_ptr<DataProfileDataInfo> UnMarshalling(Parcel &parcel);
    void Dump(std::string, int32_t);
};

struct DataProfilesInfo : public Parcelable {
    int32_t serial;
    int32_t profilesSize;
    std::vector<DataProfileDataInfo> profiles;
    bool isRoaming;

    bool ReadFromParcel(Parcel &parcel);
    virtual bool Marshalling(Parcel &parcel) const override;
    std::shared_ptr<DataProfilesInfo> UnMarshalling(Parcel &parcel);
    void Dump(std::string, int32_t);
};

struct DataCallInfo : public Parcelable {
    int32_t serial;
    int32_t radioTechnology; /* Voice radio technology */
    DataProfileDataInfo dataProfileInfo;
    bool modemCognitive; /* 1:APN setting setDataProfile. 0: no */
    bool roamingAllowed;
    bool isRoaming;

    bool ReadFromParcel(Parcel &parcel);
    virtual bool Marshalling(Parcel &parcel) const override;
    std::shared_ptr<DataCallInfo> UnMarshalling(Parcel &parcel);
    void Dump(std::string, int32_t);
};
} // namespace OHOS
#endif // OHOS_RIL_DATA_PARCEL_H
