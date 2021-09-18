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

#ifndef NETWORK_STATE_H
#define NETWORK_STATE_H

#include "parcel.h"

namespace OHOS {
namespace Telephony {
#define MSG_NS_SPN_UPDATED 0xF1
const std::string SPN_INFO_UPDATED_ACTION = "ohos.action.telephonySpnInfoUpdated";
const std::string CUR_PLMN = "CUR_PLMN";
const std::string CUR_PLMN_SHOW = "CUR_PLMN_SHOW";
const std::string CUR_SPN = "CUR_SPN";
const std::string CUR_SPN_SHOW = "CUR_SPN_SHOW";
const std::string CUR_REG_STATE = "CUR_REG_STATE";
const std::string CUR_SPN_SHOW_RULE = "CUR_SPN_SHOW_RULE";

typedef enum { DOMAIN_TYPE_PS, DOMAIN_TYPE_CS } DomainType;

typedef enum {
    REG_STATE_UNKNOWN,
    REG_STATE_IN_SERVICE,
    REG_STATE_NO_SERVICE,
    REG_STATE_EMERGENCY_ONLY,
    REG_STATE_SEARCH
} RegServiceState;

typedef enum {
    ROAMING_STATE_UNKNOWN,
    ROAMING_STATE_UNSPEC,
    ROAMING_STATE_DOMESTIC,
    ROAMING_STATE_INTERNATIONAL
} RoamingType;

typedef enum {
    RADIO_TECHNOLOGY_UNKNOWN,
    RADIO_TECHNOLOGY_GSM,
    RADIO_TECHNOLOGY_WCDMA,
    RADIO_TECHNOLOGY_LTE
} RadioTech;

typedef enum { MODE_TYPE_UNKNOWN = -1, MODE_TYPE_AUTO = 0, MODE_TYPE_MANUAL = 1 } SelectionMode;

const int NETWORK_MAX_NAME_LEN = 15;
const int NETWORK_MAX_FULL_NAME_LEN = 31;
const int NETWORK_MAX_PLMN_LEN = 31;

struct OperatorInformation {
    char operatorNumeric[NETWORK_MAX_PLMN_LEN + 1];
    char fullName[NETWORK_MAX_FULL_NAME_LEN + 1];
    char shortName[NETWORK_MAX_NAME_LEN + 1];
};

class NetworkState : public Parcelable {
public:
    NetworkState();
    virtual ~NetworkState() = default;
    void Init();
    bool operator==(const NetworkState &other) const;
    bool ReadFromParcel(Parcel &parcel);
    virtual bool Marshalling(Parcel &parcel) const override;
    static NetworkState *Unmarshalling(Parcel &parcel);
    void SetOperatorInfo(const std::string &longName, const std::string &shortName, const std::string &numeric,
        DomainType domainType);
    void SetEmergency(bool isEmergency);
    void SetNetworkType(RadioTech tech, DomainType domainType);
    void SetRoaming(RoamingType roamingType, DomainType domainType);
    void SetNetworkState(RegServiceState state, DomainType domainType);
    int32_t GetPsRegStatus() const;
    int32_t GetCsRegStatus() const;
    int32_t GetPsRoamingStatus() const;
    int32_t GetCsRoamingStatus() const;
    /*
     * Obtains RAT of the PS domain on the registered network.
     * @return Returns RAT of the PS domain on the registered network
     */
    int32_t GetPsRadioTech() const;

    /*
     * Obtains RAT of the CS domain on the registered network.
     * @return Returns RAT of the CS domain on the registered network
     */
    int32_t GetCsRadioTech() const;

    /*
     * Obtains the operator name in the long alphanumeric format of the registered network.
     * @return Returns operator name in the long alphanumeric format
     */
    std::string GetLongOperatorName() const;

    /*
     * Obtains the operator name in the short alphanumeric format of the registered network.
     * @return Returns operator name in the short alphanumeric format
     */
    std::string GetShortOperatorName() const;

    /*
     * Obtains the PLMN code of the registered network.
     * @return Returns the PLMN code
     */
    std::string GetPlmnNumeric() const;

    /*
     * Obtains the network registration status of the device.
     * @return Returns the network registration status
     */
    int32_t GetRegStatus() const;

    /*
     * Checks whether this device is allowed to make emergency calls only.
     * @return Returns the device emergency calls state.
     */
    bool IsEmergency() const;

    /*
     * Checks whether the device is roaming.
     * @return Returns roaming state.
     */
    bool IsRoaming() const;

    std::string ToString() const;

private:
    bool isEmergency_;
    OperatorInformation psOperatorInfo_;
    OperatorInformation csOperatorInfo_;
    RoamingType csRoaming_;
    RoamingType psRoaming_;
    RegServiceState psRegStatus_;
    RegServiceState csRegStatus_;
    RadioTech psRadioTech_;
    RadioTech csRadioTech_;
};
} // namespace Telephony
} // namespace OHOS
#endif // NETWORK_STATE_H
