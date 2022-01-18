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
#include "network_search_types.h"

namespace OHOS {
namespace Telephony {
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
    void SetNrState(NrState state);
    void SetCfgTech(RadioTech tech);
    RegServiceState GetPsRegStatus() const;
    RegServiceState GetCsRegStatus() const;
    RoamingType GetPsRoamingStatus() const;
    RoamingType GetCsRoamingStatus() const;
    /*
     * Obtains RAT of the PS domain on the registered network.
     * @return Returns RAT of the PS domain on the registered network
     */
    RadioTech GetPsRadioTech() const;
    /*
     * Obtains RAT of the CS domain on the registered network.
     * @return Returns RAT of the CS domain on the registered network
     */
    RadioTech GetCsRadioTech() const;
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
    RegServiceState GetRegStatus() const;
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
    /*
     * Obtains the NSA network registration status of the device.
     * @return Returns nsa state.
     */
    NrState GetNrState() const;
    /*
     *  Obtains the radio Access technology after config conversion.
     * @return Returns Access technology .
     */
    RadioTech GetCfgTech() const;
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
    RadioTech cfgTech_;
    NrState nrState_;
};
} // namespace Telephony
} // namespace OHOS
#endif // NETWORK_STATE_H
