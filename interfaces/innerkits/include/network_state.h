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
    bool Marshalling(Parcel &parcel) const override;
    static NetworkState *Unmarshalling(Parcel &parcel);
    void SetOperatorInfo(const std::string &longName, const std::string &shortName, const std::string &numeric,
        DomainType domainType);
    void SetEmergency(bool isEmergency);
    void SetNetworkType(RadioTech tech, DomainType domainType);
    void SetNetworkTypeV2(RadioTech tech, DomainType domainType);
    void SetRoaming(RoamingType roamingType, DomainType domainType);
    void SetNetworkState(RegServiceState state, DomainType domainType);
    void SetNrState(NrState state);
    void SetCfgTech(RadioTech tech);
    void SetCfgTechV2(RadioTech tech);
    void SetLongOperatorName(const std::string &longName, DomainType domainType);
    RegServiceState GetPsRegStatus() const;
    RegServiceState GetCsRegStatus() const;
    RoamingType GetPsRoamingStatus() const;
    RoamingType GetCsRoamingStatus() const;
    bool IsCdma() const;
    bool IsGsm() const;
    /*
     * Obtains RAT of the PS domain on the registered network.
     * @return Returns RAT of the PS domain on the registered network
     */
    RadioTech GetPsRadioTech() const;
    /*
     * Obtains RAT of the PS domain on the registered network.
     * @return Returns last RAT of the PS domain on the registered network
     */
    RadioTech GetLastPsRadioTech() const;
    /*
     * Obtains RAT of the CS domain on the registered network.
     * @return Returns RAT of the CS domain on the registered network
     */
    RadioTech GetCsRadioTech() const;
    /*
     * Obtains RAT of the PS domain on the registered network.
     * @return Returns RAT of the PS domain on the registered network
     */
    RadioTech GetPsRadioTechV2() const;
    /*
     * Obtains RAT of the PS domain on the registered network.
     * @return Returns last RAT of the PS domain on the registered network
     */
    RadioTech GetLastPsRadioTechV2() const;
    /*
     * Obtains RAT of the CS domain on the registered network.
     * @return Returns RAT of the CS domain on the registered network
     */
    RadioTech GetCsRadioTechV2() const;
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
     * Obtains the radio access technology after config conversion.
     * @return Returns access technology.
     */
    RadioTech GetCfgTech() const;
    /*
     * Obtains the radio Access technology after config conversion.
     * @return Returns last access technology.
     */
    RadioTech GetLastCfgTech() const;
    /*
     * Obtains the radio access technology after config conversion.
     * @return Returns access technology.
     */
    RadioTech GetCfgTechV2() const;
    /*
     * Obtains the radio Access technology after config conversion.
     * @return Returns last access technology.
     */
    RadioTech GetLastCfgTechV2() const;

private:
    bool ReadParcelString(Parcel &parcel);
    bool ReadParcelInt(Parcel &parcel);
    bool MarshallingString(Parcel &parcel) const;
    bool MarshallingInt(Parcel &parcel) const;
    inline bool ReadParcelToRegServiceState(Parcel &parcel, RegServiceState &regServiceState);
    inline bool ReadParcelToNrState(Parcel &parcel, NrState &nrState);
    inline bool ReadParcelToRadioTech(Parcel &parcel, RadioTech &tech);
    inline bool ReadParcelToRoamingType(Parcel &parcel, RoamingType &roamingType);

private:
    bool isEmergency_;
    OperatorInformation psOperatorInfo_;
    OperatorInformation csOperatorInfo_;
    RoamingType csRoaming_;
    RoamingType psRoaming_;
    RegServiceState psRegStatus_;
    RegServiceState csRegStatus_;
    RadioTech psRadioTech_;
    RadioTech lastPsRadioTech_;
    RadioTech lastCfgTech_;
    RadioTech csRadioTech_;
    RadioTech cfgTech_;
    NrState nrState_;
    RadioTech psRadioTechV2_;
    RadioTech lastPsRadioTechV2_;
    RadioTech lastCfgTechV2_;
    RadioTech csRadioTechV2_;
    RadioTech cfgTechV2_;
};

inline bool NetworkState::ReadParcelToRegServiceState(Parcel &parcel, RegServiceState &regServiceState)
{
    int32_t regServiceStateInt;
    if (!parcel.ReadInt32(regServiceStateInt)) {
        return false;
    }
    regServiceState = static_cast<RegServiceState>(regServiceStateInt);
    return true;
}

inline bool NetworkState::ReadParcelToRoamingType(Parcel &parcel, RoamingType &roamingType)
{
    int32_t roamingTypeInt;
    if (!parcel.ReadInt32(roamingTypeInt)) {
        return false;
    }
    roamingType = static_cast<RoamingType>(roamingTypeInt);
    return true;
}

inline bool NetworkState::ReadParcelToNrState(Parcel &parcel, NrState &nrState)
{
    int32_t nrStateInt;
    if (!parcel.ReadInt32(nrStateInt)) {
        return false;
    }
    nrState = static_cast<NrState>(nrStateInt);
    return true;
}

inline bool NetworkState::ReadParcelToRadioTech(Parcel &parcel, RadioTech &tech)
{
    int32_t techInt;
    if (!parcel.ReadInt32(techInt)) {
        return false;
    }
    tech = static_cast<RadioTech>(techInt);
    return true;
}
} // namespace Telephony
} // namespace OHOS
#endif // NETWORK_STATE_H
