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

#include "network_state.h"

#include <securec.h>
#include "telephony_log_wrapper.h"

namespace OHOS {
namespace Telephony {
NetworkState::NetworkState()
{
    Init();
}

void NetworkState::Init()
{
    TELEPHONY_LOGD("NetworkState::Init");
    isEmergency_ = false;
    csRoaming_ = RoamingType::ROAMING_STATE_UNKNOWN;
    psRoaming_ = RoamingType::ROAMING_STATE_UNKNOWN;
    psRegStatus_ = RegServiceState::REG_STATE_UNKNOWN;
    csRegStatus_ = RegServiceState::REG_STATE_UNKNOWN;
    psOperatorInfo_.fullName = "";
    csOperatorInfo_.fullName = "";
    psOperatorInfo_.shortName = "";
    csOperatorInfo_.shortName = "";
    psOperatorInfo_.operatorNumeric = "";
    csOperatorInfo_.operatorNumeric = "";
    psRadioTech_ = RadioTech::RADIO_TECHNOLOGY_UNKNOWN;
    csRadioTech_ = RadioTech::RADIO_TECHNOLOGY_UNKNOWN;
    cfgTech_ = RadioTech::RADIO_TECHNOLOGY_UNKNOWN;
    nrState_ = NrState::NR_STATE_NOT_SUPPORT;
}

bool NetworkState::ReadFromParcel(Parcel &parcel)
{
    if (!parcel.ReadBool(isEmergency_)) {
        return false;
    }

    if (!ReadParcelString(parcel)) {
        return false;
    }

    if (!ReadParcelInt(parcel)) {
        return false;
    }
    return true;
}

bool NetworkState::ReadParcelString(Parcel &parcel)
{
    std::string readString;
    if (!parcel.ReadString(readString)) {
        return false;
    }
    psOperatorInfo_.fullName = readString;
    if (!parcel.ReadString(readString)) {
        return false;
    }
    psOperatorInfo_.shortName = readString;
    if (!parcel.ReadString(readString)) {
        return false;
    }
    psOperatorInfo_.operatorNumeric = readString;
    if (!parcel.ReadString(readString)) {
        return false;
    }
    csOperatorInfo_.fullName = readString;
    if (!parcel.ReadString(readString)) {
        return false;
    }
    csOperatorInfo_.shortName = readString;
    if (!parcel.ReadString(readString)) {
        return false;
    }
    csOperatorInfo_.operatorNumeric = readString;
    return true;
}

bool NetworkState::ReadParcelInt(Parcel &parcel)
{
    int32_t rat;
    if (!parcel.ReadInt32(rat)) {
        return false;
    }
    csRoaming_ = static_cast<RoamingType>(rat);
    if (!parcel.ReadInt32(rat)) {
        return false;
    }
    psRoaming_ = static_cast<RoamingType>(rat);
    if (!parcel.ReadInt32(rat)) {
        return false;
    }
    psRegStatus_ = static_cast<RegServiceState>(rat);
    if (!parcel.ReadInt32(rat)) {
        return false;
    }
    csRegStatus_ = static_cast<RegServiceState>(rat);
    if (!parcel.ReadInt32(rat)) {
        return false;
    }
    psRadioTech_ = static_cast<RadioTech>(rat);
    if (!parcel.ReadInt32(rat)) {
        return false;
    }
    csRadioTech_ = static_cast<RadioTech>(rat);
    if (!parcel.ReadInt32(rat)) {
        return false;
    }
    cfgTech_ = static_cast<RadioTech>(rat);
    if (!parcel.ReadInt32(rat)) {
        return false;
    }
    nrState_ = static_cast<NrState>(rat);
    return true;
}

bool NetworkState::operator==(const NetworkState &other) const
{
    return isEmergency_ == other.isEmergency_ && csRoaming_ == other.csRoaming_ && psRoaming_ == other.psRoaming_ &&
        psRegStatus_ == other.psRegStatus_ && csRegStatus_ == other.csRegStatus_ &&
        psRadioTech_ == other.psRadioTech_ && csRadioTech_ == other.csRadioTech_ &&
        cfgTech_ == other.cfgTech_ && nrState_ == other.nrState_ &&
        psOperatorInfo_.operatorNumeric == other.psOperatorInfo_.operatorNumeric &&
        psOperatorInfo_.fullName == other.psOperatorInfo_.fullName &&
        psOperatorInfo_.shortName == other.psOperatorInfo_.shortName &&
        csOperatorInfo_.operatorNumeric == other.csOperatorInfo_.operatorNumeric &&
        csOperatorInfo_.fullName == other.csOperatorInfo_.fullName &&
        csOperatorInfo_.shortName == other.csOperatorInfo_.shortName;
}

bool NetworkState::Marshalling(Parcel &parcel) const
{
    if (!parcel.WriteBool(isEmergency_)) {
        return false;
    }

    if (!parcel.WriteString(psOperatorInfo_.fullName)) {
        return false;
    }
    if (!parcel.WriteString(psOperatorInfo_.shortName)) {
        return false;
    }
    if (!parcel.WriteString(psOperatorInfo_.operatorNumeric)) {
        return false;
    }
    if (!parcel.WriteString(csOperatorInfo_.fullName)) {
        return false;
    }
    if (!parcel.WriteString(csOperatorInfo_.shortName)) {
        return false;
    }
    if (!parcel.WriteString(csOperatorInfo_.operatorNumeric)) {
        return false;
    }
    if (!parcel.WriteInt32(static_cast<int32_t>(csRoaming_))) {
        return false;
    }
    if (!parcel.WriteInt32(static_cast<int32_t>(psRoaming_))) {
        return false;
    }
    if (!parcel.WriteInt32(static_cast<int32_t>(psRegStatus_))) {
        return false;
    }
    if (!parcel.WriteInt32(static_cast<int32_t>(csRegStatus_))) {
        return false;
    }
    if (!parcel.WriteInt32(static_cast<int32_t>(psRadioTech_))) {
        return false;
    }
    if (!parcel.WriteInt32(static_cast<int32_t>(csRadioTech_))) {
        return false;
    }
    if (!parcel.WriteInt32(static_cast<int32_t>(cfgTech_))) {
        return false;
    }
    if (!parcel.WriteInt32(static_cast<int32_t>(nrState_))) {
        return false;
    }
    return true;
}

NetworkState *NetworkState::Unmarshalling(Parcel &parcel)
{
    std::unique_ptr<NetworkState> param = std::make_unique<NetworkState>();
    if (param == nullptr) {
        return nullptr;
    }
    if (!param->ReadFromParcel(parcel)) {
        return nullptr;
    }
    return param.release();
}

std::string NetworkState::GetLongOperatorName() const
{
    if (!psOperatorInfo_.fullName.empty()) {
        return psOperatorInfo_.fullName;
    } else {
        return csOperatorInfo_.fullName;
    }
}

std::string NetworkState::GetShortOperatorName() const
{
    if (!psOperatorInfo_.shortName.empty()) {
        return psOperatorInfo_.shortName;
    } else {
        return csOperatorInfo_.shortName;
    }
}

std::string NetworkState::GetPlmnNumeric() const
{
    if (!psOperatorInfo_.operatorNumeric.empty()) {
        return psOperatorInfo_.operatorNumeric;
    } else {
        return csOperatorInfo_.operatorNumeric;
    }
}

RegServiceState NetworkState::GetRegStatus() const
{
    if (psRegStatus_ == RegServiceState::REG_STATE_IN_SERVICE) {
        return psRegStatus_;
    } else {
        return csRegStatus_;
    }
}

bool NetworkState::IsEmergency() const
{
    return isEmergency_;
}

bool NetworkState::IsRoaming() const
{
    if (psRoaming_ > RoamingType::ROAMING_STATE_UNKNOWN) {
        return true;
    } else if (csRoaming_ > RoamingType::ROAMING_STATE_UNKNOWN) {
        return true;
    } else {
        return false;
    }
}

RadioTech NetworkState::GetPsRadioTech() const
{
    return psRadioTech_;
}

RadioTech NetworkState::GetLastPsRadioTech() const
{
    return lastPsRadioTech_;
}

RadioTech NetworkState::GetCsRadioTech() const
{
    return csRadioTech_;
}

RegServiceState NetworkState::GetPsRegStatus() const
{
    return psRegStatus_;
}

RegServiceState NetworkState::GetCsRegStatus() const
{
    return csRegStatus_;
}

void NetworkState::SetOperatorInfo(
    const std::string &longName, const std::string &shortName, const std::string &numeric, DomainType domainType)
{
    if (domainType == DomainType::DOMAIN_TYPE_PS) {
        psOperatorInfo_.fullName = longName;
        psOperatorInfo_.shortName = shortName;
        psOperatorInfo_.operatorNumeric = numeric;
    } else {
        csOperatorInfo_.fullName = longName;
        csOperatorInfo_.shortName = shortName;
        csOperatorInfo_.operatorNumeric = numeric;
    }
}

void NetworkState::SetEmergency(bool isEmergency)
{
    isEmergency_ = isEmergency;
}

void NetworkState::SetNetworkType(RadioTech tech, DomainType domainType)
{
    if (domainType == DomainType::DOMAIN_TYPE_CS) {
        csRadioTech_ = tech;
    } else {
        lastPsRadioTech_ = psRadioTech_;
        psRadioTech_ = tech;
    }
}

void NetworkState::SetNetworkState(RegServiceState state, DomainType domainType)
{
    if (domainType == DomainType::DOMAIN_TYPE_CS) {
        csRegStatus_ = state;
    } else {
        psRegStatus_ = state;
    }
}

void NetworkState::SetRoaming(RoamingType roamingType, DomainType domainType)
{
    if (domainType == DomainType::DOMAIN_TYPE_CS) {
        csRoaming_ = roamingType;
    } else {
        psRoaming_ = roamingType;
    }
}

RoamingType NetworkState::GetPsRoamingStatus() const
{
    return psRoaming_;
}

RoamingType NetworkState::GetCsRoamingStatus() const
{
    return csRoaming_;
}

std::string NetworkState::ToString() const
{
    int32_t csRoaming = static_cast<int32_t>(csRoaming_);
    int32_t psRoaming = static_cast<int32_t>(psRoaming_);
    int32_t psRegStatus = static_cast<int32_t>(psRegStatus_);
    int32_t csRegStatus = static_cast<int32_t>(csRegStatus_);
    int32_t psRadioTech = static_cast<int32_t>(psRadioTech_);
    int32_t csRadioTech = static_cast<int32_t>(csRadioTech_);
    int32_t cfgTech = static_cast<int32_t>(cfgTech_);
    int32_t nrState = static_cast<int32_t>(nrState_);
    std::string psOperatorInfoStr =
        psOperatorInfo_.fullName + "|" + psOperatorInfo_.operatorNumeric + "|" + psOperatorInfo_.shortName;
    std::string csOperatorInfoStr =
        csOperatorInfo_.fullName + "|" + csOperatorInfo_.operatorNumeric + "|" + csOperatorInfo_.shortName;
    std::string content("isEmergency_:" + std::to_string(isEmergency_ ? 0 : 1) +
        ",psOperatorInfo:" + psOperatorInfoStr + ",csOperatorInfo:" + csOperatorInfoStr +
        ",csRoaming:" + std::to_string(csRoaming) + ",psRoaming:" + std::to_string(psRoaming) +
        ",psRegStatus:" + std::to_string(psRegStatus) + ",csRegStatus:" + std::to_string(csRegStatus) +
        ",cfgTech:" + std::to_string(cfgTech) + ",nrState:" + std::to_string(nrState) +
        ",psRadioTech:" + std::to_string(psRadioTech) + ",csRadioTech:" + std::to_string(csRadioTech));
    return content;
}

void NetworkState::SetCfgTech(RadioTech tech)
{
    lastCfgTech_ = cfgTech_;
    cfgTech_ = tech;
}

RadioTech NetworkState::GetCfgTech() const
{
    return cfgTech_;
}

RadioTech NetworkState::GetLastCfgTech() const
{
    return lastCfgTech_;
}

void NetworkState::SetNrState(NrState state)
{
    nrState_ = state;
}

NrState NetworkState::GetNrState() const
{
    return nrState_;
}
} // namespace Telephony
} // namespace OHOS
