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
    TELEPHONY_LOGI("NetworkState::Init");
    isEmergency_ = false;
    csRoaming_ = RoamingType::ROAMING_STATE_UNKNOWN;
    psRoaming_ = RoamingType::ROAMING_STATE_UNKNOWN;
    psRegStatus_ = RegServiceState::REG_STATE_UNKNOWN;
    csRegStatus_ = RegServiceState::REG_STATE_UNKNOWN;
    memset_s(psOperatorInfo_.fullName, sizeof(psOperatorInfo_.fullName), 0x00, sizeof(psOperatorInfo_.fullName));
    memset_s(csOperatorInfo_.fullName, sizeof(csOperatorInfo_.fullName), 0x00, sizeof(csOperatorInfo_.fullName));
    memset_s(psOperatorInfo_.shortName, sizeof(psOperatorInfo_.shortName), 0x00, sizeof(psOperatorInfo_.shortName));
    memset_s(csOperatorInfo_.shortName, sizeof(csOperatorInfo_.shortName), 0x00, sizeof(csOperatorInfo_.shortName));
    memset_s(psOperatorInfo_.operatorNumeric, sizeof(psOperatorInfo_.operatorNumeric), 0x00,
        sizeof(psOperatorInfo_.operatorNumeric));
    memset_s(csOperatorInfo_.operatorNumeric, sizeof(csOperatorInfo_.operatorNumeric), 0x00,
        sizeof(csOperatorInfo_.operatorNumeric));
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

    const char *readString = parcel.ReadCString();
    if ((readString == nullptr) ||
        (strncpy_s(psOperatorInfo_.fullName, sizeof(psOperatorInfo_.fullName), readString,
        strlen(readString)) != EOK)) {
        TELEPHONY_LOGE("fail to copy memory");
        return false;
    }
    if (((readString = parcel.ReadCString()) == nullptr) ||
        (strncpy_s(psOperatorInfo_.shortName, sizeof(psOperatorInfo_.shortName), readString,
        strlen(readString)) != EOK)) {
        TELEPHONY_LOGE("fail to copy memory");
        return false;
    }
    if (((readString = parcel.ReadCString()) == nullptr) ||
        (strncpy_s(psOperatorInfo_.operatorNumeric, sizeof(psOperatorInfo_.operatorNumeric), readString,
        strlen(readString)) != EOK)) {
        TELEPHONY_LOGE("fail to copy memory");
        return false;
    }
    if (((readString = parcel.ReadCString()) == nullptr) ||
        (strncpy_s(csOperatorInfo_.fullName, sizeof(csOperatorInfo_.fullName), readString,
        strlen(readString)) != EOK)) {
        TELEPHONY_LOGE("fail to copy memory");
        return false;
    }
    if (((readString = parcel.ReadCString()) == nullptr) ||
        (strncpy_s(csOperatorInfo_.shortName, sizeof(csOperatorInfo_.shortName), readString,
        strlen(readString)) != EOK)) {
        TELEPHONY_LOGE("fail to copy memory");
        return false;
    }
    if (((readString = parcel.ReadCString()) == nullptr) ||
        (strncpy_s(csOperatorInfo_.operatorNumeric, sizeof(csOperatorInfo_.operatorNumeric), readString,
        strlen(readString)) != EOK)) {
        TELEPHONY_LOGE("fail to copy memory");
        return false;
    }

    csRoaming_ = static_cast<RoamingType>(parcel.ReadInt32());
    psRoaming_ = static_cast<RoamingType>(parcel.ReadInt32());
    psRegStatus_ = static_cast<RegServiceState>(parcel.ReadInt32());
    csRegStatus_ = static_cast<RegServiceState>(parcel.ReadInt32());
    psRadioTech_ = static_cast<RadioTech>(parcel.ReadInt32());
    csRadioTech_ = static_cast<RadioTech>(parcel.ReadInt32());
    cfgTech_ = static_cast<RadioTech>(parcel.ReadInt32());
    nrState_ = static_cast<NrState>(parcel.ReadInt32());
    return true;
}

bool NetworkState::operator==(const NetworkState &other) const
{
    return isEmergency_ == other.isEmergency_ && csRoaming_ == other.csRoaming_ && psRoaming_ == other.psRoaming_ &&
        psRegStatus_ == other.psRegStatus_ && csRegStatus_ == other.csRegStatus_ &&
        psRadioTech_ == other.psRadioTech_ && csRadioTech_ == other.csRadioTech_ &&
        cfgTech_ == other.cfgTech_ && nrState_ == other.nrState_ &&
        !memcmp(psOperatorInfo_.operatorNumeric, other.psOperatorInfo_.operatorNumeric,
            strlen(psOperatorInfo_.operatorNumeric)) &&
        !memcmp(psOperatorInfo_.fullName, other.psOperatorInfo_.fullName, strlen(psOperatorInfo_.fullName)) &&
        !memcmp(psOperatorInfo_.shortName, other.psOperatorInfo_.shortName, strlen(psOperatorInfo_.shortName)) &&
        !memcmp(csOperatorInfo_.operatorNumeric, other.csOperatorInfo_.operatorNumeric,
            strlen(csOperatorInfo_.operatorNumeric)) &&
        !memcmp(csOperatorInfo_.fullName, other.csOperatorInfo_.fullName, strlen(csOperatorInfo_.fullName)) &&
        !memcmp(csOperatorInfo_.shortName, other.csOperatorInfo_.shortName, strlen(csOperatorInfo_.shortName));
}

bool NetworkState::Marshalling(Parcel &parcel) const
{
    if (!parcel.WriteBool(isEmergency_)) {
        return false;
    }
    if (!parcel.WriteCString(psOperatorInfo_.fullName)) {
        return false;
    }
    if (!parcel.WriteCString(psOperatorInfo_.shortName)) {
        return false;
    }
    if (!parcel.WriteCString(psOperatorInfo_.operatorNumeric)) {
        return false;
    }
    if (!parcel.WriteCString(csOperatorInfo_.fullName)) {
        return false;
    }
    if (!parcel.WriteCString(csOperatorInfo_.shortName)) {
        return false;
    }
    if (!parcel.WriteCString(csOperatorInfo_.operatorNumeric)) {
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
    if (strlen(psOperatorInfo_.fullName) > 0) {
        return std::string(psOperatorInfo_.fullName);
    } else {
        return std::string(csOperatorInfo_.fullName);
    }
}

std::string NetworkState::GetShortOperatorName() const
{
    if (strlen(psOperatorInfo_.shortName) > 0) {
        return std::string(psOperatorInfo_.shortName);
    } else {
        return std::string(csOperatorInfo_.shortName);
    }
}

std::string NetworkState::GetPlmnNumeric() const
{
    if (strlen(psOperatorInfo_.operatorNumeric) > 0) {
        return std::string(psOperatorInfo_.operatorNumeric);
    } else {
        return std::string(csOperatorInfo_.operatorNumeric);
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
        if (strncpy_s(psOperatorInfo_.fullName, sizeof(psOperatorInfo_.fullName),
            longName.c_str(), longName.length()) != 0) {
            return;
        }
        if (strncpy_s(psOperatorInfo_.shortName, sizeof(psOperatorInfo_.shortName),
            shortName.c_str(), shortName.length()) != 0) {
            return;
        }
        if (strncpy_s(psOperatorInfo_.operatorNumeric, sizeof(psOperatorInfo_.operatorNumeric),
            numeric.c_str(), numeric.length()) != 0) {
            return;
        }
    } else {
        if (strncpy_s(csOperatorInfo_.fullName, sizeof(psOperatorInfo_.fullName),
            longName.c_str(), longName.length()) != 0) {
            return;
        }
        if (strncpy_s(csOperatorInfo_.shortName, sizeof(psOperatorInfo_.shortName),
            shortName.c_str(), shortName.length()) != 0) {
            return;
        }
        if (strncpy_s(csOperatorInfo_.operatorNumeric, sizeof(psOperatorInfo_.operatorNumeric),
            numeric.c_str(), numeric.length()) != 0) {
            return;
        }
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
    std::string psFullName(psOperatorInfo_.fullName);
    std::string psOperatorNumeric(psOperatorInfo_.operatorNumeric);
    std::string psShortName(psOperatorInfo_.shortName);
    std::string psOperatorInfoStr = psFullName + "|" + psOperatorNumeric + "|" + psShortName;
    std::string csFullName(csOperatorInfo_.fullName);
    std::string csOperatorNumeric(csOperatorInfo_.operatorNumeric);
    std::string csShortName(csOperatorInfo_.shortName);
    std::string csOperatorInfoStr = csFullName + "|" + csOperatorNumeric + "|" + csShortName;
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
    cfgTech_ = tech;
}

RadioTech NetworkState::GetCfgTech() const
{
    return cfgTech_;
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
