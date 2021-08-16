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
#include <string>
#include "telephony_log_wrapper.h"

namespace OHOS {
namespace Telephony {
NetworkState::NetworkState()
{
    Init();
}

void NetworkState::Init()
{
    TELEPHONY_LOGE("NetworkState::Init");
    isEmergency_ = false;
    csRoaming_ = ROAMING_STATE_UNKNOWN;
    psRoaming_ = ROAMING_STATE_UNKNOWN;
    psRegStatus_ = REG_STATE_UNKNOWN;
    csRegStatus_ = REG_STATE_UNKNOWN;
    psOperatorInfo_.fullName[0] = '\0';
    csOperatorInfo_.fullName[0] = '\0';
    psOperatorInfo_.shortName[0] = '\0';
    csOperatorInfo_.shortName[0] = '\0';
    psOperatorInfo_.operatorNumeric[0] = '\0';
    csOperatorInfo_.operatorNumeric[0] = '\0';
    psRadioTech_ = RADIO_TECHNOLOGY_UNKNOWN;
    csRadioTech_ = RADIO_TECHNOLOGY_UNKNOWN;
}

bool NetworkState::ReadFromParcel(Parcel &parcel)
{
    if (!parcel.ReadBool(isEmergency_)) {
        return false;
    }

    const char *readString = parcel.ReadCString();
    if ((readString == nullptr) ||
        (memcpy_s(psOperatorInfo_.fullName, NETWORK_MAX_FULL_NAME_LEN, readString, NETWORK_MAX_FULL_NAME_LEN) != 0)) {
        TELEPHONY_LOGE("fail to copy memory");
        return false;
    }
    if (((readString = parcel.ReadCString()) == nullptr) ||
        (memcpy_s(psOperatorInfo_.shortName, NETWORK_MAX_NAME_LEN, readString, NETWORK_MAX_NAME_LEN) != 0)) {
        TELEPHONY_LOGE("fail to copy memory");
        return false;
    }
    if (((readString = parcel.ReadCString()) == nullptr) ||
        (memcpy_s(psOperatorInfo_.operatorNumeric, NETWORK_MAX_PLMN_LEN, readString, NETWORK_MAX_PLMN_LEN) != 0)) {
        TELEPHONY_LOGE("fail to copy memory");
        return false;
    }
    if (((readString = parcel.ReadCString()) == nullptr) ||
        (memcpy_s(csOperatorInfo_.fullName, NETWORK_MAX_FULL_NAME_LEN, readString, NETWORK_MAX_FULL_NAME_LEN) != 0)) {
        TELEPHONY_LOGE("fail to copy memory");
        return false;
    }
    if (((readString = parcel.ReadCString()) == nullptr) ||
        (memcpy_s(csOperatorInfo_.shortName, NETWORK_MAX_NAME_LEN, readString, NETWORK_MAX_NAME_LEN) != 0)) {
        TELEPHONY_LOGE("fail to copy memory");
        return false;
    }
    if (((readString = parcel.ReadCString()) == nullptr) ||
        (memcpy_s(csOperatorInfo_.operatorNumeric, NETWORK_MAX_PLMN_LEN, readString, NETWORK_MAX_PLMN_LEN) != 0)) {
        TELEPHONY_LOGE("fail to copy memory");
        return false;
    }

    csRoaming_ = static_cast<RoamingType>(parcel.ReadInt32());
    psRoaming_ = static_cast<RoamingType>(parcel.ReadInt32());
    psRegStatus_ = static_cast<RegServiceState>(parcel.ReadInt32());
    csRegStatus_ = static_cast<RegServiceState>(parcel.ReadInt32());
    psRadioTech_ = static_cast<RadioTech>(parcel.ReadInt32());
    csRadioTech_ = static_cast<RadioTech>(parcel.ReadInt32());
    return true;
}

bool NetworkState::operator==(const NetworkState &other) const
{
    return isEmergency_ == other.isEmergency_ && csRoaming_ == other.csRoaming_ && psRoaming_ == other.psRoaming_ &&
        psRegStatus_ == other.psRegStatus_ && csRegStatus_ == other.csRegStatus_ &&
        psRadioTech_ == other.psRadioTech_ && csRadioTech_ == other.csRadioTech_ &&
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
    if (!parcel.WriteInt32(csRoaming_)) {
        return false;
    }
    if (!parcel.WriteInt32(psRoaming_)) {
        return false;
    }
    if (!parcel.WriteInt32(psRegStatus_)) {
        return false;
    }
    if (!parcel.WriteInt32(csRegStatus_)) {
        return false;
    }
    if (!parcel.WriteInt32(psRadioTech_)) {
        return false;
    }
    if (!parcel.WriteInt32(csRadioTech_)) {
        return false;
    }
    return true;
}

NetworkState *NetworkState::Unmarshalling(Parcel &parcel)
{
    NetworkState *param = new (std::nothrow) NetworkState();
    if (param == nullptr) {
        return nullptr;
    }
    if (!param->ReadFromParcel(parcel)) {
        delete param;
        param = nullptr;
    }
    return param;
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

int32_t NetworkState::GetRegStatus() const
{
    if (psRegStatus_ == REG_STATE_IN_SERVICE) {
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
    if (psRoaming_ > ROAMING_STATE_UNKNOWN) {
        return true;
    } else if (csRoaming_ > ROAMING_STATE_UNKNOWN) {
        return true;
    } else {
        return false;
    }
}

int32_t NetworkState::GetPsRadioTech() const
{
    return psRadioTech_;
}

int32_t NetworkState::GetCsRadioTech() const
{
    return csRadioTech_;
}

int32_t NetworkState::GetPsRegStatus() const
{
    return psRegStatus_;
}

int32_t NetworkState::GetCsRegStatus() const
{
    return csRegStatus_;
}

void NetworkState::SetOperatorInfo(
    const std::string &longName, const std::string &shortName, const std::string &numeric, DomainType domainType)
{
    if (domainType == DOMAIN_TYPE_PS) {
        if (memcpy_s(static_cast<void *>(psOperatorInfo_.fullName), NETWORK_MAX_FULL_NAME_LEN,
            static_cast<const void *>(longName.c_str()), NETWORK_MAX_FULL_NAME_LEN) != 0) {
            return;
        }
        if (memcpy_s(static_cast<void *>(psOperatorInfo_.shortName), NETWORK_MAX_NAME_LEN,
            static_cast<const void *>(shortName.c_str()), NETWORK_MAX_NAME_LEN) != 0) {
            return;
        }
        if (memcpy_s(static_cast<void *>(psOperatorInfo_.operatorNumeric), NETWORK_MAX_PLMN_LEN,
            static_cast<const void *>(numeric.c_str()), NETWORK_MAX_PLMN_LEN) != 0) {
            return;
        }
    } else {
        if (memcpy_s(static_cast<void *>(csOperatorInfo_.fullName), NETWORK_MAX_FULL_NAME_LEN,
            static_cast<const void *>(longName.c_str()), NETWORK_MAX_FULL_NAME_LEN) != 0) {
            return;
        }
        if (memcpy_s(static_cast<void *>(csOperatorInfo_.shortName), NETWORK_MAX_NAME_LEN,
            static_cast<const void *>(shortName.c_str()), NETWORK_MAX_NAME_LEN) != 0) {
            return;
        }
        if (memcpy_s(static_cast<void *>(csOperatorInfo_.operatorNumeric), NETWORK_MAX_PLMN_LEN,
            static_cast<const void *>(numeric.c_str()), NETWORK_MAX_PLMN_LEN) != 0) {
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
    if (domainType == DOMAIN_TYPE_CS) {
        csRadioTech_ = tech;
    } else {
        psRadioTech_ = tech;
    }
}

void NetworkState::SetNetworkState(RegServiceState state, DomainType domainType)
{
    if (domainType == DOMAIN_TYPE_CS) {
        csRegStatus_ = state;
    } else {
        psRegStatus_ = state;
    }
}

void NetworkState::SetRoaming(RoamingType roamingType, DomainType domainType)
{
    if (domainType == DOMAIN_TYPE_CS) {
        csRoaming_ = roamingType;
    } else {
        psRoaming_ = roamingType;
    }
}

int32_t NetworkState::GetPsRoamingStatus() const
{
    return psRoaming_;
}

int32_t NetworkState::GetCsRoamingStatus() const
{
    return csRoaming_;
}

std::string NetworkState::ToString() const
{
    int csRoaming = (int)csRoaming_;
    int psRoaming = (int)psRoaming_;
    int psRegStatus = (int)psRegStatus_;
    int csRegStatus = (int)csRegStatus_;
    int psRadioTech = (int)psRadioTech_;
    int csRadioTech = (int)csRadioTech_;
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
        ",psRadioTech:" + std::to_string(psRadioTech) + ",csRadioTech:" + std::to_string(csRadioTech));
    return content;
}
} // namespace Telephony
} // namespace OHOS