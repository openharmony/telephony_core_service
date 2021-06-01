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

#include "../../interfaces/innerkits/common/signal_information.h"
#include "hril_network_parcel.h"

namespace OHOS {
constexpr int GSM_RSSI_MINIMUM = 0;
constexpr int GSM_RSSI_MAXIMUM = 61;
constexpr int GSM_RSSI_INVALID = 99;
constexpr int CDMA_RSSI_MINIMUM = 0;
constexpr int CDMA_RSSI_INVALID = -120;
constexpr int SIGNAL_LEVEL_INVALID = 0;
const int *SignalInformation::g_gsmSignalThreshold = SignalInformation::GSM_SIGNAL_THRESHOLD_5BAR;
const int *SignalInformation::g_cdmaSignalThreshold = SignalInformation::CDMA_SIGNAL_THRESHOLD_5BAR;
int SignalInformation::g_signalBar = 5;

std::unique_ptr<SignalInformation> SignalInformation::UnMarshalling(Parcel &parcel)
{
    return nullptr;
}

GsmSignalInformation::GsmSignalInformation() {}

GsmSignalInformation::~GsmSignalInformation() {}

bool GsmSignalInformation::operator==(const GsmSignalInformation &gsm) const
{
    return gsmRssi_ == gsm.gsmRssi_ && timeAdvance_ == gsm.timeAdvance_;
}

void GsmSignalInformation::SetValue(const int32_t gsmRssi, const int32_t timeAdvance)
{
    gsmRssi_ = gsmRssi;
    timeAdvance_ = timeAdvance;
}

int32_t GsmSignalInformation::GetTimeAdvance() const
{
    return timeAdvance_;
}

int32_t GsmSignalInformation::GetRssi() const
{
    return gsmRssi_;
}

int32_t GsmSignalInformation::GetSignalLevel() const
{
    int32_t level = SIGNAL_LEVEL_INVALID;
    int32_t gsmRssi = GetRssi();
    for (int i = g_signalBar; i >= 0; --i) {
        if (gsmRssi >= g_gsmSignalThreshold[i]) {
            level = i;
            break;
        }
    }
    return level;
}

std::u16string GsmSignalInformation::ToString() const
{
    return (
        Str8ToStr16("gsmRssi_: " + std::to_string(gsmRssi_) + " timeAdvance_: " + std::to_string(timeAdvance_)));
}

SignalInformation::NetworkType GsmSignalInformation::GetNetworkType() const
{
    return SignalInformation::NetworkType::GSM;
}

sptr<SignalInformation> GsmSignalInformation::NewInstance() const
{
    std::unique_ptr<GsmSignalInformation> gsm = std::make_unique<GsmSignalInformation>();
    if (gsm == nullptr) {
        return nullptr;
    }
    gsm->SetValue(this->gsmRssi_, this->timeAdvance_);
    return gsm.release();
};

bool GsmSignalInformation::Marshalling(Parcel &parcel) const
{
    if (!parcel.WriteInt32(static_cast<int32_t>(SignalInformation::NetworkType::GSM))) {
        return false;
    }
    if (!parcel.WriteInt32(gsmRssi_)) {
        return false;
    }
    if (!parcel.WriteInt32(timeAdvance_)) {
        return false;
    }
    return true;
}

std::unique_ptr<GsmSignalInformation> GsmSignalInformation::UnMarshalling(Parcel &parcel)
{
    std::unique_ptr<GsmSignalInformation> signal = std::make_unique<GsmSignalInformation>();
    if (signal && !signal->ReadFromParcel(parcel)) {
        signal = nullptr;
    }
    return signal;
}

bool GsmSignalInformation::ReadFromParcel(Parcel &parcel)
{
    if (!parcel.ReadInt32(gsmRssi_)) {
        return false;
    }
    if (!parcel.ReadInt32(timeAdvance_)) {
        return false;
    }
    return true;
}

bool GsmSignalInformation::ValidateGsmValue() const
{
    if (gsmRssi_ == GSM_RSSI_INVALID) {
        return true;
    }
    return (gsmRssi_ > GSM_RSSI_MINIMUM && gsmRssi_ <= GSM_RSSI_MAXIMUM);
}

CdmaSignalInformation::CdmaSignalInformation() {}

CdmaSignalInformation::~CdmaSignalInformation() {}

void CdmaSignalInformation::SetValue(const int32_t cdmaRssi, const int32_t cdmaEcno)
{
    cdmaRssi_ = cdmaRssi;
    cdmaEcno_ = cdmaEcno;
}

bool CdmaSignalInformation::operator==(const CdmaSignalInformation &cdma) const
{
    return (cdmaRssi_ == cdma.cdmaRssi_ && cdmaEcno_ == cdma.cdmaEcno_);
}

int32_t CdmaSignalInformation::GetCdmaRssi() const
{
    return (cdmaRssi_ > CDMA_RSSI_MINIMUM) ? -cdmaRssi_ : CDMA_RSSI_INVALID;
}

int32_t CdmaSignalInformation::GetSignalLevel() const
{
    int32_t cdmaRssi = GetCdmaRssi();
    int32_t level = SIGNAL_LEVEL_INVALID;
    for (int i = g_signalBar; i >= 0; --i) {
        if (cdmaRssi >= g_cdmaSignalThreshold[i]) {
            level = i;
            break;
        }
    }
    return level;
}

std::u16string CdmaSignalInformation::ToString() const
{
    return (Str8ToStr16("cdmaRssi_: " + std::to_string(cdmaRssi_) + " cdmaEcno_: " + std::to_string(cdmaEcno_)));
}

SignalInformation::NetworkType CdmaSignalInformation::GetNetworkType() const
{
    return SignalInformation::NetworkType::CDMA;
};

sptr<SignalInformation> CdmaSignalInformation::NewInstance() const
{
    std::unique_ptr<CdmaSignalInformation> cdma = std::make_unique<CdmaSignalInformation>();
    if (cdma == nullptr) {
        return nullptr;
    }
    cdma->SetValue(this->cdmaRssi_, this->cdmaEcno_);
    return cdma.release();
}

bool CdmaSignalInformation::Marshalling(Parcel &parcel) const
{
    if (!parcel.WriteInt32(static_cast<int32_t>(SignalInformation::NetworkType::CDMA))) {
        return false;
    }
    if (!parcel.WriteInt32(cdmaRssi_)) {
        return false;
    }
    if (!parcel.WriteInt32(cdmaEcno_)) {
        return false;
    }
    return true;
}

std::unique_ptr<CdmaSignalInformation> CdmaSignalInformation::UnMarshalling(Parcel &parcel)
{
    std::unique_ptr<CdmaSignalInformation> signal = std::make_unique<CdmaSignalInformation>();
    if (signal && !signal->ReadFromParcel(parcel)) {
        signal = nullptr;
    }
    return signal;
}

bool CdmaSignalInformation::ReadFromParcel(Parcel &parcel)
{
    if (!parcel.ReadInt32(cdmaRssi_)) {
        return false;
    }
    if (!parcel.ReadInt32(cdmaEcno_)) {
        return false;
    }
    return true;
}

bool CdmaSignalInformation::ValidateCdmaValue() const
{
    return (cdmaRssi_ > CDMA_RSSI_MINIMUM);
}
} // namespace OHOS