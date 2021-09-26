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

#include "signal_information.h"

#include <string_ex.h>
#include "telephony_log_wrapper.h"

namespace OHOS {
namespace Telephony {
constexpr int32_t GSM_RXLEV_MINIMUM = 1;
constexpr int32_t GSM_RXLEV_MAXIMUM = 63;
constexpr int32_t GSM_RSSI_INVALID = -110;
constexpr int32_t CDMA_RSSI_MINIMUM = 0;
constexpr int32_t CDMA_RSSI_INVALID = -120;
constexpr int32_t LTE_RSRP_MINIMUM = 0;
constexpr int32_t LTE_RSRP_MAXIMUM = 99;
constexpr int32_t LTE_RSSI_INVALID = -121;
constexpr int32_t WCDMA_RSCP_MINIMUM = 0;
constexpr int32_t WCDMA_RSCP_MAXIMUM = 99;
constexpr int32_t WCDMA_RSSI_INVALID = -113;
constexpr int32_t SIGNAL_LEVEL_INVALID = 0;
constexpr int32_t SIGNAL_FIVE_BARS = 5;
constexpr int32_t SIGNAL_FOUR_BARS = 4;
const int32_t *GSM_SIGNAL_THRESHOLD = SignalInformation::GSM_SIGNAL_THRESHOLD_5BAR;
const int32_t *CDMA_SIGNAL_THRESHOLD = SignalInformation::CDMA_SIGNAL_THRESHOLD_5BAR;
const int32_t *LTE_SIGNAL_THRESHOLD = SignalInformation::LTE_SIGNAL_THRESHOLD_5BAR;
const int32_t *WCDMA_SIGNAL_THRESHOLD = SignalInformation::WCDMA_SIGNAL_THRESHOLD_5BAR;
int32_t SignalInformation::signalBar_ = SIGNAL_FIVE_BARS;

SignalInformation::SignalInformation()
{
    InitSignalBar();
}

void SignalInformation::InitSignalBar(const int32_t bar)
{
    if (bar == SIGNAL_FOUR_BARS) {
        GSM_SIGNAL_THRESHOLD = SignalInformation::GSM_SIGNAL_THRESHOLD_4BAR;
        CDMA_SIGNAL_THRESHOLD = SignalInformation::CDMA_SIGNAL_THRESHOLD_4BAR;
        LTE_SIGNAL_THRESHOLD = SignalInformation::LTE_SIGNAL_THRESHOLD_4BAR;
        WCDMA_SIGNAL_THRESHOLD = SignalInformation::WCDMA_SIGNAL_THRESHOLD_4BAR;
        signalBar_ = SIGNAL_FOUR_BARS;
    } else {
        GSM_SIGNAL_THRESHOLD = SignalInformation::GSM_SIGNAL_THRESHOLD_5BAR;
        CDMA_SIGNAL_THRESHOLD = SignalInformation::CDMA_SIGNAL_THRESHOLD_5BAR;
        LTE_SIGNAL_THRESHOLD = SignalInformation::LTE_SIGNAL_THRESHOLD_5BAR;
        WCDMA_SIGNAL_THRESHOLD = SignalInformation::WCDMA_SIGNAL_THRESHOLD_5BAR;
        signalBar_ = SIGNAL_FIVE_BARS;
    }
}

std::unique_ptr<SignalInformation> SignalInformation::UnMarshalling(Parcel &parcel)
{
    return nullptr;
}

bool GsmSignalInformation::operator==(const GsmSignalInformation &gsm) const
{
    return gsmRxlev_ == gsm.gsmRxlev_ && gsmBer_ == gsm.gsmBer_;
}

void GsmSignalInformation::SetValue(const int32_t gsmRssi, const int32_t gsmBer)
{
    gsmRxlev_ = gsmRssi;
    gsmBer_ = gsmBer;
}

int32_t GsmSignalInformation::GetRssi() const
{
    return gsmRxlev_;
}

int32_t GsmSignalInformation::GetGsmBer() const
{
    return gsmBer_;
}

int32_t GsmSignalInformation::GetSignalLevel() const
{
    int32_t level = SIGNAL_LEVEL_INVALID;
    int32_t gsmRxlev = GetRssi();
    int32_t gsmRssi = GSM_RSSI_INVALID;
    if (ValidateGsmValue()) {
        for (int i = 0; i <= gsmRxlev; ++i) {
            if (i != 0) {
                ++gsmRssi;
            }
        }
        for (int i = signalBar_; i >= 0; --i) {
            if (gsmRssi >= GSM_SIGNAL_THRESHOLD[i]) {
                level = i;
                break;
            }
        }
    } else {
        TELEPHONY_LOGE("GsmSignalInformation::GetSignalLevel Value is Invalid\n");
    }
    return level;
}

SignalInformation::NetworkType GsmSignalInformation::GetNetworkType() const
{
    return SignalInformation::NetworkType::GSM;
}

std::string GsmSignalInformation::ToString() const
{
    int netWorkType = static_cast<int>(GsmSignalInformation::GetNetworkType());
    std::string content("networkType:" + std::to_string(netWorkType) + ",gsmRxlev:" + std::to_string(gsmRxlev_) +
        ",signalLevel:" + std::to_string(GsmSignalInformation::GetSignalLevel()) +
        ",gsmBer:" + std::to_string(gsmBer_));
    return content;
}

sptr<SignalInformation> GsmSignalInformation::NewInstance() const
{
    std::unique_ptr<GsmSignalInformation> gsm = std::make_unique<GsmSignalInformation>();
    if (gsm == nullptr) {
        return nullptr;
    }
    gsm->SetValue(this->gsmRxlev_, this->gsmBer_);
    return gsm.release();
}

bool GsmSignalInformation::Marshalling(Parcel &parcel) const
{
    if (!parcel.WriteInt32(static_cast<int32_t>(SignalInformation::NetworkType::GSM))) {
        return false;
    }
    if (!parcel.WriteInt32(gsmRxlev_)) {
        return false;
    }
    if (!parcel.WriteInt32(gsmBer_)) {
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
    if (!parcel.ReadInt32(gsmRxlev_)) {
        return false;
    }
    if (!parcel.ReadInt32(gsmBer_)) {
        return false;
    }
    return true;
}

bool GsmSignalInformation::ValidateGsmValue() const
{
    return (gsmRxlev_ >= GSM_RXLEV_MINIMUM && gsmRxlev_ <= GSM_RXLEV_MAXIMUM);
}

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
    for (int i = signalBar_; i >= 0; --i) {
        if (cdmaRssi >= CDMA_SIGNAL_THRESHOLD[i]) {
            level = i;
            break;
        }
    }
    return level;
}

SignalInformation::NetworkType CdmaSignalInformation::GetNetworkType() const
{
    return SignalInformation::NetworkType::CDMA;
}

std::string CdmaSignalInformation::ToString() const
{
    int netWorkType = static_cast<int>(CdmaSignalInformation::GetNetworkType());
    std::string content(",networkType:" + std::to_string(netWorkType) + ",cdmaRssi:" + std::to_string(cdmaRssi_) +
        ",cdmaEcno:" + std::to_string(cdmaEcno_) +
        ",signalLevel:" + std::to_string(CdmaSignalInformation::GetSignalLevel()));
    return content;
}

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

bool LteSignalInformation::operator==(const LteSignalInformation &lte) const
{
    return rxlev_ == lte.rxlev_ && lteRsrp_ == lte.lteRsrp_ && lteRsrq_ == lte.lteRsrq_ && lteSnr_ == lte.lteSnr_;
}

void LteSignalInformation::SetValue(
    const int32_t rxlev, const int32_t lteRsrp, const int32_t lteRsrq, const int32_t lteSnr)
{
    rxlev_ = rxlev;
    lteRsrp_ = lteRsrp;
    lteRsrq_ = lteRsrq;
    lteSnr_ = lteSnr;
}

int32_t LteSignalInformation::GetRxlev() const
{
    return rxlev_;
}

int32_t LteSignalInformation::GetRsrp() const
{
    return lteRsrp_;
}

int32_t LteSignalInformation::GetRsrq() const
{
    return lteRsrq_;
}

int32_t LteSignalInformation::GetSnr() const
{
    return lteSnr_;
}

int32_t LteSignalInformation::GetSignalLevel() const
{
    int32_t level = SIGNAL_LEVEL_INVALID;
    int32_t lteRsrp = GetRsrp();
    int32_t lteRssi = LTE_RSSI_INVALID;
    if (ValidateLteValue()) {
        for (int i = 0; i <= lteRsrp; ++i) {
            if (i != 0) {
                ++lteRssi;
            }
        }
        for (int i = signalBar_; i >= 0; --i) {
            if (lteRssi >= LTE_SIGNAL_THRESHOLD[i]) {
                level = i;
                break;
            }
        }
    } else {
        TELEPHONY_LOGE("LteSignalInformation::GetSignalLevel Value is Invalid\n");
    }
    return level;
}

SignalInformation::NetworkType LteSignalInformation::GetNetworkType() const
{
    return SignalInformation::NetworkType::LTE;
}

std::string LteSignalInformation::ToString() const
{
    int netWorkType = static_cast<int>(LteSignalInformation::GetNetworkType());
    std::string content("networkType:" + std::to_string(netWorkType) + ",lteRsrp:" + std::to_string(lteRsrp_) +
        ",lteRsrq:" + std::to_string(lteRsrq_) + ",lteSnr:" + std::to_string(lteSnr_) + ",lteRxlev:" +
        std::to_string(rxlev_) + ",signalLevel:" + std::to_string(LteSignalInformation::GetSignalLevel()));
    return content;
}

sptr<SignalInformation> LteSignalInformation::NewInstance() const
{
    std::unique_ptr<LteSignalInformation> lte = std::make_unique<LteSignalInformation>();
    if (lte == nullptr) {
        return nullptr;
    }
    lte->SetValue(this->rxlev_, this->lteRsrp_, this->lteRsrq_, this->lteSnr_);
    return lte.release();
}

bool LteSignalInformation::Marshalling(Parcel &parcel) const
{
    if (!parcel.WriteInt32(static_cast<int32_t>(SignalInformation::NetworkType::LTE))) {
        return false;
    }
    if (!parcel.WriteInt32(rxlev_)) {
        return false;
    }
    if (!parcel.WriteInt32(lteRsrp_)) {
        return false;
    }
    if (!parcel.WriteInt32(lteRsrq_)) {
        return false;
    }
    if (!parcel.WriteInt32(lteSnr_)) {
        return false;
    }
    return true;
}

std::unique_ptr<LteSignalInformation> LteSignalInformation::UnMarshalling(Parcel &parcel)
{
    std::unique_ptr<LteSignalInformation> signal = std::make_unique<LteSignalInformation>();
    if (signal && !signal->ReadFromParcel(parcel)) {
        signal = nullptr;
    }
    return signal;
}

bool LteSignalInformation::ReadFromParcel(Parcel &parcel)
{
    if (!parcel.ReadInt32(rxlev_)) {
        return false;
    }
    if (!parcel.ReadInt32(lteRsrp_)) {
        return false;
    }
    if (!parcel.ReadInt32(lteRsrq_)) {
        return false;
    }
    if (!parcel.ReadInt32(lteSnr_)) {
        return false;
    }
    return true;
}

bool LteSignalInformation::ValidateLteValue() const
{
    return (lteRsrp_ >= LTE_RSRP_MINIMUM && lteRsrp_ <= LTE_RSRP_MAXIMUM);
}

bool WcdmaSignalInformation::operator==(const WcdmaSignalInformation &wcdma) const
{
    return wcdmaRxlev_ == wcdma.wcdmaRxlev_ && wcdmaRscp_ == wcdma.wcdmaRscp_ && wcdmaEcio_ == wcdma.wcdmaEcio_ &&
        wcdmaBer_ == wcdma.wcdmaBer_;
}

void WcdmaSignalInformation::SetValue(
    const int32_t wcdmaRxlev, const int32_t wcdmaRscp, const int32_t wcdmaEcio, const int32_t wcdmaBer)
{
    wcdmaRxlev_ = wcdmaRxlev;
    wcdmaRscp_ = wcdmaRscp;
    wcdmaEcio_ = wcdmaEcio;
    wcdmaBer_ = wcdmaBer;
}

int32_t WcdmaSignalInformation::GetRxlev() const
{
    return wcdmaRxlev_;
}

int32_t WcdmaSignalInformation::GetRscp() const
{
    return wcdmaRscp_;
}

int32_t WcdmaSignalInformation::GetEcno() const
{
    return wcdmaEcio_;
}

int32_t WcdmaSignalInformation::GetBer() const
{
    return wcdmaBer_;
}

int32_t WcdmaSignalInformation::GetSignalLevel() const
{
    int32_t level = SIGNAL_LEVEL_INVALID;
    int32_t wcdmaRscp = GetRscp();
    int32_t wcdmaRssi = WCDMA_RSSI_INVALID;
    if (ValidateWcdmaValue()) {
        for (int i = 0; i <= wcdmaRscp; ++i) {
            if (i != 0) {
                ++wcdmaRssi;
            }
        }
        for (int i = signalBar_; i >= 0; --i) {
            if (wcdmaRssi >= WCDMA_SIGNAL_THRESHOLD[i]) {
                level = i;
                break;
            }
        }
    } else {
        TELEPHONY_LOGE("WcdmaSignalInformation::GetSignalLevel Value is Invalid\n");
    }
    return level;
}

SignalInformation::NetworkType WcdmaSignalInformation::GetNetworkType() const
{
    return SignalInformation::NetworkType::WCDMA;
}

std::string WcdmaSignalInformation::ToString() const
{
    int netWorkType = static_cast<int>(WcdmaSignalInformation::GetNetworkType());
    std::string content("networkType:" + std::to_string(netWorkType) + ",wcdmaRscp:" + std::to_string(wcdmaRscp_) +
        ",wcdmaEcio:" + std::to_string(wcdmaEcio_) + ",wcdmaBer:" + std::to_string(wcdmaBer_) + ",wcdmaRxlev:" +
        std::to_string(wcdmaRxlev_) + ",signalLevel:" + std::to_string(WcdmaSignalInformation::GetSignalLevel()));
    return content;
}

sptr<SignalInformation> WcdmaSignalInformation::NewInstance() const
{
    std::unique_ptr<WcdmaSignalInformation> wcdma = std::make_unique<WcdmaSignalInformation>();
    if (wcdma == nullptr) {
        return nullptr;
    }
    wcdma->SetValue(this->wcdmaRxlev_, this->wcdmaRscp_, this->wcdmaEcio_, this->wcdmaBer_);
    return wcdma.release();
}

bool WcdmaSignalInformation::Marshalling(Parcel &parcel) const
{
    if (!parcel.WriteInt32(static_cast<int32_t>(SignalInformation::NetworkType::LTE))) {
        return false;
    }
    if (!parcel.WriteInt32(wcdmaRxlev_)) {
        return false;
    }
    if (!parcel.WriteInt32(wcdmaRscp_)) {
        return false;
    }
    if (!parcel.WriteInt32(wcdmaEcio_)) {
        return false;
    }
    if (!parcel.WriteInt32(wcdmaBer_)) {
        return false;
    }
    return true;
}

std::unique_ptr<WcdmaSignalInformation> WcdmaSignalInformation::UnMarshalling(Parcel &parcel)
{
    std::unique_ptr<WcdmaSignalInformation> signal = std::make_unique<WcdmaSignalInformation>();
    if (signal && !signal->ReadFromParcel(parcel)) {
        signal = nullptr;
    }
    return signal;
}

bool WcdmaSignalInformation::ReadFromParcel(Parcel &parcel)
{
    if (!parcel.ReadInt32(wcdmaRxlev_)) {
        return false;
    }
    if (!parcel.ReadInt32(wcdmaRscp_)) {
        return false;
    }
    if (!parcel.ReadInt32(wcdmaEcio_)) {
        return false;
    }
    if (!parcel.ReadInt32(wcdmaBer_)) {
        return false;
    }
    return true;
}

bool WcdmaSignalInformation::ValidateWcdmaValue() const
{
    return (wcdmaRscp_ > WCDMA_RSCP_MINIMUM && wcdmaRscp_ <= WCDMA_RSCP_MAXIMUM);
}
} // namespace Telephony
} // namespace OHOS
