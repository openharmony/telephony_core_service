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

#ifndef UNTITLED_SIGNAL_INFORMATION_H
#define UNTITLED_SIGNAL_INFORMATION_H

#include "parcel.h"

namespace OHOS {
namespace Telephony {
static constexpr int MAX_SIGNAL_NUM = 2;
class SignalInformation : public Parcelable {
public:
    enum class NetworkType { GSM = 1, CDMA, LTE, TDSCDMA, WCDMA };
    static constexpr int NO_VALUE = 0x1AAAAAAA;
    static constexpr int32_t GSM_SIGNAL_THRESHOLD_5BAR[] = {-110, -109, -103, -97, -91, -85};
    static constexpr int32_t CDMA_SIGNAL_THRESHOLD_5BAR[] = {-113, -112, -106, -99, -92, -85};
    static constexpr int32_t LTE_SIGNAL_THRESHOLD_5BAR[] = {-121, -120, -115, -110, -105, -97};
    static constexpr int32_t WCDMA_SIGNAL_THRESHOLD_5BAR[] = {-113, -112, -105, -99, -93, -87};
    static constexpr int32_t GSM_SIGNAL_THRESHOLD_4BAR[] = {-110, -103, -97, -91, -85};
    static constexpr int32_t CDMA_SIGNAL_THRESHOLD_4BAR[] = {-113, -106, -99, -92, -85};
    static constexpr int32_t LTE_SIGNAL_THRESHOLD_4BAR[] = {-121, -115, -109, -103, -97};
    static constexpr int32_t WCDMA_SIGNAL_THRESHOLD_4BAR[] = {-113, -105, -99, -93, -87};

public:
    virtual SignalInformation::NetworkType GetNetworkType() const = 0;
    virtual bool Marshalling(Parcel &parcel) const = 0;
    static void InitSignalBar(const int32_t bar = 5);
    static std::unique_ptr<SignalInformation> UnMarshalling(Parcel &parcel);
    virtual bool ReadFromParcel(Parcel &parcel) = 0;
    virtual int32_t GetSignalLevel() const = 0;
    virtual std::string ToString() const = 0;
    virtual sptr<SignalInformation> NewInstance() const = 0;
    SignalInformation();
    virtual ~SignalInformation() = default;

protected:
    static int32_t signalBar_;
};

class GsmSignalInformation : public SignalInformation {
public:
    GsmSignalInformation() = default;
    ~GsmSignalInformation() = default;
    void SetValue(const int32_t gsmRssi = 0, const int32_t gsmBer = 0);
    bool operator==(const GsmSignalInformation &gsm) const;
    int32_t GetRssi() const;
    int32_t GetGsmBer() const;
    int32_t GetSignalLevel() const override;
    std::string ToString() const override;
    sptr<SignalInformation> NewInstance() const override;
    SignalInformation::NetworkType GetNetworkType() const override;
    bool Marshalling(Parcel &parcel) const override;
    static std::unique_ptr<GsmSignalInformation> UnMarshalling(Parcel &parcel);
    bool ReadFromParcel(Parcel &parcel) override;
    bool ValidateGsmValue() const;

private:
    int32_t gsmRxlev_ = 0;
    int32_t gsmBer_ = 0;
};

class CdmaSignalInformation : public SignalInformation {
public:
    CdmaSignalInformation() = default;
    ~CdmaSignalInformation() = default;
    void SetValue(const int32_t cdmaRssi = 0, const int32_t cdmaEcno = 0);
    bool operator==(const CdmaSignalInformation &cdma) const;
    int32_t GetCdmaRssi() const;
    int32_t GetSignalLevel() const override;
    std::string ToString() const override;
    SignalInformation::NetworkType GetNetworkType() const override;
    sptr<SignalInformation> NewInstance() const override;
    bool Marshalling(Parcel &parcel) const override;
    static std::unique_ptr<CdmaSignalInformation> UnMarshalling(Parcel &parcel);
    bool ReadFromParcel(Parcel &parcel) override;
    bool ValidateCdmaValue() const;
    bool ValidateEvdoValue() const;

private:
    int32_t cdmaRssi_ = -1;
    int32_t cdmaEcno_ = -1;
};

class LteSignalInformation : public SignalInformation {
public:
    LteSignalInformation() = default;
    ~LteSignalInformation() = default;
    void SetValue(
        const int32_t rxlev = 0, const int32_t lteRsrp = 0, const int32_t lteRsrq = 0, const int32_t lteSnr = 0);
    bool operator==(const LteSignalInformation &lte) const;
    int32_t GetRxlev() const;
    int32_t GetRsrp() const;
    int32_t GetRsrq() const;
    int32_t GetSnr() const;
    int32_t GetSignalLevel() const override;
    std::string ToString() const override;
    SignalInformation::NetworkType GetNetworkType() const override;
    sptr<SignalInformation> NewInstance() const override;
    bool Marshalling(Parcel &parcel) const override;
    static std::unique_ptr<LteSignalInformation> UnMarshalling(Parcel &parcel);
    bool ReadFromParcel(Parcel &parcel) override;
    bool ValidateLteValue() const;

private:
    int32_t rxlev_ = 0;
    int32_t lteRsrp_ = 0;
    int32_t lteRsrq_ = 0;
    int32_t lteSnr_ = 0;
};

class WcdmaSignalInformation : public SignalInformation {
public:
    WcdmaSignalInformation() = default;
    ~WcdmaSignalInformation() = default;
    void SetValue(const int32_t wcdmaRxlev = 0, const int32_t wcdmaRscp = 0, const int32_t wcdmaEcio = 0,
        const int32_t wcdmaBer = 0);
    bool operator==(const WcdmaSignalInformation &wcdma) const;
    int32_t GetRxlev() const;
    int32_t GetRscp() const;
    int32_t GetEcno() const;
    int32_t GetBer() const;
    int32_t GetSignalLevel() const override;
    std::string ToString() const override;
    SignalInformation::NetworkType GetNetworkType() const override;
    sptr<SignalInformation> NewInstance() const override;
    bool Marshalling(Parcel &parcel) const override;
    static std::unique_ptr<WcdmaSignalInformation> UnMarshalling(Parcel &parcel);
    bool ReadFromParcel(Parcel &parcel) override;
    bool ValidateWcdmaValue() const;

private:
    int32_t wcdmaRxlev_ = 0;
    int32_t wcdmaRscp_ = 0;
    int32_t wcdmaEcio_ = 0;
    int32_t wcdmaBer_ = 0;
};
} // namespace Telephony
} // namespace OHOS
#endif // UNTITLED_SIGNAL_INFORMATION_H
