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
class SignalInformation : public Parcelable {
public:
    enum class NetworkType { GSM = 1, CDMA, LTE, TDSCDMA };
    static constexpr int NO_VALUE = 0x1AAAAAAA;
    static constexpr int GSM_SIGNAL_THRESHOLD_5BAR[] = {2, 4, 6, 8, 10, 12};
    static constexpr int CDMA_SIGNAL_THRESHOLD_5BAR[] = {-113, -112, -106, -99, -92, -85};
    static constexpr int EDVO_SIGNAL_THRESHOLD_5BAR[] = {-113, -112, -106, -99, -92, -85};
    static constexpr int LTE_SIGNAL_THRESHOLD_5BAR[] = {-121, -120, -115, -110, -105, -97};
    static constexpr int TDSCDMA_SIGNAL_THRESHOLD_5BAR[] = {-112, -111, -105, -99, -93, -87};
    static constexpr int GSM_SIGNAL_THRESHOLD_4BAR[] = {2, 3, 5, 8, 12};
    static constexpr int CDMA_SIGNAL_THRESHOLD_4BAR[] = {-113, -109, -101, -93, -85};
    static constexpr int EDVO_SIGNAL_THRESHOLD_4BAR[] = {-113, -109, -101, -93, -85};
    static constexpr int LTE_SIGNAL_THRESHOLD_4BAR[] = {-121, -120, -114, -107, -97};
    static constexpr int TDSCDMA_SIGNAL_THRESHOLD_4BAR[] = {-112, -111, -103, -95, -87};
    static const int *g_gsmSignalThreshold;
    static const int *g_cdmaSignalThreshold;
    static int g_signalBar;
    virtual SignalInformation::NetworkType GetNetworkType() const = 0;
    virtual bool Marshalling(Parcel &parcel) const = 0;
    static std::unique_ptr<SignalInformation> UnMarshalling(Parcel &parcel);
    virtual bool ReadFromParcel(Parcel &parcel) = 0;
    virtual int32_t GetSignalLevel() const = 0;
    virtual sptr<SignalInformation> NewInstance() const = 0;
    SignalInformation() = default;
    virtual ~SignalInformation() = default;
};

class GsmSignalInformation : public SignalInformation {
public:
    GsmSignalInformation();
    ~GsmSignalInformation();
    void SetValue(const int32_t gsmRssi = 0, const int32_t timeAdvance = 0);
    bool operator==(const GsmSignalInformation &gsm) const;
    int32_t GetRssi() const;
    int32_t GetSignalLevel() const override;
    int32_t GetTimeAdvance() const;
    std::u16string ToString() const;
    sptr<SignalInformation> NewInstance() const override;
    SignalInformation::NetworkType GetNetworkType() const override;
    bool Marshalling(Parcel &parcel) const override;
    static std::unique_ptr<GsmSignalInformation> UnMarshalling(Parcel &parcel);
    bool ReadFromParcel(Parcel &parcel) override;
    bool ValidateGsmValue() const;

private:
    int32_t gsmRssi_ = 0;
    int32_t timeAdvance_ = 0;
};

class CdmaSignalInformation : public SignalInformation {
public:
    CdmaSignalInformation();
    ~CdmaSignalInformation();
    void SetValue(const int32_t cdmaRssi = 0, const int32_t cdmaEcno = 0);
    bool operator==(const CdmaSignalInformation &cdma) const;
    int32_t GetCdmaRssi() const;
    int32_t GetSignalLevel() const override;
    std::u16string ToString() const;
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
} // namespace OHOS
#endif // UNTITLED_SIGNAL_INFORMATION_H
