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

#ifndef NETWORK_INFORMATION_H
#define NETWORK_INFORMATION_H

#include "parcel.h"

namespace OHOS {
namespace Telephony {
enum class NetworkPlmnState {
    NETWORK_PLMN_STATE_UNKNOWN = 0,
    NETWORK_PLMN_STATE_AVAILABLE = 1,
    NETWORK_PLMN_STATE_REGISTERED = 2,
    NETWORK_PLMN_STATE_FORBIDDEN = 3
};

enum class NetworkRat { NETWORK_GSM_OR_GPRS = 0, NETWORK_WCDMA = 2, NETWORK_LTE = 7 };

class NetworkInformation : public Parcelable {
public:
    void SetOperateInformation(const std::string &operatorLongName, const std::string &operatorShortName,
        const std::string &operatorNumeric, int32_t state, int32_t rat_);
    int32_t GetNetworkState() const;
    std::string GetOperatorShortName() const;
    std::string GetOperatorLongName() const;
    std::string GetOperatorNumeric() const;
    int32_t GetRadioTech() const;
    bool ReadFromParcel(Parcel &parcel);
    bool Marshalling(Parcel &parcel) const override;
    static NetworkInformation *Unmarshalling(Parcel &parcel);

private:
    NetworkPlmnState networkPlmnState_ = NetworkPlmnState::NETWORK_PLMN_STATE_UNKNOWN;
    std::string operatorShortName_;
    std::string operatorLongName_;
    std::string operatorNumeric_;
    NetworkRat rat_ = NetworkRat::NETWORK_GSM_OR_GPRS;
};
} // namespace Telephony
} // namespace OHOS
#endif // NETWORK_INFORMATION_H
