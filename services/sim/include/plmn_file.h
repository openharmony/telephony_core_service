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

#ifndef OHOS_PLMN_FILE_H
#define OHOS_PLMN_FILE_H

#include <iostream>
#include <sstream>

#include "parcel.h"
#include "sim_utils.h"
#include "telephony_log_wrapper.h"

namespace OHOS {
namespace Telephony {
class PlmnFile : public Parcelable {
public:
    bool ReadFromParcel(Parcel &parcel);
    virtual bool Marshalling(Parcel &parcel) const override;
    static PlmnFile *UnMarshalling(Parcel &parcel);
    PlmnFile(unsigned char *bytes, int offset);
    ~PlmnFile();

private:
    PlmnFile(const std::string &plmn, int accessTechs);
    std::string AccessTechString();
    static const uint32_t OFFSET_A = 3;
    static const uint32_t OFFSET_B = 4;
    static const uint32_t OFFSET_ALL = 8;
    static const uint32_t RAT_UMTS = 0x8000;
    static const uint32_t RAT_LTE = 0x4000;
    static const uint32_t RAT_GSM = 0x0080;
    static const uint32_t RAT_GSM_COMPACT = 0x0040;
    static const uint32_t RAT_EVDO = 0x0020;
    static const uint32_t RAT_1X = 0x0010;
    static const uint32_t RAT_REMAINED = 0x3F0F;
    std::string plmn_ = "";
    uint32_t rat_ = 0;
};
} // namespace Telephony
} // namespace OHOS
#endif // OHOS_PLMN_FILE_H
