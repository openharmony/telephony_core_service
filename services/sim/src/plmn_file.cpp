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
#include "plmn_file.h"

namespace OHOS {
namespace Telephony {
PlmnFile::PlmnFile(unsigned char *bytes, int offset)
{
    this->plmn_ = SIMUtils::BcdPlmnConvertToString("", offset);
    const char *plmnData = reinterpret_cast<const char *>(bytes);
    uint32_t aValue = atoi(plmnData + offset + OFFSET_A);
    uint32_t bValue = atoi(plmnData + offset + OFFSET_B);
    this->rat_ = (aValue << OFFSET_ALL) | bValue;
}

PlmnFile::PlmnFile(const std::string &plmn, int accessTechs)
{
    this->plmn_ = plmn;
    this->rat_ = accessTechs;
}

bool PlmnFile::ReadFromParcel(Parcel &parcel)
{
    return true;
}

bool PlmnFile::Marshalling(Parcel &parcel) const
{
    if (!parcel.WriteCString(plmn_.c_str())) {
        TELEPHONY_LOGE("PlmnFile::Marshalling write source plmn_ to parcel failed");
        return false;
    }
    if (!parcel.WriteInt32(rat_)) {
        TELEPHONY_LOGE("PlmnFile::Marshalling write source rat_ to parcel failed");
        return false;
    }
    return true;
}

PlmnFile::~PlmnFile() {}

PlmnFile *PlmnFile::UnMarshalling(Parcel &parcel)
{
    return nullptr;
}
} // namespace Telephony
} // namespace OHOS
