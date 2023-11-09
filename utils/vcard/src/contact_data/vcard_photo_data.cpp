/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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
#include "vcard_photo_data.h"

#include "telephony_errors.h"

namespace OHOS {
namespace Telephony {

int32_t VCardPhotoData::BuildValuesBucket(OHOS::DataShare::DataShareValuesBucket &valuesBucket)
{
    valuesBucket.Put(ContactData::TYPE_ID, TypeId::PHOTO);
    valuesBucket.Put(ContactData::DETAIL_INFO, bytes_);
    return TELEPHONY_SUCCESS;
}

int32_t VCardPhotoData::BuildData(std::shared_ptr<DataShare::DataShareResultSet> resultSet)
{
    if (resultSet == nullptr) {
        return TELEPHONY_ERROR;
    }
    int32_t index;
    resultSet->GetColumnIndex(ContactData::DETAIL_INFO, index);
    resultSet->GetString(index, bytes_);
    return TELEPHONY_SUCCESS;
}

void VCardPhotoData::InitPhotoData(std::string &format, std::string &hexBytes)
{
    format_ = format;
    bytes_ = hexBytes;
}

void VCardPhotoData::SetFormat(std::string &format)
{
    format_ = format;
}
void VCardPhotoData::SetHexBytes(std::string &hexBytes)
{
    hexBytes_ = hexBytes;
}
std::string VCardPhotoData::GetFormat()
{
    return format_;
}
std::string VCardPhotoData::GetHexBytes()
{
    return hexBytes_;
}

std::string VCardPhotoData::GetBytes()
{
    return bytes_;
}

void VCardPhotoData::SetBytes(const std::string &bytes)
{
    bytes_ = bytes;
}

} // namespace Telephony
} // namespace OHOS
