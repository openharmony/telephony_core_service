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
#include "vcard_nickname_data.h"

#include "telephony_errors.h"

namespace OHOS {
namespace Telephony {

int32_t VCardNicknameData::BuildValuesBucket(OHOS::DataShare::DataShareValuesBucket &valuesBucket)
{
    valuesBucket.Put(ContactData::TYPE_ID, TypeId::NICKNAME);
    valuesBucket.Put(ContactData::DETAIL_INFO, nickname_);
    return TELEPHONY_SUCCESS;
}

int32_t VCardNicknameData::BuildData(std::shared_ptr<DataShare::DataShareResultSet> resultSet)
{
    if (resultSet == nullptr) {
        return TELEPHONY_ERROR;
    }
    int32_t index;
    resultSet->GetColumnIndex(ContactData::DETAIL_INFO, index);
    resultSet->GetString(index, nickname_);
    return TELEPHONY_SUCCESS;
}

void VCardNicknameData::SetNickName(const std::string &nickname)
{
    nickname_ = nickname;
}

std::string VCardNicknameData::GetNickName()
{
    return nickname_;
}

} // namespace Telephony
} // namespace OHOS
