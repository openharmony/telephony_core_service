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
#include "vcard_birthday_data.h"

#include "telephony_errors.h"

namespace OHOS {
namespace Telephony {

int32_t VCardBirthdayData::BuildValuesBucket(OHOS::DataShare::DataShareValuesBucket &valuesBucket)
{
    valuesBucket.Put(ContactData::TYPE_ID, TypeId::CONTACT_EVENT);
    valuesBucket.Put(ContactData::DETAIL_INFO, birthday_);
    valuesBucket.Put(ContactData::LABEL_ID, static_cast<int32_t>(EventType::EVENT_BIRTHDAY));
    return TELEPHONY_SUCCESS;
}

int32_t VCardBirthdayData::BuildData(std::shared_ptr<DataShare::DataShareResultSet> resultSet)
{
    return TELEPHONY_SUCCESS;
}

void VCardBirthdayData::InitBirthdayData(std::string &birthday)
{
    birthday_ = birthday;
}

std::string VCardBirthdayData::GetBirthday()
{
    return birthday_;
}
} // namespace Telephony
} // namespace OHOS
