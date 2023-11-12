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

#ifndef OHOS_VCARD_EVENT_DATA_H
#define OHOS_VCARD_EVENT_DATA_H

#include "vcard_contact_data.h"

namespace OHOS {
namespace Telephony {
class VCardEventData : public VCardContactData {
public:
    VCardEventData()
    {
        eventDate_ = "";
        type_ = 0;
        label_ = "";
    };
    ~VCardEventData() {}
    virtual int32_t BuildValuesBucket(OHOS::DataShare::DataShareValuesBucket &valuesBucket);
    virtual int32_t BuildData(std::shared_ptr<DataShare::DataShareResultSet> resultSet);
    std::string GetEventDate();
    void SetEventDate(const std::string &eventDate);
    std::string GetLabelId();
    void SetLabelId(const std::string &labelId);
    std::string GetLabelName();
    void SetLabelName(const std::string &labelName);

private:
    std::string eventDate_;
    int32_t type_;
    std::string label_;
    std::string labelId_;
    std::string labelName_;
};
} // namespace Telephony
} // namespace OHOS
#endif // OHOS_VCARD_EVENT_DATA_H
