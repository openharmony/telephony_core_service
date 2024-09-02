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
 
#ifndef OHOS_VCARD_GROUP_DATA_H
#define OHOS_VCARD_GROUP_DATA_H
 
#include "vcard_contact_data.h"
 
namespace OHOS {
namespace Telephony {
class VCardGroupData : public VCardContactData {
public:
    VCardGroupData()
    {
        groupName_ = "";
        groupId_ = 0;
    }
    ~VCardGroupData() {}
    virtual int32_t BuildValuesBucket(OHOS::DataShare::DataShareValuesBucket &valuesBucket);
    virtual int32_t BuildData(std::shared_ptr<DataShare::DataShareResultSet> resultSet);
    void SetGroupName(std::string groupName);
    std::string GetGroupName();
    void SetGroupId(int32_t groupId);
    int32_t GetGroupId();
    
private:
    std::string groupName_;
    int32_t groupId_;
};
} // namespace Telephony
} // namespace OHOS
#endif // OHOS_VCARD_GROUP_DATA_H