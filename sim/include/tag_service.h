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

#ifndef OHOS_TAG_SERVICE_H
#define OHOS_TAG_SERVICE_H

#include <iostream>
#include "sim_utils.h"

namespace OHOS {
namespace Telephony {
class TagService {
public:
    unsigned char *record_ = nullptr;
    std::string recordData_ = "";
    int recordLen_ = 0;
    int tsOffset_ = 0;
    int tsLength_ = 0;
    int curOffset_ = 0;
    int curDataOffset_ = 0;
    int curDataLength_ = 0;
    bool hasValidTs_ = false;
    TagService(const std::string &data, int offSet);
    ~TagService();
    bool NextObject();
    bool IsValidObject();
    int GetTag();
    std::shared_ptr<unsigned char> GetData(int &dataLen);

private:
    bool FetchCurrentTs();
    const int CHINESE_FLAG = 0x80;
    const int UCS_FLAG = 0x81;
    const int CHINESE_POS = 2;
    const int UCS_POS = 3;
};
} // namespace Telephony
} // namespace OHOS
#endif // OHOS_TAG_SERVICE_H