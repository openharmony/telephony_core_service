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

#include <charconv>
#include <cinttypes>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <string>
#include <vector>

#include "sim_constant.h"
#include "sim_utils.h"

namespace OHOS {
namespace Telephony {
class TagService {
public:
    explicit TagService(const std::string &data);
    explicit TagService(const std::vector<uint8_t> &data);
    virtual ~TagService();
    bool Next();
    int GetTagCode() const;
    void GetValue(std::vector<uint8_t> &result) const;
    uint8_t GetLength() const;
    constexpr static uint8_t HEX_TYPE = 16;

private:
    uint8_t length_ = 0;
    std::string tag_;
    size_t offset_ = 0;
    std::vector<uint8_t> data_;
    size_t dataOffset_ = 0;
    bool hasNext_ = true;
    constexpr static uint8_t CHINESE_FLAG = 0x80;
    constexpr static uint8_t UCS_FLAG = 0x81;
    constexpr static uint8_t CHINESE_POS = 2;
    constexpr static uint8_t UCS_POS = 3;
    constexpr static uint8_t CUR_OFFSET = 1;
};
} // namespace Telephony
} // namespace OHOS
#endif // OHOS_TAG_SERVICE_H