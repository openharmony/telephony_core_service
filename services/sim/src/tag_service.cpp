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

#include "tag_service.h"

#include "telephony_common_utils.h"

namespace OHOS {
namespace Telephony {
static const int CONTINUE = 0;
static const int FINISH = 1;
static const int ERROR = -1;
static const size_t FIRST = 0;
static const size_t SECOND = 1;
static const uint8_t BYTE_ZERO = 0;
static const uint8_t WORD_LEN = 2;
constexpr size_t BUFF_SIZE = 3;
constexpr size_t CHAR_LEN = 2;

TagService::TagService(const std::string &data)
{
    if (data.empty() || data.size() % CHINESE_POS) {
        return;
    }
    for (auto it = data.begin(); it != data.end(); it += CHINESE_POS) {
        uint8_t res = 0;
        std::from_chars(std::addressof(*it), std::addressof(*(it + CHINESE_POS)), res, HEX_TYPE);
        data_.push_back(res);
    }
}

TagService::TagService(const std::vector<uint8_t> &data) : data_(data) {}

TagService::~TagService() {}

int TagService::GetTagCode() const
{
    TELEPHONY_LOGI("GetTagCode : %{public}s", tag_.c_str());
    std::string tagTemp = tag_.c_str();
    if (!IsValidHexValue(tagTemp)) {
        TELEPHONY_LOGE("GetTagCode return ERR");
        return ERR;
    }
    int i = std::stoi(tag_, nullptr, HEX_TYPE);
    return i;
}

void TagService::GetValue(std::vector<uint8_t> &result) const
{
    result.clear();
    for (uint8_t i = 0; i < length_; ++i) {
        result.push_back(data_.at(dataOffset_ + i));
    }
}

uint8_t TagService::GetLength() const
{
    return length_;
}

static int TagFunc(const uint8_t arg, const size_t order, std::string &tag)
{
    switch (order) {
        case FIRST:
            if (arg == BYTE_ZERO || arg == UINT8_MAX) {
                return ERROR;
            } else {
                char buff[BUFF_SIZE] = {BYTE_ZERO, BYTE_ZERO, BYTE_ZERO};
                std::to_chars(buff, buff + CHAR_LEN, arg, TagService::HEX_TYPE);
                tag.append(std::begin(buff), std::end(buff));
                return FINISH;
            }
        default:
            break;
    }
    return ERROR;
}

static int LengthFunc(const uint8_t arg, const size_t order, uint8_t &len)
{
    switch (order) {
        case FIRST:
            if (arg < CHINESE_FLAG) {
                len = arg;
                return FINISH;
            } else if (arg == UCS_FLAG) {
                len = BYTE_ZERO;
                return CONTINUE;
            }
            break;
        case SECOND:
            len = arg;
            return FINISH;
        default:
            break;
    }
    return ERROR;
}

bool TagService::Next()
{
    TELEPHONY_LOGI("TagService::Next begin!!");
    if (!hasNext_ || offset_ >= data_.size()) {
        hasNext_ = false;
        return false;
    }
    constexpr int INT_ZERO = 0;
    /* parse tag */
    tag_.clear();
    size_t order = INT_ZERO;
    for (; offset_ < data_.size(); ++offset_, ++order) {
        const auto res = TagFunc(data_.at(offset_), order, tag_);
        if (res < INT_ZERO) {
            hasNext_ = false;
            return hasNext_;
        } else if (res > INT_ZERO) {
            ++offset_;
            break;
        }
    }
    TELEPHONY_LOGI("TagService::Next for tag : %{public}s", tag_.c_str());
    /* parse length */
    if (offset_ >= data_.size()) {
        hasNext_ = false;
        return false;
    }
    length_ = INT_ZERO;
    order = INT_ZERO;
    for (; offset_ < data_.size(); ++offset_, ++order) {
        const auto res = LengthFunc(data_.at(offset_), order, length_);
        if (res < INT_ZERO) {
            hasNext_ = false;
            return hasNext_;
        } else if (res > INT_ZERO) {
            ++offset_;
            break;
        }
    }
    TELEPHONY_LOGI("TagService::Next for length : %{public}d", length_);
    /* parse value */
    dataOffset_ = offset_;
    offset_ += static_cast<size_t>(length_);
    if (offset_ > data_.size()) {
        hasNext_ = false;
    }
    TELEPHONY_LOGI("TagService::Next for value : %{public}s",
        SIMUtils::HexVecToHexStr(std::vector<uint8_t>(data_.begin() + dataOffset_, data_.begin() +
        dataOffset_ + length_)).c_str());
    return hasNext_;
}
} // namespace Telephony
} // namespace OHOS
