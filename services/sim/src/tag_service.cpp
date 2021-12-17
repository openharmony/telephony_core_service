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

namespace OHOS {
namespace Telephony {
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

static const int kCONTINUE = 0;
static const int kFINISH = 1;
static const int kERROR = -1;
static const size_t kFst = 0;
static const size_t kSnd = 1;
static const uint8_t BYTE_ZERO = 0;
static const uint8_t WORD_LEN = 2;
static int TagFunc(const uint8_t arg, const size_t order, std::string &tag)
{
    constexpr size_t BuffSize = 3;
    constexpr size_t CharLen = 2;
    switch (order) {
        case kFst:
            if (arg == BYTE_ZERO || arg == UINT8_MAX) {
                return kERROR;
            } else {
                char buff[BuffSize] = {BYTE_ZERO, BYTE_ZERO, BYTE_ZERO};
                std::to_chars(buff, buff + CharLen, arg, TagService::HEX_TYPE);
                tag.append(std::begin(buff), std::end(buff));
                return kFINISH;
            }
        default:
            break;
    }
    return kERROR;
}

static int LengthFunc(const uint8_t arg, const size_t order, uint8_t &len)
{
    switch (order) {
        case kFst:
            if (arg < CHINESE_FLAG) {
                len = arg;
                return kFINISH;
            } else if (arg == UCS_FLAG) {
                len = BYTE_ZERO;
                return kCONTINUE;
            }
            break;
        case kSnd:
            len = arg;
            return kFINISH;
        default:
            break;
    }
    return kERROR;
}

static std::string HexVecToHexStr(const std::vector<uint8_t> &arr)
{
    std::stringstream ss;
    for (auto it = arr.begin(); it != arr.end(); it++) {
        ss << std::setiosflags(std::ios::uppercase) << std::hex << std::setw(WORD_LEN) << std::setfill('0') << int(*it);
    }
    return ss.str();
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
        HexVecToHexStr(std::vector<uint8_t>(data_.begin() + dataOffset_, data_.begin() + dataOffset_ + length_))
            .c_str());
    return hasNext_;
}
} // namespace Telephony
} // namespace OHOS
