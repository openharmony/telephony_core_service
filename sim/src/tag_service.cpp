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
TagService::TagService(const std::string &data, int offSet)
{
    if (data.empty()) {
        return;
    }
    recordData_ = data;
    int length = 0;
    std::shared_ptr<unsigned char> record = SIMUtils::HexStringConvertToBytes(data, length);
    record_ = record.get();
    tsOffset_ = offSet;
    tsLength_ = length;
    curOffset_ = offSet;
    hasValidTs_ = FetchCurrentTs();
}

TagService::~TagService() {}

bool TagService::NextObject()
{
    if (!hasValidTs_) {
        return false;
    }
    curOffset_ = curDataOffset_ + curDataLength_;
    hasValidTs_ = FetchCurrentTs();
    return hasValidTs_;
}

bool TagService::IsValidObject()
{
    return hasValidTs_;
}

int TagService::GetTag()
{
    if (!hasValidTs_) {
        return 0;
    }
    return record_[curOffset_] & BYTE_VALUE;
}

std::shared_ptr<unsigned char> TagService::GetData(int &dataLen)
{
    if (!hasValidTs_) {
        return nullptr;
    }
    if (curDataLength_ <= 0) {
        return nullptr;
    }
    unsigned char *cache = (unsigned char *)calloc(curDataLength_, sizeof(unsigned char));
    if (cache == nullptr) {
        return nullptr;
    }
    std::shared_ptr<unsigned char> ret(cache);
    SIMUtils::ArrayCopy(record_, curDataOffset_, ret.get(), 0, curDataLength_);
    dataLen = curDataLength_;
    return ret;
}

bool TagService::FetchCurrentTs()
{
    if (record_ == nullptr) {
        return false;
    }
    if ((record_[curOffset_] == 0) || ((record_[curOffset_] & BYTE_VALUE) == BYTE_VALUE)) {
        return false;
    }

    if ((record_[curOffset_ + 1] & BYTE_VALUE) < CHINESE_FLAG) {
        curDataLength_ = record_[curOffset_ + 1] & BYTE_VALUE;
        curDataOffset_ = curOffset_ + CHINESE_POS;
    } else if ((record_[curOffset_ + 1] & BYTE_VALUE) == UCS_FLAG) {
        curDataLength_ = record_[curOffset_ + CHINESE_POS] & BYTE_VALUE;
        curDataOffset_ = curOffset_ + UCS_POS;
    } else {
        return false;
    }

    if ((curDataLength_ + curDataOffset_) > (tsOffset_ + tsLength_)) {
        return false;
    }

    return true;
}
} // namespace Telephony
} // namespace OHOS
