/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#include "asn1_decoder.h"

#include <cctype>
#include <cstdio>
#include <securec.h>
#include "asn1_constants.h"
#include "asn1_utils.h"

namespace OHOS {
namespace Telephony {
Asn1Decoder::Asn1Decoder(const std::vector<uint8_t> &src, uint32_t offset, uint32_t decodeLen)
{
    TELEPHONY_LOGD("enter Asn1Decoder");
    if ((offset > (std::numeric_limits<uint32_t>::max() - decodeLen)) || ((offset + decodeLen) > src.size())) {
        TELEPHONY_LOGE("Out of the bounds: byteLen=%{public}zu, offset=%{public}u, decodeLen=%{public}u.",
            src.size(), offset, decodeLen);
        return;
    }

    srcData_ = src;
    position_ = offset;
    end_ = offset + decodeLen;

    TELEPHONY_LOGD("byteLen:%{public}zu, offset:%{public}u, decodeLen:%{public}u", src.size(), offset, decodeLen);
}

bool Asn1Decoder::Asn1HasNextNode()
{
    return position_ < end_;
}

std::shared_ptr<Asn1Node> Asn1Decoder::Asn1NextNode()
{
    TELEPHONY_LOGD("enter Asn1NextNode");
    if (end_ <= position_ || srcData_.empty()) {
        TELEPHONY_LOGE("No bytes to parse.");
        return nullptr;
    }

    uint32_t offset = position_;
    uint32_t tagStart = offset;
    if (offset >= srcData_.size()) {
        return nullptr;
    }
    uint8_t byteTag = srcData_[offset];
    offset++;
    uint8_t lowFiveBit = 0x1F;
    // the lower 5 bits of variable bitTag is tag number, 0x1F represent invalid val.
    if ((byteTag & lowFiveBit) == lowFiveBit) {
        while (offset < end_ && (static_cast<uint8_t>(srcData_[offset]) & BIT8_MASK) != 0) {
            offset++;
        }
        offset++;
    }
    if (offset >= end_) {
        TELEPHONY_LOGE("No bytes to parse.");
        return nullptr;
    }
    int32_t tag = -1;
    bool ret = Asn1Utils::BytesToInt(srcData_, tagStart, offset - tagStart, tag);
    if (!ret || tag < 0) {
        TELEPHONY_LOGE("Cannot parse tag at position: %{public}u", tagStart);
        return nullptr;
    }
    return BuildAsn1Node(static_cast<uint32_t>(tag), offset, tagStart);
}

std::shared_ptr<Asn1Node> Asn1Decoder::BuildAsn1Node(const uint32_t tag, uint32_t offset, uint32_t tagStart)
{
    if (srcData_.empty() || offset >= srcData_.size()) {
        TELEPHONY_LOGE("srcData_ is empty");
        return nullptr;
    }
    uint32_t dataLen;
    uint8_t byteLen = srcData_[offset];
    offset++;
    // The highest bit being 1 indicates that the following 7 bits represent the length of the length field.
    if ((byteLen & BIT8_MASK) == 0) {
        dataLen = static_cast<uint32_t>(byteLen);
    } else {
        uint32_t lenLen = static_cast<uint32_t>(byteLen & MAX_INT8);
        if (offset + lenLen > end_) {
            TELEPHONY_LOGE("Cannot parse tag at position: %{public}u", tagStart);
            return nullptr;
        }
        int32_t len = 0;
        if (!Asn1Utils::BytesToInt(srcData_, offset, lenLen, len)) {
            TELEPHONY_LOGE("Cannot convert tag at offset:%{public}u", offset);
            return nullptr;
        }
        dataLen = static_cast<uint32_t>(len);
        offset += lenLen;
    }
    if (offset + dataLen > end_) {
        TELEPHONY_LOGE("Incomplete data at position: offset=%{public}u, dataLen=%{public}u, leftLength=%{public}u.",
            offset, dataLen, (end_ - offset));
        return nullptr;
    }
    std::vector<uint8_t> byteStream(srcData_.begin() + offset, srcData_.begin() + offset + dataLen);
    std::shared_ptr<Asn1Node> asn1Node = std::make_shared<Asn1Node>(tag, byteStream, 0, dataLen);
    position_ = offset + dataLen;
    return asn1Node;
}
} // namespace Telephony
}
