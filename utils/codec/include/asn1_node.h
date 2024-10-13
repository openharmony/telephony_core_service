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

#ifndef ASN1_NODE_H
#define ASN1_NODE_H

#include <cstdbool>
#include <cstdint>
#include <list>
#include <mutex>
#include "telephony_log_wrapper.h"

namespace OHOS {
namespace Telephony {
class Asn1Node {
public:
    Asn1Node(const uint32_t tag, const std::vector<uint8_t> &src, uint32_t offset, uint32_t length);
    uint32_t Asn1NodeToHexStr(std::string &destStr);
    uint32_t Asn1NodeToBytes(std::vector<uint8_t> &dest);
    std::shared_ptr<Asn1Node> Asn1GetChild(const uint32_t tag);
    bool Asn1HasChild(const uint32_t tag);
    std::shared_ptr<Asn1Node> Asn1GetGrandson(const uint32_t firstLevelTag, const uint32_t secondLevelTag);
    std::shared_ptr<Asn1Node> Asn1GetGreatGrandson(const uint32_t firstLevelTag, const uint32_t secondLevelTag,
        const uint32_t thirdLevelTag);
    int32_t Asn1GetChildren(const uint32_t tag, std::list<std::shared_ptr<Asn1Node>> &children);
    uint32_t Asn1GetHeadAsHexStr(std::string &headHex);
    uint32_t Asn1AsBytes(std::vector<uint8_t> &output);
    int32_t Asn1AsInteger();
    uint32_t Asn1AsString(std::string &output);
    int32_t Asn1AsBits();

    void SetDataLength(const uint32_t dataLength)
    {
        dataLength_ = dataLength;
    }

    void SetConstructed(bool constructed)
    {
        constructed_ = constructed;
    }

    void SetEncodedLength(const uint32_t encodedLength)
    {
        encodedLength_ = encodedLength;
    }

    uint32_t GetEncodedLength()
    {
        return encodedLength_ ;
    }

    void AddNodeChildren(const std::shared_ptr<Asn1Node> &asn1Node)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        children_.push_back(asn1Node);
    }

    uint32_t GetNodeTag()
    {
        return tag_;
    }

private:
    int32_t Asn1BuildChildren();
    void Asn1Write(std::vector<uint8_t> &dest);

private:
    uint32_t tag_ = 0;
    std::list<std::shared_ptr<Asn1Node>> children_;
    bool constructed_ = false;
    std::vector<uint8_t> dataBytes_ = {};
    uint32_t dataOffset_ = 0;
    uint32_t dataLength_ = 0;
    uint32_t encodedLength_ = 0;
    std::mutex mutex_;
};
} // namespace Telephony
} // namespace OHOS
#endif // ASN1_NODE_H_