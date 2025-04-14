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

#include "asn1_node.h"

#include <cctype>
#include <cstdio>
#include <securec.h>
#include "asn1_constants.h"
#include "asn1_decoder.h"
#include "asn1_utils.h"
#include "telephony_errors.h"

namespace OHOS {
namespace Telephony {
namespace {
const uint32_t MAX_DATA_LENGTH = 4;
const uint32_t MIN_DATA_LENGTH = 1;
}

Asn1Node::Asn1Node(const uint32_t tag, const std::vector<uint8_t> &src, uint32_t offset, uint32_t length)
{
    TELEPHONY_LOGD("enter InitAsn1Node %{public}u", tag);
    tag_ = tag;
    constructed_ = Asn1Utils::IsConstructedTag(tag);
    dataBytes_ = src;
    dataOffset_ = offset;
    dataLength_ = length;
    encodedLength_ = Asn1Utils::ByteCountForUint(tag) + Asn1Utils::CalculateEncodedBytesNumForLength(length) + length;
}

uint32_t Asn1Node::Asn1NodeToHexStr(std::string &destStr)
{
    TELEPHONY_LOGD("enter Asn1NodeToHexStr");
    std::vector<uint8_t> byteStream;
    uint32_t byteLen = Asn1NodeToBytes(byteStream);
    destStr = Asn1Utils::BytesToHexStr(byteStream);
    return static_cast<uint32_t>(destStr.length());
}

uint32_t Asn1Node::Asn1NodeToBytes(std::vector<uint8_t> &byteStream)
{
    uint32_t byteLen = 0;
    if (encodedLength_ == 0) {
        TELEPHONY_LOGE("encoded length is 0");
        return byteLen;
    }
    Asn1Write(byteStream);
    return static_cast<uint32_t>(byteStream.size());
}

void Asn1Node::Asn1Write(std::vector<uint8_t> &dest)
{
    // Write the tag.
    TELEPHONY_LOGD("enter Asn1Write tag:%{public}x", tag_);
    std::vector<uint8_t> uintByte;
    uint32_t bytesLen = Asn1Utils::UintToBytes(tag_, uintByte);
    if (bytesLen == 0 || uintByte.empty()) {
        TELEPHONY_LOGE("failed to transform uint data to bytes.");
        return;
    }
    dest.insert(dest.end(), uintByte.begin(), uintByte.end());

    // Write the length.
    if (dataLength_ <= MAX_INT8) {
        dest.push_back(static_cast<char>(dataLength_));
        TELEPHONY_LOGD("dataLength_: %{public}u, length's length:0", dataLength_);
    } else {
        // Bytes required for encoding the length
        uint8_t encodeLens = static_cast<uint8_t>(Asn1Utils::ByteCountForUint(dataLength_) | BIT8_MASK);
        dest.push_back(static_cast<char>(encodeLens));
        std::vector<uint8_t> uintByteStr;
        bytesLen = Asn1Utils::UintToBytes(dataLength_, uintByteStr);
        if (bytesLen == 0 || uintByteStr.empty()) {
            TELEPHONY_LOGE("failed to transform uint data to bytes.");
            return;
        }
        dest.insert(dest.end(), uintByteStr.begin(), uintByteStr.end());
        TELEPHONY_LOGD("dataLength_: %{public}u, length's length:%{public}d", dataLength_, bytesLen);
    }

    // Write the data.
    std::lock_guard<std::mutex> lock(mutex_);
    if (constructed_ && dataBytes_.empty()) {
        std::shared_ptr<Asn1Node> asn1Node = nullptr;
        for (auto it = children_.begin(); it != children_.end(); ++it) {
            asn1Node = *it;
            if (asn1Node == nullptr) {
                break;
            }
            asn1Node->Asn1Write(dest);
        }
    } else if (!dataBytes_.empty()) {
        TELEPHONY_LOGD("dataLen: %{public}u", dataLength_);
        dest.insert(dest.end(), dataBytes_.begin(), dataBytes_.end());
    }
}

std::shared_ptr<Asn1Node> Asn1Node::Asn1GetChild(const uint32_t tag)
{
    if (!constructed_) {
        TELEPHONY_LOGE("TAG not found tag = %{public}u.", tag);
        return nullptr;
    }
    if (Asn1BuildChildren() != TELEPHONY_ERR_SUCCESS) {
        TELEPHONY_LOGE("build children err.");
        return nullptr;
    }
    std::shared_ptr<Asn1Node> curNode = nullptr;
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto it = children_.begin(); it != children_.end(); ++it) {
        curNode = *it;
        if (curNode == nullptr) {
            break;
        }
        if (curNode->GetNodeTag() == tag) {
            return curNode;
        }
    }
    return nullptr;
}

bool Asn1Node::Asn1HasChild(const uint32_t tag)
{
    return (Asn1GetChild(tag) != nullptr);
}

std::shared_ptr<Asn1Node> Asn1Node::Asn1GetGrandson(const uint32_t firstLevelTag, const uint32_t secondLevelTag)
{
    std::shared_ptr<Asn1Node> resultNode = nullptr;
    resultNode = Asn1GetChild(firstLevelTag);
    if (resultNode == nullptr) {
        return nullptr;
    }
    resultNode = resultNode->Asn1GetChild(secondLevelTag);
    return resultNode;
}

std::shared_ptr<Asn1Node> Asn1Node::Asn1GetGreatGrandson(const uint32_t firstLevelTag, const uint32_t secondLevelTag,
    const uint32_t thirdLevelTag)
{
    std::shared_ptr<Asn1Node> resultNode = nullptr;
    resultNode = Asn1GetGrandson(firstLevelTag, secondLevelTag);
    if (resultNode == nullptr) {
        return nullptr;
    }
    resultNode = resultNode->Asn1GetChild(thirdLevelTag);
    return resultNode;
}

int32_t Asn1Node::Asn1GetChildren(const uint32_t tag, std::list<std::shared_ptr<Asn1Node>> &children)
{
    TELEPHONY_LOGD("enter Asn1GetChildren");
    if (!constructed_) {
        TELEPHONY_LOGE("TAG not found tag = %{public}u.", tag);
        return TELEPHONY_ERR_SUCCESS;
    }
    if (Asn1BuildChildren() != TELEPHONY_ERR_SUCCESS) {
        TELEPHONY_LOGE("children is null");
        return TELEPHONY_ERR_FAIL;
    }
    std::shared_ptr<Asn1Node> curNode = nullptr;
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto it = children_.begin(); it != children_.end(); ++it) {
        curNode = *it;
        if (curNode == nullptr) {
            break;
        }
        if (curNode->GetNodeTag() == tag) {
            children.push_back(curNode);
        }
    }
    return TELEPHONY_ERR_SUCCESS;
}

int32_t Asn1Node::Asn1BuildChildren()
{
    if (!constructed_) {
        TELEPHONY_LOGE("TAG not constructed = %{public}d.", constructed_);
        return TELEPHONY_ERR_FAIL;
    }

    std::lock_guard<std::mutex> lock(mutex_);
    if (children_.empty()) {
        TELEPHONY_LOGD("children is empty");
    }

    if (!dataBytes_.empty()) {
        Asn1Decoder decoder(dataBytes_, dataOffset_, dataLength_ - dataOffset_);
        while (decoder.Asn1HasNextNode()) {
            auto subNode = decoder.Asn1NextNode();
            if (subNode == nullptr) {
                break;
            }
            children_.push_back(std::move(subNode));
        }

        dataBytes_.clear();
        dataOffset_ = 0;
    }
    return TELEPHONY_ERR_SUCCESS;
}

uint32_t Asn1Node::Asn1GetHeadAsHexStr(std::string &headHex)
{
    std::string cursor = "";
    uint32_t cursorLen = 0;
    // get tag
    std::vector<uint8_t> byteStream;
    uint32_t byteLen = Asn1Utils::UintToBytes(tag_, byteStream);
    if (byteLen == 0 || byteStream.empty()) {
        TELEPHONY_LOGE("failed to transform uint data to bytes.");
        return TELEPHONY_ERR_FAIL;
    }
    cursor += Asn1Utils::BytesToHexStr(byteStream);
    cursorLen += static_cast<uint32_t>(cursor.length());

    std::string hexStr = "";
    std::string curHexStr = "";
    // get length
    if (dataLength_ <= MAX_INT8) {
        cursorLen += Asn1Utils::ByteToHexStr(static_cast<uint8_t>(dataLength_), hexStr);
    } else {
        uint32_t bytesCount = Asn1Utils::ByteCountForUint(dataLength_);
        cursorLen += Asn1Utils::ByteToHexStr(static_cast<uint8_t>(bytesCount | BIT8_MASK), hexStr);

        std::vector<uint8_t> dataLenStream;
        byteLen = Asn1Utils::UintToBytes(dataLength_, dataLenStream);
        if (byteLen == 0 || dataLenStream.empty()) {
            TELEPHONY_LOGE("failed to transform uint data to bytes.");
            return TELEPHONY_ERR_FAIL;
        }
        curHexStr = Asn1Utils::BytesToHexStr(dataLenStream);
        cursorLen += static_cast<uint32_t>(curHexStr.length());
    }
    cursor += hexStr;
    cursor += curHexStr;
    headHex = cursor;
    return cursorLen;
}

uint32_t Asn1Node::Asn1AsBytes(std::vector<uint8_t> &output)
{
    uint32_t dataLen = 0;
    if (constructed_) {
        TELEPHONY_LOGE("Cannot get value of a constructed node.");
        return dataLen;
    }

    if (dataBytes_.empty()) {
        TELEPHONY_LOGE("Data bytes cannot be nullptr.");
        return dataLen;
    }

    std::vector<uint8_t> dataBytes = dataBytes_;
    if ((dataLength_ - dataOffset_) > dataBytes.size()) {
        TELEPHONY_LOGE("dataOffset_ is out of string range.");
        return dataLen;
    }
    std::vector<uint8_t> byteSteamSegment(dataBytes.begin() + dataOffset_, dataBytes.begin() + dataLength_);
    output = byteSteamSegment;
    dataLen = dataLength_ - dataOffset_;
    return dataLen;
}

int32_t Asn1Node::Asn1AsInteger()
{
    if (constructed_) {
        TELEPHONY_LOGE("Cannot get value of a constructed node.");
        return TELEPHONY_ERR_ARGUMENT_INVALID;
    }

    if (dataBytes_.empty()) {
        TELEPHONY_LOGE("Data bytes cannot be nullptr.");
        return TELEPHONY_ERR_ARGUMENT_INVALID;
    }
    int32_t dataLen = 0;
    if (!Asn1Utils::BytesToInt(dataBytes_, dataOffset_, dataLength_, dataLen)) {
        TELEPHONY_LOGE("Cannot convert tag at offset:%{public}u", dataOffset_);
        return TELEPHONY_ERR_ARGUMENT_INVALID;
    }
    return dataLen;
}

uint32_t Asn1Node::Asn1AsString(std::string &output)
{
    uint32_t hexStrLen = 0;
    if (constructed_) {
        TELEPHONY_LOGE("Cannot get value of a constructed node.");
        return hexStrLen;
    }

    if (dataBytes_.empty()) {
        TELEPHONY_LOGE("Data bytes cannot be nullptr.");
        return hexStrLen;
    }
    std::string hexStr = Asn1Utils::BytesToHexStr(dataBytes_);
    output = hexStr;
    return static_cast<uint32_t>(hexStr.length());
}

int32_t Asn1Node::Asn1AsBits()
{
    int32_t integerVal = 0;
    if (constructed_) {
        TELEPHONY_LOGE("Cannot get value of a constructed node.");
        return integerVal;
    }

    if (dataBytes_.empty()) {
        TELEPHONY_LOGE("Data bytes cannot be nullptr.");
        return integerVal;
    }

    if (dataLength_ > MAX_DATA_LENGTH || dataLength_ < MIN_DATA_LENGTH) {
        TELEPHONY_LOGE("dataLength_ is invalid.");
        return integerVal;
    }

    int32_t dataBits = 0;
    if (!Asn1Utils::BytesToInt(dataBytes_, dataOffset_ + 1, dataLength_ - 1, dataBits)) {
        TELEPHONY_LOGE("Cannot convert tag at offset:%{public}u", dataOffset_ + 1);
        return integerVal;
    }
    uint32_t bits = static_cast<uint32_t>(dataBits);
    int32_t index = static_cast<int32_t>(dataLength_) - 1;
    for (index; index < sizeof(int32_t); index++) {
        bits <<= OFFSET_EIGHT_BIT;
    }
    integerVal = static_cast<int32_t>(Asn1Utils::ReverseInt(bits));
    return integerVal;
}
} // namespace Telephony
}