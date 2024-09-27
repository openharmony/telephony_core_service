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

#include "asn1_builder.h"

#include <cctype>
#include <cstdio>
#include <securec.h>
#include "asn1_constants.h"
#include "asn1_node.h"
#include "asn1_utils.h"
#include "telephony_errors.h"

namespace OHOS {
namespace Telephony {
namespace {
const uint32_t FIVE_BYTE_LENGTH = 5;
const uint32_t ONE_BYTE_OCCPUPIED_BIT_COUNT = 8;
}

void Asn1Builder::Asn1AddChild(const std::shared_ptr<Asn1Node> node)
{
    std::lock_guard<std::mutex> lock(mutex_);
    children_.push_back(node);
}

int32_t Asn1Builder::Asn1AddChildAsBytes(uint32_t tag, const std::vector<uint8_t> &childByte, uint32_t byteLen)
{
    TELEPHONY_LOGD("enter Asn1AddChildAsBytes");
    if (childByte.empty()) {
        TELEPHONY_LOGE("childByte is empty.");
        return TELEPHONY_ERR_ARGUMENT_NULL;
    }

    if (Asn1Utils::IsConstructedTag(tag)) {
        TELEPHONY_LOGE("Cannot set value of a constructed tag: %{public}u", tag);
        return TELEPHONY_ERR_FAIL;
    }
    std::shared_ptr<Asn1Node> node = std::make_shared<Asn1Node>(tag, childByte, 0, byteLen);
    Asn1AddChild(node);
    return TELEPHONY_ERR_SUCCESS;
}

int32_t Asn1Builder::Asn1AddChildAsString(uint32_t tag, const std::string &childStr)
{
    TELEPHONY_LOGD("enter Asn1AddChildAsString");
    if (childStr.empty()) {
        TELEPHONY_LOGE("childStr is empty.");
        return TELEPHONY_ERR_ARGUMENT_NULL;
    }

    std::vector<uint8_t> bytes = Asn1Utils::StringToBytes(childStr);
    return Asn1AddChildAsBytes(tag, bytes, bytes.size());
}

int32_t Asn1Builder::Asn1AddChildAsInteger(uint32_t tag, uint32_t childInt)
{
    TELEPHONY_LOGD("enter Asn1AddChildAsInteger");
    if (Asn1Utils::IsConstructedTag(tag)) {
        TELEPHONY_LOGE("Cannot set value of a constructed tag: %{public}u", tag);
        return TELEPHONY_ERR_FAIL;
    }
    std::vector<uint8_t> intBytes;
    uint32_t bytesLen = Asn1Utils::UintToBytes(childInt, intBytes);
    if (bytesLen == 0 || intBytes.empty()) {
        TELEPHONY_LOGE("failed to transform uint data to bytes.");
        return TELEPHONY_ERR_FAIL;
    }

    std::shared_ptr<Asn1Node> node = std::make_shared<Asn1Node>(tag, intBytes, 0, bytesLen);
    Asn1AddChild(node);
    return TELEPHONY_ERR_SUCCESS;
}

int32_t Asn1Builder::Asn1AddChildAsSignedInteger(uint32_t tag, int32_t childSignedInt)
{
    TELEPHONY_LOGD("enter Asn1AddChildAsSignedInteger");
    if (Asn1Utils::IsConstructedTag(tag)) {
        TELEPHONY_LOGE("Cannot set value of a constructed tag: %{public}u", tag);
        return TELEPHONY_ERR_FAIL;
    }
    std::vector<uint8_t> intBytes;
    uint32_t bytesLen = Asn1Utils::IntToBytes(childSignedInt, intBytes);
    std::shared_ptr<Asn1Node> node = std::make_shared<Asn1Node>(tag, intBytes, 0, bytesLen);
    Asn1AddChild(node);
    return TELEPHONY_ERR_SUCCESS;
}

int32_t Asn1Builder::Asn1AddChildAsBits(uint32_t tag, int32_t childBits)
{
    TELEPHONY_LOGD("enter Asn1AddChildAsBits");
    if (Asn1Utils::IsConstructedTag(tag)) {
        TELEPHONY_LOGE("Cannot set value of a constructed tag: %{public}u", tag);
        return TELEPHONY_ERR_FAIL;
    }

    uint32_t dataLength = 0;
    std::vector<uint8_t> childByte(FIVE_BYTE_LENGTH, '\0');
    uint32_t reverseInt = Asn1Utils::ReverseInt(childBits);
    for (uint32_t i = 1; i < childByte.size(); i++) {
        childByte[i] = static_cast<uint8_t>(reverseInt >> ((sizeof(uint32_t) - i) * ONE_BYTE_OCCPUPIED_BIT_COUNT));
        if (childByte[i] != 0) {
            dataLength = i;
        }
    }
    dataLength++;
    childByte[0] = Asn1Utils::CountTrailingZeros(childByte[dataLength - 1]);

    std::shared_ptr<Asn1Node> node = std::make_shared<Asn1Node>(tag, childByte, 0, dataLength);
    Asn1AddChild(node);
    return TELEPHONY_ERR_SUCCESS;
}

int32_t Asn1Builder::Asn1AddChildAsBoolean(uint32_t tag, bool flag)
{
    TELEPHONY_LOGD("enter Asn1AddChildAsBoolean");
    std::vector<uint8_t> boolByteVec = {};
    if (flag) {
        boolByteVec.push_back(static_cast<uint8_t>(MAX_UINT8));
    } else {
        boolByteVec.push_back(static_cast<uint8_t>(0));
    }
    int32_t ret = Asn1AddChildAsBytes(tag, boolByteVec, boolByteVec.size());
    return ret;
}

std::shared_ptr<Asn1Node> Asn1Builder::Asn1Build()
{
    TELEPHONY_LOGD("enter Asn1Build");
    std::vector<uint8_t> byteStream = {};
    std::shared_ptr<Asn1Node> newNode = std::make_shared<Asn1Node>(tag_, byteStream, 0, 0);
    if (newNode == nullptr) {
        TELEPHONY_LOGE("newNode is nullptr.");
        return nullptr;
    }
    // calculate newNode's length, and move asn1Node from builder to newNode
    std::shared_ptr<Asn1Node> asn1Node = nullptr;
    uint32_t dataLen = 0;
    std::lock_guard<std::mutex> lock(mutex_);
    for (const auto &it = children_.begin(); it != children_.end(); ++it) {
        asn1Node = *it;
        if (asn1Node == nullptr) {
            break;
        }
        dataLen += asn1Node->GetEncodedLength();
        newNode->AddNodeChildren(std::move(asn1Node));
    }
    children_.clear();
    newNode->SetDataLength(dataLen);

    // refresh node info
    newNode->SetConstructed(true);
    newNode->SetEncodedLength(Asn1Utils::ByteCountForUint(tag_) +
        Asn1Utils::CalculateEncodedBytesNumForLength(dataLen) + dataLen);

    return newNode;
}

uint32_t Asn1Builder::Asn1BuilderToHexStr(std::string &destStr)
{
    TELEPHONY_LOGD("enter Asn1BuilderToHexStr");
    uint32_t strLen = 0;
    std::shared_ptr<Asn1Node> node = Asn1Build();
    if (node == nullptr) {
        return strLen;
    }
    strLen = node->Asn1NodeToHexStr(destStr);
    TELEPHONY_LOGD("destStr:%{public}s", destStr.c_str());
    return strLen;
}
} // namespace Telephony
}