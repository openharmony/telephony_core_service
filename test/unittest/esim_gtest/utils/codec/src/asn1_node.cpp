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
uint32_t Asn1Node::Asn1NodeToHexStr(std::string &destStr)
{
    auto mock = MockAsn1Node::GetMock();
    if (mock == nullptr) {
        return -1;
    }
    return mock->Asn1NodeToHexStr(destStr);
}

uint32_t Asn1Node::Asn1NodeToBytes(std::vector<uint8_t> &byteStream)
{
    auto mock = MockAsn1Node::GetMock();
    if (mock == nullptr) {
        return -1;
    }
    return mock->Asn1NodeToBytes(byteStream);
}

void Asn1Node::Asn1Write(std::vector<uint8_t> &dest)
{
    auto mock = MockAsn1Node::GetMock();
    if (mock == nullptr) {
        return;
    }
    return mock->Asn1Write(dest);
}

std::shared_ptr<Asn1Node> Asn1Node::Asn1GetChild(const uint32_t tag)
{
    auto mock = MockAsn1Node::GetMock();
    if (mock == nullptr) {
        return nullptr;
    }
    return mock->Asn1GetChild(tag);
}

bool Asn1Node::Asn1HasChild(const uint32_t tag)
{
    auto mock = MockAsn1Node::GetMock();
    if (mock == nullptr) {
        return false;
    }
    return mock->Asn1HasChild(tag);
}

std::shared_ptr<Asn1Node> Asn1Node::Asn1GetGrandson(const uint32_t firstLevelTag, const uint32_t secondLevelTag)
{
    auto mock = MockAsn1Node::GetMock();
    if (mock == nullptr) {
        return nullptr;
    }
    return mock->Asn1GetGrandson(firstLevelTag, secondLevelTag);
}

std::shared_ptr<Asn1Node> Asn1Node::Asn1GetGreatGrandson(const uint32_t firstLevelTag, const uint32_t secondLevelTag,
    const uint32_t thirdLevelTag)
{
    auto mock = MockAsn1Node::GetMock();
    if (mock == nullptr) {
        return nullptr;
    }
    return mock->Asn1GetGreatGrandson(firstLevelTag, secondLevelTag, thirdLevelTag);
}

int32_t Asn1Node::Asn1GetChildren(const uint32_t tag, std::list<std::shared_ptr<Asn1Node>> &children)
{
    auto mock = MockAsn1Node::GetMock();
    if (mock == nullptr) {
        return -1;
    }
    return mock->Asn1GetChildren(tag, children);
}

int32_t Asn1Node::Asn1BuildChildren()
{
    auto mock = MockAsn1Node::GetMock();
    if (mock == nullptr) {
        return -1;
    }
    return mock->Asn1BuildChildren();
}

uint32_t Asn1Node::Asn1GetHeadAsHexStr(std::string &headHex)
{
    auto mock = MockAsn1Node::GetMock();
    if (mock == nullptr) {
        return -1;
    }
    return mock->Asn1GetHeadAsHexStr(headHex);
}

uint32_t Asn1Node::Asn1AsBytes(std::vector<uint8_t> &output)
{
    auto mock = MockAsn1Node::GetMock();
    if (mock == nullptr) {
        return -1;
    }
    return mock->Asn1AsBytes(output);
}

int32_t Asn1Node::Asn1AsInteger()
{
    auto mock = MockAsn1Node::GetMock();
    if (mock == nullptr) {
        return -1;
    }
    return mock->Asn1AsInteger();
}

uint32_t Asn1Node::Asn1AsString(std::string &output)
{
    auto mock = MockAsn1Node::GetMock();
    if (mock == nullptr) {
        return -1;
    }
    return mock->Asn1AsString(output);
}

int32_t Asn1Node::Asn1AsBits()
{
    auto mock = MockAsn1Node::GetMock();
    if (mock == nullptr) {
        return -1;
    }
    return mock->Asn1AsBits();
}

void Asn1Node::SetDataLength(const uint32_t dataLength)
{
    auto mock = MockAsn1Node::GetMock();
    if (mock == nullptr) {
        return;
    }
    return mock->SetDataLength(dataLength);
}
void Asn1Node::SetConstructed(bool constructed)
{
    auto mock = MockAsn1Node::GetMock();
    if (mock == nullptr) {
        return;
    }
    return mock->SetConstructed(constructed);
}

void Asn1Node::SetEncodedLength(const uint32_t encodedLength)
{
    auto mock = MockAsn1Node::GetMock();
    if (mock == nullptr) {
        return;
    }
    return mock->SetEncodedLength(encodedLength);
}
uint32_t Asn1Node::GetEncodedLength()
{
    auto mock = MockAsn1Node::GetMock();
    if (mock == nullptr) {
        return -1;
    }
    return mock->GetEncodedLength();
}

void Asn1Node::AddNodeChildren(const std::shared_ptr<Asn1Node> &asn1Node)
{
    auto mock = MockAsn1Node::GetMock();
    if (mock == nullptr) {
        return;
    }
    return mock->AddNodeChildren(asn1Node);
}
uint32_t Asn1Node::GetNodeTag()
{
    auto mock = MockAsn1Node::GetMock();
    if (mock == nullptr) {
        return -1;
    }
    return mock->GetNodeTag();
}

MockAsn1Node::MockAsn1Node()
{
    mock.store(this);
}

MockAsn1Node::~MockAsn1Node()
{
    mock.store(nullptr);
}
} // namespace Telephony
} // OHOS