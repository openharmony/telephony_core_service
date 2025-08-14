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
void Asn1Builder::Asn1AddChild(const std::shared_ptr<Asn1Node> node)
{
    auto mock = MockAsn1Builder::GetMock();
    if (mock == nullptr) {
        return;
    }
    return mock->Asn1AddChild(node);
}

int32_t Asn1Builder::Asn1AddChildAsBytes(uint32_t tag, const std::vector<uint8_t> &childByte, uint32_t byteLen)
{
    auto mock = MockAsn1Builder::GetMock();
    if (mock == nullptr) {
        return -1;
    }
    return mock->Asn1AddChildAsBytes(tag, childByte, byteLen);
}

int32_t Asn1Builder::Asn1AddChildAsString(uint32_t tag, const std::string &childStr)
{
    auto mock = MockAsn1Builder::GetMock();
    if (mock == nullptr) {
        return -1;
    }
    return mock->Asn1AddChildAsString(tag, childStr);
}

int32_t Asn1Builder::Asn1AddChildAsInteger(uint32_t tag, uint32_t childInt)
{
    auto mock = MockAsn1Builder::GetMock();
    if (mock == nullptr) {
        return -1;
    }
    return mock->Asn1AddChildAsInteger(tag, childInt);
}

int32_t Asn1Builder::Asn1AddChildAsSignedInteger(uint32_t tag, int32_t childSignedInt)
{
    auto mock = MockAsn1Builder::GetMock();
    if (mock == nullptr) {
        return -1;
    }
    return mock->Asn1AddChildAsSignedInteger(tag, childSignedInt);
}

int32_t Asn1Builder::Asn1AddChildAsBits(uint32_t tag, int32_t childBits)
{
    auto mock = MockAsn1Builder::GetMock();
    if (mock == nullptr) {
        return -1;
    }
    return mock->Asn1AddChildAsBits(tag, childBits);
}

int32_t Asn1Builder::Asn1AddChildAsBoolean(uint32_t tag, bool flag)
{
    auto mock = MockAsn1Builder::GetMock();
    if (mock == nullptr) {
        return -1;
    }
    return mock->Asn1AddChildAsBoolean(tag, flag);
}

std::shared_ptr<Asn1Node> Asn1Builder::Asn1Build()
{
    auto mock = MockAsn1Builder::GetMock();
    if (mock == nullptr) {
        return nullptr;
    }
    return mock->Asn1Build();
}

uint32_t Asn1Builder::Asn1BuilderToHexStr(std::string &destStr)
{
    auto mock = MockAsn1Builder::GetMock();
    if (mock == nullptr) {
        return -1;
    }
    return mock->Asn1BuilderToHexStr(destStr);
}

MockAsn1Builder::~MockAsn1Builder()
{
    mock.store(nullptr);
}
} // namespace Telephony
} // namespace OHOS