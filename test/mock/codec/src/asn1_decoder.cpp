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
    srcData_ = src;
    position_ = offset;
    end_ = offset + decodeLen;
}

bool Asn1Decoder::Asn1HasNextNode()
{
    auto mock = MockAsn1Decoder::GetMock();
    if (mock == nullptr) {
        return false;
    }
    return mock->Asn1HasNextNode();
}

std::shared_ptr<Asn1Node> Asn1Decoder::Asn1NextNode()
{
    auto mock = MockAsn1Decoder::GetMock();
    if (mock == nullptr) {
        return nullptr;
    }
    return mock->Asn1NextNode();
}

std::shared_ptr<Asn1Node> Asn1Decoder::BuildAsn1Node(const uint32_t tag, uint32_t offset, uint32_t tagStart)
{
    auto mock = MockAsn1Decoder::GetMock();
    if (mock == nullptr) {
        return nullptr;
    }
    return mock->BuildAsn1Node(tag, offset, tagStart);
}

MockAsn1Decoder::~MockAsn1Decoder()
{
    mock.store(nullptr);
}
} // namespace Telephony
} // namespace OHOS
