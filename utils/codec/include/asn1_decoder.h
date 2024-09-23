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

#ifndef ASN1_DECODER_H
#define ASN1_DECODER_H

#include <cstdbool>
#include <cstdint>
#include <list>
#include <vector>
#include "asn1_node.h"
#include "telephony_log_wrapper.h"

namespace OHOS {
namespace Telephony {
class Asn1Decoder {
public:
    Asn1Decoder(const std::vector<uint8_t> &src, uint32_t offset, uint32_t decodeLen);
    bool Asn1HasNextNode();
    std::shared_ptr<Asn1Node> Asn1NextNode();

private:
    std::shared_ptr<Asn1Node> BuildAsn1Node(const uint32_t tag, uint32_t offset, uint32_t tagStart);

private:
    std::vector<uint8_t> srcData_ = {};
    uint32_t position_ = 0;
    uint32_t end_ = 0;
};
} // namespace Telephony
} // namespace OHOS
#endif // ASN1_DECODER_H
