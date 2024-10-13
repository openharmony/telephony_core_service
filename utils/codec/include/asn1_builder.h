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

#ifndef ASN1_BUILDER_H
#define ASN1_BUILDER_H

#include <cstdbool>
#include <cstdint>
#include <list>
#include <mutex>
#include <vector>
#include "asn1_node.h"
#include "telephony_log_wrapper.h"

namespace OHOS {
namespace Telephony {
class Asn1Builder {
public:
    explicit Asn1Builder(const uint32_t tag) : tag_(tag) {};
    void Asn1AddChild(const std::shared_ptr<Asn1Node> node);
    int32_t Asn1AddChildAsBytes(uint32_t tag, const std::vector<uint8_t> &childByte, uint32_t byteLen);
    int32_t Asn1AddChildAsString(uint32_t tag, const std::string &childStr);
    int32_t Asn1AddChildAsInteger(uint32_t tag, uint32_t childInt);
    int32_t Asn1AddChildAsSignedInteger(uint32_t tag, int32_t childSignedInt);
    int32_t Asn1AddChildAsBits(uint32_t tag, int32_t childBits);
    int32_t Asn1AddChildAsBoolean(uint32_t tag, bool flag);
    std::shared_ptr<Asn1Node> Asn1Build();
    uint32_t Asn1BuilderToHexStr(std::string &destStr);
private:
    uint32_t tag_ = 0;
    std::list<std::shared_ptr<Asn1Node>> children_;
    std::mutex mutex_;
};
} // namespace Telephony
} // namespace OHOS
#endif // ASN1_BUILDER_H