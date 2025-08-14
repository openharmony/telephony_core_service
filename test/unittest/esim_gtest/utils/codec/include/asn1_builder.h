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

#ifndef ASN1_BUILDER_MOCK_H
#define ASN1_BUILDER_MOCK_H

#include <cstdbool>
#include <cstdint>
#include <list>
#include <mutex>
#include <vector>
#include "asn1_node.h"
#include "telephony_log_wrapper.h"
#include "gmock/gmock.h"


namespace OHOS {
namespace Telephony {
class Asn1Builder {
public:
    Asn1Builder(const uint32_t tag) : tag_(tag) {};
    virtual ~Asn1Builder() = default;
    virtual void Asn1AddChild(const std::shared_ptr<Asn1Node> node);
    virtual int32_t Asn1AddChildAsBytes(uint32_t tag, const std::vector<uint8_t> &childByte, uint32_t byteLen);
    virtual int32_t Asn1AddChildAsString(uint32_t tag, const std::string &childStr);
    virtual int32_t Asn1AddChildAsInteger(uint32_t tag, uint32_t childInt);
    virtual int32_t Asn1AddChildAsSignedInteger(uint32_t tag, int32_t childSignedInt);
    virtual int32_t Asn1AddChildAsBits(uint32_t tag, int32_t childBits);
    virtual int32_t Asn1AddChildAsBoolean(uint32_t tag, bool flag);
    virtual std::shared_ptr<Asn1Node> Asn1Build();
    virtual uint32_t Asn1BuilderToHexStr(std::string &destStr);
private:
    uint32_t tag_ = 0;
};

class MockAsn1Builder : public Asn1Builder {
public:
    MockAsn1Builder(const uint32_t tag) : Asn1Builder(tag)
    {
        mock.store(this);
    }
    ~MockAsn1Builder() override;
    MOCK_METHOD1(Asn1AddChild, void(const std::shared_ptr<Asn1Node> node));
    MOCK_METHOD3(Asn1AddChildAsBytes, int32_t(uint32_t tag, const std::vector<uint8_t> &childByte, uint32_t byteLen));
    MOCK_METHOD2(Asn1AddChildAsString, int32_t(uint32_t tag, const std::string &childStr));
    MOCK_METHOD2(Asn1AddChildAsInteger, int32_t(uint32_t tag, uint32_t childInt));
    MOCK_METHOD2(Asn1AddChildAsSignedInteger, int32_t(uint32_t tag, int32_t childSignedInt));
    MOCK_METHOD2(Asn1AddChildAsBits, int32_t(uint32_t tag, int32_t childBits));
    MOCK_METHOD2(Asn1AddChildAsBoolean, int32_t(uint32_t tag, bool flag));
    MOCK_METHOD0(Asn1Build, std::shared_ptr<Asn1Node>());
    MOCK_METHOD1(Asn1BuilderToHexStr, uint32_t(std::string &destStr));
    static MockAsn1Builder *GetMock()
    {
        return mock.load();
    }
private:
    static inline std::atomic<MockAsn1Builder *> mock = nullptr;
    uint32_t tag_ = 0;
};
} // namespace Telephony
} // namespace OHOS
#endif // ASN1_BUILDER_MOCK_H