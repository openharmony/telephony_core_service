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

#ifndef ASN1_NODE_MOCK_H
#define ASN1_NODE_MOCK_H

#include <cstdbool>
#include <cstdint>
#include <list>
#include <mutex>
#include "telephony_log_wrapper.h"
#include "gmock/gmock.h"

namespace OHOS {
namespace Telephony {
class Asn1Node {
public:
    Asn1Node() = default;
    Asn1Node(const uint32_t tag, const std::vector<uint8_t> &src, uint32_t offset, uint32_t length);
    virtual ~Asn1Node() = default;
    virtual uint32_t Asn1NodeToHexStr(std::string &destStr);
    virtual uint32_t Asn1NodeToBytes(std::vector<uint8_t> &dest);
    virtual std::shared_ptr<Asn1Node> Asn1GetChild(const uint32_t tag);
    virtual bool Asn1HasChild(const uint32_t tag);
    virtual std::shared_ptr<Asn1Node> Asn1GetGrandson(const uint32_t firstLevelTag, const uint32_t secondLevelTag);
    virtual std::shared_ptr<Asn1Node> Asn1GetGreatGrandson(const uint32_t firstLevelTag, const uint32_t secondLevelTag,
        const uint32_t thirdLevelTag);
    virtual int32_t Asn1GetChildren(const uint32_t tag, std::list<std::shared_ptr<Asn1Node>> &children);
    virtual uint32_t Asn1GetHeadAsHexStr(std::string &headHex);
    virtual uint32_t Asn1AsBytes(std::vector<uint8_t> &output);
    virtual int32_t Asn1AsInteger();
    virtual uint32_t Asn1AsString(std::string &output);
    virtual int32_t Asn1AsBits();
    virtual void SetDataLength(const uint32_t dataLength);
    virtual void SetConstructed(bool constructed);
    virtual void SetEncodedLength(const uint32_t encodedLength);
    virtual uint32_t GetEncodedLength();
    virtual void AddNodeChildren(const std::shared_ptr<Asn1Node> &asn1Node);
    virtual uint32_t GetNodeTag();
    virtual int32_t Asn1BuildChildren();
    virtual void Asn1Write(std::vector<uint8_t> &dest);
private:
    [[maybe_unused]] uint32_t tag_ = 0;
    [[maybe_unused]] std::list<std::shared_ptr<Asn1Node>> children_;
    [[maybe_unused]] bool constructed_ = false;
    [[maybe_unused]] std::vector<uint8_t> dataBytes_ = {};
    [[maybe_unused]] uint32_t dataOffset_ = 0;
    [[maybe_unused]] uint32_t dataLength_ = 0;
    [[maybe_unused]] uint32_t encodedLength_ = 0;
    [[maybe_unused]] std::mutex mutex_;
};

class MockAsn1Node : public Asn1Node {
public:
    MockAsn1Node();
    ~MockAsn1Node() override;
    MOCK_METHOD1(Asn1NodeToHexStr, uint32_t(std::string &destStr));
    MOCK_METHOD1(Asn1NodeToBytes, uint32_t(std::vector<uint8_t> &dest));
    MOCK_METHOD1(Asn1GetChild, std::shared_ptr<Asn1Node>(const uint32_t tag));
    MOCK_METHOD1(Asn1HasChild, bool(const uint32_t tag));
    MOCK_METHOD2(Asn1GetGrandson,
        std::shared_ptr<Asn1Node>(const uint32_t firstLevelTag, const uint32_t secondLevelTag));
    MOCK_METHOD3(Asn1GetGreatGrandson,
        std::shared_ptr<Asn1Node>(const uint32_t firstLevelTag, const uint32_t secondLevelTag,
        const uint32_t thirdLevelTag));
    MOCK_METHOD2(Asn1GetChildren, int32_t(const uint32_t tag, std::list<std::shared_ptr<Asn1Node>> &children));
    MOCK_METHOD1(Asn1GetHeadAsHexStr, uint32_t(std::string &headHex));
    MOCK_METHOD1(Asn1AsBytes, uint32_t(std::vector<uint8_t> &output));
    MOCK_METHOD0(Asn1AsInteger, int32_t());
    MOCK_METHOD1(Asn1AsString, uint32_t(std::string &output));
    MOCK_METHOD0(Asn1AsBits, int32_t());
    MOCK_METHOD1(SetDataLength, void(const uint32_t dataLength));
    MOCK_METHOD1(SetConstructed, void(bool constructed));
    MOCK_METHOD1(SetEncodedLength, void(const uint32_t encodedLength));
    MOCK_METHOD0(GetEncodedLength, uint32_t());
    MOCK_METHOD1(AddNodeChildren, void(const std::shared_ptr<Asn1Node> &asn1Node));
    MOCK_METHOD0(GetNodeTag, uint32_t());
    MOCK_METHOD0(Asn1BuildChildren, int32_t());
    MOCK_METHOD1(Asn1Write, void(std::vector<uint8_t> &dest));
    static MockAsn1Node *GetMock()
    {
        return mock.load();
    }
private:
    static inline std::atomic<MockAsn1Node *> mock = nullptr;
};
} // namespace Telephony
} // namespace OHOS
#endif // ASN1_NODE_MOCK_H
