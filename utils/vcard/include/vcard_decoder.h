/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

#ifndef OHOS_VCARD_DECODER_H
#define OHOS_VCARD_DECODER_H
#include <string>
#include <vector>

#include "vcard_contact.h"
#include "vcard_file_utils.h"

namespace OHOS {
namespace Telephony {
class VCardDecodeListener {
public:
    virtual ~VCardDecodeListener() = default;
    virtual void OnStarted() = 0;
    virtual void OnEnded() = 0;
    virtual void OnOneContactStarted() = 0;
    virtual void OnOneContactEnded() = 0;
    virtual void OnRawDataCreated(std::shared_ptr<VCardRawData> rawData) = 0;
};

class VCardDecoder {
public:
    VCardDecoder();
    static std::shared_ptr<VCardDecoder> Create(const std::string &path, int32_t &errorCode);
    static std::shared_ptr<VCardDecoder> Create(std::shared_ptr<std::ifstream> file_, int32_t &errorCode);
    virtual void AddVCardDecodeListener(std::shared_ptr<VCardDecodeListener> listener);
    virtual void Decode(int32_t &errorCode);
    virtual bool DecodeOne(int32_t &errorCode);
    bool IsEnd();
    virtual ~VCardDecoder();

protected:
    static VCardFileUtils fileUtils_;
    static std::string GetVersion();
    static std::shared_ptr<VCardDecoder> GetDecoder(const std::string &version);
};
} // namespace Telephony
} // namespace OHOS
#endif // OHOS_VCARD_DECODER_H