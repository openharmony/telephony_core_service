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

#ifndef TEL_AES_CRYPTO_UTILS_H
#define TEL_AES_CRYPTO_UTILS_H

#include <string>

#include "hks_api.h"
#include "hks_param.h"
#include "hks_type.h"

namespace OHOS {
namespace Telephony {
class TelAesCryptoUtils {
public:
    static std::string AesCryptoEncrypt(const std::string &srcData);
    static std::string AesCryptoDecrypt(std::string &srcData);
    static int SaveEncryptString(const std::string &key, int32_t id, const std::string &rawData);
    static std::string ObtainDecryptString(const std::string &key, int32_t id, const std::string &defValue);

private:
    static int32_t InitParamSet(struct HksParamSet **paramSet, const struct HksParam *params, uint32_t paramCount);
    static std::string AesCryptoEncryptInner(const struct HksBlob *keyAlias, struct HksParamSet *genParamSet,
        struct HksParamSet *encryptParamSet, const std::string &srcData);
    static std::string AesCryptoDecryptInner(const struct HksBlob *keyAlias,
        struct HksParamSet *decryptGcmParamSet, std::string &srcData);
    static int32_t AesCryptoLoopUpdate(const struct HksBlob *handle, const struct HksParamSet *paramSet,
        const struct HksBlob *inData, struct HksBlob *outData);
    static bool HexToDec(char hex, uint8_t &decodeValue);
    static std::string DecToHexString(const uint8_t *data, size_t len);
    static std::pair<uint8_t *, size_t> HexToDecString(const std::string &hexString);
};
} // namespace Telephony
} // namespace OHOS
#endif // TEL_AES_CRYPTO_UTILS_H