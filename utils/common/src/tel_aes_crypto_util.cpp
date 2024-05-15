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

#include "tel_aes_crypto_util.h"

#include <algorithm>

#include "securec.h"
#include "tel_profile_util.h"
#include "telephony_log_wrapper.h"

namespace OHOS {
namespace Telephony {
constexpr uint32_t MAX_UPDATE_SIZE = 1024;
constexpr uint32_t AAD_SIZE = 16;
constexpr uint32_t NONCE_SIZE = 12;
constexpr uint32_t AEAD_SIZE = 16;
constexpr uint8_t AAD[AAD_SIZE] = {0};
constexpr uint8_t NONCE[NONCE_SIZE] = {0};
constexpr uint8_t AEAD[AEAD_SIZE] = {0};
constexpr const char TEL_AES_KEY_ALIAS[] = "TelAesKeyAlias";

constexpr size_t HEX_UNIT_LEN = 2;
constexpr int32_t ENCODE_UNIT_LEN = 3;
constexpr int32_t HEX_OFFSET = 16;
constexpr int32_t DEC_OFFSET = 10;

#define AES_ALGORITHM_PARAM                     \
    {                                           \
        .tag = HKS_TAG_ALGORITHM,               \
        .uint32Param = HKS_ALG_AES              \
    }, {                                        \
        .tag = HKS_TAG_KEY_SIZE,                \
        .uint32Param = HKS_AES_KEY_SIZE_128     \
    }, {                                        \
        .tag = HKS_TAG_PADDING,                 \
        .uint32Param = HKS_PADDING_NONE         \
    }, {                                        \
        .tag = HKS_TAG_BLOCK_MODE,              \
        .uint32Param = HKS_MODE_GCM             \
    }, {                                        \
        .tag = HKS_TAG_AUTH_STORAGE_LEVEL,              \
        .uint32Param = HKS_AUTH_STORAGE_LEVEL_DE             \
    }

#define GCM_MODE_PARAM                          \
    {                                           \
        .tag = HKS_TAG_DIGEST,                  \
        .uint32Param = HKS_DIGEST_NONE          \
    }, {                                        \
        .tag = HKS_TAG_ASSOCIATED_DATA,         \
        .blob = {                               \
            .size = AAD_SIZE,                   \
            .data = (uint8_t *)AAD              \
        }                                       \
    }, {                                        \
        .tag = HKS_TAG_NONCE,                   \
        .blob = {                               \
            .size = NONCE_SIZE,                 \
            .data = (uint8_t *)NONCE            \
        }                                       \
    }

int TelAesCryptoUtils::SaveEncryptString(const std::string &key, int32_t id, const std::string &rawData)
{
    auto telProfileUtil = DelayedSingleton<TelProfileUtil>::GetInstance();
    std::string encryptValue = AesCryptoEncrypt(rawData);
    return telProfileUtil->SaveString(key + std::to_string(id), encryptValue);
}

std::string TelAesCryptoUtils::ObtainDecryptString(const std::string &key, int32_t id, const std::string &defValue)
{
    auto telProfileUtil = DelayedSingleton<TelProfileUtil>::GetInstance();
    std::string encryptValue = telProfileUtil->ObtainString(key + std::to_string(id), defValue);
    std::string str = AesCryptoDecrypt(encryptValue);
    return str;
}

std::string TelAesCryptoUtils::AesCryptoEncrypt(const std::string &srcData)
{
    if (srcData.empty()) {
        return "";
    }
    struct HksBlob keyAlias = { strlen(TEL_AES_KEY_ALIAS), (uint8_t *)TEL_AES_KEY_ALIAS };

    struct HksParamSet *genParamSet = nullptr;
    struct HksParam genParams[] = {
        {
            .tag = HKS_TAG_PURPOSE,
            .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT
        },
        AES_ALGORITHM_PARAM
    };
    int32_t ret = InitParamSet(&genParamSet, genParams, sizeof(genParams) / sizeof(HksParam));
    if (ret != 0) {
        HksFreeParamSet(&genParamSet);
        TELEPHONY_LOGE("InitParamSet genParamSet failed");
        return "";
    }

    struct HksParamSet *encryptParamSet = nullptr;
    static struct HksParam encryptParams[] = {
        {
            .tag = HKS_TAG_PURPOSE,
            .uint32Param = HKS_KEY_PURPOSE_ENCRYPT
        }, {
            .tag = HKS_TAG_AE_TAG,
            .blob = {
                .size = AEAD_SIZE,
                .data = (uint8_t *)AEAD
            }
        },
        AES_ALGORITHM_PARAM,
        GCM_MODE_PARAM
    };
    ret = InitParamSet(&encryptParamSet, encryptParams, sizeof(encryptParams) / sizeof(HksParam));
    if (ret != 0) {
        TELEPHONY_LOGE("InitParamSet encryptParamSet failed");
        HksFreeParamSet(&genParamSet);
        HksFreeParamSet(&encryptParamSet);
        return "";
    }

    std::string encryptData = AesCryptoEncryptInner(&keyAlias, genParamSet, encryptParamSet, srcData);
    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&encryptParamSet);
    return encryptData;
}

std::string TelAesCryptoUtils::AesCryptoDecrypt(std::string &srcData)
{
    if (srcData.empty()) {
        return "";
    }
    struct HksBlob keyAlias = { strlen(TEL_AES_KEY_ALIAS), (uint8_t *)TEL_AES_KEY_ALIAS };

    struct HksParamSet *decryptGcmParamSet = nullptr;
    static struct HksParam decryptGcmParams[] = {
        {
            .tag = HKS_TAG_PURPOSE,
            .uint32Param = HKS_KEY_PURPOSE_DECRYPT
        },
        AES_ALGORITHM_PARAM,
        GCM_MODE_PARAM,
        {
            .tag = HKS_TAG_AE_TAG,
            .blob = {
                .size = AEAD_SIZE,
                .data = (uint8_t *)AEAD
            }
        }
    };
    int32_t ret = InitParamSet(&decryptGcmParamSet, decryptGcmParams, sizeof(decryptGcmParams) / sizeof(HksParam));
    if (ret != 0) {
        TELEPHONY_LOGE("InitParamSet decryptGcmParamSet failed");
        HksFreeParamSet(&decryptGcmParamSet);
        return "";
    }
    std::string decryptData = AesCryptoDecryptInner(&keyAlias, decryptGcmParamSet, srcData);
    HksFreeParamSet(&decryptGcmParamSet);
    return decryptData;
}

int32_t TelAesCryptoUtils::InitParamSet(struct HksParamSet **paramSet, const struct HksParam *params,
    uint32_t paramCount)
{
    int32_t ret = HksInitParamSet(paramSet);
    if (ret != 0) {
        TELEPHONY_LOGE("HksInitParamSet failed");
        return ret;
    }

    ret = HksAddParams(*paramSet, params, paramCount);
    if (ret != 0) {
        TELEPHONY_LOGE("HksAddParams failed");
        return ret;
    }

    ret = HksBuildParamSet(paramSet);
    if (ret != 0) {
        TELEPHONY_LOGE("HksBuildParamSet failed");
        return ret;
    }
    return ret;
}

std::string TelAesCryptoUtils::AesCryptoEncryptInner(const struct HksBlob *keyAlias,
    struct HksParamSet *genParamSet, struct HksParamSet *encryptParamSet, const std::string &srcData)
{
    struct HksBlob inData = {
        srcData.length(),
        const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(srcData.c_str()))
    };

    // 1. Generate Key
    int32_t ret;
    if (HksKeyExist(keyAlias, genParamSet) != 0) {
        ret = HksGenerateKey(keyAlias, genParamSet, nullptr);
        if (ret != 0) {
            TELEPHONY_LOGE("HksGenerateKey failed");
            return "";
        }
    }

    // 2. Encrypt
    uint8_t handleData[sizeof(uint64_t)] = {0};
    struct HksBlob handle = { sizeof(uint64_t), handleData };
    ret = HksInit(keyAlias, encryptParamSet, &handle, nullptr);
    if (ret != 0) {
        TELEPHONY_LOGE("HksInit failed");
        return "";
    }

    uint8_t *cipher = (uint8_t *)calloc(srcData.length() + AEAD_SIZE, sizeof(uint8_t));
    if (cipher == nullptr) {
        return "";
    }
    struct HksBlob cipherText = { srcData.length() + AEAD_SIZE, cipher };
    ret = AesCryptoLoopUpdate(&handle, encryptParamSet, &inData, &cipherText);
    if (ret != 0) {
        TELEPHONY_LOGE("AesCryptoLoopUpdate failed");
        free(cipher);
        return "";
    }
    std::string encryptStr = DecToHexString(cipherText.data, cipherText.size);
    free(cipher);
    return encryptStr;
}

std::string TelAesCryptoUtils::AesCryptoDecryptInner(const struct HksBlob *keyAlias,
    struct HksParamSet *decryptGcmParamSet, std::string &srcData)
{
    std::pair<uint8_t *, size_t> decryptDataPair = HexToDecString(srcData);
    if (decryptDataPair.first == nullptr || decryptDataPair.second <= 0) {
        TELEPHONY_LOGE("decryptDataPair is invalid");
        if (decryptDataPair.first != nullptr) {
            free(decryptDataPair.first);
        }
        return "";
    }
    struct HksBlob inData = { decryptDataPair.second, decryptDataPair.first };

    inData.size -= AEAD_SIZE;
    for (uint32_t i = 0; i < decryptGcmParamSet->paramsCnt; i++) {
        if (decryptGcmParamSet->params[i].tag == HKS_TAG_AE_TAG) {
            if (memcpy_s(decryptGcmParamSet->params[i].blob.data, AEAD_SIZE,
                inData.data + inData.size, AEAD_SIZE) != 0) {
                TELEPHONY_LOGE("AesCryptoDecryptInner memcpy_s failed");
                free(inData.data);
                return "";
            }
            break;
        }
    }

    uint8_t handleData[sizeof(uint64_t)] = {0};
    struct HksBlob handle = { sizeof(uint64_t), handleData };
    int32_t ret = HksInit(keyAlias, decryptGcmParamSet, &handle, nullptr);
    if (ret != 0) {
        TELEPHONY_LOGE("AesCryptoDecryptInner HksInit failed");
        free(inData.data);
        return "";
    }

    // Update & Finish
    uint8_t *plain = (uint8_t *)calloc(decryptDataPair.second, sizeof(uint8_t));
    if (plain == nullptr) {
        TELEPHONY_LOGE("AesCryptoDecryptInner calloc failed");
        free(inData.data);
        return "";
    }
    struct HksBlob plainText = { decryptDataPair.second, plain };
    ret = AesCryptoLoopUpdate(&handle, decryptGcmParamSet, &inData, &plainText);
    free(inData.data);
    if (ret != 0) {
        TELEPHONY_LOGE("AesCryptoLoopUpdate failed");
        free(plain);
        return "";
    }

    std::string decryptStr((char *)plainText.data);
    free(plain);
    return decryptStr;
}

int32_t TelAesCryptoUtils::AesCryptoLoopUpdate(const struct HksBlob *handle, const struct HksParamSet *paramSet,
    const struct HksBlob *inData, struct HksBlob *outData)
{
    uint32_t inDataSize = inData->size;
    uint32_t handledInDataSize = 0;
    struct HksBlob inDataSeg = *inData;
    struct HksBlob outDataSeg = { MAX_UPDATE_SIZE, NULL };
    uint8_t *cur = outData->data;
    outData->size = 0;

    while (handledInDataSize < inDataSize) {
        uint32_t aesDataLen = std::min(MAX_UPDATE_SIZE, (inDataSize - handledInDataSize));
        inDataSeg.size = aesDataLen;
        outDataSeg.size = aesDataLen + AEAD_SIZE;
        outDataSeg.data = (uint8_t *)malloc(outDataSeg.size);
        if (outDataSeg.data == nullptr) {
            return HKS_FAILURE;
        }
        int32_t hksResult = 0;
        if (handledInDataSize + aesDataLen < inDataSize) {
            hksResult = HksUpdate(handle, paramSet, &inDataSeg, &outDataSeg);
        } else {
            hksResult = HksFinish(handle, paramSet, &inDataSeg, &outDataSeg);
        }

        if (hksResult != 0) {
            TELEPHONY_LOGE("AesCryptoDecryptInner HksUpdate failed");
            free(outDataSeg.data);
            return HKS_FAILURE;
        }
        if (memcpy_s(cur, outDataSeg.size, outDataSeg.data, outDataSeg.size) != EOK) {
            free(outDataSeg.data);
            return HKS_FAILURE;
        }
        cur += outDataSeg.size;
        outData->size += outDataSeg.size;
        free(outDataSeg.data);
        inDataSeg.data += aesDataLen;
        handledInDataSize += aesDataLen;
    }
    return 0;
}

bool TelAesCryptoUtils::HexToDec(char hex, uint8_t &decodeValue)
{
    if (hex >= '0' && hex <= '9') {
        decodeValue = static_cast<uint8_t>(hex - '0');
        return true;
    }
    if (hex >= 'a' && hex <= 'f') {
        decodeValue = static_cast<uint8_t>(hex - 'a' + DEC_OFFSET);
        return true;
    }
    return false;
}

std::string TelAesCryptoUtils::DecToHexString(const uint8_t *data, size_t len)
{
    if (data == nullptr || len == 0) {
        return "";
    }

    std::string hexString;
    char encodeUnit[ENCODE_UNIT_LEN] = {0};
    for (size_t i = 0; i < len; i++) {
        if (sprintf_s(encodeUnit, ENCODE_UNIT_LEN, "%02x", data[i]) <= 0) {
            TELEPHONY_LOGE("DecToHexString failed");
            return "";
        }
        hexString.push_back(encodeUnit[0]);
        hexString.push_back(encodeUnit[1]);
    }

    return hexString;
}

std::pair<uint8_t *, size_t> TelAesCryptoUtils::HexToDecString(const std::string &hexString)
{
    if (hexString.empty() || hexString.length() % HEX_UNIT_LEN != 0) {
        TELEPHONY_LOGE("HexToDecString failed");
        return std::make_pair(nullptr, 0);
    }

    size_t pos = 0;
    size_t len = hexString.length() / HEX_UNIT_LEN;
    uint8_t *data = reinterpret_cast<uint8_t *>(calloc(len + 1, sizeof(uint8_t)));
    if (data == nullptr) {
        TELEPHONY_LOGE("HexToDecString failed");
        return std::make_pair(nullptr, 0);
    }
    uint8_t decodeUnitFirst;
    uint8_t decodeUnitSecond;
    for (size_t i = 0; i < len; i++) {
        if (!HexToDec(hexString.at(pos), decodeUnitFirst) || !HexToDec(hexString.at(pos + 1), decodeUnitSecond)) {
            free(data);
            TELEPHONY_LOGE("HexToDecString failed");
            return std::make_pair(nullptr, 0);
        }
        data[i] = static_cast<uint8_t>(decodeUnitFirst * HEX_OFFSET + decodeUnitSecond);
        pos += HEX_UNIT_LEN;
    }
    return std::make_pair(data, len);
}
} // namespace UpdateEngine
} // namespace OHOS