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
#include "vcard_decoder.h"

#include "telephony_errors.h"
#include "telephony_log_wrapper.h"
#include "vcard_decoder_v21.h"
#include "vcard_decoder_v30.h"
#include "vcard_decoder_v40.h"

namespace OHOS {
namespace Telephony {

VCardFileUtils VCardDecoder::fileUtils_;

VCardDecoder::VCardDecoder() {}
VCardDecoder::~VCardDecoder() {}

std::shared_ptr<VCardDecoder> VCardDecoder::Create(const std::string &path, int32_t &errorCode)
{
    errorCode = fileUtils_.Open(path);
    if (errorCode != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE("Failed to read path %{public}s", path.c_str());
        fileUtils_.Close();
        errorCode = TELEPHONY_ERR_VCARD_FILE_INVALID;
        return nullptr;
    }
    errorCode = TELEPHONY_SUCCESS;
    return GetDecoder(GetVersion());
}

std::shared_ptr<VCardDecoder> VCardDecoder::Create(std::shared_ptr<std::ifstream> file, int32_t &errorCode)
{
    if (file == nullptr) {
        TELEPHONY_LOGE("file is nullptr");
        errorCode = TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    fileUtils_.SetInputStream(file);
    errorCode = TELEPHONY_SUCCESS;
    return GetDecoder(GetVersion());
}

std::string VCardDecoder::GetVersion()
{
    std::string line;
    std::string version;
    while (fileUtils_.ReadLine(line)) {
        auto index = line.find(VCARD_TYPE_VERSION);
        if (index == std::string::npos) {
            continue;
        }
        version = line.substr(index + std::string(VCARD_TYPE_VERSION).length() + 1);
        break;
    }
    fileUtils_.Reset();
    return version;
}

std::shared_ptr<VCardDecoder> VCardDecoder::GetDecoder(const std::string &version)
{
    TELEPHONY_LOGI("Get version result %{public}s", version.c_str());
    if (version.find(std::string(VERSION_30)) != std::string::npos) {
        return std::make_shared<VCardDecoderV30>();
    }
    if (version.find(std::string(VERSION_40)) != std::string::npos) {
        return std::make_shared<VCardDecoderV40>();
    }
    return std::make_shared<VCardDecoderV21>();
}

void VCardDecoder::AddVCardDecodeListener(std::shared_ptr<VCardDecodeListener> listener) {}

void VCardDecoder::Decode(int32_t &errorCode) {}

bool VCardDecoder::DecodeOne(int32_t &errorCode)
{
    return false;
}

bool VCardDecoder::IsEnd()
{
    return fileUtils_.IsEnd();
}

} // namespace Telephony
} // namespace OHOS
