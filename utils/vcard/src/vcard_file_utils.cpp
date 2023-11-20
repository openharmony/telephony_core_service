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
#include "vcard_file_utils.h"

#include <iostream>

#include "telephony_errors.h"
#include "telephony_log_wrapper.h"

namespace OHOS {
namespace Telephony {

int32_t VCardFileUtils::Open(const std::string &filePath)
{
    char path[PATH_MAX] = { '\0' };
    if (realpath(filePath.c_str(), path) == nullptr) {
        TELEPHONY_LOGE("get real path fail");
        return TELEPHONY_ERR_VCARD_FILE_INVALID;
    }
    std::string realPath = path;
    file_ = std::make_shared<std::ifstream>(realPath);
    if (!file_->is_open()) {
        return TELEPHONY_ERR_VCARD_FILE_INVALID;
    }
    return TELEPHONY_SUCCESS;
}

void VCardFileUtils::SetInputStream(std::shared_ptr<std::ifstream> file)
{
    file_ = file;
}

int32_t VCardFileUtils::Close()
{
    if (file_ == nullptr) {
        TELEPHONY_LOGE("file_ is nullptr");
        return TELEPHONY_ERR_LOCAL_PTR_NULL;
    }
    if (file_->is_open()) {
        file_->close();
        file_ = nullptr;
    }
    return TELEPHONY_SUCCESS;
}

bool VCardFileUtils::ReadLine(std::string &line)
{
    if (file_ == nullptr) {
        TELEPHONY_LOGE("file_ is nullptr");
        return false;
    }
    std::getline(*file_, line);
    return !IsEnd();
}

bool VCardFileUtils::PeekLine(std::string &line)
{
    if (file_ == nullptr) {
        TELEPHONY_LOGE("file_ is nullptr");
        return false;
    }
    std::streampos currentPosition = file_->tellg();
    file_->peek();
    std::getline(*file_, line);
    file_->seekg(currentPosition);
    return !IsEnd();
}

void VCardFileUtils::Reset()
{
    if (file_ == nullptr) {
        TELEPHONY_LOGE("file_ is nullptr");
        return;
    }
    file_->clear();
    file_->seekg(0, std::ios::beg);
}

bool VCardFileUtils::IsEnd()
{
    if (file_ == nullptr) {
        TELEPHONY_LOGE("file_ is nullptr");
        return false;
    }
    return file_->peek() == EOF;
}

void VCardFileUtils::SkipEmptyLines()
{
    if (file_ == nullptr) {
        TELEPHONY_LOGE("file_ is nullptr");
        return;
    }
    std::string line;
    std::streampos currentPosition = file_->tellg();
    while (std::getline(*file_, line)) {
        if (!line.empty()) {
            file_->seekg(currentPosition);
            break;
        }
        currentPosition = file_->tellg();
    }
}

} // namespace Telephony
} // namespace OHOS
