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

#ifndef OHOS_FILE_MANAGER_H
#define OHOS_FILE_MANAGER_H
#include <cstdint>
#include <fstream>

namespace OHOS {
namespace Telephony {
class VCardFileUtils {
public:
    int32_t Open(const std::string &filePath);
    int32_t Close();
    void SetInputStream(std::shared_ptr<std::ifstream> file_);
    bool ReadLine(std::string &line);
    bool PeekLine(std::string &line);
    void Reset();
    bool IsEnd();
    void SkipEmptyLines();

private:
    std::shared_ptr<std::ifstream> file_ = nullptr;
};
} // namespace Telephony
} // namespace OHOS
#endif // OHOS_FILE_MANAGER_H