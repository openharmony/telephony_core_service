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

#ifndef OPERATOR_NAME_UTILS_H
#define OPERATOR_NAME_UTILS_H

#include <mutex>

#include "cJSON.h"
#include "iosfwd"
#include "string"

namespace OHOS {
namespace Telephony {
class OperatorNameUtils {
    struct OperatorNameCust {
        std::vector<std::string> mccMnc = {};
        std::string zhCN = "";
        std::string enUS = "";
        std::string zhTW = "";
        std::string zhHK = "";
        std::string zhHans = "";
        std::string zhHant = "";
    };

public:
    static OperatorNameUtils &GetInstance();
    void Init();
    bool IsInit();
    std::string GetCustomName(const std::string &numeric);

private:
    OperatorNameUtils() = default;
    ~OperatorNameUtils() = default;
    void ParserOperatorNames(std::vector<OperatorNameCust> &vec, cJSON *itemRoots);
    int32_t LoaderJsonFile(char *&content, const char *path) const;
    int32_t ParserOperatorNameCustJson(std::vector<OperatorNameCust> &vec);
    int32_t CloseFile(FILE *f) const;
    std::string GetNameByLocale(OperatorNameCust &value);
    std::string ParseString(cJSON *value);

private:
    static OperatorNameUtils operatorNameUtils_;
    bool isInit_ = false;
    std::vector<OperatorNameCust> nameArray_ = {};
    std::mutex mutex_;
};
} // namespace Telephony
} // namespace OHOS
#endif
