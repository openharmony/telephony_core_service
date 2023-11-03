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

#include <json/json.h>

#include "iosfwd"
#include "string"
namespace Json {
class Value;
}

namespace OHOS {
namespace Telephony {
class OperatorNameUtils {
    struct OperatorNameCust {
        std::vector<std::string> mccMnc = {};
        std::string zhHansCN = "";
        std::string enLatnUS = "";
        std::string zhHantTW = "";
        std::string zhHantHK = "";
    };

public:
    static OperatorNameUtils &GetInstance();
    void Init();
    bool IsInit();
    std::string GetCustomName(const std::string &numeric);

private:
    OperatorNameUtils() = default;
    ~OperatorNameUtils() = default;
    void ParserOperatorNames(std::vector<OperatorNameCust> &vec, Json::Value &root);
    int32_t LoaderJsonFile(char *&content, const char *path) const;
    int32_t ParserOperatorNameCustJson(std::vector<OperatorNameCust> &vec);
    int32_t CloseFile(FILE *f) const;
    std::string GetNameByLocale(OperatorNameCust &value);

private:
    static OperatorNameUtils operatorNameUtils_;
    bool isInit_ = false;
    std::vector<OperatorNameCust> nameArray_ = {};
};
} // namespace Telephony
} // namespace OHOS
#endif
