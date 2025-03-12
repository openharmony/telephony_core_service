/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#ifndef OHOS_SIM_FILE_PARSE_H
#define OHOS_SIM_FILE_PARSE_H
#include <string>
#include "sim_file.h"

namespace OHOS {
namespace Telephony {
class SimFileParse {
public:
    std::string ParseSpn(const std::string &rawData, int spnStatus, SimFile &simFile);
    void ParsePnn(const std::vector<std::string> &records, SimFile &simFile);
    void ParseOpl(const std::vector<std::string> &records, SimFile &simFile);
    void ParseOpl5g(const std::vector<std::string> &records, SimFile &simFile);
    void ParseEhplmn(std::string data, SimFile &simFile);
    void ParseSpdi(std::string data, SimFile &simFile);
private:
};
} // namespace Telephony
} // namespace OHOS
#endif // OHOS_SIM_FILE_PARSE_H