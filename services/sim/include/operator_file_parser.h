/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#ifndef OHOS_OPERATOR_FILE_PARSER_H
#define OHOS_OPERATOR_FILE_PARSER_H
#include <json/json.h>

#include "core_service_errors.h"
#include "operator_config_types.h"
#include "sim_state_type.h"
#include "telephony_log_wrapper.h"

namespace OHOS {
namespace Telephony {
class OperatorFileParser {
public:
    bool ParseFromCustomSystem(int32_t slotId, OperatorConfig &opc, Json::Value &opcJson);
    bool ParseOperatorConfigFromFile(OperatorConfig &poc, const std::string &path, Json::Value &opcJson);
    bool WriteOperatorConfigJson(std::string filename, const Json::Value &root);
    std::string GetOperatorConfigFilePath(std::string filename);
    void ClearFilesCache();
    bool isCachePathExit();
    virtual ~OperatorFileParser();

private:
    void ParseOperatorConfigFromJson(const Json::Value &root, OperatorConfig &poc);
    bool LoaderJsonFile(char *&content, const std::string &path);
    void ParseArray(const std::string key, const Json::Value &arrayValue_, OperatorConfig &poc);
    bool CloseFile(FILE *f);
    inline static const char *DEFAULT_OPERATE_CONFIG_PATH = "etc/operator_config.json";
    inline static const char *DEFAULT_OPERATE_CONFIG_DIR = "/data/service/el1/public/telephony/operatorconfig";
    inline static const int MODE_SLOT_0 = 11;
    inline static const int MODE_SLOT_1 = 12;
    inline static const int SUCCESS = 0;
};
} // namespace Telephony
} // namespace OHOS
#endif // OHOS_OPERATOR_FILE_PARSER_H