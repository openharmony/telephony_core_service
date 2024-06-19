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

#include "operator_file_parser.h"
#include <sys/stat.h>
#include <sys/types.h>
#include <climits>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <iterator>
#include <string_ex.h>
#include <unistd.h>
#include "config_policy_utils.h"
#include "sim_utils.h"
#include "telephony_types.h"

namespace OHOS {
namespace Telephony {
OperatorFileParser::~OperatorFileParser() {}

bool OperatorFileParser::WriteOperatorConfigJson(std::string filename, const cJSON *root)
{
    if (root == nullptr) {
        TELEPHONY_LOGE("json is invalid");
        return false;
    }
    if (!isCachePathExit()) {
        if (mkdir(DEFAULT_OPERATE_CONFIG_DIR, S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH) != SUCCESS) {
            TELEPHONY_LOGE("CreateDirFailed");
            return false;
        }
    }
    FILE *file = nullptr;
    file = fopen(GetOperatorConfigFilePath(filename).c_str(), "w");
    if (file == nullptr) {
        printf("OpenFileFailed");
        return false;
    }
    char *cjValue = cJSON_Print(root);
    int ret = fwrite(cjValue, sizeof(char), strlen(cjValue), file);
    (void)fclose(file);
    free(cjValue);
    cjValue = nullptr;
    file = nullptr;
    if (ret == 0) {
        printf("write json to file failed!");
        return false;
    }
    return true;
}

void OperatorFileParser::ClearFilesCache()
{
    if (isCachePathExit()) {
        TELEPHONY_LOGI("removeAllCache");
        DeleteFiles();
    }
}

void OperatorFileParser::DeleteFiles()
{
    std::filesystem::path dirPath = std::string(DEFAULT_OPERATE_CONFIG_DIR);
    std::error_code errorCode;
    std::filesystem::remove_all(dirPath, errorCode);
    if (errorCode.operator bool()) {
        TELEPHONY_LOGE("delete fail, error code : %{public}d", errorCode.value());
    } else {
        TELEPHONY_LOGI("delete success");
    }
}

bool OperatorFileParser::isCachePathExit()
{
    return access(DEFAULT_OPERATE_CONFIG_DIR, F_OK) == SUCCESS;
}

std::string OperatorFileParser::GetOperatorConfigFilePath(std::string filename)
{
    if (filename.empty()) {
        TELEPHONY_LOGE("filename is empty");
        return filename;
    }
    return std::string(DEFAULT_OPERATE_CONFIG_DIR) + "/" + filename;
}

bool OperatorFileParser::ParseFromCustomSystem(int32_t slotId, OperatorConfig &opc, cJSON *root)
{
    int mode = MODE_SLOT_0;
    if (slotId == SimSlotId::SIM_SLOT_1) {
        mode = MODE_SLOT_1;
    }
    CfgFiles *cfgFiles = GetCfgFilesEx(DEFAULT_OPERATE_CONFIG_PATH, mode, nullptr);
    if (cfgFiles == nullptr) {
        TELEPHONY_LOGE("ParseFromCustomSystem cfgFiles is null");
        return false;
    }
    char *filePath = nullptr;
    cJSON *tempRoot = nullptr;
    std::lock_guard<std::mutex> lock(mutex_);
    tempConfig_.clear();
    for (size_t i = 0; i < MAX_CFG_POLICY_DIRS_CNT; i++) {
        filePath = cfgFiles->paths[i];
        if (filePath && *filePath != '\0') {
            bool ret = ParseOperatorConfigFromFile(opc, filePath, tempRoot, true);
            if (!ret) {
                TELEPHONY_LOGE("ParseFromCustomSystem path %{public}s fail", filePath);
                continue;
            }
        }
    }
    CreateJsonFromOperatorConfig(root);
    FreeCfgFiles(cfgFiles);
    filePath = nullptr;
    tempRoot = nullptr;
    return true;
}

void OperatorFileParser::CreateJsonFromOperatorConfig(cJSON *root)
{
    for (auto it = tempConfig_.begin(); it != tempConfig_.end(); ++it) {
        cJSON *jsontemp = cJSON_Parse(it->second.c_str());
        if (jsontemp != nullptr) {
            cJSON_AddItemToObject(root, it->first.c_str(), jsontemp);
        }
    }
    tempConfig_.clear();
}

bool OperatorFileParser::ParseOperatorConfigFromFile(
    OperatorConfig &opc, const std::string &path, cJSON *root, bool needSaveTempOpc)
{
    char *content = nullptr;
    int contentLength = LoaderJsonFile(content, path);
    if (contentLength == LOADER_JSON_ERROR) {
        TELEPHONY_LOGE("ParseOperatorConfigFromFile  %{public}s is fail!", path.c_str());
        return false;
    }
    root = cJSON_Parse(content);
    free(content);
    content = nullptr;
    if (root == nullptr) {
        TELEPHONY_LOGE("ParseOperatorConfigFromFile root is error!");
        return false;
    }
    ParseOperatorConfigFromJson(root, opc, needSaveTempOpc);
    cJSON_Delete(root);
    return true;
}

void OperatorFileParser::ParseOperatorConfigFromJson(const cJSON *root, OperatorConfig &opc, bool needSaveTempOpc)
{
    TELEPHONY_LOGD("ParseOperatorConfigFromJson");
    cJSON *value = root->child;
    char *tempChar = nullptr;
    std::map<std::u16string, std::u16string> &configValue = opc.configValue;
    while (value) {
        if (needSaveTempOpc) {
            tempChar = cJSON_PrintUnformatted(value);
            tempConfig_[value->string] = tempChar != nullptr ? tempChar : "";
            free(tempChar);
        }
        tempChar = cJSON_Print(value);
        configValue[Str8ToStr16(value->string)] = tempChar != nullptr ? Str8ToStr16(tempChar) : u"";
        TELEPHONY_LOGI("ParseOperatorConfigFromFile key %{public}s value %{public}s", value->string,
            Str16ToStr8(configValue[Str8ToStr16(value->string)]).c_str());
        free(tempChar);
        if (value->type == cJSON_Array) {
            TELEPHONY_LOGD("parse type arrayValue");
            if (cJSON_GetArraySize(value) > 0) {
                ParseArray(value->string, value, opc);
            }
        } else if (value->type == cJSON_String) {
            TELEPHONY_LOGD("parse type stringValue");
            opc.stringValue[value->string] = value->valuestring;
            configValue[Str8ToStr16(value->string)] = Str8ToStr16(value->valuestring);
        } else if (value->type == cJSON_Number) {
            TELEPHONY_LOGD("parse type initValue");
            int64_t lValue = static_cast<int64_t>(cJSON_GetNumberValue(value));
            configValue[Str8ToStr16(value->string)] = Str8ToStr16(std::to_string(lValue));
            if (lValue > INT_MAX) {
                TELEPHONY_LOGD("value is long");
                opc.longValue[value->string] = lValue;
            } else {
                TELEPHONY_LOGD("value is int");
                opc.intValue[value->string] = static_cast<int32_t>(lValue);
            }
        } else if (value->type == cJSON_True) {
            TELEPHONY_LOGD("parse type booleanValue true");
            opc.boolValue[value->string] = true;
            configValue[Str8ToStr16(value->string)] = Str8ToStr16("true");
        } else if (value->type == cJSON_False) {
            TELEPHONY_LOGD("parse type booleanValue false");
            opc.boolValue[value->string] = false;
            configValue[Str8ToStr16(value->string)] = Str8ToStr16("false");
        }
        value = value->next;
    }
    tempChar = nullptr;
}

int32_t OperatorFileParser::LoaderJsonFile(char *&content, const std::string &path)
{
    std::ifstream ifs;
    ifs.open(path);
    if (ifs.fail()) {
        TELEPHONY_LOGE("LoaderJsonFile path PATH: %{public}s failed", path.c_str());
        return LOADER_JSON_ERROR;
    }
    ifs.seekg(0, std::ios::end);
    uint64_t len = static_cast<uint64_t>(ifs.tellg());
    if (len == 0 || len > MAX_BYTE_LEN) {
        TELEPHONY_LOGE("LoaderJsonFile len <= 0 or len > MAX_BYTE_LEN!");
        ifs.close();
        return LOADER_JSON_ERROR;
    }
    content = static_cast<char *>(malloc(len + 1));
    if (content == nullptr) {
        TELEPHONY_LOGE("LoaderJsonFile malloc content fail!");
        ifs.close();
        return LOADER_JSON_ERROR;
    }
    if (memset_s(content, len + 1, 0, len + 1) != EOK) {
        TELEPHONY_LOGE("LoaderJsonFile memset_s failed");
        free(content);
        content = nullptr;
        ifs.close();
        return LOADER_JSON_ERROR;
    }
    ifs.seekg(0, std::ios::beg);
    ifs.read(content, len);
    ifs.close();
    return len;
}

bool OperatorFileParser::CloseFile(FILE *f)
{
    int ret_close = fclose(f);
    if (ret_close != 0) {
        TELEPHONY_LOGE("LoaderJsonFile ret_close != 0!");
        return false;
    }
    return true;
}

void OperatorFileParser::ParseArray(const std::string key, const cJSON *value, OperatorConfig &opc)
{
    if (value == nullptr || cJSON_GetArraySize(value) <= 0 || value->child == nullptr) {
        return;
    }
    cJSON *arrayValue = value->child;
    auto valueType = arrayValue->type;
    if (valueType == cJSON_String) {
        TELEPHONY_LOGI("parse string array");
        if (opc.stringArrayValue.find(key) == opc.stringArrayValue.end()) {
            opc.stringArrayValue[key] = std::vector<std::string>();
        }
        while (arrayValue) {
            opc.stringArrayValue[key].push_back(arrayValue->valuestring);
            arrayValue = arrayValue->next;
        }
    } else if (valueType == cJSON_Number && static_cast<int64_t>(cJSON_GetNumberValue(arrayValue)) > INT_MAX) {
        TELEPHONY_LOGI("parse long array");
        if (opc.longArrayValue.find(key) == opc.longArrayValue.end()) {
            opc.longArrayValue[key] = std::vector<int64_t>();
        }
        while (arrayValue) {
            opc.longArrayValue[key].push_back(static_cast<int64_t>(cJSON_GetNumberValue(arrayValue)));
            arrayValue = arrayValue->next;
        }
    } else if (valueType == cJSON_Number) {
        TELEPHONY_LOGI("parse int array");
        if (opc.intArrayValue.find(key) == opc.intArrayValue.end()) {
            opc.intArrayValue[key] = std::vector<int32_t>();
        }
        while (arrayValue) {
            opc.intArrayValue[key].push_back(static_cast<int32_t>(cJSON_GetNumberValue(arrayValue)));
            arrayValue = arrayValue->next;
        }
    }
    arrayValue = nullptr;
}
} // namespace Telephony
} // namespace OHOS
