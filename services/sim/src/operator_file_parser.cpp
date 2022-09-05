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

bool OperatorFileParser::WriteOperatorConfigJson(std::string filename, const Json::Value &root)
{
    if (!isCachePathExit()) {
        if (mkdir(DEFAULT_OPERATE_CONFIG_DIR, S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH) != SUCCESS) {
            TELEPHONY_LOGE("CreateDirFailed");
            return false;
        }
    }
    std::fstream ofs;
    ofs.open(GetOperatorConfigFilePath(filename).c_str(), std::ios::ate | std::ios::out);
    if (!ofs.is_open()) {
        TELEPHONY_LOGE("OpenFileFailed");
        return false;
    }
    Json::StreamWriterBuilder jswBuilder;
    jswBuilder["emitUTF8"] = true;
    std::unique_ptr<Json::StreamWriter> jsWriter(jswBuilder.newStreamWriter());
    std::ostringstream os;
    jsWriter->write(root, &os);
    ofs << os.str();
    ofs.close();
    return true;
}

void OperatorFileParser::ClearFilesCache()
{
    if (isCachePathExit()) {
        TELEPHONY_LOGI("removeAllCache");
        rmdir(DEFAULT_OPERATE_CONFIG_DIR);
    }
}

bool OperatorFileParser::isCachePathExit()
{
    return access(DEFAULT_OPERATE_CONFIG_DIR, F_OK) == SUCCESS;
}

std::string OperatorFileParser::GetOperatorConfigFilePath(std::string filename)
{
    return std::string(DEFAULT_OPERATE_CONFIG_DIR) + "/" + filename;
}

bool OperatorFileParser::ParseFromCustomSystem(int32_t slotId, OperatorConfig &opc, Json::Value &opcJson)
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
    for (size_t i = 0; i < MAX_CFG_POLICY_DIRS_CNT; i++) {
        filePath = cfgFiles->paths[i];
        if (filePath && *filePath != '\0') {
            Json::Value temp;
            bool ret = ParseOperatorConfigFromFile(opc, filePath, temp);
            if (!ret) {
                TELEPHONY_LOGE("ParseFromCustomSystem path %{public}s fail", filePath);
                continue;
            }
            Json::Value::Members mem = temp.getMemberNames();
            for (auto mem : temp.getMemberNames()) {
                opcJson[std::string(mem)] = temp[mem];
            }
        }
    }
    FreeCfgFiles(cfgFiles);
    return true;
}

bool OperatorFileParser::ParseOperatorConfigFromFile(OperatorConfig &opc, const std::string &path, Json::Value &opcJson)
{
    char *content = nullptr;
    int contentLength = LoaderJsonFile(content, path);
    if (contentLength == LOADER_JSON_ERROR) {
        TELEPHONY_LOGE("ParseOperatorConfigFromFile  %{public}s is fail!", path.c_str());
        return false;
    }
    const std::string rawJson(content);
    free(content);
    content = nullptr;
    JSONCPP_STRING err;
    Json::CharReaderBuilder builder;
    Json::CharReader *reader(builder.newCharReader());
    if (!reader->parse(rawJson.c_str(), rawJson.c_str() + contentLength, &opcJson, &err)) {
        TELEPHONY_LOGE("ParseOperatorConfigFromFile reader is error!");
        return false;
    }
    delete reader;
    reader = nullptr;
    ParseOperatorConfigFromJson(opcJson, opc);
    return true;
}

void OperatorFileParser::ParseOperatorConfigFromJson(const Json::Value &root, OperatorConfig &opc)
{
    TELEPHONY_LOGI("ParseOperatorConfigFromJson");
    Json::Value::Members mems = root.getMemberNames();
    std::map<std::u16string, std::u16string> &configValue = opc.configValue;
    for (auto mem : mems) {
        auto keyStr8 = std::string(mem);
        auto value = root[mem];
        configValue[Str8ToStr16(keyStr8)] = Str8ToStr16(value.toStyledString());
        TELEPHONY_LOGI("ParseOperatorConfigFromJson key %{public}s value %{public}s", keyStr8.c_str(),
            value.toStyledString().c_str());
        auto valueType = root[mem].type();
        if (valueType == Json::arrayValue) {
            TELEPHONY_LOGI("parse type arrayValue");
            if (value.size() > 0) {
                ParseArray(keyStr8, value, opc);
            }
            continue;
        }
        if (valueType == Json::stringValue) {
            TELEPHONY_LOGI("parse type stringValue");
            opc.stringValue[keyStr8] = value.asString();
            configValue[Str8ToStr16(keyStr8)] = Str8ToStr16(value.asString());
            continue;
        }
        if (valueType == Json::intValue) {
            TELEPHONY_LOGI("parse type initValue");
            int64_t lValue = static_cast<int64_t>(stoll(value.asString()));
            configValue[Str8ToStr16(keyStr8)] = Str8ToStr16(value.asString());
            if (value > INT_MAX) {
                TELEPHONY_LOGI("value is long");
                opc.longValue[keyStr8] = lValue;
            } else {
                TELEPHONY_LOGI("value is int");
                opc.intValue[keyStr8] = static_cast<int32_t>(lValue);
            }
            continue;
        }
        if (valueType == Json::booleanValue) {
            TELEPHONY_LOGI("parse type booleanValue");
            opc.boolValue[keyStr8] = value.asBool();
            configValue[Str8ToStr16(keyStr8)] = Str8ToStr16(value.asString());
            continue;
        }
    }
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

void OperatorFileParser::ParseArray(const std::string key, const Json::Value &arrayValue_, OperatorConfig &opc)
{
    if (arrayValue_.size() <= 0) {
        return;
    }
    int32_t first = 0;
    auto valueType = arrayValue_[first].type();
    if (valueType == Json::stringValue) {
        TELEPHONY_LOGI("parse string array");
        if (opc.stringArrayValue.find(key) == opc.stringArrayValue.end()) {
            opc.stringArrayValue[key] = std::vector<std::string>();
        }
        for (auto value : arrayValue_) {
            opc.stringArrayValue[key].push_back(value.asString());
        }
        return;
    }
    if (valueType == Json::intValue && static_cast<int64_t>(stoll(arrayValue_[first].asString())) > INT_MAX) {
        TELEPHONY_LOGI("parse long array");
        if (opc.longArrayValue.find(key) == opc.longArrayValue.end()) {
            opc.longArrayValue[key] = std::vector<int64_t>();
        }
        for (auto value : arrayValue_) {
            opc.longArrayValue[key].push_back(static_cast<int64_t>(stoll(value.asString())));
        }
        return;
    }
    if (valueType == Json::intValue) {
        TELEPHONY_LOGI("parse int array");
        if (opc.intArrayValue.find(key) == opc.intArrayValue.end()) {
            opc.intArrayValue[key] = std::vector<int32_t>();
        }
        for (auto value : arrayValue_) {
            opc.intArrayValue[key].push_back(value.asInt());
        }
        return;
    }
}
} // namespace Telephony
} // namespace OHOS
