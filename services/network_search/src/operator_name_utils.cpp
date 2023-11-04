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

#include "operator_name_utils.h"

#include <securec.h>

#include "config_policy_utils.h"
#include "cstdint"
#include "cstdio"
#include "cstdlib"
#include "cstring"
#include "iosfwd"
#include "json/config.h"
#include "json/reader.h"
#include "json/value.h"
#include "locale_config.h"
#include "memory"
#include "parameter.h"
#include "telephony_errors.h"
#include "telephony_log_wrapper.h"

namespace OHOS {
namespace Telephony {
OperatorNameUtils OperatorNameUtils::operatorNameUtils_;
const char *PATH = "/etc/telephony/operator_name.json";
const char *ITEM_OPERATOR_NAMES = "operator_names";
const char *ITEM_PLMN = "mcc_mnc_array";
const char *ITEM_ZH_HANS_CN = "zh-Hans-CN";
const char *ITEM_EN_LATN_US = "en-Latn-US";
const char *ITEM_ZH_HANT_TW = "zh-Hant-TW";
const char *ITEM_ZH_HANT_HK = "zh-Hant-HK";
const int MAX_BYTE_LEN = 10 * 1024 * 1024;

OperatorNameUtils &OperatorNameUtils::GetInstance()
{
    return operatorNameUtils_;
}

void OperatorNameUtils::Init()
{
    if (isInit_) {
        TELEPHONY_LOGI("has init");
        return;
    }
    ParserOperatorNameCustJson(nameArray_);
    TELEPHONY_LOGI("init success");
    isInit_ = true;
}

bool OperatorNameUtils::IsInit()
{
    TELEPHONY_LOGI("is init %{public}d", isInit_);
    return isInit_;
}

int32_t OperatorNameUtils::ParserOperatorNameCustJson(std::vector<OperatorNameCust> &vec)
{
    char *content = nullptr;
    char buf[MAX_PATH_LEN];
    char *path = GetOneCfgFile(PATH, buf, MAX_PATH_LEN);
    int32_t ret = TELEPHONY_SUCCESS;
    if (path && *path != '\0') {
        ret = LoaderJsonFile(content, path);
    }
    if (ret != TELEPHONY_SUCCESS) {
        TELEPHONY_LOGE(" load fail!");
        return ret;
    }
    if (content == nullptr) {
        TELEPHONY_LOGE("content is nullptr!");
        return TELEPHONY_ERR_READ_DATA_FAIL;
    }
    const int contentLength = strlen(content);
    const std::string rawJson(content);
    free(content);
    content = nullptr;
    JSONCPP_STRING err;
    Json::Value root;
    Json::CharReaderBuilder builder;
    Json::CharReader *reader(builder.newCharReader());
    if (!reader->parse(rawJson.c_str(), rawJson.c_str() + contentLength, &root, &err)) {
        TELEPHONY_LOGE("reader is error!");
        return TELEPHONY_ERR_READ_DATA_FAIL;
    }
    delete reader;
    reader = nullptr;
    Json::Value itemRoots = root[ITEM_OPERATOR_NAMES];
    if (itemRoots.size() == 0) {
        TELEPHONY_LOGE(" itemRoots size == 0!");
        return TELEPHONY_ERR_READ_DATA_FAIL;
    }
    ParserOperatorNames(vec, itemRoots);
    return TELEPHONY_SUCCESS;
}

int32_t OperatorNameUtils::LoaderJsonFile(char *&content, const char *path) const
{
    long len = 0;
    char realPath[PATH_MAX] = { 0x00 };
    if (realpath(path, realPath) == nullptr) {
        TELEPHONY_LOGE("realpath fail! #PATH: %{public}s", path);
        return TELEPHONY_ERR_READ_DATA_FAIL;
    }
    FILE *f = fopen(realPath, "rb");
    if (f == nullptr) {
        return TELEPHONY_ERR_READ_DATA_FAIL;
    }
    int ret_seek_end = fseek(f, 0, SEEK_END);
    if (ret_seek_end != 0) {
        TELEPHONY_LOGE("ret_seek_end != 0!");
        CloseFile(f);
        return TELEPHONY_ERR_READ_DATA_FAIL;
    }
    len = ftell(f);
    int ret_seek_set = fseek(f, 0, SEEK_SET);
    if (ret_seek_set != 0) {
        CloseFile(f);
        return TELEPHONY_ERR_READ_DATA_FAIL;
    }
    if (len == 0 || len > static_cast<long>(MAX_BYTE_LEN)) {
        TELEPHONY_LOGE("len is valid!");
        CloseFile(f);
        return TELEPHONY_ERR_READ_DATA_FAIL;
    }
    content = static_cast<char *>(malloc(len + 1));
    if (content == nullptr) {
        CloseFile(f);
        return TELEPHONY_ERR_READ_DATA_FAIL;
    }
    if (memset_s(content, len + 1, 0, len + 1) != EOK) {
        TELEPHONY_LOGE("memset_s failed");
        free(content);
        content = nullptr;
        CloseFile(f);
        return TELEPHONY_ERR_READ_DATA_FAIL;
    }
    size_t ret_read = fread(content, 1, len, f);
    if (ret_read != static_cast<size_t>(len)) {
        free(content);
        content = nullptr;
        CloseFile(f);
        return TELEPHONY_ERR_READ_DATA_FAIL;
    }
    return CloseFile(f);
}

void OperatorNameUtils::ParserOperatorNames(std::vector<OperatorNameCust> &vec, Json::Value &root)
{
    for (int32_t i = 0; i < static_cast<int32_t>(root.size()); i++) {
        Json::Value itemRoot = root[i];
        OperatorNameCust nameCust;
        if (itemRoot[ITEM_PLMN].isArray()) {
            for (auto value : itemRoot[ITEM_PLMN]) {
                nameCust.mccMnc.push_back(value.asString());
            }
        }
        if (itemRoot[ITEM_ZH_HANS_CN].isString()) {
            nameCust.zhHansCN = itemRoot[ITEM_ZH_HANS_CN].asString();
        }
        if (itemRoot[ITEM_EN_LATN_US].isString()) {
            nameCust.enLatnUS = itemRoot[ITEM_EN_LATN_US].asString();
        }
        if (itemRoot[ITEM_ZH_HANT_TW].isString()) {
            nameCust.zhHantTW = itemRoot[ITEM_ZH_HANT_TW].asString();
        }
        if (itemRoot[ITEM_ZH_HANT_HK].isString()) {
            nameCust.zhHantHK = itemRoot[ITEM_ZH_HANT_HK].asString();
        }
        vec.push_back(nameCust);
    }
}

int32_t OperatorNameUtils::CloseFile(FILE *f) const
{
    int ret_close = fclose(f);
    if (ret_close != 0) {
        TELEPHONY_LOGE("ret_close != 0!");
        return TELEPHONY_ERR_READ_DATA_FAIL;
    }
    return TELEPHONY_SUCCESS;
}

std::string OperatorNameUtils::GetNameByLocale(OperatorNameCust &value)
{
    std::string locale = OHOS::Global::I18n::LocaleConfig::GetSystemLocale();
    TELEPHONY_LOGD("locale is %{public}s", locale.c_str());
    if (locale == std::string(ITEM_ZH_HANS_CN)) {
        return value.zhHansCN;
    }
    if (locale == std::string(ITEM_ZH_HANT_TW)) {
        return value.zhHantTW;
    }
    if (locale == std::string(ITEM_ZH_HANT_HK)) {
        return value.zhHantHK;
    }
    return value.enLatnUS;
}

std::string OperatorNameUtils::GetCustomName(const std::string &numeric)
{
    if (!IsInit()) {
        Init();
    }
    TELEPHONY_LOGD("Start");
    for (OperatorNameCust value : nameArray_) {
        auto obj = std::find(value.mccMnc.begin(), value.mccMnc.end(), numeric);
        if (obj != value.mccMnc.end()) {
            std::string name = GetNameByLocale(value);
            TELEPHONY_LOGD("Name is %{public}s", name.c_str());
            return name;
        }
    }
    TELEPHONY_LOGD("Not found name %{public}s", numeric.c_str());
    return "";
}
} // namespace Telephony
} // namespace OHOS
