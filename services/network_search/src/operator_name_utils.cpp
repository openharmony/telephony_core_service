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
#include "locale_config.h"
#include "locale_info.h"
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
const char *ITEM_ZH_CN = "zh_CN";
const char *ITEM_EN_US = "en_US";
const char *ITEM_ZH_TW = "zh_TW";
const char *ITEM_ZH_HK = "zh_HK";
const char *ITEM_ZH_HANS = "zh_Hans";
const char *ITEM_ZH_HANT = "zh_Hant";
const int MAX_BYTE_LEN = 10 * 1024 * 1024;

OperatorNameUtils &OperatorNameUtils::GetInstance()
{
    return operatorNameUtils_;
}

void OperatorNameUtils::Init()
{
    std::unique_lock<std::mutex> lock(mutex_);
    if (isInit_) {
        TELEPHONY_LOGI("has init");
        return;
    }
    nameArray_.clear();
    ParserOperatorNameCustJson(nameArray_);
    TELEPHONY_LOGI("init success");
    isInit_ = true;
}

bool OperatorNameUtils::IsInit()
{
    TELEPHONY_LOGD("is init %{public}d nameArray_ size %{public}zu", isInit_, nameArray_.size());
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
        TELEPHONY_LOGE("load fail!");
        return ret;
    }
    if (content == nullptr) {
        TELEPHONY_LOGE("content is nullptr!");
        return TELEPHONY_ERR_READ_DATA_FAIL;
    }
    cJSON *root = cJSON_Parse(content);
    free(content);
    content = nullptr;
    if (root == nullptr) {
        TELEPHONY_LOGE("json root is error!");
        return TELEPHONY_ERR_READ_DATA_FAIL;
    }

    cJSON *itemRoots = cJSON_GetObjectItem(root, ITEM_OPERATOR_NAMES);
    if (itemRoots == nullptr || !cJSON_IsArray(itemRoots) || cJSON_GetArraySize(itemRoots) == 0) {
        TELEPHONY_LOGE("operator name itemRoots is invalid");
        cJSON_Delete(root);
        itemRoots = nullptr;
        root = nullptr;
        return TELEPHONY_ERR_READ_DATA_FAIL;
    }
    ParserOperatorNames(vec, itemRoots);
    cJSON_Delete(root);
    itemRoots = nullptr;
    root = nullptr;
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

void OperatorNameUtils::ParserOperatorNames(std::vector<OperatorNameCust> &vec, cJSON *itemRoots)
{
    cJSON *itemRoot = nullptr;
    cJSON *plmnArray = nullptr;
    cJSON *arrValue = nullptr;
    for (int32_t i = 0; i < cJSON_GetArraySize(itemRoots); i++) {
        itemRoot = cJSON_GetArrayItem(itemRoots, i);
        if (itemRoot == nullptr) {
            continue;
        }
        OperatorNameCust nameCust;
        plmnArray = cJSON_GetObjectItem(itemRoot, ITEM_PLMN);
        if (plmnArray == nullptr || !cJSON_IsArray(plmnArray)) {
            continue;
        }
        for (int32_t j = 0; j < cJSON_GetArraySize(plmnArray); j++) {
            arrValue = cJSON_GetArrayItem(plmnArray, j);
            if (arrValue != nullptr && cJSON_IsNumber(arrValue)) {
                nameCust.mccMnc.push_back(std::to_string(static_cast<int32_t>(cJSON_GetNumberValue(arrValue))));
            }
        }

        nameCust.zhCN = ParseString(cJSON_GetObjectItem(itemRoot, ITEM_ZH_CN));
        nameCust.enUS = ParseString(cJSON_GetObjectItem(itemRoot, ITEM_EN_US));
        nameCust.zhTW = ParseString(cJSON_GetObjectItem(itemRoot, ITEM_ZH_TW));
        nameCust.zhHK = ParseString(cJSON_GetObjectItem(itemRoot, ITEM_ZH_HK));
        nameCust.zhHans = ParseString(cJSON_GetObjectItem(itemRoot, ITEM_ZH_HANS));
        nameCust.zhHant = ParseString(cJSON_GetObjectItem(itemRoot, ITEM_ZH_HANT));
        vec.push_back(nameCust);
    }
    itemRoot = nullptr;
    plmnArray = nullptr;
    arrValue = nullptr;
}

std::string OperatorNameUtils::ParseString(cJSON *value)
{
    if (value != nullptr && value->type == cJSON_String && value->valuestring != nullptr) {
        return value->valuestring;
    }
    return "";
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
    OHOS::Global::I18n::LocaleInfo localeInfo(locale);
    std::string languageCode = localeInfo.GetLanguage() + "_" + localeInfo.GetRegion();
    std::string countryCodeTempScript = "";
    if (!(localeInfo.GetScript().empty())) {
        countryCodeTempScript = localeInfo.GetLanguage() + "_" + localeInfo.GetScript();
    }
    TELEPHONY_LOGD("locale is %{public}s, languageCode is %{public}s, countryCodeTempScript is %{public}s",
        locale.c_str(), languageCode.c_str(), countryCodeTempScript.c_str());
    if (countryCodeTempScript == std::string(ITEM_ZH_HANS)) {
        languageCode = std::string(ITEM_ZH_HANS);
    }
    if (countryCodeTempScript == std::string(ITEM_ZH_HANT)) {
        languageCode = std::string(ITEM_ZH_HANT);
    }
    if (languageCode == std::string(ITEM_ZH_CN)) {
        return value.zhCN;
    }
    if (languageCode == std::string(ITEM_ZH_TW)) {
        return value.zhTW;
    }
    if (languageCode == std::string(ITEM_ZH_HK)) {
        return value.zhHK;
    }
    if (languageCode == std::string(ITEM_ZH_HANS)) {
        return value.zhHans;
    }
    if (languageCode == std::string(ITEM_ZH_HANT)) {
        return value.zhHant;
    }
    if (languageCode == std::string(ITEM_EN_US)) {
        return value.enUS;
    }
    return value.enUS;
}

std::string OperatorNameUtils::GetCustomName(const std::string &numeric)
{
    if (!IsInit()) {
        Init();
    }
    TELEPHONY_LOGD("Start");
    std::unique_lock<std::mutex> lock(mutex_);
    if (nameArray_.empty()) {
        TELEPHONY_LOGE("nameArray_ is empty");
        return "";
    }
    for (OperatorNameCust &value : nameArray_) {
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
