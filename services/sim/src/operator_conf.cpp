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

#include <string_ex.h>

#include "operator_conf.h"

namespace OHOS {
namespace Telephony {
OperatorConf::OperatorConf(std::shared_ptr<ISimFileManager> simFileManager)
    : simFileManager_(simFileManager)
{
    TELEPHONY_LOGI("OperatorConf construct");
}

OperatorConf::~OperatorConf() {}

bool OperatorConf::GetOperatorConfigs(int32_t slotId, OperatorConfig &poc)
{
    std::string path = CARRIER_THRID_PART_XML_PATH;
    if (ParseDoc(path, poc)) { // get thridPart XML Config
        return true;
    } else { // get Default XML Config
        path = CARRIER_PATH + GetMcc() + GetMncLengthThree() + CARRIER_XML;
        if (ParseDoc(path, poc)) {
            return true;
        } else {
            path = CARRIER_PATH + GetMcc() + GetMncLengthTwo() + CARRIER_XML;
            return ParseDoc(path, poc);
        }
    }
}

bool OperatorConf::ParseDoc(const std::string docname, OperatorConfig &poc)
{
    xmlDocPtr doc;
    xmlNodePtr cur;
    TELEPHONY_LOGI("OperatorConf ParseDoc docname = %{public}s", docname.c_str());
    doc = xmlParseFile((const char *)docname.c_str());
    if (doc == NULL) {
        TELEPHONY_LOGE("OperatorConf xml not exist");
        return false;
    }
    cur = xmlDocGetRootElement(doc);
    if (cur == NULL) {
        TELEPHONY_LOGE("OperatorConf xml cur not exist");
        xmlFreeDoc(doc);
        return false;
    }
    if (xmlStrcmp(cur->name, (const xmlChar *)OPERATOR_CONFIG_LIST.c_str())) {
        TELEPHONY_LOGE("OperatorConf xml is not format");
        xmlFreeDoc(doc);
        return false;
    }
    cur = cur->xmlChildrenNode;
    while (cur != NULL) {
        if (!xmlStrcmp(cur->name, (const xmlChar *)OPERATOR_CONFIG.c_str())) {
            ParseChild(doc, cur, poc);
        }
        cur = cur->next;
    }
    xmlFreeDoc(doc);
    return true;
}

void OperatorConf::ParseChild(xmlDocPtr doc, xmlNodePtr cur, OperatorConfig &poc)
{
    xmlChar *text = nullptr;
    xmlChar *name = nullptr;
    xmlChar *value = nullptr;
    cur = cur->xmlChildrenNode;
    while (cur != NULL) {
        text = xmlNodeListGetString(doc, cur->xmlChildrenNode, NODE);
        name = xmlGetProp(cur, (const xmlChar *)CARRIER_NAME.c_str());
        value = xmlGetProp(cur, (const xmlChar *)CARRIER_VALUE.c_str());
        std::string second = "";
        if (value != NULL) {
            second = (char *)value;
        } else if (text != NULL) {
            second = (char *)text;
        }
        TELEPHONY_LOGI(
            "OperatorConf ParseChild cur->name = %{public}s name = %{public}s "
            "value = %{public}s text = %{public}s ",
            (char *)cur->name, (char *)name, (char *)value, (char *)text);
        std::string arrayName((char *)cur->name);
        if (name != NULL) {
            poc.configValue.emplace(
                std::pair<std::u16string, std::u16string>(Str8ToStr16((char *)name), Str8ToStr16(second)));
        }
        cur = cur->next;
    }
    xmlFree(name);
    xmlFree(value);
    xmlFree(text);
}

std::string OperatorConf::GetMcc()
{
    int32_t slotId = CoreManager::DEFAULT_SLOT_ID;
    if (simFileManager_ == nullptr) {
        TELEPHONY_LOGE("OperatorConf GetMcc failed by nullptr");
        return TEST_MCC;
    }
    std::string imsi = Str16ToStr8(simFileManager_->GetIMSI(slotId));
    if (imsi.empty()) {
        TELEPHONY_LOGE("OperatorConf GetMcc failed empty imsi");
        return TEST_MCC;
    }
    return imsi.substr(STRING_HEAD, MCC_LENGTH);
}

std::string OperatorConf::GetMncLengthTwo()
{
    int32_t slotId = CoreManager::DEFAULT_SLOT_ID;
    if (simFileManager_ == nullptr) {
        TELEPHONY_LOGE("OperatorConf GetMnc2 failed by nullptr");
        return TEST_MNC;
    }
    std::string imsi = Str16ToStr8(simFileManager_->GetIMSI(slotId));
    if (imsi.empty()) {
        TELEPHONY_LOGE("OperatorConf GetMnc2 failed empty imsi");
        return TEST_MNC;
    }
    return imsi.substr(MCC_LENGTH, MNC_LENGTH);
}

std::string OperatorConf::GetMncLengthThree()
{
    int32_t slotId = CoreManager::DEFAULT_SLOT_ID;
    if (simFileManager_ == nullptr) {
        TELEPHONY_LOGE("OperatorConf GetMnc3 failed by nullptr");
        return TEST_MNC;
    }
    std::string imsi = Str16ToStr8(simFileManager_->GetIMSI(slotId));
    if (imsi.empty()) {
        TELEPHONY_LOGE("OperatorConf GetMnc3 failed empty imsi");
        return TEST_MNC;
    }
    return imsi.substr(MCC_LENGTH, MNC_THREE);
}
} // namespace Telephony
} // namespace OHOS