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

#ifndef OHOS_OPERATOR_CONF_H
#define OHOS_OPERATOR_CONF_H

#include <vector>
#include <libxml/xmlmemory.h>
#include <libxml/parser.h>

#include "iremote_broker.h"
#include "event_handler.h"
#include "inner_event.h"
#include "common_event.h"
#include "common_event_manager.h"
#include "want.h"
#include "telephony_log_wrapper.h"
#include "core_manager.h"
#include "i_sim_account_manager.h"
#include "i_sim_file_manager.h"
#include "sim_constant.h"

namespace OHOS {
namespace Telephony {
static const std::u16string DEFAULT_CONFIG = u"localConfig";
static const std::string COMMON_EVENT_TELEPHONY_CARRIER_CONFIG_CHANGED =
    "usual.event.telephony.CARRIER_CONFIG_CHANGED";
static const std::int64_t TIME_OUT_LINE = 5;
static const std::string TEST_MCC = "204";
static const std::string TEST_MNC = "04";
static const std::string CARRIER_PATH = "/data/OperatorConfig/carrier_config_";
static const std::string CARRIER_XML = ".xml";
static const std::string CARRIER_THRID_PART_XML_PATH = "/data/OperatorConfig/thrid_part_config.xml";
static const std::string CARRIER_CONFIG_LIST = "carrier_config_list";
static const std::string CARRIER_CONFIG = "carrier_config";
static const std::string CARRIER_NAME = "name";
static const std::string CARRIER_VALUE = "value";

class OperatorConf {
public:
    OperatorConf(std::shared_ptr<ISimFileManager> simFileManager);
    virtual ~OperatorConf();
    bool GetOperatorConfigs(int32_t slotId, OperatorConfig &poc);

private:
    bool ParseDoc(const std::string path, OperatorConfig &poc);
    void ParseChild(xmlDocPtr, xmlNodePtr, OperatorConfig &poc);
    std::string GetMcc();
    std::string GetMncLengthTwo();
    std::string GetMncLengthThree();
    static const int NODE = 1;
    static const int32_t STRING_HEAD = 0;
    static const int32_t MNC_LENGTH = 2;
    static const int32_t MNC_THREE = 3;
    static const int32_t MCC_LENGTH = 3;
    std::shared_ptr<ISimFileManager> simFileManager_ = nullptr;
};
} // namespace Telephony
} // namespace OHOS
#endif // OHOS_OPERATOR_CONF_H