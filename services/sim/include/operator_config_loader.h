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

#ifndef OHOS_OPERATOR_CONF_H
#define OHOS_OPERATOR_CONF_H

#include <libxml/parser.h>
#include <libxml/xmlmemory.h>
#include <vector>

#include "common_event.h"
#include "common_event_manager.h"
#include "config_policy_utils.h"
#include "datashare_helper.h"
#include "datashare_predicates.h"
#include "datashare_result_set.h"
#include "datashare_values_bucket.h"
#include "event_handler.h"
#include "inner_event.h"
#include "iremote_broker.h"
#include "iservice_registry.h"
#include "operator_config_cache.h"
#include "sim_constant.h"
#include "sim_file_manager.h"
#include "system_ability_definition.h"
#include "telephony_log_wrapper.h"
#include "want.h"

namespace OHOS {
namespace Telephony {
static const std::string OPKEY_URI = "datashare:///com.ohos.opkeyability";
const std::string OPKEY_INFO_URI = "datashare:///com.ohos.opkeyability/opkey/opkey_info";

class OperatorConfigLoader {
public:
    explicit OperatorConfigLoader(
        std::shared_ptr<SimFileManager> simFileManager, std::shared_ptr<OperatorConfigCache> operatorConfigCache);
    virtual ~OperatorConfigLoader();
    OperatorConfig LoadOperatorConfig(int32_t slotId);

private:
    std::string LoadOpKeyOnMccMnc(int32_t slotId);
    std::shared_ptr<DataShare::DataShareHelper> CreateDataAHelper() const;
    std::shared_ptr<DataShare::DataShareHelper> CreateOpKeyHelper();
    std::string GetOpKey(std::shared_ptr<DataShare::DataShareResultSet> resultSet, int32_t slotId);
    bool MatchOperatorRule(std::shared_ptr<DataShare::DataShareResultSet> &resultSet, int row);

private:
    std::shared_ptr<SimFileManager> simFileManager_ = nullptr;
    std::shared_ptr<OperatorConfigCache> operatorConfigCache_ = nullptr;
    std::shared_ptr<DataShare::DataShareHelper> opKeyDataAbilityHelper_ = nullptr;
    std::string iccidFromSim_;
    std::string imsiFromSim_;
    std::string spnFromSim_;
    std::string gid1FromSim_;
    std::string gid2FromSim_;
};
} // namespace Telephony
} // namespace OHOS
#endif // OHOS_OPERATOR_CONF_H
