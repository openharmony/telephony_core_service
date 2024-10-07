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

#ifndef TELEPHONY_SIM_RDB_HELPER_H
#define TELEPHONY_SIM_RDB_HELPER_H

#include <vector>

#include "datashare_helper.h"
#include "datashare_predicates.h"
#include "datashare_result_set.h"
#include "datashare_values_bucket.h"
#include "iservice_registry.h"
#include "result_set.h"
#include "sim_constant.h"
#include "sim_rdb_info.h"
#include "sim_utils.h"
#include "system_ability_definition.h"
#include "telephony_data_helper.h"
#include "telephony_log_wrapper.h"
#include "uri.h"

namespace OHOS {
namespace Telephony {
class SimRdbHelper {
public:
    SimRdbHelper();
    ~SimRdbHelper();

    int32_t GetDefaultMainCardSlotId();
    int32_t GetDefaultMessageCardSlotId();
    int32_t GetDefaultVoiceCardSlotId();
    int32_t GetDefaultCellularDataCardSlotId();
    int32_t SetDefaultMainCard(int32_t simId);
    int32_t SetDefaultVoiceCard(int32_t simId);
    int32_t SetDefaultMessageCard(int32_t simId);
    int32_t SetDefaultCellularData(int32_t simId);
    int32_t InsertData(int64_t &id, const DataShare::DataShareValuesBucket &values);
    int32_t QueryDataByIccId(std::string iccId, SimRdbInfo &simBean);
    int32_t QueryAllData(std::vector<SimRdbInfo> &vec);
    int32_t QueryAllValidData(std::vector<SimRdbInfo> &vec);
    int32_t UpdateDataBySimId(int32_t simId, const DataShare::DataShareValuesBucket &values);
    int32_t UpdateDataByIccId(std::string iccId, const DataShare::DataShareValuesBucket &values);
    int32_t ForgetAllData();
    int32_t ForgetAllData(int32_t slotId);
    int32_t ClearData();
    int32_t UpdateOpKeyInfo();
    bool IsDataShareError();
    void ResetDataShareError();

private:
    std::shared_ptr<TelephonyDataHelper> mTelephonyDatahelper = DelayedSingleton<TelephonyDataHelper>::GetInstance();
    std::shared_ptr<DataShare::DataShareHelper> CreateDataHelper();
    std::shared_ptr<DataShare::DataShareHelper> CreateOpKeyHelper();
    std::shared_ptr<DataShare::DataShareHelper> CreateDataHelper(const int waitTime);
    int Insert(
        std::shared_ptr<DataShare::DataShareHelper> dataShareHelper, const DataShare::DataShareValuesBucket &values);
    std::shared_ptr<DataShare::DataShareResultSet> Query(std::shared_ptr<DataShare::DataShareHelper> dataShareHelper,
        std::vector<std::string> &columns, const DataShare::DataSharePredicates &predicates);
    int Update(std::shared_ptr<DataShare::DataShareHelper> dataShareHelper,
        const DataShare::DataShareValuesBucket &value, const DataShare::DataSharePredicates &predicates);
    int Delete(
        std::shared_ptr<DataShare::DataShareHelper> dataShareHelper, const DataShare::DataSharePredicates &predicates);
    void SaveDataToBean(std::shared_ptr<DataShare::DataShareResultSet> result, SimRdbInfo &simBean);

private:
    enum class DefaultCardType {
        MAIN,
        VOICE,
        SMS,
        DATA,
    };
};
} // namespace Telephony
} // namespace OHOS
#endif // TELEPHONY_SIM_RDB_HELPER_H
