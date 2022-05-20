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

#include "iservice_registry.h"
#include "system_ability_definition.h"
#include "data_ability_helper.h"
#include "data_ability_predicates.h"
#include "abs_shared_result_set.h"
#include "values_bucket.h"
#include "result_set.h"
#include "uri.h"
#include "sim_utils.h"
#include "sim_constant.h"
#include "sim_rdb_info.h"
#include "telephony_log_wrapper.h"

namespace OHOS {
namespace Telephony {
class SimRdbHelper {
public:
    SimRdbHelper();
    ~SimRdbHelper();
    int32_t GetDefaultMainCardSlotId();
    int32_t GetDefaultMessageCardSlotId();
    int32_t GetDefaultCellularDataCardSlotId();
    int32_t SetDefaultMainCard(int32_t slotId);
    int32_t SetDefaultVoiceCard(int32_t slotId);
    int32_t SetDefaultMessageCard(int32_t slotId);
    int32_t SetDefaultCellularData(int32_t slotId);
    bool RemoveDefaultVoiceCard();
    bool RemoveDefaultMessageCard();
    bool RemoveDefaultCellularCard();

    int32_t InsertData(int64_t &id, const NativeRdb::ValuesBucket &values);
    int32_t QueryDataBySlotId(int32_t slotId, SimRdbInfo &simBean);
    int32_t QueryDataByIccId(std::string iccId, SimRdbInfo &simBean);
    int32_t QueryAllData(std::vector<SimRdbInfo> &vec);
    int32_t QueryAllValidData(std::vector<SimRdbInfo> &vec);
    int32_t UpdateDataBySlotId(int32_t slotId, const NativeRdb::ValuesBucket &values);
    int32_t UpdateDataByIccId(std::string iccId, const NativeRdb::ValuesBucket &values);
    int32_t ForgetAllData();
    int32_t ClearData();

private:
    std::shared_ptr<AppExecFwk::DataAbilityHelper> CreateDataAHelper();
    int Insert(const NativeRdb::ValuesBucket &values);
    std::shared_ptr<NativeRdb::AbsSharedResultSet> Query(std::vector<std::string> &columns,
                                                         const NativeRdb::DataAbilityPredicates &predicates);
    int Update(const NativeRdb::ValuesBucket &value, const NativeRdb::DataAbilityPredicates &predicates);
    int Delete(const NativeRdb::DataAbilityPredicates &predicates);
    void SaveDataToBean(std::shared_ptr<NativeRdb::AbsSharedResultSet> result, SimRdbInfo &simBean);

    inline const static std::string MAIN_CARD = "1";
    const static int32_t SUCCESS = 1;
    std::shared_ptr<AppExecFwk::DataAbilityHelper> helper_ = nullptr;
};
} // namespace Telephony
} // namespace OHOS
#endif // TELEPHONY_SIM_RDB_HELPER_H