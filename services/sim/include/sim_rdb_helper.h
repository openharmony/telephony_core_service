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
#include "sim_state_type.h"
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
    virtual ~SimRdbHelper();

    virtual int32_t GetDefaultMainCardSlotId();
    virtual int32_t GetDefaultMessageCardSlotId();
    virtual int32_t GetDefaultVoiceCardSlotId();
    virtual int32_t GetDefaultCellularDataCardSlotId();
    virtual int32_t SetDefaultMainCard(int32_t simId);
    virtual int32_t SetDefaultVoiceCard(int32_t simId);
    virtual int32_t SetDefaultMessageCard(int32_t simId);
    virtual int32_t SetDefaultCellularData(int32_t simId);
    virtual int32_t InsertData(int64_t &id, const DataShare::DataShareValuesBucket &values);
    virtual int32_t QueryDataByIccId(std::string iccId, SimRdbInfo &simBean);
    virtual int32_t QueryAllData(std::vector<SimRdbInfo> &vec);
    virtual int32_t QueryAllValidData(std::vector<SimRdbInfo> &vec);
    virtual int32_t UpdateDataBySimId(int32_t simId, const DataShare::DataShareValuesBucket &values);
    virtual int32_t UpdateDataByIccId(std::string iccId, const DataShare::DataShareValuesBucket &values);
    virtual int32_t ForgetAllData();
    virtual int32_t ForgetAllData(int32_t slotId, bool isNeedUpdateSimLabel, bool isUpdateActiveState);
    virtual int32_t ClearSimLabel(SimType simType);
    virtual int32_t UpdateEsimOpName(const std::string &iccId, const std::string &operatorName);
    virtual int32_t UpdateSimPresent(std::string iccId, bool isShowPresent, int labelIndex);

    virtual int32_t ClearData();
    virtual int32_t UpdateOpKeyInfo();
    virtual bool IsDataShareError();
    virtual void ResetDataShareError();

private:
    std::shared_ptr<TelephonyDataHelper> mTelephonyDatahelper = DelayedSingleton<TelephonyDataHelper>::GetInstance();
    virtual std::shared_ptr<DataShare::DataShareHelper> CreateDataHelper();
    virtual std::shared_ptr<DataShare::DataShareHelper> CreateOpKeyHelper(int waitTime);
    virtual std::shared_ptr<DataShare::DataShareHelper> CreateDataHelper(const int waitTime);
    virtual int Insert(
        std::shared_ptr<DataShare::DataShareHelper> dataShareHelper, const DataShare::DataShareValuesBucket &values);
    virtual std::shared_ptr<DataShare::DataShareResultSet> Query(std::shared_ptr<DataShare::DataShareHelper>
        dataShareHelper, std::vector<std::string> &columns, const DataShare::DataSharePredicates &predicates);
    virtual int Update(std::shared_ptr<DataShare::DataShareHelper> dataShareHelper,
        const DataShare::DataShareValuesBucket &value, const DataShare::DataSharePredicates &predicates);
    virtual int Delete(
        std::shared_ptr<DataShare::DataShareHelper> dataShareHelper, const DataShare::DataSharePredicates &predicates);
    virtual void SaveDataToBean(std::shared_ptr<DataShare::DataShareResultSet> result, SimRdbInfo &simBean);

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
