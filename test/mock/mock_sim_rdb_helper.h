/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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
#ifndef TELEPHONY_SIM_RDB_HELPER_MOCK_H
#define TELEPHONY_SIM_RDB_HELPER_MOCK_H

#include "datashare_helper.h"
#include "sim_rdb_helper.h"
#include <gmock/gmock.h>

namespace OHOS {
namespace Telephony {
class MockSimRdbHelper : public SimRdbHelper {
public:
    MockSimRdbHelper() = default;
    ~MockSimRdbHelper() = default;

    MOCK_METHOD0(GetDefaultMainCardSlotId, int32_t());
    MOCK_METHOD0(GetDefaultMessageCardSlotId, int32_t());
    MOCK_METHOD0(GetDefaultVoiceCardSlotId, int32_t());
    MOCK_METHOD0(GetDefaultCellularDataCardSlotId, int32_t());
    MOCK_METHOD1(SetDefaultMainCard, int32_t(int32_t simId));
    MOCK_METHOD1(SetDefaultVoiceCard, int32_t(int32_t simId));
    MOCK_METHOD1(SetDefaultMessageCard, int32_t(int32_t simId));
    MOCK_METHOD1(SetDefaultCellularData, int32_t(int32_t simId));
    MOCK_METHOD2(InsertData, int32_t(int64_t &id, const DataShare::DataShareValuesBucket &values));
    MOCK_METHOD2(QueryDataByIccId, int32_t(std::string iccId, SimRdbInfo &simBean));
    MOCK_METHOD1(QueryAllData, int32_t(std::vector<SimRdbInfo> &vec));
    MOCK_METHOD1(QueryAllValidData, int32_t(std::vector<SimRdbInfo> &vec));
    MOCK_METHOD2(UpdateDataBySimId, int32_t(int32_t simId, const DataShare::DataShareValuesBucket &values));
    MOCK_METHOD2(UpdateDataByIccId, int32_t(std::string iccId, const DataShare::DataShareValuesBucket &values));
    MOCK_METHOD0(ForgetAllData, int32_t());
    MOCK_METHOD1(ForgetAllData, int32_t(int32_t slotId));
    MOCK_METHOD0(ClearData, int32_t());
    MOCK_METHOD0(UpdateOpKeyInfo, int32_t());
    MOCK_METHOD0(IsDataShareError, bool());
    MOCK_METHOD0(ResetDataShareError, void());
};
} // namespace Telephony
} // namespace OHOS

#endif // TELEPHONY_SIM_RDB_HELPER_MOCK_H