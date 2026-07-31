/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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

#ifndef OHOS_CARD_FILE_DETECT_MANAGER_H
#define OHOS_CARD_FILE_DETECT_MANAGER_H

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "datashare_values_bucket.h"
#include "sim_rdb_helper.h"
#include "sim_rdb_info.h"
#include "telephony_log_wrapper.h"

namespace OHOS {
namespace Telephony {

class CardFileDetectManager {
public:
    CardFileDetectManager();
    ~CardFileDetectManager();

    int32_t SaveCardFileDetectData(const CardFileDetectData &data);
    int32_t GetAllCardFileDetectData(std::vector<SimRdbInfo> &result);
    int32_t GetAllSimCardInfo(std::vector<SimCardInfo> &results);

private:
    int32_t InsertCardFileDetectData(const CardFileDetectData &data);
    int32_t UpdateCardFileDetectData(const CardFileDetectData &data);
    bool IsIccIdExists(const std::string &iccId);
    void BuildDataShareValues(const CardFileDetectData &data, DataShare::DataShareValuesBucket &values);

    std::shared_ptr<SimRdbHelper> simRdbHelper_;
};
} // namespace Telephony
} // namespace OHOS
#endif // OHOS_CARD_FILE_DETECT_MANAGER_H