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

#ifndef CELLULAR_DATA_RDB_HELPER_H
#define CELLULAR_DATA_RDB_HELPER_H

#include <memory>
#include <utility>

#include "datashare_helper.h"
#include "datashare_predicates.h"
#include "datashare_result_set.h"
#include "datashare_values_bucket.h"
#include "vcard_constant.h"

namespace OHOS {
namespace Telephony {
class VCardRdbHelper {
public:
    VCardRdbHelper();
    static int32_t InsertRawContact(const DataShare::DataShareValuesBucket &rawContactValues);
    static int32_t InsertContactData(const std::vector<DataShare::DataShareValuesBucket> &contactsDataValues);
    std::shared_ptr<DataShare::DataShareResultSet> QueryContact(
        std::vector<std::string> &columns, const DataShare::DataSharePredicates &predicates);
    static std::shared_ptr<DataShare::DataShareResultSet> QueryAccount(
        std::vector<std::string> &columns, const DataShare::DataSharePredicates &predicates);
    static std::shared_ptr<DataShare::DataShareResultSet> QueryRawContact(
        std::vector<std::string> &columns, const DataShare::DataSharePredicates &predicates);
    static std::shared_ptr<DataShare::DataShareResultSet> QueryContactData(
        std::vector<std::string> &columns, const DataShare::DataSharePredicates &predicates);
    static void SetDataHelper(std::shared_ptr<DataShare::DataShareHelper> dataShareHelper);
    static void Release();
    static VCardRdbHelper &GetInstance();
    static int32_t QueryRawContactMaxId();
    static int32_t BatchInsertRawContact(const std::vector<DataShare::DataShareValuesBucket> &rawContactValues);
    static int32_t BatchInsertContactData(const std::vector<DataShare::DataShareValuesBucket> &contactsDataValues);

private:
    static std::shared_ptr<DataShare::DataShareHelper> dataShareHelper_;
};
} // namespace Telephony
} // namespace OHOS
#endif // CELLULAR_DATA_RDB_HELPER_H
