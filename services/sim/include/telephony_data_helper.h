/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#ifndef OHOS_TELEPHONY_DATA_HELPER_H
#define OHOS_TELEPHONY_DATA_HELPER_H

#include <mutex>
#include <singleton.h>
#include "datashare_helper.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"
#include "uri.h"

namespace OHOS {
namespace Telephony {
class TelephonyDataHelper : public DelayedSingleton<TelephonyDataHelper> {
    DECLARE_DELAYED_SINGLETON(TelephonyDataHelper);

public:
    static constexpr const char *SIM_DB_URI =
        "datashare:///com.ohos.telephonydataability/entry/sim/sim_info?Proxy=true";
    static constexpr const char *SIM_URI = "datashare:///com.ohos.simability";
    static constexpr const char *OPKEY_DB_URI =
        "datashare:///com.ohos.telephonydataability/entry/opkey/opkey_info?Proxy=true";
    static constexpr const char *OPKEY_URI = "datashare:///com.ohos.opkeyability";
    static constexpr const char *PDP_DB_URI =
        "datashare:///com.ohos.telephonydataability/entry/net/pdp_profile?Proxy=true";
    static constexpr const char *PDP_URI = "datashare:///com.ohos.pdpprofileability";
    std::shared_ptr<DataShare::DataShareHelper> CreateOpKeyHelper();
    std::shared_ptr<DataShare::DataShareHelper> CreateSimHelper();
    std::shared_ptr<DataShare::DataShareHelper> CreatePdpHelper();
    bool IsDataShareError();
    void ResetDataShareError();

private:
    std::shared_ptr<DataShare::DataShareHelper> CreateDataHelper(const std::string &strUri, const std::string &extUri);
    std::mutex lock_;
    bool mIsDataShareError = false;
};
}  // namespace Telephony
}  // namespace OHOS
#endif  // OHOS_TELEPHONY_DATA_HELPER_H