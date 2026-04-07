/*
 * Copyright (C) 2026-2026 Huawei Device Co., Ltd.
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

#ifndef OHOS_MULTI_SIM_HELPER_H
#define OHOS_MULTI_SIM_HELPER_H

#include "multi_sim_controller.h"
#include "datashare_values_bucket.h"

namespace OHOS {
namespace Telephony {
class MultiSimHelper {
public:
    MultiSimHelper();
    ~MultiSimHelper();

    bool AnnouncePrimarySimIdChanged(int32_t simId);
    bool AnnounceDefaultVoiceSimIdChanged(int32_t simId);
    bool AnnounceDefaultSmsSimIdChanged(int32_t simId);
    bool AnnounceDefaultCellularDataSimIdChanged(int32_t simId);
    void PublishSetPrimaryEvent(bool setDone, bool isUserSet);
    std::string EncryptIccId(const std::string &iccid);
    void SimDataBuilder(int32_t slotId, DataShare::DataShareValuesBucket &values, const std::string &iccId,
        int32_t simLabel, bool isEsim);
    void BuildSimPresentValues(int32_t slotId, DataShare::DataShareValuesBucket &values, const std::string &iccId);

private:
    bool PublishSimFileEvent(const AAFwk::Want &want, int eventCode, const std::string &eventData);
};
} // namespace Telephony
} // namespace OHOS
#endif // OHOS_MULTI_SIM_CONTROLLER_H