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
#ifndef I_OPERATOR_CONFIG_HISYSEVENT_H
#define I_OPERATOR_CONFIG_HISYSEVENT_H

#include "operator_config_hisysevent_enum.h"

namespace OHOS {
namespace Telephony {
class IOperatorConfigHisysevent {
public:
    virtual ~IOperatorConfigHisysevent() = default;
    virtual void InitOperatorConfigHisysevent(int32_t slotId, int32_t simState) = 0;
    virtual void SetMatchSimResult(int32_t slotId, const char* opkey, const char* opname, int32_t matchSimState) = 0;
    virtual void SetMatchSimFile(int32_t slotId, MatchSimFileType simFileType, const std::string &simFile) = 0;
    virtual void SetMatchSimReason(int32_t slotId, MatchSimReason matchSimReason) = 0;
    virtual void SetMatchSimStateTracker(MatchSimState matchSimStateTracker, int32_t slotId = -1) = 0;
    virtual void SetMatchSimStateTracker(int8_t matchSimStateTracker, int32_t slotId) = 0;
    virtual void ReportMatchSimChr(int32_t slotId) = 0;
};
}
}
#endif