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
#ifndef OPERATOR_CONFIG_HISYSEVENT_H
#define OPERATOR_CONFIG_HISYSEVENT_H

#include "i_operator_config_hisysevent.h"
#include "operator_config_matchsim_info.h"

namespace OHOS {
namespace Telephony {
constexpr int32_t SIM_SLOTS = 2;
class OperatorConfigHisysevent : public IOperatorConfigHisysevent {
public:
    OperatorConfigHisysevent();
    ~OperatorConfigHisysevent() override = default;
    void InitOperatorConfigHisysevent(int32_t slotId, int32_t simState) override;
    void SetMatchSimResult(int32_t slotId, const char* opkey, const char* opname, int32_t matchSimState) override;
    void SetMatchSimFile(int32_t slotId, MatchSimFileType simFileType, const std::string &simFile) override;
    void SetMatchSimReason(int32_t slotId, MatchSimReason matchSimReason) override;
    void SetMatchSimStateTracker(MatchSimState matchSimStateTracker, int32_t slotId = -1) override;
    void SetMatchSimStateTracker(int8_t matchSimStateTracker, int32_t slotId) override;
    void ReportMatchSimChr(int32_t slotId) override;

private:
    bool IsValidSlotId(int32_t slotId);
    void ClearMatchSimFailReason(int32_t slotId);
    bool IsMatchSimFailReason(MatchSimState matchSimStateTracker);
    void ProcessMatchSimStateTracker(MatchSimState matchSimStateTracker, int32_t slotId);
    void ProcessMatchSimFile(int32_t slotId, MatchSimFileType simFileType, const char *simFile);
    void UpdateMatchSimInfo(int32_t slotId, MatchSimState matchSimStateTracker);

private:
    MatchSimInfo matchSimInfo_[SIM_SLOTS];
};
}
}
#endif