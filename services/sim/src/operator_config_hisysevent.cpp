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
#include "operator_config_hisysevent.h"
#include "core_service_hisysevent.h"
#include "operator_config_hisysevent_enum.h"

namespace OHOS {
namespace Telephony {
constexpr int32_t MAIN_SLOT = 0;
constexpr int32_t SLAVE_SLOT = 1;
OperatorConfigHisysevent::OperatorConfigHisysevent() {}

void OperatorConfigHisysevent::InitOperatorConfigHisysevent(int32_t slotId, int32_t simState)
{
    if (!IsValidSlotId(slotId)) {
        return;
    }
    auto &info = matchSimInfo_[slotId];
    info.slotId = slotId;
    info.simState = simState;
    info.matchSimFileState = 0U;
    info.matchSimReason = 0;
    info.matchSimStateTracker = 0U;
    info.matchSimFailReason = 0U;
    info.matchSimState = 0;
    info.clear();
}

void OperatorConfigHisysevent::SetMatchSimResult(
    int32_t slotId, const char* opkey, const char* opname, int32_t matchSimState)
{
    if (!IsValidSlotId(slotId)) {
        return;
    }
    auto &info = matchSimInfo_[slotId];
    info.SetOpKey(opkey);
    info.SetOpname(opname);
    info.matchSimState = matchSimState;
}

void OperatorConfigHisysevent::SetMatchSimFile(int32_t slotId, MatchSimFileType simFileType, const std::string &simFile)
{
    if (!IsValidSlotId(slotId)) {
        return;
    }
    if ((static_cast<int8_t>(simFileType)) < 0 ||
        (static_cast<int8_t>(simFileType)) >= static_cast<int8_t>(sizeof(uint8_t) * CHAR_BIT)) {
        return;
    }
    ProcessMatchSimFile(slotId, simFileType, simFile.c_str());
}

void OperatorConfigHisysevent::SetMatchSimReason(int32_t slotId, MatchSimReason matchSimReason)
{
    if (!IsValidSlotId(slotId)) {
        return;
    }
    if (matchSimInfo_[slotId].matchSimReason == 0) {
        matchSimInfo_[slotId].matchSimReason = static_cast<int8_t>(matchSimReason);
    }
}

void OperatorConfigHisysevent::SetMatchSimStateTracker(int8_t matchSimStateTracker, int32_t slotId)
{
    ProcessMatchSimStateTracker(static_cast<MatchSimState>(matchSimStateTracker), slotId);
}

void OperatorConfigHisysevent::SetMatchSimStateTracker(MatchSimState matchSimStateTracker, int32_t slotId)
{
    ProcessMatchSimStateTracker(matchSimStateTracker, slotId);
}

void OperatorConfigHisysevent::ReportMatchSimChr(int32_t slotId)
{
    if (!IsValidSlotId(slotId)) {
        return;
    }
    CoreServiceHiSysEvent::WriteMatchSimBehaviorEvent(slotId, matchSimInfo_[slotId]);
}

void OperatorConfigHisysevent::ProcessMatchSimStateTracker(MatchSimState matchSimStateTracker, int32_t slotId)
{
    if (static_cast<int8_t>(matchSimStateTracker) < 0 ||
        static_cast<int8_t>(matchSimStateTracker) >= static_cast<int8_t>(sizeof(uint32_t) * CHAR_BIT)) {
        return;    
    }

    if (slotId == -1) {
        UpdateMatchSimInfo(MAIN_SLOT, matchSimStateTracker);
        UpdateMatchSimInfo(SLAVE_SLOT, matchSimStateTracker);
    } else {
        if (!IsValidSlotId(slotId)) {
            return;
        }
        if (matchSimStateTracker == MatchSimReason::SEND_OPC_SUCC ||
            matchSimStateTracker == MatchSimState::SEND_OPC_FAIL) {
            ClearMatchSimFailReason(slotId);
        }
        UpdateMatchSimInfo(slotId, matchSimStateTracker);
    }
}

inline void OperatorConfigHisysevent::UpdateMatchSimInfo(int32_t slotId, MatchSimState matchSimStateTracker)
{
    if (IsMatchSimFailReason(matchSimStateTracker)) {
        matchSimInfo_[slotId].matchSimFailReason |= (1U << static_cast<uint32_t>(matchSimStateTracker));
    }
    matchSimInfo_[slotId].matchSimStateTracker |= (1U << static_cast<uint32_t>(matchSimStateTracker));
}

void OperatorConfigHisysevent::ProcessMatchSimFile(int32_t slotId, MatchSimFileType simFileType, const char *simFile)
{
    auto& info = matchSimInfo_[slotId];
    switch (simFileType) {
        case MatchSimFileType::MATCH_SPN:
            info.SetSpn(simFile);
            break;
        case MatchSimFileType::MATCH_GID1:
            info.SetGid1(simFile);
            break;
        case MatchSimFileType::MATCH_GID2:
            info.SetGid2(simFile);
            break;
        case MatchSimFileType::MATCH_MCCMNC:
            info.SetMccMnc(simFile);
            break;
        default:
            break;
    }
    info.matchSimFileState |= (1U << static_cast<uint8_t>(simFileType));
}

inlie bool OperatorConfigHisysevent::IsMatchSimFailReason(MatchSimState matchSimStateTracker)
{
    return matchSimStateTracker == MatchSimState::SEND_OPC_FAIL ||
           matchSimStateTracker == MatchSimState::IMS_CLOUD_FAIL ||
           matchSimStateTracker == MatchSimState::GET_OPKEY_FAIL_CREATE_OPKEY_URI ||
           matchSimStateTracker == MatchSimState::CREATE_SIM_HELPER_FAIL ||
           matchSimStateTracker == MatchSimState::GET_OPKEY_FROM_SIM_FAIL ||
           matchSimStateTracker == MatchSimState::CREATE_OPKEY_HELPER_FAIL ||
           matchSimStateTracker == MatchSimState::GET_ALL_RULE_FROM_OPKEY_FAIL;
}

inline void OperatorConfigHisysevent::ClearMatchSimFailReason(int32_t slotId)
{
    matchSimInfo_[slotId].matchSimFailReason = 0U;
}

inline bool OperatorConfigHisysevent::IsValidSlotId(int32_t slotId)
{
    return (slotId >= 0) && slotId < SIM_SLOTS;
}
}
}