/*
 * Copyright (C) 2021-2022 Huawei Device Co., Ltd.
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

#ifndef OHOS_MULTI_SIM_CONTROLLER_H
#define OHOS_MULTI_SIM_CONTROLLER_H

#include <list>

#include "i_network_search.h"
#include "if_system_ability_manager.h"
#include "radio_protocol_controller.h"
#include "rdb_sim_helper.h"
#include "sim_constant.h"
#include "sim_data.h"
#include "sim_file_manager.h"
#include "sim_rdb_helper.h"
#include "sim_state_manager.h"
#include "telephony_errors.h"
#include "want.h"

namespace OHOS {
namespace Telephony {
class MultiSimController {
public:
    MultiSimController(std::shared_ptr<Telephony::ITelRilManager> telRilManager,
        std::vector<std::shared_ptr<Telephony::SimStateManager>> simStateManager,
        std::vector<std::shared_ptr<Telephony::SimFileManager>> simFileManager,
        const std::shared_ptr<AppExecFwk::EventRunner> &runner);
    virtual ~MultiSimController();

    void Init();
    bool InitData(int32_t slotId);
    void SetNetworkSearchManager(std::shared_ptr<INetworkSearch> networkSearchManager);
    bool RefreshActiveIccAccountInfoList();
    int32_t GetDefaultVoiceSlotId();
    bool SetDefaultVoiceSlotId(int32_t slotId);
    int32_t GetDefaultSmsSlotId();
    bool SetDefaultSmsSlotId(int32_t slotId);
    bool GetSimAccountInfo(int32_t slotId, IccAccountInfo &info);
    int32_t GetDefaultCellularDataSlotId();
    bool SetDefaultCellularDataSlotId(int32_t slotId);
    int32_t GetPrimarySlotId();
    bool SetPrimarySlotId(int32_t slotId);
    std::u16string GetShowNumber(int32_t slotId);
    bool SetShowNumber(int32_t slotId, std::u16string Number, bool force = false);
    std::u16string GetShowName(int32_t slotId);
    bool SetShowName(int32_t slotId, std::u16string name, bool force = false);
    bool IsSimActive(int32_t slotId);
    bool IsSimActivatable(int32_t slotId);
    bool SetActiveSim(int32_t slotId, int32_t enable, bool force = false);
    bool SetActiveSimToRil(int32_t slotId, int32_t type, int32_t enable);
    bool ForgetAllData();
    bool ForgetAllData(int32_t slotId);
    int32_t GetSlotId(int32_t simId);
    int32_t SaveImsSwitch(int32_t slotId, int32_t imsSwitchValue);
    int32_t QueryImsSwitch(int32_t slotId, int32_t &imsSwitchValue);
    bool GetListFromDataBase();
    bool GetActiveSimAccountInfoList(std::vector<IccAccountInfo> &iccAccountInfoList);
    int32_t GetRadioProtocolTech(int32_t slotId);
    void GetRadioProtocol(int32_t slotId);

private:
    bool IsValidData(int32_t slotId);
    int32_t GetFirstActivedSlotId();
    bool InitShowName(int slotId);
    bool InitShowNumber(int slotId);
    bool InitActive(int slotId);
    bool InitIccId(int slotId);
    int32_t UpdateDataByIccId(int slotId, std::string newIccId);
    int32_t InsertData(int slotId, std::string newIccId);
    void SortCache();
    std::u16string GetIccId(int32_t slotId);
    bool SetIccId(int32_t slotId, std::u16string iccId);
    int32_t GetDefaultCellularDataSlotIdUnit();
    bool AnnounceDefaultMainSlotIdChanged(int32_t slotId);
    bool AnnounceDefaultVoiceSlotIdChanged(int32_t slotId);
    bool AnnounceDefaultSmsSlotIdChanged(int32_t slotId);
    bool AnnounceDefaultCellularDataSlotIdChanged(int32_t slotId);
    bool PublishSimFileEvent(const AAFwk::Want &want, int eventCode, const std::string &eventData);

private:
    int32_t maxCount_ = 0;
    bool ready_ = false;
    std::vector<std::shared_ptr<Telephony::SimStateManager>> simStateManager_;
    std::vector<std::shared_ptr<Telephony::SimFileManager>> simFileManager_;
    std::unique_ptr<SimRdbHelper> simDbHelper_ = nullptr;
    std::shared_ptr<INetworkSearch> networkSearchManager_ = nullptr;
    IccAccountInfo iccAccountInfo_;
    std::vector<IccAccountInfo> iccAccountInfoList_;
    std::vector<SimRdbInfo> localCacheInfo_;
    std::mutex mutex_;
    std::shared_ptr<RadioProtocolController> radioProtocolController_ = nullptr;
};
} // namespace Telephony
} // namespace OHOS
#endif // OHOS_MULTI_SIM_CONTROLLER_H
