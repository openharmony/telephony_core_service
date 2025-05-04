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
 #ifndef OHOS_MULTI_SIM_CONTROLLER_MOCK_H
#define OHOS_MULTI_SIM_CONTROLLER_MOCK_H

#include <gmock/gmock.h>
#include "multi_sim_controller.h"
#include "radio_protocol_controller.h"
#include "sim_constant.h"
#include "sim_file_manager.h"
#include "sim_rdb_helper.h"
#include "sim_state_manager.h"
#include "telephony_errors.h"
#include "tel_event_handler.h"

namespace OHOS {
namespace Telephony {
class MultiSimControllerMock : public MultiSimController {
public:
    explicit MultiSimControllerMock(std::shared_ptr<Telephony::ITelRilManager> telRilManager = nullptr,
        std::vector<std::shared_ptr<Telephony::SimStateManager>> simStateManager = {},
        std::vector<std::shared_ptr<Telephony::SimFileManager>> simFileManager = {})
        : MultiSimController(telRilManager, simStateManager, simFileManager) {
    }

    ~MultiSimControllerMock() override = default;

    MOCK_METHOD2(AddExtraManagers, void(std::shared_ptr<Telephony::SimStateManager> simStateManager,
        std::shared_ptr<Telephony::SimFileManager> simFileManager));

    MOCK_METHOD0(Init, void());
    MOCK_METHOD1(InitData, bool(int32_t slotId));
    MOCK_METHOD0(GetDefaultVoiceSlotId, int32_t());
    MOCK_METHOD1(SetDefaultVoiceSlotId, int32_t(int32_t slotId));
    MOCK_METHOD0(GetDefaultSmsSlotId, int32_t());
    MOCK_METHOD1(SetDefaultSmsSlotId, int32_t(int32_t slotId));
    MOCK_METHOD3(GetSimAccountInfo, int32_t(int32_t slotId, bool denied, IccAccountInfo &info));
    MOCK_METHOD0(GetDefaultCellularDataSlotId, int32_t());
    MOCK_METHOD1(SetDefaultCellularDataSlotId, int32_t(int32_t slotId));
    MOCK_METHOD0(GetPrimarySlotId, int32_t());
    MOCK_METHOD1(SetPrimarySlotId, int32_t(int32_t slotId));
    MOCK_METHOD2(GetShowNumber, int32_t(int32_t slotId, std::u16string &showNumber));
    MOCK_METHOD3(SetShowNumber, int32_t(int32_t slotId, std::u16string Number, bool force));
    MOCK_METHOD2(SetShowNumberToDB, int32_t(int32_t slotId, std::u16string Number));
    MOCK_METHOD2(GetShowName, int32_t(int32_t slotId, std::u16string &showName));
    MOCK_METHOD3(SetShowName, int32_t(int32_t slotId, std::u16string name, bool force));
    MOCK_METHOD2(GetSimTelephoneNumber, int32_t(int32_t slotId, std::u16string &telephoneNumber));
    MOCK_METHOD1(IsSimActive, bool(int32_t slotId));
    MOCK_METHOD3(SetActiveSim, int32_t(int32_t slotId, int32_t enable, bool force));
    MOCK_METHOD3(SetActiveSimSatellite, int32_t(int32_t slotId, int32_t enable, bool force));
    MOCK_METHOD3(SetActiveSimToRil, bool(int32_t slotId, int32_t type, int32_t enable));
    MOCK_METHOD0(ForgetAllData, bool());
    MOCK_METHOD1(ForgetAllData, bool(int32_t slotId));
    MOCK_METHOD1(ResetSetPrimarySlotRemain, void(int32_t slotId));
    MOCK_METHOD1(GetSlotId, int32_t(int32_t simId));
    MOCK_METHOD1(GetSimId, int32_t(int32_t slotId));
    MOCK_METHOD2(SaveImsSwitch, int32_t(int32_t slotId, int32_t imsSwitchValue));
    MOCK_METHOD2(QueryImsSwitch, int32_t(int32_t slotId, int32_t &imsSwitchValue));
    MOCK_METHOD0(GetListFromDataBase, bool());
    MOCK_METHOD2(GetActiveSimAccountInfoList, int32_t(bool denied, std::vector<IccAccountInfo> &iccAccountInfoList));
    MOCK_METHOD1(GetRadioProtocolTech, int32_t(int32_t slotId));
    MOCK_METHOD1(GetRadioProtocol, void(int32_t slotId));
    MOCK_METHOD1(InitShowName, bool(int slotId));
    MOCK_METHOD0(ReCheckPrimary, void());
    MOCK_METHOD0(IsDataShareError, bool());
    MOCK_METHOD0(ResetDataShareError, void());
    MOCK_METHOD0(UpdateOpKeyInfo, int32_t());
    MOCK_METHOD1(IsSetActiveSimInProgress, bool(int32_t slotId));
    MOCK_METHOD0(IsSetPrimarySlotIdInProgress, bool());
    MOCK_METHOD1(SavePrimarySlotId, int32_t(int32_t slotId));
    MOCK_METHOD0(GetDefaultMainSlotByIccId, int32_t());
    MOCK_METHOD1(IsValidData, bool(int32_t slotId));
    MOCK_METHOD1(InitIccId, bool(int32_t slotId));
};
} // namespace Telephony
} // namespace OHOS

#endif // OHOS_MULTI_SIM_CONTROLLER_MOCK_H