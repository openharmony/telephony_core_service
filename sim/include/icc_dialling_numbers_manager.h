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

#ifndef OHOS_ICC_DIALLING_NUMBERS_MANAGER_H
#define OHOS_ICC_DIALLING_NUMBERS_MANAGER_H

#include <iostream>
#include <cstring>
#include <string>
#include "core_manager.h"
#include "event_handler.h"
#include "event_runner.h"
#include "i_icc_dialling_numbers_manager.h"
#include "icc_dialling_numbers_controller.h"
#include "telephony_log.h"

namespace OHOS {
namespace Telephony {
class IccDiallingNumbersManager : public IIccDiallingNumbersManager {
public:
    IccDiallingNumbersManager(const std::shared_ptr<ISimFileManager> &simFileManager);
    virtual ~IccDiallingNumbersManager();
    void Init();
    std::vector<std::shared_ptr<DiallingNumbersInfo>> QueryIccDiallingNumbers(int slotId, int type);
    bool AddIccDiallingNumbers(int slotId, int type, const std::shared_ptr<DiallingNumbersInfo> &diallingNumber);
    bool DelIccDiallingNumbers(int slotId, int type, int index);
    bool UpdateIccDiallingNumbers(
        int slotId, int type, const std::shared_ptr<DiallingNumbersInfo> &diallingNumber, int index);
    enum class HandleRunningState { STATE_NOT_START, STATE_RUNNING };

protected:
    std::shared_ptr<ISimFileManager> simFileManager_ = nullptr;
    std::shared_ptr<IccDiallingNumbersController> phoneBookCtrl_ = nullptr;
    std::shared_ptr<AppExecFwk::EventRunner> eventLoopPhoneBookCtrl_ = nullptr;
    HandleRunningState statePhoneBookCtrl__ = HandleRunningState::STATE_NOT_START;
};
} // namespace Telephony
} // namespace OHOS
#endif // OHOS_ICC_DIALLING_NUMBERS_MANAGER_H
