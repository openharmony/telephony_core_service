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

#ifndef OHOS_SIM_FILE_MANAGER_H
#define OHOS_SIM_FILE_MANAGER_H

#include <stdlib.h>
#include <cstring>
#include <string>
#include "core_manager.h"
#include "event_handler.h"
#include "event_runner.h"
#include "sim_file_controller.h"
#include "usim_file_controller.h"
#include "i_tel_ril_manager.h"
#include "i_sim_file_manager.h"
#include "sim_file.h"
#include "telephony_log_wrapper.h"

namespace OHOS {
namespace Telephony {
class SimFileManager : public ISimFileManager {
public:
    SimFileManager(std::shared_ptr<IRilManager> rilManager, std::shared_ptr<Telephony::ISimStateManager> state);
    virtual ~SimFileManager();
    void Init();
    virtual std::u16string GetSimOperatorNumeric(int32_t slotId);
    virtual std::u16string GetIsoCountryCodeForSim(int32_t slotId);
    virtual std::u16string GetSimSpn(int32_t slotId);
    virtual std::u16string GetSimIccId(int32_t slotId);
    virtual std::u16string GetIMSI(int32_t slotId);
    virtual std::u16string GetLocaleFromDefaultSim();
    virtual std::u16string GetSimGid1(int32_t slotId);
    virtual std::u16string GetSimTelephoneNumber(int32_t slotId);
    virtual std::u16string GetVoiceMailIdentifier(int32_t slotId);
    virtual std::u16string GetVoiceMailNumber(int32_t slotId);
    virtual int ObtainSpnCondition(bool roaming, std::string operatorNum);
    virtual void RegisterImsiLoaded(std::shared_ptr<AppExecFwk::EventHandler> eventHandler);
    virtual void UnregisterImsiLoaded(const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    virtual void RegisterAllFilesLoaded(std::shared_ptr<AppExecFwk::EventHandler> eventHandler);
    virtual void UnregisterAllFilesLoaded(const std::shared_ptr<AppExecFwk::EventHandler> &handler);
    virtual void RegisterPhoneNotify(const std::shared_ptr<AppExecFwk::EventHandler> &handler, int what);
    virtual void UnRegisterPhoneNotify(const std::shared_ptr<AppExecFwk::EventHandler> &observerCallBack, int what);
    virtual void SetImsi(std::string imsi);
    std::shared_ptr<IccFile> GetIccFile();
    std::shared_ptr<IccFileController> GetIccFileController();
    std::shared_ptr<SimDiallingNumbersHandler> ObtainDiallingNumberHandler();
    virtual bool SetVoiceMail(const std::u16string &mailName, const std::u16string &mailNumber, int32_t slotId);
    enum class HandleRunningState { STATE_NOT_START, STATE_RUNNING };

protected:
    std::shared_ptr<IRilManager> rilManager_ = nullptr;
    std::shared_ptr<IccFileController> fileController_ = nullptr;
    std::shared_ptr<IccFile> simFile_ = nullptr;
    std::shared_ptr<SimDiallingNumbersHandler> diallingNumberHandler_ = nullptr;
    std::shared_ptr<AppExecFwk::EventRunner> eventLoopRecord_ = nullptr;
    std::shared_ptr<AppExecFwk::EventRunner> eventLoopFileController_ = nullptr;
    HandleRunningState stateRecord_ = HandleRunningState::STATE_NOT_START;
    HandleRunningState stateHandler_ = HandleRunningState::STATE_NOT_START;
    std::shared_ptr<Telephony::ISimStateManager> simStateManager_ = nullptr;

private:
    bool InitDiallingNumberHandler();
};
} // namespace Telephony
} // namespace OHOS

#endif // OHOS_SIM_FILE_MANAGER_H
