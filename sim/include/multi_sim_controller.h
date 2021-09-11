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

#ifndef TELEPHONY_MULTISIMCONTROLLER_H
#define TELEPHONY_MULTISIMCONTROLLER_H

#include <list>
#include "i_sim_manager.h"
#include "common_event.h"
#include "common_event_manager.h"
#include "want.h"
#include "if_system_ability_manager.h"
#include "telephony_log_wrapper.h"
#include "core_manager.h"
#include "sim_constant.h"
#include "telephony_state_registry_proxy.h"

namespace OHOS {
namespace Telephony {
class MultiSimController {
public:
    MultiSimController();
    virtual ~MultiSimController();
    bool RefreshIccAccountInfoList();
    bool GetListFromDataBase();
    int32_t GetDefaultVoiceSlotId();
    bool SetDefaultVoiceSlotId(int32_t subId);
    int32_t GetDefaultSmsSlotId();
    bool SetDefaultSmsSlotId(int32_t subId);
    bool AnnounceDefaultVoiceSlotIdChanged(int32_t subId);
    bool AnnounceDefaultSmsSlotIdChanged(int32_t subId);
    bool PublishSimFileEvent(const AAFwk::Want &want, int eventCode, const std::string &eventData);
    std::shared_ptr<Core> GetCoreInstance(int32_t subId);

    std::list<IccAccountInfo> iccAccountInfoList_;
    const std::string DEFAULT_VOICE_SLOTID_CHANGE_ACTION = "com.hos.action.DEFAULT_VOICE_SLOTID_CHANGE";
    const std::string DEFAULT_SMS_SLOTID_CHANGE_ACTION = "com.hos.action.DEFAULT_SMS_SLOTID_CHANGE";

private:
    static const int32_t EVENT_CODE = 1;
    inline static const std::string PARAM_SUBID = "subId";
    inline static const std::string DEFAULT_VOICE_SLOT_CHANGED = "defaultVoiceSlotChanged";
    inline static const std::string DEFAULT_SMS_SLOT_CHANGED = "defaultSmsSlotChanged";
    // fixme this four is test data for list
    IccAccountInfo operationInfoOne_;

    // fixme this is simulate for database
    std::list<IccAccountInfo> dataList_;

    // fixme this to value should be save into database, now is test
    int32_t defaultVoiceSlotId_ = CoreManager::DEFAULT_SLOT_ID;
    int32_t defaultSmsSlotId_ = CoreManager::DEFAULT_SLOT_ID;
};
} // namespace Telephony
} // namespace OHOS
#endif // TELEPHONY_MULTISIMCONTROLLER_H
