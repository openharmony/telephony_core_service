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

#ifndef OHOS_TELEPHONY_STATE_IPC_INTERFACE_CODE_H
#define OHOS_TELEPHONY_STATE_IPC_INTERFACE_CODE_H

namespace OHOS {
namespace Telephony {
enum class StateNotifyInterfaceCode {
    CELL_INFO = 0,
    CELLULAR_DATA_STATE,
    CELLULAR_DATA_FLOW,
    SIGNAL_INFO,
    NET_WORK_STATE,
    CALL_STATE,
    CALL_STATE_FOR_ID,
    SIM_STATE,
    ADD_OBSERVER,
    REMOVE_OBSERVER,
    CFU_INDICATOR,
    VOICE_MAIL_MSG_INDICATOR,
    ICC_ACCOUNT_CHANGE
};
} // namespace Telephony
} // namespace OHOS
#endif // OHOS_TELEPHONY_STATE_IPC_INTERFACE_CODE_H