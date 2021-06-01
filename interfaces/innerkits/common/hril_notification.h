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
#ifndef OHOS_RIL_NOTIFICATION_H
#define OHOS_RIL_NOTIFICATION_H
typedef enum {
    HNOTI_CALL_BASE = 1000,
    HNOTI_CALL_STATE_UPDATED,

    HNOTI_SMS_BASE = 1100,
    HNOTI_SMS_NEW_SMS,
    HNOTI_SMS_STATUS_REPORT,
    HNOTI_SMS_NEW_SMS_STORED_ON_SIM,

    HNOTI_SIM_BASE = 1200,

    HNOTI_DATA_BASE = 1300,
    HNOTI_DATA_PDP_CONTEXT_LIST_UPDATED,

    HNOTI_NETWORK_BASE = 1400,
    HNOTI_NETWORK_CS_REG_STATUS_UPDATED,
    HNOTI_NETWORK_SIGNAL_STRENGTH_UPDATED,

    HNOTI_COMMON_BASE = 1500,
    HNOTI_MODEM_RADIO_STATE_UPDATED,
} HRilNotification;
#endif // OHOS_RIL_NOTIFICATION_H