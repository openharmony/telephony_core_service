/*
 * Copyright (C) 2022-2023 Huawei Device Co., Ltd.
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

#ifndef TELEPHONY_IMS_CORE_SERVICE_CALLBACK_INTERFACE_H
#define TELEPHONY_IMS_CORE_SERVICE_CALLBACK_INTERFACE_H

#include "iremote_broker.h"

#include "ims_core_service_types.h"
#include "ims_reg_types.h"

namespace OHOS {
namespace Telephony {
class ImsCoreServiceCallbackInterface : public IRemoteBroker {
public:
    virtual ~ImsCoreServiceCallbackInterface() = default;

    /**
     * UpdateImsServiceStatusChanged
     *
     * @param imsServiceStatus contains the ability of ims Voice/Video/Ut/Sms/CallComposer
     * @return Returns nullptr on failure, others on success.
     */
    virtual int32_t UpdateImsServiceStatusChanged(int32_t slotId, const ImsServiceStatus &imsServiceStatus) = 0;

    /**
     * GetImsRegistrationStatusResponse
     *
     * @param slotId
     * @param imsRegStatus
     * @return Returns nullptr on failure, others on success.
     */
    virtual int32_t GetImsRegistrationStatusResponse(int32_t slotId, const ImsRegistrationStatus &imsRegStatus) = 0;

public:
    DECLARE_INTERFACE_DESCRIPTOR(u"OHOS.Telephony.ImsCoreServiceCallback");
};
} // namespace Telephony
} // namespace OHOS

#endif // TELEPHONY_IMS_CORE_SERVICE_CALLBACK_INTERFACE_H
