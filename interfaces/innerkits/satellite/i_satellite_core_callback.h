/*
 * Copyright (C) 2023-2024 Huawei Device Co., Ltd.
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

#ifndef I_SATELLITE_CORE_CALLBACK_H
#define I_SATELLITE_CORE_CALLBACK_H

#include "iremote_proxy.h"
#include "satellite_core_callback_ipc_interface_code.h"
#include "event_handler.h"

namespace OHOS {
namespace Telephony {
using namespace AppExecFwk;

class ISatelliteCoreCallback : public IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.telephony.ISatelliteCoreCallback");

public:
    /**
     * @brief SetRadioStateResponse.
     *
     * @param event event which contains the response data.
     * @return Returns {@code TELEPHONY_SUCCESS} on success, others on failure.
     */
    virtual int32_t SetRadioStateResponse(InnerEvent::Pointer &event) = 0;

    /**
     * @brief RadioStateChanged.
     *
     * @param event event which contains the response data.
     * @return Returns {@code TELEPHONY_SUCCESS} on success, others on failure.
     */
    virtual int32_t RadioStateChanged(InnerEvent::Pointer &event) = 0;

    /**
     * @brief SimStateChanged.
     *
     * @param event event which contains the response data.
     * @return Returns {@code TELEPHONY_SUCCESS} on success, others on failure.
     */
    virtual int32_t SimStateChanged(InnerEvent::Pointer &event) = 0;

    /**
     * @brief SatelliteStatusChanged.
     *
     * @param event event which contains the response data.
     * @return Returns {@code TELEPHONY_SUCCESS} on success, others on failure.
     */
    virtual int32_t SatelliteStatusChanged(InnerEvent::Pointer &event) = 0;
};

} // namespace Telephony
} // namespace OHOS
#endif // I_SATELLITE_CORE_CALLBACK_H