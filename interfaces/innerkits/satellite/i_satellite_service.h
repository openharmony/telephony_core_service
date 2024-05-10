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

#ifndef I_SATELLITE_SERVICE_H
#define I_SATELLITE_SERVICE_H

#include "i_satellite_core_callback.h"
#include "iremote_proxy.h"
#include "telephony_types.h"

namespace OHOS {
namespace Telephony {
using SatelliteMessage = GsmSimMessageParam;

namespace {
const int32_t TELEPHONY_SATELLITE_SERVICE_ABILITY_ID = 4012;
}

enum SatelliteServiceProxyType {
    PROXY_SATELLITE_CALL = 0,
    PROXY_SATELLITE_SMS = 1,
};

enum class SatelliteCapability : uint32_t {
    NONE    = 0x0,
    CALL    = 0x1,
    SMS     = 0x1 << 1,
    DATA    = 0x1 << 2,
};

class ISatelliteService : public IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.telephony.ISatelliteService");

public:
    /**
     * @brief Get the result of whether the satellite mode is on.
     *
     * @return True if satellite mode is turn on, false otherwise.
     */
    virtual bool IsSatelliteEnabled() = 0;

    /**
     * @brief Register a callback to service, so that service can send result to the caller.
     *
     * @param slotId sim slot id
     * @param what identify the callback data
     * @param callback callback object to deal with the callback data
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    virtual int32_t RegisterCoreNotify(int32_t slotId, int32_t what, const sptr<ISatelliteCoreCallback> &callback) = 0;

    /**
     * @brief Register a callback to service, so that service can send result to the caller.
     *
     * @param slotId sim slot id
     * @param what identify which callback should be unregister
     * @param callback callback object to deal with the callback data
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    virtual int32_t UnRegisterCoreNotify(int32_t slotId, int32_t what) = 0;

    /**
     * @brief Set the radio state.
     *
     * @param slotId sim slot id
     * @param eventId radio event id
     * @param isRadioOn radio on or off
     * @param rst whether to enable automatic reset of the modem
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    virtual int32_t SetRadioState(int32_t slotId, int32_t isRadioOn, int32_t rst) = 0;

    /**
     * @brief Get satellite imei
     *
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    virtual std::string GetImei() = 0;

    /**
     * @brief Get satellite capability
     *
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    virtual int32_t GetSatelliteCapability() = 0;

    /**
     * @brief Get the pointer of service.
     *
     * @param SatelliteServiceProxyType service type, call or sms
     * @return Remote object of the service.
     */
    virtual sptr<IRemoteObject> GetProxyObjectPtr(SatelliteServiceProxyType proxyType) = 0;
};
} // namespace Telephony
} // namespace OHOS
#endif // I_SATELLITE_SERVICE_H