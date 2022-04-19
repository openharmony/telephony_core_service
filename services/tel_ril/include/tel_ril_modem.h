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

#ifndef TEL_RIL_MODEM_H
#define TEL_RIL_MODEM_H

#include "hril_modem_parcel.h"
#include "tel_ril_base.h"
#include "telephony_types.h"

namespace OHOS {
namespace Telephony {
class TelRilModem : public TelRilBase {
public:
    TelRilModem(int32_t slotId, sptr<IRemoteObject> cellularRadio, std::shared_ptr<ObserverHandler> observerHandler,
        std::shared_ptr<TelRilHandler> handler);
    ~TelRilModem() = default;
    /**
     * @brief Turn on and off radio response (for flight mode)
     * @param data is HDF service callback message
     */
    int32_t SetRadioStateResponse(MessageParcel &data);
    int32_t GetRadioStateResponse(MessageParcel &data);
    int32_t ShutDown(const AppExecFwk::InnerEvent::Pointer &response)
    {
        return 0;
    }
    int32_t RadioStateUpdated(MessageParcel &data);
    int32_t VoiceRadioTechUpdated(MessageParcel &data);
    /**
     * @brief Radio Status Change response
     * @param data is HDF service callback message
     */
    int32_t SetRadioState(int32_t fun, int32_t rst, const AppExecFwk::InnerEvent::Pointer &response);
    int32_t GetRadioState(const AppExecFwk::InnerEvent::Pointer &response);
    int32_t GetImei(const AppExecFwk::InnerEvent::Pointer &response);
    int32_t GetMeid(const AppExecFwk::InnerEvent::Pointer &response);
    int32_t GetVoiceRadioTechnology(const AppExecFwk::InnerEvent::Pointer &response);
    int32_t GetBasebandVersion(const AppExecFwk::InnerEvent::Pointer &response);
    int32_t GetImeiResponse(MessageParcel &data);
    int32_t GetMeidResponse(MessageParcel &data);
    int32_t GetVoiceRadioTechnologyResponse(MessageParcel &data);
    int32_t GetBasebandVersionResponse(MessageParcel &data);
    bool IsCommonRespOrNotify(uint32_t code);
    ModemPowerState radioState_ = ModemPowerState::CORE_SERVICE_POWER_NOT_AVAILABLE;

private:
    void AddHandlerToMap();
    bool IsCommonResponse(uint32_t code);
    bool IsCommonNotification(uint32_t code);
};
} // namespace Telephony
} // namespace OHOS
#endif // TEL_RIL_MODEM_H
