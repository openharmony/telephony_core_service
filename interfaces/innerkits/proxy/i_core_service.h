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

#ifndef I_BASE_PHONE_SERVICE_H
#define I_BASE_PHONE_SERVICE_H

#include <iremote_broker.h>
#include "network_state.h"
#include "signal_information.h"

namespace OHOS {
class ICoreService : public IRemoteBroker {
public:
    virtual ~ICoreService() = default;

    virtual int32_t GetPsRadioTech(int32_t slotId) = 0;
    virtual int32_t GetCsRadioTech(int32_t slotId) = 0;
    virtual std::u16string GetOperatorNumeric(int32_t slotId) = 0;
    virtual std::u16string GetOperatorName(int32_t slotId) = 0;
    virtual std::vector<sptr<SignalInformation>> GetSignalInfoList(int32_t slotId) = 0;
    virtual const sptr<NetworkState> GetNetworkStatus(int32_t slotId) = 0;
    virtual void SetHRilRadioState(int32_t slotId, bool isOn) = 0;
    virtual int32_t GetRadioState(int32_t slotId) = 0;

    virtual bool HasSimCard(int32_t slotId) = 0;
    virtual int32_t GetSimState(int32_t slotId) = 0;
    virtual std::u16string GetSimOperator(int32_t slotId) = 0;
    virtual std::u16string GetIsoCountryCode(int32_t slotId) = 0;
    virtual std::u16string GetSpn(int32_t slotId) = 0;
    virtual std::u16string GetIccId(int32_t slotId) = 0;
    virtual std::u16string GetIMSI(int32_t slotId) = 0;
    virtual bool IsSimActive(int32_t slotId) = 0;

    enum {
        GET_PS_RADIO_TECH = 0,
        GET_CS_RADIO_TECH,
        GET_OPERATOR_NUMERIC,
        GET_OPERATOR_NAME,
        GET_SIGNAL_INFO_LIST,
        GET_NETWORK_STATE,
        GET_CELL_INFO_LIST,
        SET_RADIO_STATE,
        GET_RADIO_STATE,
        HAS_SIM_CARD,
        GET_SIM_STATE,
        GET_ISO_COUNTRY_CODE,
        GET_SPN,
        GET_ICCID,
        GET_IMSI,
        IS_SIM_ACTIVE,
        GET_SIM_OPERATOR_NUMERIC,
    };

public:
    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.telephony.ICoreService");
};
} // namespace OHOS

#endif // I_BASE_PHONE_SERVICE_H
