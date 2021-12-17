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

#ifndef TEL_RIL_DATA_H
#define TEL_RIL_DATA_H

#include "hril_data_parcel.h"
#include "i_tel_ril_manager.h"
#include "tel_ril_base.h"

namespace OHOS {
namespace Telephony {
class TelRilData : public TelRilBase {
public:
    TelRilData(sptr<IRemoteObject> cellularRadio, std::shared_ptr<ObserverHandler> observerHandler);
    ~TelRilData() = default;
    DataProfileDataInfo ChangeDPToHalDataProfile(ITelRilManager::CellularDataProfile dataProfile);
    void DeactivatePdpContext(int32_t cid, int32_t reason, const AppExecFwk::InnerEvent::Pointer &response);
    void DeactivatePdpContextResponse(MessageParcel &data);
    void UnRegisterCallDataListChanged(int what);
    void SetApnConnectNetworkResponse(MessageParcel &data);
    void ActivatePdpContext(int32_t radioTechnology, ITelRilManager::CellularDataProfile dataProfile, bool isRoaming,
        bool allowRoaming, const AppExecFwk::InnerEvent::Pointer &response);
    void ActivatePdpContextResponse(MessageParcel &data);
    void GetPdpContextList(const AppExecFwk::InnerEvent::Pointer &response);
    void GetPdpContextListResponse(MessageParcel &data);
    void PdpContextListUpdated(MessageParcel &data);
    bool IsDataRespOrNotify(uint32_t code);
    void ProcessDataRespOrNotify(uint32_t code, MessageParcel &data);

private:
    bool IsDataResponse(uint32_t code);
    bool IsDataNotification(uint32_t code);
    void AddHandlerToMap();

private:
    using Func = void (TelRilData::*)(MessageParcel &data);
    std::map<uint32_t, Func> memberFuncMap_;
};
} // namespace Telephony
} // namespace OHOS
#endif // TEL_RIL_DATA_H
