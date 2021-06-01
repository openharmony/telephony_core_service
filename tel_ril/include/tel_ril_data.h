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

#include <memory>
#include <map>
#include <unordered_map>
#include "observer_handler.h"
#include "telephony_log.h"
#include "tel_ril_base.h"
#include "i_tel_ril_manager.h"
#include "hril_data_parcel.h"
#include "hril_types.h"

namespace OHOS {
class TelRilData : public TelRilBase {
public:
    TelRilData(sptr<IRemoteObject> cellularRadio, std::shared_ptr<ObserverHandler> observerHandler);
    ~TelRilData() = default;
    DataProfileDataInfo ChangeDPToHalDataProfile(CellularDataProfile dataProfile);
    void DeactivatePdpContext(int32_t cid, int32_t reason, const AppExecFwk::InnerEvent::Pointer &response);
    void DeactivatePdpContextResponse(OHOS::MessageParcel &data);
    void PdpContextListUpdated(const std::shared_ptr<AppExecFwk::EventHandler> &handler, int what, void *obj);
    void UnRegisterCallDataListChanged(int what);
    void SetApnConnectNetworkResponse(OHOS::MessageParcel &data);
    void ActivatePdpContext(int32_t radioTechnology, CellularDataProfile dataProfile, bool isRoaming,
        bool allowRoaming, const AppExecFwk::InnerEvent::Pointer &response);
    void ActivatePdpContextResponse(OHOS::MessageParcel &data);
    void PdpContextListUpdated(OHOS::MessageParcel &data);
    bool IsDataRespOrNotify(uint32_t code);
    void ProcessDataRespOrNotify(uint32_t code, OHOS::MessageParcel &data);

private:
    bool IsDataResponse(uint32_t code);
    bool IsDataNotification(uint32_t code);
    void AddHandlerToMap();

private:
    using Func = void (TelRilData::*)(MessageParcel &data);
    std::map<uint32_t, Func> memberFuncMap_;
};
} // namespace OHOS
#endif // TEL_RIL_DATA_H
