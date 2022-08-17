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
#include "tel_ril_base.h"
#include "telephony_types.h"

namespace OHOS {
namespace Telephony {
class TelRilData : public TelRilBase {
public:
    TelRilData(int32_t slotId, sptr<IRemoteObject> cellularRadio, std::shared_ptr<ObserverHandler> observerHandler,
        std::shared_ptr<TelRilHandler> handler);
    ~TelRilData() = default;
    DataProfileDataInfo ChangeDPToHalDataProfile(DataProfile dataProfile);
    int32_t DeactivatePdpContext(int32_t cid, int32_t reason, const AppExecFwk::InnerEvent::Pointer &response);
    int32_t DeactivatePdpContextResponse(MessageParcel &data);
    int32_t SetInitApnInfo(const DataProfile &dataProfile, const AppExecFwk::InnerEvent::Pointer &response);
    int32_t SetInitApnInfoResponse(MessageParcel &data);
    int32_t ActivatePdpContext(int32_t radioTechnology, DataProfile dataProfile, bool isRoaming, bool allowRoaming,
        const AppExecFwk::InnerEvent::Pointer &response);
    int32_t ActivatePdpContextResponse(MessageParcel &data);
    int32_t GetPdpContextList(const AppExecFwk::InnerEvent::Pointer &response);
    int32_t GetPdpContextListResponse(MessageParcel &data);
    int32_t PdpContextListUpdated(MessageParcel &data);
    bool IsDataRespOrNotify(uint32_t code);
    int32_t GetLinkBandwidthInfo(const int32_t cid, const AppExecFwk::InnerEvent::Pointer &response);
    int32_t GetLinkBandwidthInfoResponse(MessageParcel &data);
    int32_t SetLinkBandwidthReportingRule(
        LinkBandwidthRule linkBandwidth, const AppExecFwk::InnerEvent::Pointer &response);
    int32_t SetLinkBandwidthReportingRuleResponse(MessageParcel &data);
    int32_t SetDataPermitted(const int32_t dataPermitted, const AppExecFwk::InnerEvent::Pointer &response);
    int32_t SetDataPermittedResponse(MessageParcel &data);

private:
    bool IsDataResponse(uint32_t code);
    bool IsDataNotification(uint32_t code);
    void AddHandlerToMap();
    void DataResponseError(HRilErrType errCode, const AppExecFwk::InnerEvent::Pointer &response);

    std::mutex responseErrorLock_;
};
} // namespace Telephony
} // namespace OHOS
#endif // TEL_RIL_DATA_H
