/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#ifndef OHOS_ESIM_FILE_H
#define OHOS_ESIM_FILE_H

#include "apdu_command.h"
#include "asn1_builder.h"
#include "asn1_decoder.h"
#include "asn1_node.h"
#include "asn1_utils.h"
#include "esim_state_type.h"
#include "esim_service.h"
#include "icc_file.h"
#include "request_apdu_build.h"
#include "reset_response.h"
#include "tel_ril_sim_parcel.h"

namespace OHOS {
namespace Telephony {
class EsimFile : public IccFile {
public:
    std::string ObtainDefaultSmdpAddress();
    ResponseEsimResult CancelSession(const std::u16string &transactionId, CancelReason cancelReason);
    EuiccProfile ObtainProfile(int32_t portIndex, const std::u16string &iccId);

private:
    bool ProcessObtainDefaultSmdpAddress(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &responseEvent);
    bool ProcessObtainDefaultSmdpAddressDone(const AppExecFwk::InnerEvent::Pointer &event);
    bool ProcessCancelSession(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &responseEvent);
    bool ProcessCancelSessionDone(const AppExecFwk::InnerEvent::Pointer &event);
    bool ProcessGetProfile(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &responseEvent);
    bool ProcessGetProfileDone(const AppExecFwk::InnerEvent::Pointer &event);

    EsimProfile esimProfile_;
    std::string defaultDpAddress_ = "";
    EuiccProfile euiccProfile_;
    ResponseEsimResult cancelSessionResult_;

    std::mutex obtainDefaultSmdpAddressMutex_;
    std::condition_variable obtainDefaultSmdpAddressCv_;
    bool isObtainDefaultSmdpAddressReady_ = false;

    std::mutex cancelSessionMutex_;
    std::condition_variable cancelSessionCv_;
    bool isCancelSessionReady_ = false;

    std::mutex obtainProfileMutex_;
    std::condition_variable obtainProfileCv_;
    bool isObtainProfileReady_ = false;
};
} // namespace Telephony
} // namespace OHOS

#endif // OHOS_ESIM_FILE_H
