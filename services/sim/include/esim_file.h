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
constexpr static const int32_t ATR_LENGTH = 47;
class EsimFile : public IccFile {
public:
    ResultState DisableProfile(int32_t portIndex, std::u16string &iccId);
    std::string ObtainSmdsAddress(int32_t portIndex);
    EuiccRulesAuthTable ObtainRulesAuthTable(int32_t portIndex);
    ResponseEsimResult ObtainEuiccChallenge(int32_t portIndex);
    bool ProcessObtainEUICCChallenge(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &responseEvent);
    bool ProcessObtainEUICCChallengeDone(const AppExecFwk::InnerEvent::Pointer &event);
    bool ProcessDisableProfile(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &responseEvent);
    bool ProcessDisableProfileDone(const AppExecFwk::InnerEvent::Pointer &event);
    bool ProcessObtainSmdsAddress(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &responseEvent);
    bool ProcessObtainSmdsAddressDone(const AppExecFwk::InnerEvent::Pointer &event);
    bool ProcessRequestRulesAuthTable(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &responseEvent);
    bool ProcessRequestRulesAuthTableDone(const AppExecFwk::InnerEvent::Pointer &event);
    bool RequestRulesAuthTableParseTagCtxComp0(std::shared_ptr<Asn1Node> &root);

private:
    std::string smdsAddress_ = "";
    EuiccRulesAuthTable eUiccRulesAuthTable_;
    ResultState disableProfileResult_ = ResultState::RESULT_UNDEFINED_ERROR;
    ResponseEsimResult responseChallengeResult_;

    std::mutex disableProfileMutex_;
    std::condition_variable disableProfileCv_;
    bool isDisableProfileReady_ = false;

    std::mutex smdsAddressMutex_;
    std::condition_variable smdsAddressCv_;
    bool isSmdsAddressReady_ = false;

    std::mutex rulesAuthTableMutex_;
    std::condition_variable rulesAuthTableCv_;
    bool isRulesAuthTableReady_ = false;

    std::mutex euiccChallengeMutex_;
    std::condition_variable euiccChallengeCv_;
    bool isEuiccChallengeReady_ = false;
};
} // namespace Telephony
} // namespace OHOS

#endif // OHOS_ESIM_FILE_H