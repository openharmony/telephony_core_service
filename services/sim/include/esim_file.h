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
#include "esim_service.h"
#include "esim_state_type.h"
#include "icc_file.h"
#include "request_apdu_build.h"
#include "reset_response.h"
#include "tel_ril_sim_parcel.h"

namespace OHOS {
namespace Telephony {
constexpr static const int32_t WAIT_TIME_LONG_SECOND_FOR_ESIM = 20;
class EsimFile : public IccFile {
public:
    ResultState DeleteProfile(const std::u16string &iccId);
    ResultState SwitchToProfile(int32_t portIndex, const std::u16string &iccId, bool forceDeactivateSim);
    ResultState SetProfileNickname(const std::u16string &iccId, const std::u16string &nickname);

private:
    bool ProcessDeleteProfile(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &responseEvent);
    bool ProcessDeleteProfileDone(const AppExecFwk::InnerEvent::Pointer &event);
    bool ProcessSwitchToProfile(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &responseEvent);
    bool ProcessSwitchToProfileDone(const AppExecFwk::InnerEvent::Pointer &event);
    bool ProcessSetNickname(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &responseEvent);
    bool ProcessSetNicknameDone(const AppExecFwk::InnerEvent::Pointer &event);

protected:
    ResultState delProfile_ = ResultState::RESULT_UNDEFINED_ERROR;
    ResultState switchResult_ = ResultState::RESULT_UNDEFINED_ERROR;
    ResultState setNicknameResult_ = ResultState::RESULT_UNDEFINED_ERROR;

private:
    std::mutex deleteProfileMutex_;
    std::condition_variable deleteProfileCv_;
    bool isDeleteProfileReady_ = false;

    std::mutex switchToProfileMutex_;
    std::condition_variable switchToProfileCv_;
    bool isSwitchToProfileReady_ = false;

    std::mutex setNicknameMutex_;
    std::condition_variable setNicknameCv_;
    bool isSetNicknameReady_ = false;
};
} // namespace Telephony
} // namespace OHOS
#endif // OHOS_ESIM_FILE_H
