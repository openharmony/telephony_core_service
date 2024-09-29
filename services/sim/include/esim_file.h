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
    ResultState ResetMemory(ResetOption resetOption);
    ResultState SetDefaultSmdpAddress(std::u16string defaultSmdpAddress);
    bool IsEsimSupported();
    ResponseEsimResult SendApduData(std::u16string &aid, std::u16string &apduData);

private:
    bool ProcessResetMemory(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &responseEvent);
    bool ProcessResetMemoryDone(const AppExecFwk::InnerEvent::Pointer &event);
    bool setDefaultSmdpAddress(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &responseEvent);
    bool setDefaultSmdpAddressDone(const AppExecFwk::InnerEvent::Pointer &event);
    bool ProcessSendApduData(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &responseEvent);
    bool ProcessSendApduDataDone(const AppExecFwk::InnerEvent::Pointer &event);
    bool ProcessObtainEUICCSupportDone(const AppExecFwk::InnerEvent::Pointer &event);

    ResultState resetResult_ = ResultState::RESULT_UNDEFINED_ERROR;
    ResultState setDpAddressResult_ = ResultState::RESULT_UNDEFINED_ERROR;
    ResponseEsimResult transApduDataResponse_;
    bool isSupported_ = false;

    std::mutex resetMemoryMutex_;
    std::condition_variable resetMemoryCv_;
    bool isResetMemoryReady_ = false;

    std::mutex setDefaultSmdpAddressMutex_;
    std::condition_variable setDefaultSmdpAddressCv_;
    bool isSetDefaultSmdpAddressReady_ = false;

    std::mutex SendApduDataMutex_;
    std::condition_variable SendApduDataCv_;
    bool isSendApduDataReady_ = false;
};
} // namespace Telephony
} // namespace OHOS

#endif // OHOS_ESIM_FILE_H