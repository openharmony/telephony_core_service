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
constexpr static const int32_t ATR_LEN = 47;
class EsimFile : public IccFile {
public:
    void ProcessEvent(const AppExecFwk::InnerEvent::Pointer &event);
    EuiccNotificationList RetrieveNotificationList(int32_t portIndex, Event events);
    EuiccNotification ObtainRetrieveNotification(int32_t portIndex, int32_t seqNumber);
    ResultState RemoveNotificationFromList(int32_t portIndex, int32_t seqNumber);

private:
    void createNotification(std::shared_ptr<Asn1Node> &node, EuiccNotification& euicc);
    bool ProcessRetrieveNotificationList(
        int32_t slotId, Event events, const AppExecFwk::InnerEvent::Pointer &responseEvent);
    bool ProcessRetrieveNotificationListDone(const AppExecFwk::InnerEvent::Pointer &event);
    bool RetrieveNotificationParseCompTag(std::shared_ptr<Asn1Node> &root);
    bool ProcessRetrieveNotification(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &responseEvent);
    bool ProcessRetrieveNotificationDone(const AppExecFwk::InnerEvent::Pointer &event);
    bool RetrieveNotificatioParseTagCtxComp0(std::shared_ptr<Asn1Node> &root);
    bool ProcessRemoveNotification(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &responseEvent);
    bool ProcessRemoveNotificationDone(const AppExecFwk::InnerEvent::Pointer &event);

    ResultState removeNotifResult_ = ResultState::RESULT_UNDEFINED_ERROR;
    EuiccNotificationList eUiccNotificationList_;
    EuiccNotificationList retrieveNotificationList_;

    std::mutex retrieveNotificationListMutex_;
    std::condition_variable retrieveNotificationListCv_;
    bool isRetrieveNotificationListReady_ = false;

    std::mutex retrieveNotificationMutex_;
    std::condition_variable retrieveNotificationCv_;
    bool isRetrieveNotificationReady_ = false;

    std::mutex removeNotificationMutex_;
    std::condition_variable removeNotificationCv_;
    bool isRemoveNotificationReady_ = false;
};
} // namespace Telephony
} // namespace OHOS

#endif // OHOS_ESIM_FILE_H