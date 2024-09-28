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
    ResponseEsimResult ObtainPrepareDownload(int32_t portIndex, const std::u16string hashCc,
        const std::u16string smdpSigned2, const std::u16string smdpSignature2, const std::u16string smdpCertificate);
    ResponseEsimBppResult ObtainLoadBoundProfilePackage(int32_t portIndex, const std::u16string boundProfilePackage);
    EuiccNotificationList ListNotifications(int32_t portIndex, Event events);

private:
    bool ProcessPrepareDownload(int32_t slotId);
    bool ProcessPrepareDownloadDone(const AppExecFwk::InnerEvent::Pointer &event);
    bool DecodeBoundProfilePackage(const std::string& boundProfilePackageStr, std::shared_ptr<Asn1Node> &bppNode);
    void BuildApduForInitSecureChannel(
        RequestApduBuild& codec, std::shared_ptr<Asn1Node> &bppNode, std::shared_ptr<Asn1Node> &initSecureChannelReq);
    void BuildApduForFirstSequenceOf87(RequestApduBuild& codec, std::shared_ptr<Asn1Node> &firstSequenceOf87);
    void BuildApduForSequenceOf88(RequestApduBuild& codec, std::shared_ptr<Asn1Node> &sequenceOf88);
    void BuildApduForSequenceOf86(RequestApduBuild& codec, std::shared_ptr<Asn1Node> &bppNode,
        std::shared_ptr<Asn1Node> &sequenceOf86);
    bool ProcessLoadBoundProfilePackage(int32_t slotId);
    bool ProcessLoadBoundProfilePackageDone(const AppExecFwk::InnerEvent::Pointer &event);
    std::shared_ptr<Asn1Node> LoadBoundProfilePackageParseProfileInstallResult(std::shared_ptr<Asn1Node> &root);
    bool LoadBoundProfilePackageParseNotificationMetadata(std::shared_ptr<Asn1Node> &notificationMetadata);
    bool RealProcessLoadBoundProfilePackageDone(std::string combineHexStr);
    bool ProcessListNotifications(
        int32_t slotId, Event events, const AppExecFwk::InnerEvent::Pointer &responseEvent);
    bool ProcessListNotificationsDone(const AppExecFwk::InnerEvent::Pointer &event);
    void createNotification(std::shared_ptr<Asn1Node> &node, EuiccNotification& euicc);
    bool ProcessListNotificationsAsn1Response(std::shared_ptr<Asn1Node> root);

protected:
    ResponseEsimResult preDownloadResult_;
    ResponseEsimBppResult loadBPPResult_;
    EuiccNotificationList eUiccNotificationList_;

private:
    std::mutex prepareDownloadMutex_;
    std::condition_variable prepareDownloadCv_;
    bool isPrepareDownloadReady_ = false;

    std::mutex loadBppMutex_;
    std::condition_variable loadBppCv_;
    bool isLoadBppReady_ = false;

    std::mutex listNotificationsMutex_;
    std::condition_variable listNotificationsCv_;
    bool isListNotificationsReady_ = false;
};
} // namespace Telephony
} // namespace OHOS

#endif // OHOS_ESIM_FILE_H