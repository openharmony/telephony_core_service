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
class EsimFile : public IccFile {
public:
    ResponseEsimResult ObtainEuiccInfo2(int32_t portIndex);
    ResponseEsimResult AuthenticateServer(
        int32_t portIndex, const std::u16string &matchingId, const std::u16string &serverSigned1,
        const std::u16string &serverSignature1, const std::u16string &euiccCiPkIdToBeUsed,
        const std::u16string serverCertificate);
private:
    bool ProcessObtainEUICCInfo2(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &responseEvent);
    bool ProcessObtainEUICCInfo2Done(const AppExecFwk::InnerEvent::Pointer &event);
    void EuiccInfo2ParseProfileVersion(EuiccInfo2 *euiccInfo2, std::shared_ptr<Asn1Node> &root);
    void EuiccInfo2ParseSvn(EuiccInfo2 *euiccInfo2, std::shared_ptr<Asn1Node> &root, uint32_t byteLen);
    void EuiccInfo2ParseEuiccFirmwareVer(EuiccInfo2 *euiccInfo2, std::shared_ptr<Asn1Node> &root);
    void EuiccInfo2ParseExtCardResource(EuiccInfo2 *euiccInfo2, std::shared_ptr<Asn1Node> &root);
    void EuiccInfo2ParseUiccCapability(EuiccInfo2 *euiccInfo2, std::shared_ptr<Asn1Node> &root);
    void EuiccInfo2ParseTs102241Version(EuiccInfo2 *euiccInfo2, std::shared_ptr<Asn1Node> &root);
    void EuiccInfo2ParseGlobalPlatformVersion(EuiccInfo2 *euiccInfo2, std::shared_ptr<Asn1Node> &root);
    void EuiccInfo2ParseRspCapability(EuiccInfo2 *euiccInfo2, std::shared_ptr<Asn1Node> &root);
    void EuiccInfo2ParseEuiccCiPKIdListForVerification(EuiccInfo2 *euiccInfo2, std::shared_ptr<Asn1Node> &root);
    void EuiccInfo2ParseEuiccCiPKIdListForSigning(EuiccInfo2 *euiccInfo2, std::shared_ptr<Asn1Node> &root);
    void EuiccInfo2ParseEuiccCategory(EuiccInfo2 *euiccInfo2, std::shared_ptr<Asn1Node> &root);
    void EuiccInfo2ParsePpVersion(EuiccInfo2 *euiccInfo2, std::shared_ptr<Asn1Node> &root);
    void CopyApdCmdToReqInfo(ApduSimIORequestInfo *pReqInfo, ApduCommand *apdCmd);
    bool ProcessAuthenticateServer(int32_t slotId);
    bool ProcessAuthenticateServerDone(const AppExecFwk::InnerEvent::Pointer &event);
    bool RealProcsessAuthenticateServerDone(std::string combineHexStr);
    bool ProcessIfNeedMoreResponse(IccFileData &fileData, int eventId);
    bool CombineResponseDataFinish(IccFileData &fileData);
    void Asn1AddChildAsBase64(std::shared_ptr<Asn1Builder> &builder, const std::string &base64Src);
    void AddDeviceCapability(std::shared_ptr<Asn1Builder> &devCapsBuilder);
    void AddCtxParams1(std::shared_ptr<Asn1Builder> &ctxParams1Builder, Es9PlusInitAuthResp *pbytes);
    void GetImeiBytes(std::string &imeiBytes, const std::string &imei);
    void CovertAuthToApiStruct(ResponseEsimResult &dst, AuthServerResponse &src);
    void ConvertAuthInputParaFromApiStru(Es9PlusInitAuthResp &dst, EsimProfile &src);
    bool MergeRecvLongDataComplete(IccFileData &fileData);

    ResponseEsimResult responseInfo2Result_;
    ResponseEsimResult responseAuthenticateResult_;

    std::mutex euiccInfo2Mutex_;
    std::condition_variable euiccInfo2Cv_;
    bool isEuiccInfo2Ready_ = false;

    std::mutex authenticateServerMutex_;
    std::condition_variable authenticateServerCv_;
    bool isAuthenticateServerReady_ = false;
};
} // namespace Telephony
} // namespace OHOS
#endif // OHOS_ESIM_FILE_H