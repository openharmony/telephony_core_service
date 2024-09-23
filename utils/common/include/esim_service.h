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

#ifndef ESIM_SERVICE_PROFILE_H
#define ESIM_SERVICE_PROFILE_H

#include <stdbool.h>
#include "esim_state_type.h"
#include "asn1_node.h"
#include "asn1_builder.h"
#include "asn1_decoder.h"
#include "asn1_utils.h"

namespace OHOS {
namespace Telephony {
#define VERSION_BYTES_LEN 3
#define BASE64_TO_HEX_RATIO 2

#define APDU_MSG_STATUS_WAIT_RSP     (1)
#define APDU_MSG_STATUS_RCV_RSP      (2)
#define APDU_MSG_STATUS_DECODE_OK    (0)

#define SVN_RAW_LENGTH_MIN (3)
#define EUICC_INFO_RAW_LENGTH (1024)
#define EUICC_INFO_SVN_LENGTH (255)
#define EUICC_INFO_VERSION_MIN_LENGTH (3)
#define EUICC_INFO2_RAW_LENGTH (2048)
#define EUICC_INFO2_VERSION_TYPE_LENGTH (32)
#define EUICC_INFO2_EXT_CARD_RES_LENGTH (128)
#define EUICC_INFO2_CAPABILITY_LENGTH (128)
#define EUICC_INFO2_CIPKID_LIST_LENGTH (1024)
#define EUICC_INFO2_FORBIDDEN_PROFILE_POLICY_RULES_LEN (128)
#define EUICC_INFO2_SAS_ACCREDITATION_NUMBER_LEN (255)
#define VERSION_HIGH (0)
#define VERSION_MIDDLE (1)
#define VERSION_LOW (2)
#define ESIM_PROFILE_STATE_DISABLED (0)
#define ESIM_PROFILE_STATE_ENABLED (1)
#define ESIM_PROFILE_STATE_UNSPECIFIED (-1)
#define SERVICE_PROVIDER_NAME_LENGTH (255)
#define PROFILE_NICK_NAME_LENGTH (255)
#define PROFILE_ICCID_LENGTH (255)
#define PROFILE_NAME_LENGTH (255)
#define TRANSACTION_ID_LENGTH (255)
#define CANCEL_SESSION_RESP_LEN (1024)
#define SERVER_SIGNED1_LENGTH (255)
#define SERVER_SIGNATURE1_LENGTH (255)
#define EUICC_CI_PK_ID_TO_BE_USED_LENGTH (255)
#define SERVER_CERTIFICATE_LENGTH (2048)
#define EUICC_MEMORY_RESET_BIT_STR_FILL_LEN (0x05)
#define EUICC_MEMORY_RESET_BIT_STR_VALUE (0xA0)
#define PROFILE_ICCID_BYTE_LENGTH (255)
#define PROFILE_ICCID_MASK_LEN (13)
#define PROFILE_CLASS_TESTING (0) // Testing profiles
#define PROFILE_CLASS_PROVISIONING (1) // Provisioning profiles which are pre-loaded on eUICC
#define PROFILE_CLASS_OPERATIONAL (2) // Operational profiles which can be pre-loaded or downloaded
#define PROFILE_OPERATOR_ID_MCCMNC_LEN (10)
#define PROFILE_OPERATOR_ID_GID1_LEN (10)
#define PROFILE_OPERATOR_ID_GID2_LEN (10)
#define PROFILE_ICON_LENGTH (2048)
#define AUTH_SERVER_RESPONSE_LENGTH (10240)
#define AUTH_SERVER_TAC_LEN (4)
#define AUTH_SERVER_IMEI_LEN (8)
#define LAST_BYTE_OF_IMEI (7)
#define EUICC_PRE_DOWNLOAD_RESP_MAX_LENGTH (510)
#define SMDP_HASHCC_LENGTH (64)
#define SMDP_SIGNED2_LENGTH (2048)
#define SMDP_SIGNATURE2_LENGTH (2048)
#define SMDP_CERTIFICATE_LENGTH (2048)
#define BOUND_PROFILE_PACKAGE_MAX_LENGTH (20480)
#define LOAD_BPP_RESULTS_LENGTH (10240)
#define TARGET_ADDRESS_MAX_LENGTH (128)
#define SEQUENCE_NUMBER_BYTES_NUMBER_MAX (10)
#define NOTIF_ADDRESS_LENGTH (255)
#define ICCID_NUMBER_MAX (10)
#define EVENT_INSTALL (1152)
#define CMD_HEX_MAX_DATA_LENGTH (255)

typedef struct TagEuiccInfo {
    std::string raw;
    uint rawLen;
    std::string svn;
} EuiccInfo1;

typedef struct TagEuiccInfo2 {
    std::string raw;
    uint rawLen;
    std::string svn;
    std::string profileVersion;
    std::string firmwareVer; // VersionType,
    std::string extCardResource; // OCTET STRING,
    std::string uiccCapability; // BIT STRING
    std::string ts102241Version;
    std::string globalPlatformVersion;
    std::string rspCapability; // BIT STRING
    std::string euiccCiPKIdListForVerification;
    std::string euiccCiPKIdListForSigning;
    int32_t euiccCategory;
    std::string forbiddenProfilePolicyRules; // BIT STRING
    std::string ppVersion;
    std::string sasAccreditationNumber; // UTF8String
} EuiccInfo2;

typedef struct TagEsimProfile {
    std::u16string iccId = u"";
    std::u16string portIndex = u"";
    std::u16string nickname = u"";
    std::u16string hashCc = u"";
    std::u16string smdpSigned2 = u"";
    std::u16string smdpSignature2 = u"";
    std::u16string smdpCertificate = u"";
    int seqNumber = 0;
    bool activeAfterDown;
    bool forceDeactivateSim = false;
    OHOS::Telephony::ResetOption option = OHOS::Telephony::ResetOption::DELETE_OPERATIONAL_PROFILES;
    std::u16string transactionId = u"";
    OHOS::Telephony::CancelReason cancelReason = OHOS::Telephony::CancelReason::CANCEL_REASON_POSTPONED;
    std::u16string serverSigned1;
    std::u16string serverSignature1;
    std::u16string euiccCiPkIdToBeUsed;
    std::u16string serverCertificate;
    std::u16string matchingId;
    std::u16string imei;
    std::u16string toBeSendApduDataHexStr;
    std::u16string boundProfilePackage;
    OHOS::Telephony::Event events = OHOS::Telephony::Event::EVENT_DONOTHING;
    std::u16string defaultSmdpAddress = u"";
    std::u16string aid = u"";
    std::u16string apduData = u"";
} EsimProfile;

typedef struct TagEs9PlusInitAuthResp {
    std::string serverSigned1;
    std::string serverSignature1;
    std::string euiccCiPKIdToBeUsed;
    std::string serverCertificate;
    std::string matchingId;
    std::string imei;
} Es9PlusInitAuthResp;

typedef struct TagAuthServerResponse {
    int errCode;
    std::string transactionId;
    std::string respStr;
    int respLength;
} AuthServerResponse;

typedef struct TagOperatorId {
    std::string mccMnc;
    std::string gid1;
    std::string gid2;
} EsimOperatorId;

typedef struct TagEuiccProfileInfo {
    std::string iccid;
    std::string nickname;
    std::string serviceProviderName;
    std::string profileName;
    int profileClass; // Profile class for the subscription.
    int profileState; // The profile state of the subscription.
    EsimOperatorId operatorId; // The operator Id of the subscription.
    int policyRules; // The policy rules of the subscription.
    std::list<std::shared_ptr<Asn1Node>> accessRules; // UiccAccessRule
} EuiccProfileInfo;

typedef struct TagPrepareDownloadResp {
    std::string hashCc;
    std::string smdpSigned2;
    std::string smdpSignature2;
    std::string smdpCertificate;
}PrepareDownloadResp;
} // namespace Telephony
} // namespace OHOS
#endif // ESIM_SERVICE_PROFILE_H
