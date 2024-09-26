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

#ifndef ESIM_SERVICE_PROFILE_H
#define ESIM_SERVICE_PROFILE_H

#include "asn1_builder.h"
#include "asn1_decoder.h"
#include "asn1_node.h"
#include "asn1_utils.h"
#include "esim_state_type.h"

#include <stdbool.h>

namespace OHOS {
namespace Telephony {
#define EUICC_MEMORY_RESET_BIT_STR_FILL_LEN (0x05)
#define EUICC_MEMORY_RESET_BIT_STR_VALUE (0xA0)
constexpr int32_t VERSION_BYTES_LEN = 3;
constexpr int32_t BASE64_TO_HEX_RATIO 2;
constexpr int32_t APDU_MSG_STATUS_WAIT_RSP = 1;
constexpr int32_t APDU_MSG_STATUS_RCV_RSP = 2;
constexpr int32_t APDU_MSG_STATUS_DECODE_OK = 0;
constexpr int32_t SVN_RAW_LENGTH_MIN = 3;
constexpr int32_t EUICC_INFO_RAW_LENGTH = 1024;
constexpr int32_t EUICC_INFO_SVN_LENGTH = 255;
constexpr int32_t EUICC_INFO_VERSION_MIN_LENGTH = 3;
constexpr int32_t EUICC_INFO2_RAW_LENGTH = 2048;
constexpr int32_t EUICC_INFO2_VERSION_TYPE_LENGTH = 32;
constexpr int32_t EUICC_INFO2_EXT_CARD_RES_LENGTH = 128;
constexpr int32_t EUICC_INFO2_CAPABILITY_LENGTH = 128;
constexpr int32_t EUICC_INFO2_CIPKID_LIST_LENGTH = 1024;
constexpr int32_t EUICC_INFO2_FORBIDDEN_PROFILE_POLICY_RULES_LEN = 128;
constexpr int32_t EUICC_INFO2_SAS_ACCREDITATION_NUMBER_LEN = 255;
constexpr int32_t VERSION_HIGH = 0;
constexpr int32_t VERSION_MIDDLE = 1;
constexpr int32_t VERSION_LOW = 2;
constexpr int32_t ESIM_PROFILE_STATE_DISABLED = 0;
constexpr int32_t ESIM_PROFILE_STATE_ENABLED = 1;
constexpr int32_t ESIM_PROFILE_STATE_UNSPECIFIED = -1;
constexpr int32_t SERVICE_PROVIDER_NAME_LENGTH = 255;
constexpr int32_t PROFILE_NICK_NAME_LENGTH = 255;
constexpr int32_t PROFILE_ICCID_LENGTH = 255;
constexpr int32_t PROFILE_NAME_LENGTH = 255;
constexpr int32_t TRANSACTION_ID_LENGTH = 255;
constexpr int32_t CANCEL_SESSION_RESP_LEN = 1024;
constexpr int32_t SERVER_SIGNED1_LENGTH = 255;
constexpr int32_t SERVER_SIGNATURE1_LENGTH = 255;
constexpr int32_t EUICC_CI_PK_ID_TO_BE_USED_LENGTH = 255;
constexpr int32_t SERVER_CERTIFICATE_LENGTH = 2048;
constexpr int32_t PROFILE_ICCID_BYTE_LENGTH = 255;
constexpr int32_t PROFILE_ICCID_MASK_LEN = 13;
constexpr int32_t PROFILE_CLASS_TESTING = 0;
constexpr int32_t PROFILE_CLASS_PROVISIONING = 1;
constexpr int32_t PROFILE_CLASS_OPERATIONAL = 2;
constexpr int32_t PROFILE_OPERATOR_ID_MCCMNC_LEN = 10;
constexpr int32_t PROFILE_OPERATOR_ID_GID1_LEN = 10;
constexpr int32_t PROFILE_OPERATOR_ID_GID2_LEN = 10;
constexpr int32_t PROFILE_ICON_LENGTH = 2048;
constexpr int32_t AUTH_SERVER_RESPONSE_LENGTH = 10240;
constexpr int32_t AUTH_SERVER_TAC_LEN = 4;
constexpr int32_t AUTH_SERVER_IMEI_LEN = 8;
constexpr int32_t LAST_BYTE_OF_IMEI = 7;
constexpr int32_t EUICC_PRE_DOWNLOAD_RESP_MAX_LENGTH = 510;
constexpr int32_t SMDP_HASHCC_LENGTH = 64;
constexpr int32_t SMDP_SIGNED2_LENGTH = 2048;
constexpr int32_t SMDP_SIGNATURE2_LENGTH = 2048;
constexpr int32_t SMDP_CERTIFICATE_LENGTH = 2048;
constexpr int32_t BOUND_PROFILE_PACKAGE_MAX_LENGTH = 20480;
constexpr int32_t LOAD_BPP_RESULTS_LENGTH = 10240;
constexpr int32_t TARGET_ADDRESS_MAX_LENGTH = 128;
constexpr int32_t SEQUENCE_NUMBER_BYTES_NUMBER_MAX = 10;
constexpr int32_t NOTIF_ADDRESS_LENGTH = 255;
constexpr int32_t ICCID_NUMBER_MAX = 10;
constexpr int32_t EVENT_INSTALL = 1152;
constexpr int32_t CMD_HEX_MAX_DATA_LENGTH = 255;

typedef struct TagEuiccInfo {
    std::string raw;
    uint32_t rawLen;
    std::string svn;
} EuiccInfo1;

typedef struct TagEuiccInfo2 {
    std::string raw;
    uint32_t rawLen;
    std::string svn;
    std::string profileVersion;
    std::string firmwareVer;
    std::string extCardResource;
    std::string uiccCapability;
    std::string ts102241Version;
    std::string globalPlatformVersion;
    std::string rspCapability;
    std::string euiccCiPKIdListForVerification;
    std::string euiccCiPKIdListForSigning;
    int32_t euiccCategory;
    std::string forbiddenProfilePolicyRules;
    std::string ppVersion;
    std::string sasAccreditationNumber;
} EuiccInfo2;

typedef struct TagEsimProfile {
    std::u16string iccId = u"";
    std::u16string portIndex = u"";
    std::u16string nickname = u"";
    std::u16string hashCc = u"";
    std::u16string smdpSigned2 = u"";
    std::u16string smdpSignature2 = u"";
    std::u16string smdpCertificate = u"";
    int32_t seqNumber = 0;
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
    int32_t errCode;
    std::string transactionId;
    std::string respStr;
    int32_t respLength;
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
    int32_t profileClass;
    int32_t profileState;
    EsimOperatorId operatorId;
    int32_t policyRules;
    std::list<std::shared_ptr<Asn1Node>> accessRules;
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
