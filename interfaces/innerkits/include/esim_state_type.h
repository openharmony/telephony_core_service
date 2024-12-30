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

#ifndef OHOS_ESIM_STATE_TYPE_H
#define OHOS_ESIM_STATE_TYPE_H

#include <map>
#include <parcel.h>
#include <string>
#include <vector>

namespace OHOS {
namespace Telephony {
/**
 * @brief Result code.
 */
enum class ResultCode {
    RESULT_SOLVABLE_ERRORS = -2,
    RESULT_MUST_DISABLE_PROFILE = -1,
    RESULT_OK = 0,
    RESULT_GET_EID_FAILED = 201,
    RESULT_ACTIVATION_CODE_CHANGED = 203,
    RESULT_ACTIVATION_CODE_INVALID = 204,
    RESULT_SMDP_ADDRESS_INVALID = 205,
    RESULT_EUICC_INFO_INVALID = 206,
    RESULT_TLS_HANDSHAKE_FAILED = 207,
    RESULT_CERTIFICATE_IO_ERROR = 208,
    RESULT_CERTIFICATE_RESPONSE_TIMEOUT = 209,
    RESULT_AUTHENTICATION_FAILED = 210,
    RESULT_RESPONSE_HTTP_FAILED = 211,
    RESULT_CONFIRMATION_CODE_INCORRECT = 212,
    RESULT_EXCEEDED_CONFIRMATION_CODE_TRY_LIMIT = 213,
    RESULT_NO_PROFILE_ON_SERVER = 214,
    RESULT_TRANSACTION_ID_INVALID = 215,
    RESULT_SERVER_ADDRESS_INVALID = 216,
    RESULT_GET_BOUND_PROFILE_PACKAGE_FAILED = 217,
    RESULT_USER_CANCEL_DOWNLOAD = 218,
    RESULT_SERVER_UNAVAILABLE = 220,
    RESULT_PROFILE_NON_DELETE = 223,
    RESULT_SMDP_ADDRESS_INCORRECT = 226,
    RESULT_ANALYZE_AUTHENTICATION_SERVER_RESPONSE_FAILED = 228,
    RESULT_ANALYZE_AUTHENTICATION_CLIENT_RESPONSE_FAILED = 229,
    RESULT_ANALYZE_AUTHENTICATION_CLIENT_MATCHING_ID_REFUSED = 231,
    RESULT_PROFILE_TYPE_ERROR_AUTHENTICATION_STOPPED = 233,
    RESULT_CARRIER_SERVER_REFUSED_ERRORS = 249,
    RESULT_CERTIFICATE_INVALID = 251,
    RESULT_OUT_OF_MEMORY = 263,
    RESULT_PPR_FORBIDDEN = 268,
    RESULT_NOTHING_TO_DELETE = 270,
    RESULT_PPR_NOT_MATCH = 276,
    RESULT_CAT_BUSY = 283,
    RESULT_PROFILE_EID_INVALID = 284,
    RESULT_DOWNLOAD_TIMEOUT = 287,
    RESULT_SGP_22_OTHER = 400,
};

/**
 * @brief Inner result code.
 */
enum class ResultInnerCode {
	RESULT_EUICC_CARD_OK = 0,
    RESULT_EUICC_CARD_DEFALUT_ERROR = 10000,
    RESULT_EUICC_CARD_CHANNEL_IN_USE = 10001,
    RESULT_EUICC_CARD_CHANNEL_OPEN_FAILED = 10002,
    RESULT_EUICC_CARD_CHANNEL_OTHER_AID = 10003,
    RESULT_EUICC_CARD_CHANNEL_CLOSE_FAILED = 10004,
    RESULT_EUICC_CARD_CHANNEL_AID_EMPTY = 10005,
}

/**
 * @brief Euicc OTA update status.
 */
enum class OsuStatus {
    EUICC_UPGRADE_IN_PROGRESS = 1,
    EUICC_UPGRADE_FAILED = 2,
    EUICC_UPGRADE_SUCCESSFUL = 3,
    EUICC_UPGRADE_ALREADY_LATEST = 4,
    EUICC_UPGRADE_SERVICE_UNAVAILABLE = 5,
};

/**
 * @brief Reason for canceling a profile download session.
 */
enum class CancelReason {
    CANCEL_REASON_END_USER_REJECTION = 0,
    CANCEL_REASON_POSTPONED = 1,
    CANCEL_REASON_TIMEOUT = 2,
    CANCEL_REASON_PPR_NOT_ALLOWED = 3,
};

/**
 * @brief Options for resetting eUICC memory.
 */
enum class ResetOption {
    DELETE_OPERATIONAL_PROFILES = 1,
    DELETE_FIELD_LOADED_TEST_PROFILES = 1 << 1,
    RESET_DEFAULT_SMDP_ADDRESS = 1 << 2,
};

/**
 * @brief The profile state.
 */
enum class ProfileState {
    PROFILE_STATE_UNSPECIFIED = -1,
    PROFILE_STATE_DISABLED = 0,
    PROFILE_STATE_ENABLED = 1,
};

/**
 * @brief Profile class for the profile.
 */
enum class ProfileClass {
    PROFILE_CLASS_UNSPECIFIED = -1,
    PROFILE_CLASS_TEST = 0,
    PROFILE_CLASS_PROVISIONING = 1,
    PROFILE_CLASS_OPERATIONAL = 2,
};

/**
 * @brief The policy rules of the profile.
 */
enum class PolicyRules {
    POLICY_RULE_DISABLE_NOT_ALLOWED = 1,
    POLICY_RULE_DELETE_NOT_ALLOWED = 1 << 1,
    POLICY_RULE_DISABLE_AND_DELETE = 1 << 2,
};

/**
 * @brief The bit map of resolvable errors.
 */
enum class SolvableErrors {
    SOLVABLE_ERROR_NEED_CONFIRMATION_CODE = 1 << 0,
    SOLVABLE_ERROR_NEED_POLICY_RULE = 1 << 1,
};

/**
 * @brief Describes the UICC access rule according to the GlobalPlatform Secure Element Access Control specification.
 */
struct AccessRule {
    std::u16string certificateHashHexStr_ = u"";
    std::u16string packageName_ = u"";
    int32_t accessType_ = 0;
};

/**
 * @brief Information about the eUICC chip/device.
 */
struct OperatorId {
    std::u16string mcc_ = u"";
    std::u16string mnc_ = u"";
    std::u16string gid1_ = u"";
    std::u16string gid2_ = u"";
};

/**
 * @brief Information about an embedded profile (subscription) on an eUICC.
 */
struct EuiccProfile {
    std::u16string iccId_ = u"";
    std::u16string nickName_ = u"";
    std::u16string serviceProviderName_ = u"";
    std::u16string profileName_ = u"";
    ProfileState state_;
    ProfileClass profileClass_;
    OperatorId carrierId_;
    PolicyRules policyRules_;
    std::vector<AccessRule> accessRules_{};
};

/**
 * @brief Information about the eUICC chip/device.
 */
struct CarrierIdentifier {
    std::u16string mcc_ = u"";
    std::u16string mnc_ = u"";
    std::u16string spn_ = u"";
    std::u16string imsi_ = u"";
    std::u16string gid1_ = u"";
    std::u16string gid2_ = u"";
    int32_t carrierId_ = 0;
    int32_t specificCarrierId_ = 0;
};

/**
 * @brief the rules authorisation table stored on eUICC.
 */
struct EuiccRulesAuthTable {
    std::vector<int32_t> policyRules_;
    std::vector<CarrierIdentifier> carrierIds_{};
    std::vector<int32_t> policyRuleFlags_;
    int32_t position_ = 0;
};

/**
 * @brief ConfigInfo about prepareDownload.
 */
struct DownLoadConfigInfo {
    int32_t portIndex_ = 0;
    std::u16string hashCc_ = u"";
    std::u16string smdpSigned2_ = u"";
    std::u16string smdpSignature2_ = u"";
    std::u16string smdpCertificate_ = u"";
};

/**
 * @brief Config information about Authenticate.
 */
struct AuthenticateConfigInfo {
    int32_t portIndex_ = 0;
    std::u16string matchingId_ = u"";
    std::u16string serverSigned1_ = u"";
    std::u16string serverSignature1_ = u"";
    std::u16string euiccCiPkIdToBeUsed_ = u"";
    std::u16string serverCertificate_ = u"";
};

/**
 * @brief Result of a operation.
 * @brief Result of a bpp operation.
 */
struct ResponseEsimBppResult {
    int32_t resultCode_ = 0;
    std::u16string response_ = u"";
    int32_t seqNumber_ = 0;
    int32_t profileManagementOperation_ = 0;
    std::u16string notificationAddress_ = u"";
    std::u16string iccId_ = u"";
};

/**
 * @brief  A profile installation result or a notification generated for profile operations.
 */
enum class Event {
    EVENT_DONOTHING = 0,
    EVENT_INSTALL = 1,
    EVENT_ENABLE = 1 << 1,
    EVENT_DISABLE = 1 << 2,
    EVENT_DELETE = 1 << 3,
    EVENT_ALL = 15,
};

/**
 * @brief A signed notification which is defined in SGP.22.
 */
struct EuiccNotification {
    int32_t seq_;
    std::u16string targetAddr_ = u"";
    int32_t event_;
    std::u16string data_ = u"";
};

/**
 * @brief List of notifications.
 */
struct EuiccNotificationList {
    std::vector<EuiccNotification> euiccNotification_{};
};

/**
 * @brief The Data which is sent by the service of LPA
 */
struct EsimApduData {
    /** The flag of user actively closes the channel */
    bool closeChannelFlag_ = false;

    /** Do not use the default request header flag */
    bool unusedDefaultReqHeadFlag_ = false;

    /** The data needs to be send */
    std::u16string data_ = u"";

    /** APDU instruction type. For details, see ETSI 102 221 [55]. */
    int32_t instructionType_ = 0;

    /** APDU instruction. For details, see ETSI 102 221 [55]. */
    int32_t instruction_ = 0;

    /**
     * Command parameter 1 of the SIM data request. For details, see 3GPP
     * TS 51.011[28].
     */
    int32_t p1_ = 0;

    /**
     * Command parameter 2 of the SIM data request. For details, see 3GPP
     * TS 51.011[28].
     */
    int32_t p2_ = 0;

    /**
     * Command parameter 3 of the SIM data request. For details, see 3GPP
     * TS 51.011[28]. If p3 is a negative value, a 4-byte APDU is sent to the
     * SIM card.
     */
    int32_t p3_ = 0;
};

/**
 * @brief Euicc Information.
 */
struct EuiccInfo2 {
    std::string raw_ = "";
    uint32_t rawLen_ = 0;
    std::string svn_ = "";
    std::string profileVersion_ = "";
    std::string firmwareVer_ = "";
    std::string extCardResource_ = "";
    std::string uiccCapability_ = "";
    std::string ts102241Version_ = "";
    std::string globalPlatformVersion_ = "";
    std::string rspCapability_ = "";
    std::string euiccCiPKIdListForVerification_ = "";
    std::string euiccCiPKIdListForSigning_ = "";
    int32_t euiccCategory_ = 0;
    std::string forbiddenProfilePolicyRules_ = "";
    std::string ppVersion_ = "";
    std::string sasAccreditationNumber_ = "";
    std::string response_ = "";
    int32_t resultCode_;
};
} // namespace Telephony
} // namespace OHOS
#endif // OHOS_ESIM_STATE_TYPE_H
