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
 * @brief Result state.
 */
enum class Result {
    RESULT_RESOLVABLE_ERRORS = -2,
    RESULT_MUST_DEACTIVATE_SIM = -1,
    RESULT_OK = 0,
    RESULT_FIRST_USER = 1,
    RESULT_UNDEFINED_ERROR = 2,
};

/**
 * @brief Euicc OTA update status.
 */
enum class OsuStatus {
    EUICC_OSU_IN_PROGRESS = 1,
    EUICC_OSU_FAILED = 2,
    EUICC_OSU_SUCCEEDED = 3,
    EUICC_OSU_NOT_NEEDED = 4,
    EUICC_OSU_STATUS_UNAVAILABLE = 5,
};

/**
 * @brief Reason for canceling a profile download session.
 */
enum class CancelReason {
    CANCEL_REASON_END_USER_REJECTED = 0,
    CANCEL_REASON_POSTPONED = 1,
    CANCEL_REASON_TIMEOUT = 2,
    CANCEL_REASON_PPR_NOT_ALLOWED = 3,
};

/**
 * @brief Options for resetting eUICC memory.
 */
enum class ResetOption {
    RESET_OPTION_DELETE_OPERATIONAL_PROFILES = 1,
    RESET_OPTION_DELETE_FIELD_LOADED_TEST_PROFILES = 1 << 1,
    RESET_OPTION_RESET_DEFAULT_SMDP_ADDRESS = 1 << 2,
};

/**
 * @brief Euicc Information.
 */
struct EuiccInfo {
    std::u16string osVersion = u"";
};

/**
 * @brief Result set for downloading configuration files.
 */
struct DownloadProfileResult {
    int32_t result = 0;
    int32_t resolvableErrors = 0;
    int32_t cardId = 0;
};

/**
 * @brief Describes the UICC access rule according to the GlobalPlatform Secure Element Access Control specification.
 */
struct AccessRule {
    std::u16string certificateHashHexStr = u"";
    std::u16string packageName = u"";
    int32_t accessType = 0;
};

/**
 * @brief Information about a subscription which is downloadable to an eUICC using.
 */
struct DownloadableProfile {
    std::u16string encodedActivationCode = u"";
    std::u16string confirmationCode = u"";
    std::u16string carrierName = u"";
    std::vector<AccessRule> accessRules {};
};

/**
 * @brief List of metadata for downloaded configuration files.
 */
struct GetDownloadableProfileMetadataResult {
    DownloadableProfile downloadableProfiles;
    int32_t pprType = 0;
    bool pprFlag = false;
    int32_t resolvableErrors = 0;
    int32_t result = 0;
};

/**
 *  @brief Series data of downloadable configuration files.
 */
struct GetAvailableDownloadableProfileListResult {
    int32_t result = 0;
    std::vector<DownloadableProfile> downloadableProfiles {};
};

/**
 * @brief Information about the eUICC chip/device.
 */
struct OperatorId {
    std::u16string mcc = u"";
    std::u16string mnc = u"";
    std::u16string gid1 = u"";
    std::u16string gid2 = u"";
};

/**
 * @brief Information about an embedded profile (subscription) on an eUICC.
 */
struct EuiccProfile {
    std::u16string iccId = u"";
    std::u16string nickName = u"";
    std::u16string serviceProviderName = u"";
    std::u16string profileName = u"";
    int32_t state = 0;
    int32_t profileClass = 0;
    OperatorId carrierId;
    int32_t policyRules = 0;
    std::vector<AccessRule> accessRules {};
};

/**
 * @brief Result of a operation.
 */
struct GetEuiccProfileInfoListResult {
    int32_t result = 0;
    std::vector<EuiccProfile> profiles {};
    bool isRemovable = false;
};

/**
 * @brief Information about the eUICC chip/device.
 */
struct CarrierIdentifier {
    std::u16string mcc = u"";
    std::u16string mnc = u"";
    std::u16string spn = u"";
    std::u16string imsi = u"";
    std::u16string gid1 = u"";
    std::u16string gid2 = u"";
    int32_t carrierId = 0;
    int32_t specificCarrierId = 0;
};

/**
 * @brief the rules authorisation table stored on eUICC.
 */
struct EuiccRulesAuthTable {
    std::vector<int32_t> policyRules;
    std::vector<CarrierIdentifier> carrierIds {};
    std::vector<int32_t> policyRuleFlags;
    int32_t position = 0;
};

/**
 * @brief ConfigInfo about prepareDownload.
 */
struct DownLoadConfigInfo {
    int32_t portIndex = 0;
    std::u16string hashCc = u"";
    std::u16string smdpSigned2 = u"";
    std::u16string smdpSignature2 = u"";
    std::u16string smdpCertificate = u"";
};

/**
 * @brief Result of a operation.
 */
struct ResponseEsimResult {
    int32_t resultCode = 0;
    std::u16string response = u"";
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
};

/**
 * @brief A signed notification which is defined in SGP.22.
 */
struct EuiccNotification {
    int32_t seq;
    std::u16string targetAddr;
    int32_t event;
    std::u16string data = u"";
};

/**
 * @brief List of notifications.
 */
struct EuiccNotificationList {
    std::vector<EuiccNotification> euiccNotification {};
};
} // namespace Telephony
} // namespace OHOS
#endif // OHOS_ESIM_STATE_TYPE_H
