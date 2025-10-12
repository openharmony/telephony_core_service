// Copyright (c) 2025 Huawei Device Co., Ltd.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#[ani_rs::ani(path = "@ohos.telephony.esim.eSIM.ResetOption")]
#[repr(i32)]
pub enum ResetOption {
    DeleteOperationalProfiles = 1,
    DeleteFieldLoadedTestProfiles = 1 << 1,
    ResetDefaultSmdpAddress = 1 << 2,
}

impl From<ResetOption> for i32 {
    fn from(value: ResetOption) -> Self {
        match value {
            ResetOption::DeleteOperationalProfiles => 1,
            ResetOption::DeleteFieldLoadedTestProfiles => 1 << 1,
            ResetOption::ResetDefaultSmdpAddress => 1 << 2,
        }
    }
}

#[ani_rs::ani(path = "@ohos.telephony.esim.eSIM.ResultCode")]
#[repr(i32)]
pub enum ResultCode {
    ResultSolvableErrors = -2,
    ResultMustDisableProfile = -1,
    ResultOk = 0,
    ResultGetEidFailed = 201,
    ResultActivationCodeChanged = 203,
    ResultActivationCodeInvalid = 204,
    ResultSmdpAddressInvalid = 205,
    ResultEuiccInfoInvalid = 206,
    ResultTlsHandshakeFailed = 207,
    ResultCertificateIoError = 208,
    ResultCertificateResponseTimeout = 209,
    ResultAuthenticationFailed = 210,
    ResultResponseHttpFailed = 211,
    ResultConfirmationCodeIncorrect = 212,
    ResultExceededConfirmationCodeTryLimit = 213,
    ResultNoProfileOnServer = 214,
    ResultTransactionIdInvalid = 215,
    ResultServerAddressInvalid = 216,
    ResultGetBoundProfilePackageFailed = 217,
    ResultUserCancelDownload = 218,
    ResultServerUnavailable = 220,
    ResultProfileNonDelete = 223,
    ResultSmdpAddressIncorrect = 226,
    ResultAnalyzeAuthenticationServerResponseFailed = 228,
    ResultAnalyzeAuthenticationClientResponseFailed = 229,
    ResultAnalyzeAuthenticationClientMatchingIdRefused = 231,
    ResultProfileTypeErrorAuthenticationStopped = 233,
    ResultCarrierServerRefusedErrors = 249,
    ResultCertificateInvalid = 251,
    ResultOutOfMemory = 263,
    ResultPprForbidden = 268,
    ResultNothingToDelete = 270,
    ResultPprNotMatch = 276,
    ResultCatBusy = 283,
    ResultProfileEidInvalid = 284,
    ResultDownloadTimeout = 287,
    ResultSgp_22Other = 400,
}

impl From<i32> for ResultCode {
    fn from(value: i32) -> ResultCode {
        match value {
            -2 => ResultCode::ResultSolvableErrors,
            -1 => ResultCode::ResultMustDisableProfile,
            0 => ResultCode::ResultOk,
            201 => ResultCode::ResultGetEidFailed,
            203 => ResultCode::ResultActivationCodeChanged,
            204 => ResultCode::ResultActivationCodeInvalid,
            205 => ResultCode::ResultSmdpAddressInvalid,
            206 => ResultCode::ResultEuiccInfoInvalid,
            207 => ResultCode::ResultTlsHandshakeFailed,
            208 => ResultCode::ResultCertificateIoError,
            209 => ResultCode::ResultCertificateResponseTimeout,
            210 => ResultCode::ResultAuthenticationFailed,
            211 => ResultCode::ResultResponseHttpFailed,
            212 => ResultCode::ResultConfirmationCodeIncorrect,
            213 => ResultCode::ResultExceededConfirmationCodeTryLimit,
            214 => ResultCode::ResultNoProfileOnServer,
            215 => ResultCode::ResultTransactionIdInvalid,
            216 => ResultCode::ResultServerAddressInvalid,
            217 => ResultCode::ResultGetBoundProfilePackageFailed,
            218 => ResultCode::ResultUserCancelDownload,
            220 => ResultCode::ResultServerUnavailable,
            223 => ResultCode::ResultProfileNonDelete,
            226 => ResultCode::ResultSmdpAddressIncorrect,
            228 => ResultCode::ResultAnalyzeAuthenticationServerResponseFailed,
            229 => ResultCode::ResultAnalyzeAuthenticationClientResponseFailed,
            231 => ResultCode::ResultAnalyzeAuthenticationClientMatchingIdRefused,
            233 => ResultCode::ResultProfileTypeErrorAuthenticationStopped,
            249 => ResultCode::ResultCarrierServerRefusedErrors,
            251 => ResultCode::ResultCertificateInvalid,
            263 => ResultCode::ResultOutOfMemory,
            268 => ResultCode::ResultPprForbidden,
            270 => ResultCode::ResultNothingToDelete,
            276 => ResultCode::ResultPprNotMatch,
            283 => ResultCode::ResultCatBusy,
            284 => ResultCode::ResultProfileEidInvalid,
            287 => ResultCode::ResultDownloadTimeout,
            400 => ResultCode::ResultSgp_22Other,
            _ => ResultCode::ResultSolvableErrors,
        }
    }
}

#[ani_rs::ani(path = "@ohos.telephony.esim.eSIM.CancelReason")]
#[repr(i32)]
pub enum CancelReason {
    CancelReasonEndUserRejection = 0,
    CancelReasonPostponed = 1,
    CancelReasonTimeout = 2,
    CancelReasonPprNotAllowed = 3,
}

impl From<CancelReason> for i32 {
    fn from(cancel_reason: CancelReason) -> Self {
        cancel_reason as i32
    }
}

#[ani_rs::ani(path = "@ohos.telephony.esim.eSIM.EuiccInfoInner")]
#[derive(Debug, Clone)]
pub struct EuiccInfo {
    os_version: String,
}

impl EuiccInfo {
    pub fn new(os_version: String) -> Self {
        Self {
            os_version,
        }
    }
}

#[ani_rs::ani(path = "@ohos.telephony.esim.eSIM.ProfileState")]
#[repr(i32)]
pub enum ProfileState {
    ProfileStateUnspecified = -1,
    ProfileStateDisabled = 0,
    ProfileStateEnabled = 1,
}

impl From<i32> for ProfileState {
    fn from(value: i32) -> Self {
        match value {
            0 => ProfileState::ProfileStateDisabled,
            1 => ProfileState::ProfileStateEnabled,
            _ => ProfileState::ProfileStateUnspecified,
        }
    }
}

#[ani_rs::ani(path = "@ohos.telephony.esim.eSIM.ProfileClass")]
#[repr(i32)]
pub enum ProfileClass {
    ProfileClassUnspecified = -1,
    ProfileClassTest = 0,
    ProfileClassProvisioning = 1,
    ProfileClassOperational = 2,
}

impl From<i32> for ProfileClass {
    fn from(value: i32) -> Self {
        match value {
            0 => ProfileClass::ProfileClassTest,
            1 => ProfileClass::ProfileClassProvisioning,
            2 => ProfileClass::ProfileClassOperational,
            _ => ProfileClass::ProfileClassUnspecified,
        }
    }
}

#[ani_rs::ani(path = "@ohos.telephony.esim.eSIM.OperatorIdInner")]
#[derive(Debug, Clone)]
pub struct OperatorId {
    pub mcc: String,
    pub mnc: String,
    pub gid1: String,
    pub gid2: String,
}

#[ani_rs::ani(path = "@ohos.telephony.esim.eSIM.PolicyRules")]
#[repr(i32)]
pub enum PolicyRules {
    PolicyRuleDisableNotAllowed = 1,
    PolicyRuleDeleteNotAllowed = 1 << 1,
    PolicyRuleDisableAndDelete = 1 << 2,
}

impl From<i32> for PolicyRules {
    fn from(value: i32) -> Self {
        match value {
            1 => PolicyRules::PolicyRuleDisableNotAllowed,
            2 => PolicyRules::PolicyRuleDeleteNotAllowed,
            4 => PolicyRules::PolicyRuleDisableAndDelete,
            _ => PolicyRules::PolicyRuleDisableNotAllowed,
        }
    }
}

#[ani_rs::ani(path = "@ohos.telephony.esim.eSIM.AccessRuleInner")]
#[derive(Debug, Clone)]
pub struct AccessRule {
    pub certificate_hash_hex_str: String,
    pub package_name: String,
    pub access_type: i32,
}

impl AccessRule {
    pub fn new() -> Self {
        Self {
            certificate_hash_hex_str: "".to_string(),
            package_name: "".to_string(),
            access_type: 0,
        }
    }
}

#[ani_rs::ani(path = "@ohos.telephony.esim.eSIM.EuiccProfileInner")]
pub struct EuiccProfile {
    pub iccid: String,
    pub nick_name: String,
    pub service_provider_name: String,
    pub profile_name: String,
    pub state: ProfileState,
    pub profile_class: ProfileClass,
    pub operator_id: OperatorId,
    pub policy_rules: PolicyRules,
    pub access_rules: Vec<AccessRule>,
}

#[ani_rs::ani(path = "@ohos.telephony.esim.eSIM.GetEuiccProfileInfoListResultInner")]
pub struct GetEuiccProfileInfoListResult {
    pub response_result: ResultCode,
    pub profiles: Vec<EuiccProfile>,
    pub is_removable: bool,
}

#[ani_rs::ani(path = "@ohos.telephony.esim.eSIM.DownloadableProfileInner")]
pub struct DownloadableProfile {
    pub activation_code: String,
    pub confirmation_code: Option<String>,
    pub carrier_name: Option<String>,
    pub access_rules: Option<Vec<AccessRule>>,
}

#[ani_rs::ani(path = "@ohos.telephony.esim.eSIM.DownloadConfigurationInner")]
#[derive(Debug, Clone)]
pub struct DownloadConfiguration {
    pub switch_after_download: bool,
    pub force_disable_profile: bool,
    pub is_ppr_allowed: bool,
}

#[ani_rs::ani(path = "@ohos.telephony.esim.eSIM.SolvableErrors")]
#[repr(i32)]
pub enum SolvableErrors {
    SolvableErrorNeedConfirmationCode = 1,
    SolvableErrorNeedPolicyRule = 2,
}

impl From<SolvableErrors> for i32 {
    fn from(value: SolvableErrors) -> Self {
        value as i32
    }
}

impl From<i32> for SolvableErrors {
    fn from(value: i32) -> Self {
        match value {
            1 => SolvableErrors::SolvableErrorNeedConfirmationCode,
            2 => SolvableErrors::SolvableErrorNeedPolicyRule,
            _ => SolvableErrors::SolvableErrorNeedConfirmationCode,
        }
    }
}

#[ani_rs::ani(path = "@ohos.telephony.esim.eSIM.DownloadProfileResultInner")]
pub struct DownloadProfileResult {
    pub response_result: ResultCode,
    pub solvable_errors: SolvableErrors,
    pub card_id: i32,
}

#[ani_rs::ani(path = "@ohos.telephony.esim.eSIM.GetDownloadableProfilesResultInner")]
pub struct GetDownloadableProfilesResult {
    pub response_result: ResultCode,
    pub downloadable_profiles: Vec<DownloadableProfile>,
}

impl GetDownloadableProfilesResult {
    pub fn new(response_result: i32, profiles: Vec<DownloadableProfile>) -> Self {
        Self {
            response_result: ResultCode::from(response_result),
            downloadable_profiles: profiles,
        }
    }
}


#[ani_rs::ani(path = "@ohos.telephony.esim.eSIM.GetDownloadableProfileMetadataResultInner")]
pub struct GetDownloadableProfileMetadataResult {
    pub downloadable_profile: DownloadableProfile,
    pub ppr_type: i32,
    pub ppr_flag: bool,
    pub iccid: String,
    pub service_provider_name: String,
    pub profile_name: String,
    pub profile_class: ProfileClass,
    pub solvable_errors: SolvableErrors,
    pub response_result: ResultCode,
}

#[ani_rs::ani(path = "@ohos.telephony.esim.eSIM.OsuStatus")]
#[repr(i32)]
pub enum OsuStatus {
    EuiccUpgradeInProgress = 1,
    EuiccUpgradeFailed = 2,
    EuiccUpgradeSuccessful = 3,
    EuiccUpgradeAlreadyLatest = 4,
    EuiccUpgradeServiceUnavailable = 5,
}

impl From<i32> for OsuStatus {
    fn from(value: i32) -> Self {
        match value {
            1 => OsuStatus::EuiccUpgradeInProgress,
            2 => OsuStatus::EuiccUpgradeFailed,
            3 => OsuStatus::EuiccUpgradeSuccessful,
            4 => OsuStatus::EuiccUpgradeAlreadyLatest,
            5 => OsuStatus::EuiccUpgradeServiceUnavailable,
            _ => OsuStatus::EuiccUpgradeFailed,
        }
    }
}