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
    ResultSgp22Other = 400,
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
            400 => ResultCode::ResultSgp22Other,
            _ => panic!("Invalid value for ResultCode"),
        }
    }
}
