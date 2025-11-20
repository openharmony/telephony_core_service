/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

import { BusinessError } from '@ohos.base'

export default namespace eSIM {
  loadLibrary("esim_ani")

  export native function nativeResetMemory(slotId: int, options?:ResetOption): ResultCode;

  export function resetMemory(slotId: int, options?:ResetOption): Promise<ResultCode> {
    return new Promise<ResultCode>((resolve, reject) => {
      let p = taskpool.execute(nativeResetMemory, slotId, options)
        p.then((e: NullishType) => {
          let r = e as ResultCode
          resolve(r)
        }).catch((e: Error): void => {
          reject(e)
        })
    })
  }

  export native function nativeIsSupported(slotId: int): boolean;

  export function isSupported(slotId: int): boolean {
    return nativeIsSupported(slotId)
  }

  export native function nativeAddProfile(profile: DownloadableProfile): boolean;

  export function addProfile(profile: DownloadableProfile): Promise<boolean> {
    return new Promise<boolean>((resolve, reject) => {
      let p = taskpool.execute(nativeAddProfile, profile)
        p.then((e: NullishType) => {
          let r = e as boolean
          resolve(r)
        }).catch((e: Error): void => {
          reject(e)
        })
    })
  }

  export native function nativeGetEid(slotId: int): string;

  export function getEid(slotId: int): Promise<string> {
    return new Promise<string>((resolve, reject) => {
      let p = taskpool.execute(nativeGetEid, slotId)
        p.then((e: NullishType) => {
          let r = e as string
          resolve(r)
        }).catch((e: Error): void => {
          reject(e)
        })
    })
  }

  export native function nativeGetOsuStatus(slotId: int): OsuStatus;

  export function getOsuStatus(slotId: int): Promise<OsuStatus> {
    return new Promise<OsuStatus>((resolve, reject) => {
      let p = taskpool.execute(nativeGetOsuStatus, slotId)
        p.then((e: NullishType) => {
          let r = e as OsuStatus
          resolve(r)
        }).catch((e: Error): void => {
          reject(e)
        })
    })
  }

  export native function nativeStartOsu(slotId: int): OsuStatus;

  export function startOsu(slotId: int): Promise<OsuStatus> {
    return new Promise<OsuStatus>((resolve, reject) => {
      let p = taskpool.execute(nativeStartOsu, slotId)
        p.then((e: NullishType) => {
          let r = e as OsuStatus
          resolve(r)
        }).catch((e: Error): void => {
          reject(e)
        })
    })
  }

  export native function nativeGetDownloadableProfileMetadata(slotId: int, portIndex: int,
    profile: DownloadableProfile, forceDisableProfile: boolean): GetDownloadableProfileMetadataResult;

  export function getDownloadableProfileMetadata(slotId: int, portIndex: int,
    profile: DownloadableProfile, forceDisableProfile: boolean): Promise<GetDownloadableProfileMetadataResult> {
    return new Promise<GetDownloadableProfileMetadataResult>((resolve, reject) => {
      let p = taskpool.execute(nativeGetDownloadableProfileMetadata, slotId, portIndex, profile, forceDisableProfile)
        p.then((e: NullishType) => {
          let r = e as GetDownloadableProfileMetadataResult
          resolve(r)
        }).catch((e: Error): void => {
          reject(e)
        })
    })
  }

  export native function nativeGetDownloadableProfiles(slotId: int, portIndex: int,
    forceDisableProfile: boolean): GetDownloadableProfilesResult;

  export function getDownloadableProfiles(slotId: int, portIndex: int,
    forceDisableProfile: boolean): Promise<GetDownloadableProfilesResult> {
      return new Promise<GetDownloadableProfilesResult>((resolve, reject) => {
        let p = taskpool.execute(nativeGetDownloadableProfiles, slotId, portIndex, forceDisableProfile)
        p.then((e: NullishType) => {
          let r = e as GetDownloadableProfilesResult
          resolve(r)
        }).catch((e: Error): void => {
          reject(e)
        })
      })
    }

  export native function nativeDownloadProfile(slotId: int, portIndex: int, profile: DownloadableProfile,
    configuration: DownloadConfiguration): DownloadProfileResult;

  export function downloadProfile(slotId: int, portIndex: int, profile: DownloadableProfile,
    configuration: DownloadConfiguration): Promise<DownloadProfileResult> {
    return new Promise<DownloadProfileResult>((resolve, reject) => {
      let p = taskpool.execute(nativeDownloadProfile, slotId, portIndex, profile, configuration)
      p.then((e: NullishType) => {
        let r = e as DownloadProfileResult
        resolve(r)
      }).catch((e: Error): void => {
        reject(e)
      })
    })
  }

  export native function nativeGetEuiccProfileInfoList(slotId: int): GetEuiccProfileInfoListResult;

  export function getEuiccProfileInfoList(slotId: int): Promise<GetEuiccProfileInfoListResult> {
    return new Promise<GetEuiccProfileInfoListResult>((resolve, reject) => {
      let p = taskpool.execute(nativeGetEuiccProfileInfoList, slotId)
        p.then((e: NullishType) => {
          let r = e as GetEuiccProfileInfoListResult
          resolve(r)
        }).catch((e: Error): void => {
          reject(e)
        })
    })        
  }

  export native function nativeGetEuiccInfo(slotId: int): EuiccInfo;

  export function getEuiccInfo(slotId: int): Promise<EuiccInfo> {
    return new Promise<EuiccInfo>((resolve, reject) => {
      let p = taskpool.execute(nativeGetEuiccInfo, slotId)
        p.then((e: NullishType) => {
          let r = e as EuiccInfo
          resolve(r)
        }).catch((e: Error): void => {
          reject(e)
        })
    })
  }

  export native function nativeDeleteProfile(slotId: int, iccid: string): ResultCode;

  export function deleteProfile(slotId: int, iccid: string): Promise<ResultCode> {
    return new Promise<ResultCode>((resolve, reject) => {
      let p = taskpool.execute(nativeDeleteProfile, slotId, iccid)
        p.then((e: NullishType) => {
          let r = e as ResultCode
          resolve(r)
        }).catch((e: Error): void => {
          reject(e)
        })
    })
  }

  export native function nativeSwitchToProfile(slotId: int, portIndex: int, iccid: string,
    forceDisableProfile: boolean): ResultCode;

  export function switchToProfile(slotId: int, portIndex: int, iccid: string,
    forceDisableProfile: boolean): Promise<ResultCode> {
      return new Promise<ResultCode>((resolve, reject) => {
        let p = taskpool.execute(nativeSwitchToProfile, slotId, portIndex, iccid, forceDisableProfile)
        p.then((e: NullishType) => {
          let r = e as ResultCode
          resolve(r)
        }).catch((e: Error): void => {
          reject(e)
        })
      })
    }

  export native function nativeSetProfileNickname(slotId: int, iccid: string, nickname: string): ResultCode;

  export function setProfileNickname(slotId: int, iccid: string, nickname: string): Promise<ResultCode> {
    return new Promise<ResultCode>((resolve, reject) => {
      let p = taskpool.execute(nativeSetProfileNickname, slotId, iccid, nickname)
        p.then((e: NullishType) => {
          let r = e as ResultCode
          resolve(r)
        }).catch((e: Error): void => {
          reject(e)
        })
    })
  }

  export native function nativeReserveProfilesForFactoryRestore(slotId: int): ResultCode;

  export function reserveProfilesForFactoryRestore(slotId: int): Promise<ResultCode> {
    return new Promise<ResultCode>((resolve, reject) => {
      let p = taskpool.execute(nativeReserveProfilesForFactoryRestore, slotId)
        p.then((e: NullishType) => {
          let r = e as ResultCode
          resolve(r)
        }).catch((e: Error): void => {
          reject(e)
        })
    })
  }

  export native function nativeSetDefaultSmdpAddress(slotId: int, address: string): ResultCode;

  export function setDefaultSmdpAddress(slotId: int, address: string): Promise<ResultCode> {
      return new Promise<ResultCode>((resolve, reject) => {
      let p = taskpool.execute(nativeSetDefaultSmdpAddress, slotId, address)
      p.then((e: NullishType) => {
        let r = e as ResultCode
        resolve(r)
      }).catch((e: Error): void => {
        reject(e)
      })
    })   
  }

  export native function nativeGetDefaultSmdpAddress(slotId: int): string;

  export function getDefaultSmdpAddress(slotId: int): Promise<string> {
      return new Promise<string>((resolve, reject) => {
      let p = taskpool.execute(nativeGetDefaultSmdpAddress, slotId)
      p.then((e: NullishType) => {
        let r = e as string
        resolve(r)
      }).catch((e: Error): void => {
        reject(e)
      })
    })  
  }

  export native function nativeCancelSession(slotId: int, transactionId: string, cancelReason: CancelReason): ResultCode;

  export function cancelSession(slotId: int, transactionId: string, cancelReason: CancelReason): Promise<ResultCode> {
      return new Promise<ResultCode>((resolve, reject) => {
      let p = taskpool.execute(nativeCancelSession, slotId, transactionId, cancelReason)
      p.then((e: NullishType) => {
        let r = e as ResultCode
        resolve(r)
      }).catch((e: Error): void => {
        reject(e)
      })
    })  
  }

  export enum ResetOption {
    DELETE_OPERATIONAL_PROFILES = 1,

    DELETE_FIELD_LOADED_TEST_PROFILES = 1 << 1,

    RESET_DEFAULT_SMDP_ADDRESS = 1 << 2,
  }

  export enum ResultCode {
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
  }

  export enum CancelReason {
    CANCEL_REASON_END_USER_REJECTION = 0,
    CANCEL_REASON_POSTPONED = 1,
    CANCEL_REASON_TIMEOUT = 2,
    CANCEL_REASON_PPR_NOT_ALLOWED = 3,
  }

  export interface EuiccInfo {
    osVersion: string;
  }

  export class EuiccInfoInner implements EuiccInfo {
    osVersion: string;
  }

  export enum ProfileState {
    PROFILE_STATE_UNSPECIFIED = -1,
    PROFILE_STATE_DISABLED = 0,
    PROFILE_STATE_ENABLED = 1,
  }

  export enum ProfileClass {
    PROFILE_CLASS_UNSPECIFIED = -1,
    PROFILE_CLASS_TEST = 0,
    PROFILE_CLASS_PROVISIONING = 1,
    PROFILE_CLASS_OPERATIONAL = 2,
  }

  export interface OperatorId {
    mcc: string;
    mnc: string;
    gid1: string;
    gid2: string;
  }

  export class OperatorIdInner implements OperatorId {
    mcc: string;
    mnc: string;
    gid1: string;
    gid2: string;
  }

  export enum PolicyRules {
    POLICY_RULE_DISABLE_NOT_ALLOWED = 1,
    POLICY_RULE_DELETE_NOT_ALLOWED = 1 << 1,
    POLICY_RULE_DISABLE_AND_DELETE = 1 << 2,
  }

  export interface AccessRule {
    certificateHashHexStr: string;
    packageName: string;
    accessType: int;
  }

  export class AccessRuleInner implements AccessRule {
    certificateHashHexStr: string;
    packageName: string;
    accessType: int;
  }

  export interface EuiccProfile {
    iccid: string;
    nickName: string;
    serviceProviderName: string;
    profileName: string;
    state: ProfileState;
    profileClass: ProfileClass;
    operatorId: OperatorId;
    policyRules: PolicyRules;
    accessRules: Array<AccessRule>;
  }

  export class EuiccProfileInner implements EuiccProfile {
    iccid: string;
    nickName: string;
    serviceProviderName: string;
    profileName: string;
    state: ProfileState;
    profileClass: ProfileClass;
    operatorId: OperatorId;
    policyRules: PolicyRules;
    accessRules: Array<AccessRule>;
  }

  export interface GetEuiccProfileInfoListResult {
    responseResult: ResultCode;
    profiles: Array<EuiccProfile>;
    isRemovable: boolean;
  }

  export class GetEuiccProfileInfoListResultInner implements GetEuiccProfileInfoListResult {
    responseResult: ResultCode;
    profiles: Array<EuiccProfile>;
    isRemovable: boolean;
  }

  export interface DownloadableProfile {
    activationCode: string;
    confirmationCode?: string;
    carrierName?: string;
    accessRules?: Array<AccessRule>;
  }

  export class DownloadableProfileInner implements DownloadableProfile {
    activationCode: string;
    confirmationCode?: string;
    carrierName?: string;
    accessRules?: Array<AccessRule>;
  }

  export interface DownloadConfiguration {
    switchAfterDownload: boolean;
    forceDisableProfile: boolean;
    isPprAllowed: boolean;
  }

  export class DownloadConfigurationInner implements DownloadConfiguration {
    switchAfterDownload: boolean;
    forceDisableProfile: boolean;
    isPprAllowed: boolean;
  }

  export enum SolvableErrors {
    SOLVABLE_ERROR_NEED_CONFIRMATION_CODE = 1 << 0,
    SOLVABLE_ERROR_NEED_POLICY_RULE = 1 << 1,
  }  

  export interface DownloadProfileResult {
    responseResult: ResultCode;
    solvableErrors: SolvableErrors;
    cardId: int;
  }

  export class DownloadProfileResultInner implements DownloadProfileResult {
    responseResult: ResultCode;
    solvableErrors: SolvableErrors;
    cardId: int;
  }

  export interface GetDownloadableProfilesResult {
    responseResult: ResultCode;
    downloadableProfiles: Array<DownloadableProfile>;
  }

  export class GetDownloadableProfilesResultInner implements GetDownloadableProfilesResult {
    responseResult: ResultCode;
    downloadableProfiles: Array<DownloadableProfile>;
  }

  export interface GetDownloadableProfileMetadataResult {
    downloadableProfile: DownloadableProfile;
    pprType: int;
    pprFlag: boolean;
    iccid: string;
    serviceProviderName: string;
    profileName: string;
    profileClass: ProfileClass;
    solvableErrors: SolvableErrors;
    responseResult: ResultCode;
  }

  export class GetDownloadableProfileMetadataResultInner implements GetDownloadableProfileMetadataResult {
    downloadableProfile: DownloadableProfile;
    pprType: int;
    pprFlag: boolean;
    iccid: string;
    serviceProviderName: string;
    profileName: string;
    profileClass: ProfileClass;
    solvableErrors: SolvableErrors;
    responseResult: ResultCode;
  }

  export enum OsuStatus {
    EUICC_UPGRADE_IN_PROGRESS = 1,
    EUICC_UPGRADE_FAILED = 2,
    EUICC_UPGRADE_SUCCESSFUL = 3,
    EUICC_UPGRADE_ALREADY_LATEST = 4,
    EUICC_UPGRADE_SERVICE_UNAVAILABLE = 5,
  }

}
