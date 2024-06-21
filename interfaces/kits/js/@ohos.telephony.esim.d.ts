/*
 * Copyright (c) 2024-2024 Huawei Device Co., Ltd.
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

/**
 * @file
 * @kit TelephonyKit
 */

import type { AsyncCallback } from './@ohos.base';

/**
 * This indicates that the eSIM card performs the profile management operation synchronously.
 * Includes methods defined by GSMA Spec (SGP.22) and customized methods.
 *
 * @namespace esim
 * @syscap SystemCapability.Telephony.CoreService
 * @since 13
 */
declare namespace esim {
  /**
   * Whether embedded subscriptions are currently supported.
   *
   * @param { number } slotId - Indicates the card slot index number.
   * @returns { boolean } Returns {@code true} if the eSIM capability is supported; returns {@code false} otherwise.
   * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified.
   * 2. Incorrect parameter types.
   * @throws { BusinessError } 8300001 - Invalid parameter value.
   * @throws { BusinessError } 8300002 - Service connection failed.
   * @throws { BusinessError } 8300003 - System internal error.
   * @throws { BusinessError } 8300999 - Unknown error.
   * @syscap SystemCapability.Telephony.CoreService
   * @since 13
   */
  function isEsimSupported(slotId: number): boolean;

  /**
   * Returns the EID identifying for the eUICC hardware.
   *
   * @permission ohos.permission.GET_TELEPHONY_ESIM_STATE
   * @param { number } slotId - Indicates the card slot index number.
   * @returns { string } Returns the EID identifying the eUICC hardware.
   * @throws { BusinessError } 201 - Permission denied.
   * @throws { BusinessError } 202 - Non-system applications use system APIs.
   * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified.
   * 2. Incorrect parameter types.
   * @throws { BusinessError } 8300001 - Invalid parameter value.
   * @throws { BusinessError } 8300002 - Service connection failed.
   * @throws { BusinessError } 8300003 - System internal error.
   * @throws { BusinessError } 8300999 - Unknown error.
   * @syscap SystemCapability.Telephony.CoreService
   * @systemapi Hide this for inner system use.
   * @since 13
   */
  function getEid(slotId: number): string;

  /**
   * Returns the current status of eUICC OSU.
   * 
   * @permission ohos.permission.GET_TELEPHONY_ESIM_STATE
   * @param { number } slotId - Indicates the card slot index number.
   * @returns { Promise<OsuStatus> } Return the status of eUICC OSU update.
   * @throws { BusinessError } 201 - Permission denied.
   * @throws { BusinessError } 202 - Non-system applications use system APIs.
   * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified.
   * 2. Incorrect parameter types.
   * @throws { BusinessError } 8300001 - Invalid parameter value.
   * @throws { BusinessError } 8300002 - Service connection failed.
   * @throws { BusinessError } 8300003 - System internal error.
   * @throws { BusinessError } 8300999 - Unknown error.
   * @syscap SystemCapability.Telephony.CoreService
   * @systemapi Hide this for inner system use.
   * @since 13
   */
  function getOsuStatus(slotId: number): Promise<OsuStatus>;

  /**
   * Execute OSU if current OSU is not the latest one.
   * 
   * @permission ohos.permission.SET_TELEPHONY_ESIM_STATE
   * @param { number } slotId - Indicates the card slot index number.
   * @returns { Promise<ResultState> } Return the status of OSU update when OSU status changed.
   * @throws { BusinessError } 201 - Permission denied.
   * @throws { BusinessError } 202 - Non-system applications use system APIs.
   * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified.
   * 2. Incorrect parameter types.
   * @throws { BusinessError } 8300001 - Invalid parameter value.
   * @throws { BusinessError } 8300002 - Service connection failed.
   * @throws { BusinessError } 8300003 - System internal error.
   * @throws { BusinessError } 8300999 - Unknown error.
   * @syscap SystemCapability.Telephony.CoreService
   * @systemapi Hide this for inner system use.
   * @since 13
   */
  function startOsu(slotId: number): Promise<ResultState>;

  /**
   * Fills in the metadata for a downloadable profile.
   *
   * @permission ohos.permission.SET_TELEPHONY_ESIM_STATE
   * @param { number } slotId - Indicates the card slot index number.
   * @param { number } portIndex - Index of the port for the slot.
   * @param { DownloadableProfile } profile - The Bound Profile Package data returned by SM-DP+ server.
   * @param { boolean } forceDisableProfile - If true, the active profile must be disabled in order to perform the
   * operation. Otherwise, the resultCode should return {@link RESULT_MUST_DISABLE_PROFILE} to allow
   * the user to agree to this operation first.
   * @returns { Promise<GetDownloadableProfileMetadataResult> } Return the metadata for profile.
   * @throws { BusinessError } 201 - Permission denied.
   * @throws { BusinessError } 202 - Non-system applications use system APIs.
   * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified.
   * 2. Incorrect parameter types.
   * @throws { BusinessError } 8300001 - Invalid parameter value.
   * @throws { BusinessError } 8300002 - Service connection failed.
   * @throws { BusinessError } 8300003 - System internal error.
   * @throws { BusinessError } 8300999 - Unknown error.
   * @syscap SystemCapability.Telephony.CoreService
   * @systemapi Hide this for inner system use.
   * @since 13
   */
  function getDownloadableProfileMetadata(slotId: number, portIndex: number,
    profile: DownloadableProfile, forceDisableProfile: boolean): Promise<GetDownloadableProfileMetadataResult>;

  /**
   * Gets downloadable profile List which are available for download on this device.
   * 
   * @permission ohos.permission.GET_TELEPHONY_ESIM_STATE
   * @param { number } slotId - Indicates the card slot index number.
   * @param { number } portIndex - Index of the port for the slot.
   * @param { boolean } forceDisableProfile - If true, the active profile must be disabled in order to perform the
   * operation. Otherwise, the resultCode should return {@link RESULT_MUST_DISABLE_PROFILE} to allow
   * the user to agree to this operation first.
   * @returns { Promise<GetDownloadableProfilesResult> } Return metadata for downloadableProfile which are
   * available for download on this device.
   * @throws { BusinessError } 201 - Permission denied.
   * @throws { BusinessError } 202 - Non-system applications use system APIs.
   * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified.
   * 2. Incorrect parameter types.
   * @throws { BusinessError } 8300001 - Invalid parameter value.
   * @throws { BusinessError } 8300002 - Service connection failed.
   * @throws { BusinessError } 8300003 - System internal error.
   * @throws { BusinessError } 8300999 - Unknown error.
   * @syscap SystemCapability.Telephony.CoreService
   * @systemapi Hide this for inner system use.
   * @since 13
   */
  function getDownloadableProfiles(slotId: number, portIndex: number,
    forceDisableProfile: boolean): Promise<GetDownloadableProfilesResult>;

  /**
   * Attempt to download the given downloadable Profile.
   *
   * @permission ohos.permission.SET_TELEPHONY_ESIM_STATE
   * @param { number } slotId - Indicates the card slot index number.
   * @param { number } portIndex - Index of the port for the slot.
   * @param { DownloadableProfile } profile - The Bound Profile Package data returned by SM-DP+ server.
   * @param { boolean } switchAfterDownload - Indicates whether to enable profile after successful download.
   * @param { boolean } forceDisableProfile - If true, the active profile must be disabled in order to perform the
   * operation. Otherwise, the resultCode should return {@link RESULT_MUST_DISABLE_PROFILE} to allow
   * the user to agree to this operation first.
   * @returns { Promise<DownloadProfileResult> } Return the given downloadableProfile.
   * @throws { BusinessError } 201 - Permission denied.
   * @throws { BusinessError } 202 - Non-system applications use system APIs.
   * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified.
   * 2. Incorrect parameter types.
   * @throws { BusinessError } 8300001 - Invalid parameter value.
   * @throws { BusinessError } 8300002 - Service connection failed.
   * @throws { BusinessError } 8300003 - System internal error.
   * @throws { BusinessError } 8300999 - Unknown error.
   * @syscap SystemCapability.Telephony.CoreService
   * @systemapi Hide this for inner system use.
   * @since 13
   */
  function downloadProfile(slotId: number, portIndex: number, profile: DownloadableProfile,
      switchAfterDownload: boolean, forceDisableProfile: boolean): Promise<DownloadProfileResult>;

  /**
   * Returns a list of all euiccProfile informations.
   *
   * @permission ohos.permission.GET_TELEPHONY_ESIM_STATE
   * @param { number } slotId - Indicates the card slot index number.
   * @returns { Promise<GetEuiccProfileInfoListResult> } Return a list of eUICC profile information.
   * @throws { BusinessError } 201 - Permission denied.
   * @throws { BusinessError } 202 - Non-system applications use system APIs.
   * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified.
   * 2. Incorrect parameter types.
   * @throws { BusinessError } 8300001 - Invalid parameter value.
   * @throws { BusinessError } 8300002 - Service connection failed.
   * @throws { BusinessError } 8300003 - System internal error.
   * @throws { BusinessError } 8300999 - Unknown error.
   * @syscap SystemCapability.Telephony.CoreService
   * @systemapi Hide this for inner system use.
   * @since 13
   */
  function getEuiccProfileInfoList(slotId: number): Promise<GetEuiccProfileInfoListResult>;

  /**
   * Returns the eUICC Information.
   *
   * @permission ohos.permission.GET_TELEPHONY_ESIM_STATE
   * @param { number } slotId - Indicates the card slot index number.
   * @returns { Promise<EuiccInfo> } Returns the eUICC information to obtain.
   * @throws { BusinessError } 201 - Permission denied.
   * @throws { BusinessError } 202 - Non-system applications use system APIs.
   * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified.
   * 2. Incorrect parameter types.
   * @throws { BusinessError } 8300001 - Invalid parameter value.
   * @throws { BusinessError } 8300002 - Service connection failed.
   * @throws { BusinessError } 8300003 - System internal error.
   * @throws { BusinessError } 8300999 - Unknown error.
   * @syscap SystemCapability.Telephony.CoreService
   * @systemapi Hide this for inner system use.
   * @since 13
   */
  function getEuiccInfo(slotId: number): Promise<EuiccInfo>;

  /**
   * Deletes the given profile from eUICC.
   *
   * @permission ohos.permission.SET_TELEPHONY_ESIM_STATE
   * @param { number } slotId - Indicates the card slot index number.
   * @param { string } iccid - The iccid of the profile.
   * @returns { Promise<ResultState> } Returns the response to deletes the given profile.
   * @throws { BusinessError } 201 - Permission denied.
   * @throws { BusinessError } 202 - Non-system applications use system APIs.
   * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified.
   * 2. Incorrect parameter types.
   * @throws { BusinessError } 8300001 - Invalid parameter value.
   * @throws { BusinessError } 8300002 - Service connection failed.
   * @throws { BusinessError } 8300003 - System internal error.
   * @throws { BusinessError } 8300999 - Unknown error.
   * @syscap SystemCapability.Telephony.CoreService
   * @systemapi Hide this for inner system use.
   * @since 13
   */
  function deleteProfile(slotId: number, iccid: string): Promise<ResultState>;

  /**
   * Switch to (enable) the given profile on the eUICC.
   *
   * @permission ohos.permission.SET_TELEPHONY_ESIM_STATE_OPEN
   * @param { number } slotId - Indicates the card slot index number.
   * @param { number } portIndex - Index of the port for the slot.
   * @param { string } iccid - The iccid of the profile to switch to.
   * @param { boolean } forceDisableProfile - If true, the active profile must be disabled in order to perform the
   * operation. Otherwise, the resultCode should return {@link RESULT_MUST_DISABLE_PROFILE} to allow
   * the user to agree to this operation first.
   * @returns { Promise<ResultState> } Returns the response to switch profile.
   * @throws { BusinessError } 201 - Permission denied.
   * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified.
   * 2. Incorrect parameter types.
   * @throws { BusinessError } 8300001 - Invalid parameter value.
   * @throws { BusinessError } 8300002 - Service connection failed.
   * @throws { BusinessError } 8300003 - System internal error.
   * @throws { BusinessError } 8300999 - Unknown error.
   * @syscap SystemCapability.Telephony.CoreService
   * @since 13
   */
  function switchToProfile(slotId: number, portIndex: number, iccid: string,
    forceDisableProfile: boolean): Promise<ResultState>;

  /**
   * Adds or updates the given profile nickname.
   *
   * @permission ohos.permission.SET_TELEPHONY_ESIM_STATE_OPEN
   * @param { number } slotId - Indicates the card slot index number.
   * @param { string } iccid - The iccid of the profile.
   * @param { string } nickname - The nickname of the profile.
   * @returns { Promise<ResultState> } Returns the result of the set nickname operation.
   * @throws { BusinessError } 201 - Permission denied.
   * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified.
   * 2. Incorrect parameter types.
   * @throws { BusinessError } 8300001 - Invalid parameter value.
   * @throws { BusinessError } 8300002 - Service connection failed.
   * @throws { BusinessError } 8300003 - System internal error.
   * @throws { BusinessError } 8300999 - Unknown error.
   * @syscap SystemCapability.Telephony.CoreService
   * @since 13
   */
  function setProfileNickname(slotId: number, iccid: string, nickname: string): Promise<ResultState>;

  /**
   * Erase all specific profiles and reset the eUICC.
   *
   * @permission ohos.permission.SET_TELEPHONY_ESIM_STATE
   * @param { number } slotId - Indicates the card slot index number.
   * @param { ResetOption } options - Options for resetting eUICC memory.
   * @returns { Promise<ResultState> } Returns the result of the reset operation.
   * @throws { BusinessError } 201 - Permission denied.
   * @throws { BusinessError } 202 - Non-system applications use system APIs.
   * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified.
   * 2. Incorrect parameter types.
   * @throws { BusinessError } 8300001 - Invalid parameter value.
   * @throws { BusinessError } 8300002 - Service connection failed.
   * @throws { BusinessError } 8300003 - System internal error.
   * @throws { BusinessError } 8300999 - Unknown error.
   * @syscap SystemCapability.Telephony.CoreService
   * @systemapi Hide this for inner system use.
   * @since 13
   */
  function resetMemory(slotId: number, options?:ResetOption): Promise<ResultState>;

  /**
   * Ensure that profiles will be retained on the next factory reset.
   *
   * @permission ohos.permission.SET_TELEPHONY_ESIM_STATE
   * @param { number } slotId - Indicates the card slot index number.
   * @returns { Promise<ResultState> } Returns the result code.
   * @throws { BusinessError } 201 - Permission denied.
   * @throws { BusinessError } 202 - Non-system applications use system APIs.
   * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified.
   * 2. Incorrect parameter types.
   * @throws { BusinessError } 8300001 - Invalid parameter value.
   * @throws { BusinessError } 8300002 - Service connection failed.
   * @throws { BusinessError } 8300003 - System internal error.
   * @throws { BusinessError } 8300999 - Unknown error.
   * @syscap SystemCapability.Telephony.CoreService
   * @systemapi Hide this for inner system use.
   * @since 13
   */
  function reserveProfilesForFactoryRestore(slotId: number): Promise<ResultState>;

  /**
   * Set or update the default SM-DP+ address stored in an eUICC.
   *
   * @permission ohos.permission.SET_TELEPHONY_ESIM_STATE
   * @param { number } slotId - Indicates the card slot index number.
   * @param { string } address -  The default SM-DP+ address to set.
   * @returns { Promise<ResultState> } Returns the result code.
   * @throws { BusinessError } 201 - Permission denied.
   * @throws { BusinessError } 202 - Non-system applications use system APIs.
   * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified.
   * 2. Incorrect parameter types.
   * @throws { BusinessError } 8300001 - Invalid parameter value.
   * @throws { BusinessError } 8300002 - Service connection failed.
   * @throws { BusinessError } 8300003 - System internal error.
   * @throws { BusinessError } 8300999 - Unknown error.
   * @syscap SystemCapability.Telephony.CoreService
   * @systemapi Hide this for inner system use.
   * @since 13
   */
  function setDefaultSmdpAddress(slotId: number, address: string): Promise<ResultState>;

  /**
   * Gets the default SM-DP+ address stored in an eUICC.
   *
   * @permission ohos.permission.GET_TELEPHONY_ESIM_STATE
   * @param { number } slotId - Indicates the card slot index number.
   * @returns { Promise<string> } Returns the default SM-DP+ address.
   * @throws { BusinessError } 201 - Permission denied.
   * @throws { BusinessError } 202 - Non-system applications use system APIs.
   * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified.
   * 2. Incorrect parameter types.
   * @throws { BusinessError } 8300001 - Invalid parameter value.
   * @throws { BusinessError } 8300002 - Service connection failed.
   * @throws { BusinessError } 8300003 - System internal error.
   * @throws { BusinessError } 8300999 - Unknown error.
   * @syscap SystemCapability.Telephony.CoreService
   * @systemapi Hide this for inner system use.
   * @since 13
   */
  function getDefaultSmdpAddress(slotId: number): Promise<string>;

  /**
   * Cancel session can be used in the
   * 1.after the response to "ES9+.AuthenticateClient"
   * 2.after the response to "ES9+.GetBoundProfilePackage"
   *
   * @permission ohos.permission.SET_TELEPHONY_ESIM_STATE
   * @param { number } slotId - Indicates the card slot index number.
   * @param { string } transactionId - The transaction ID returned by SM-DP+ server.
   * @param { CancelReason } cancelReason - The cancel reason.
   * @returns { Promise<ResponseEsimResult> } Returns result code and cancel session response string.
   * @throws { BusinessError } 201 - Permission denied.
   * @throws { BusinessError } 202 - Non-system applications use system APIs.
   * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified.
   * 2. Incorrect parameter types.
   * @throws { BusinessError } 8300001 - Invalid parameter value.
   * @throws { BusinessError } 8300002 - Service connection failed.
   * @throws { BusinessError } 8300003 - System internal error.
   * @throws { BusinessError } 8300999 - Unknown error.
   * @syscap SystemCapability.Telephony.CoreService
   * @systemapi Hide this for inner system use.
   * @since 13
   */
  function cancelSession(slotId: number, transactionId: string,
    cancelReason: CancelReason): Promise<ResponseEsimResult>;

  /**
   * Establishes a single UICC access rule pursuant to the GlobalPlatform Secure Element Access Control specification.
   *
   * @interface AccessRule
   * @syscap SystemCapability.Telephony.CoreService
   * @systemapi Hide this for inner system use.
   * @since 13
   */
  export interface AccessRule {
    /**
     * Certificate hash hexadecimal string.
     * 
     * @type { string }
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 13
     */
    certificateHashHexStr: string;

    /**
     * The name of package.
     * 
     * @type { string }
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 13
     */
    packageName: string;

    /**
     * The type of access.
     * 
     * @type { number }
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 13
     */
    accessType: number;
  }

  /**
   * Information about a profile which is downloadable to an eUICC using.
   *
   * @interface DownloadableProfile
   * @syscap SystemCapability.Telephony.CoreService
   * @systemapi Hide this for inner system use.
   * @since 13
   */
  export interface DownloadableProfile {
    /**
     * Activation code. It may be empty.
     *
     * @type { string }
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 13
     */
    activationCode: string;

    /**
     * Confirmation code.
     * 
     * @type { string }
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 13
     */
    confirmationCode: string;

    /**
     * Carrier name.
     * 
     * @type { string }
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 13
     */
    carrierName: string;

    /**
     * Gets the accessRules.
     * 
     * @type { Array<AccessRule> }
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 13
     */
    accessRules: Array<AccessRule>;
  }

  /**
   * Result the metadata for a downloadableProfile.
   *
   * @interface GetDownloadableProfileMetadataResult
   * @syscap SystemCapability.Telephony.CoreService
   * @systemapi Hide this for inner system use.
   * @since 13
   */
  export interface GetDownloadableProfileMetadataResult {
    /**
     * Information about a profile which is downloadable to an eUICC using.
     * 
     * @type { DownloadableProfile }
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 13
     */
    downloadableProfile: DownloadableProfile;

    /**
     * The type of profile policy rule.
     * 
     * @type { number }
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 13
     */
    pprType: number;

    /** 
     * The flag of profile policy rule.
     * 
     * @type { boolean }
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 13
     */
    pprFlag: boolean;

    /**
     * Gets the solvable errors.
     * 
     * @type { SolvableErrors }
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 13
     */
    solvableErrors: SolvableErrors;

    /**
     * Gets the result of the operation.
     * 
     * @type { ResultState }
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 13
     */
    requestResponseResult: ResultState;
  }

  /**
   * Result of a operation.
   *
   * @interface GetDownloadableProfilesResult
   * @syscap SystemCapability.Telephony.CoreService
   * @systemapi Hide this for inner system use.
   * @since 13
   */
  export interface GetDownloadableProfilesResult {
    /**
     * Gets the result of the operation.
     * 
     * @type { ResultState }
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 13
     */
    requestResponseResult: ResultState;

    /**
     * Gets the downloadable Profiles with filled-in metadata.
     * 
     * @type { Array<DownloadableProfile> }
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 13
     */
    downloadableProfiles: Array<DownloadableProfile>;
  }

  /**
   * Result of a operation.
   *
   * @interface DownloadProfileResult
   * @syscap SystemCapability.Telephony.CoreService
   * @systemapi Hide this for inner system use.
   * @since 13
   */
  export interface DownloadProfileResult {
    /**
     * Gets the result of the operation.
     * 
     * @type { ResultState }
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 13
     */
    requestResponseResult: ResultState;

    /**
     * Gets the solvable errors.
     * 
     * @type { SolvableErrors }
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 13
     */
    solvableErrors: SolvableErrors;

    /**
     * Gets the card Id. This value comes from EuiccService and is used when resolving solvable errors.
     * 
     * @type { number }
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 13
     */
    cardId: number;
  }

  /**
   * Result of a operation.
   *
   * @interface GetEuiccProfileInfoListResult
   * @syscap SystemCapability.Telephony.CoreService
   * @systemapi Hide this for inner system use.
   * @since 13
   */
  export interface GetEuiccProfileInfoListResult {
    /**
     * Gets the result of the operation.
     * 
     * @type { ResultState }
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 13
     */
    requestResponseResult: ResultState;

    /**
     * Gets the profile list (only upon success).
     * 
     * @type { Array<EuiccProfile> }
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 13
     */
    profiles: Array<EuiccProfile>;

    /**
     * Gets whether the eUICC can be removed.
     * 
     * @type { boolean }
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 13
     */
    isRemovable: boolean;
  }

  /**
   * Information about the eUICC chip/device.
   *
   * @interface OperatorId
   * @syscap SystemCapability.Telephony.CoreService
   * @systemapi Hide this for inner system use.
   * @since 13
   */
  export interface OperatorId {
    /**
     * Mobile country code.
     * 
     * @type { string }
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 13
     */
    mcc: string;

    /**
     * Mobile network code.
     * 
     * @type { string }
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 13
     */
    mnc: string;

    /**
     * Group id level 1.
     * 
     * @type { string }
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 13
     */
    gid1: string;

    /**
     * Group id level 2.
     * 
     * @type { string }
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 13
     */
    gid2: string;
  }

  /**
   * Information about an embedded profile (subscription) on an eUICC.
   *
   * @interface EuiccProfile
   * @syscap SystemCapability.Telephony.CoreService
   * @systemapi Hide this for inner system use.
   * @since 13
   */
  export interface EuiccProfile {
    /**
     * The iccid of the profile.
     * 
     * @type { string }
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 13
     */
    iccid: string;

    /**
     * An optional nickname for the profile.
     * 
     * @type { string }
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 13
     */
    nickName: string;

    /**
     * The service provider name for the profile.
     * 
     * @type { string }
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 13
     */
    serviceProviderName: string;

    /**
     * The profile name.
     * 
     * @type { string }
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 13
     */
    profileName: string;

    /**
     * The profile state.
     *
     * @type { ProfileState }
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 13
     */
    state: ProfileState;

    /**
     * Profile class for the profile.
     *
     * @type { ProfileClass }
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 13
     */
    profileClass: ProfileClass;

    /**
     * The operator Id of the profile.
     * 
     * @type { OperatorId }
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 13
     */
    operatorId: OperatorId;

    /**
     * The policy rules of the profile.
     *
     * @type { PolicyRules }
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 13
     */
    policyRules: PolicyRules;

    /**
     * Optional access rules that specify which apps can manage this profile. Default platform management when not set.
     * 
     * @type { Array<AccessRule> }
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 13
     */
    accessRules: Array<AccessRule>;
  }

  /**
   * Information related to eUICC chips/devices.
   * 
   * @interface EuiccInfo
   * @syscap SystemCapability.Telephony.CoreService
   * @systemapi Hide this for inner system use.
   * @since 13
   */
  export interface EuiccInfo {
    /**
     * Operating system version.
     * 
     * @type { string }
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 13
     */
    osVersion: string;
  }

  /**
   * Options for resetting eUICC memory.
   *
   * @enum { number }
   * @syscap SystemCapability.Telephony.CoreService
   * @systemapi Hide this for inner system use.
   * @since 13
   */
  export enum ResetOption {
    /**
     * Deletes all operational profiles on reset.
     *
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 13
     */
    DELETE_OPERATIONAL_PROFILES = 1,

    /**
     * Deletes all field-loaded testing profiles on reset.
     *
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 13
     */
    DELETE_FIELD_LOADED_TEST_PROFILES = 1 << 1,

    /**
     * Resets the default SM-DP+ address on reset.
     *
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 13
     */
    RESET_DEFAULT_SMDP_ADDRESS = 1 << 2,
  }

  /**
   * Euicc OS upgrade status.
   *
   * @enum { number }
   * @syscap SystemCapability.Telephony.CoreService
   * @systemapi Hide this for inner system use.
   * @since 13
   */
  export enum OsuStatus {
    /**
     * The OS upgrade is in progress.
     *
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 13
     */
    EUICC_UPGRAD_IN_PROGRESS = 1,

    /**
     * The OS upgrade failed.
     *
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 13
     */
    EUICC_UPGRAD_FAILED = 2,

    /**
     * The OS upgrade successful.
     *
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 13
     */
    EUICC_UPGRAD_SUCCESSFUL = 3,

    /**
     * The OS upgrade not needed since current eUICC OS is latest.
     *
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 13
     */
    EUICC_UPGRAD_ALREADY_LATEST = 4,

    /**
     * The OS upgrade status is unavailable since eUICC service is unavailable.
     *
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 13
     */
    EUICC_UPGRAD_SERVICE_UNAVAILABLE = 5,
  }

  /**
   * Result state.
   *
   * @enum { number }
   * @syscap SystemCapability.Telephony.CoreService
   * @systemapi Hide this for inner system use.
   * @since 13
   */
  export enum ResultState {
    /**
     * Indicates that the user must resolve a solveable error.
     *
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 13
     */
    RESULT_SOLVABLE_ERRORS = -2,

    /**
     * Indicates that the active profile must be disabled to perform the operation.
     *
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 13
     */
    RESULT_MUST_DISABLE_PROFILE = -1,

    /**
     * Operation succeeded.
     *
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 13
     */
    RESULT_OK = 0,

    /**
     * undefinedError.
     *
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 13
     */
    RESULT_UNDEFINED_ERROR = 1,
  }

  /**
   * The reason for canceling a profile download session.
   *
   * @enum { number }
   * @syscap SystemCapability.Telephony.CoreService
   * @systemapi Hide this for inner system use.
   * @since 13
   */
  export enum CancelReason {
    /**
     * The end user has rejected the download.
     *
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 13
     */
    CANCEL_REASON_END_USER_REJECTION = 0,

    /**
     * The download has been postponed and you can try again later.
     *
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 13
     */
    CANCEL_REASON_POSTPONED = 1,

    /**
     * The download has been timed out and you can try again later.
     *
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 13
     */
    CANCEL_REASON_TIMEOUT = 2,

    /**
     * The profile to be downloaded cannot be installed because profile policy rules are not allowed.
     *
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 13
     */
    CANCEL_REASON_PPR_NOT_ALLOWED = 3,
  }

  /**
   * Result of a operation.
   *
   * @interface ResponseEsimResult
   * @syscap SystemCapability.Telephony.CoreService
   * @systemapi Hide this for inner system use.
   * @since 13
   */
  export interface ResponseEsimResult {
    /**
     * Gets the result of the operation.
     * 
     * @type { ResultState }
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 13
     */
    requestResponseResult: ResultState;

    /**
     * Gets the response results.
     * 
     * @type { string }
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 13
     */
    response: string;
  }

  /**
   * The profile state.
   *
   * @enum { number }
   * @syscap SystemCapability.Telephony.CoreService
   * @systemapi Hide this for inner system use.
   * @since 13
   */
  export enum ProfileState {
    /**
     * Profile state not specified.
     *
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 13
     */
    PROFILE_STATE_UNSPECIFIED = -1,

    /**
     * Disabled profiles.
     *
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 13
     */
    PROFILE_STATE_DISABLED = 0,

    /**
     * Enabled profile.
     *
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 13
     */
    PROFILE_STATE_ENABLED = 1,
  }

  /**
   * The Profile class.
   *
   * @enum { number }
   * @syscap SystemCapability.Telephony.CoreService
   * @systemapi Hide this for inner system use.
   * @since 13
   */
  export enum ProfileClass {
    /**
     * Profile class not specified.
     *
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 13
     */
    PROFILE_CLASS_UNSPECIFIED = -1,

    /**
     * Testing profiles.
     *
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 13
     */
    PROFILE_CLASS_TEST = 0,

    /**
     * Provisioning profiles that preloaded on the eUICC.
     *
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 13
     */
    PROFILE_CLASS_PROVISIONING = 1,

    /**
     * Operational profiles that can be preloaded or downloaded.
     *
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 13
     */
    PROFILE_CLASS_OPERATIONAL = 2,
  }

  /**
   * The policy rules of the profile.
   *
   * @enum { number }
   * @syscap SystemCapability.Telephony.CoreService
   * @systemapi Hide this for inner system use.
   * @since 13
   */
  export enum PolicyRules {
    /**
     * Disabling of this Profile is not allowed.
     *
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 13
     */
    POLICY_RULE_DISABLE_NOT_ALLOWED = 1,

    /**
     * Deletion of this Profile is not allowed.
     *
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 13
     */
    POLICY_RULE_DELETE_NOT_ALLOWED = 1 << 1,

    /**
     * This profile should be deleted when disabled.
     *
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 13
     */
    POLICY_RULE_DISABLE_AND_DELETE = 1 << 2,
  }

  /**
   * The solvable errors.
   *
   * @enum { number }
   * @syscap SystemCapability.Telephony.CoreService
   * @systemapi Hide this for inner system use.
   * @since 13
   */
  export enum SolvableErrors {
    /**
     * Indicates that the user needs to input a confirmation code during the download.
     *
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 13
     */
    SOLVABLE_ERROR_NEEED_CONFIRMATION_CODE = 1 << 0,

    /**
     * Indicates that the download process requires user consent to allow profile policy rules.
     *
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 13
     */
    SOLVABLE_ERROR_NEEED_POLICY_RULE = 1 << 1,
  }
}

export default esim;
