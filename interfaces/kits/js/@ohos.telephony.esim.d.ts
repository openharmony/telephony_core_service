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
 * @namespace eSIM
 * @syscap SystemCapability.Telephony.CoreService.Esim
 * @since 14
 */
declare namespace eSIM {
  /**
   * Whether embedded subscriptions are currently supported.
   *
   * @param { number } slotId - Indicates the card slot index number.
   * @returns { boolean } Returns {@code true} if the eSIM capability is supported; returns {@code false} otherwise.
   * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified.
   * 2. Incorrect parameter types. 3. Invalid parameter value.
   * @throws { BusinessError } 3120001 - Service connection failed.
   * @throws { BusinessError } 3120002 - System internal error.
   * @syscap SystemCapability.Telephony.CoreService.Esim
   * @since 14
   */
  function isSupported(slotId: number): boolean;

  /**
   * Starts a page through an ability, on which users can touch the button to download a profile.
   *
   * @param { DownloadableProfile } profile - Bound profile package data returned by the SM-DP+ server.
   * @returns { Promise<boolean> } Returns {@code true} if the profile is added successfully;
   * returns {@code false} otherwise.
   * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified.
   * 2. Incorrect parameter types. 3. Invalid parameter value.
   * @throws { BusinessError } 801 - Capability not supported.
   * @throws { BusinessError } 3120001 - Service connection failed.
   * @throws { BusinessError } 3120002 - System internal error.
   * @syscap SystemCapability.Telephony.CoreService.Esim
   * @since 14
   */
  function addProfile(profile: DownloadableProfile): Promise<boolean>;

  /**
   * Returns the EID identifying for the eUICC hardware.
   *
   * @permission ohos.permission.GET_TELEPHONY_ESIM_STATE
   * @param { number } slotId - Indicates the card slot index number.
   * @returns { string } Returns the EID. When eUICC is not ready, the return value may be null.
   * @throws { BusinessError } 201 - Permission denied.
   * @throws { BusinessError } 202 - Non-system applications use system APIs.
   * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified.
   * 2. Incorrect parameter types. 3. Invalid parameter value.
   * @throws { BusinessError } 801 - Capability not supported.
   * @throws { BusinessError } 3120001 - Service connection failed.
   * @throws { BusinessError } 3120002 - System internal error.
   * @syscap SystemCapability.Telephony.CoreService.Esim
   * @systemapi Hide this for inner system use.
   * @since 14
   */
  function getEid(slotId: number): string;

  /**
   * Returns the current status of eUICC OS upgrade.
   * 
   * @permission ohos.permission.GET_TELEPHONY_ESIM_STATE
   * @param { number } slotId - Indicates the card slot index number.
   * @returns { Promise<OsuStatus> } Return the status of eUICC OS upgrade.
   * @throws { BusinessError } 201 - Permission denied.
   * @throws { BusinessError } 202 - Non-system applications use system APIs.
   * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified.
   * 2. Incorrect parameter types. 3. Invalid parameter value.
   * @throws { BusinessError } 801 - Capability not supported.
   * @throws { BusinessError } 3120001 - Service connection failed.
   * @throws { BusinessError } 3120002 - System internal error.
   * @syscap SystemCapability.Telephony.CoreService.Esim
   * @systemapi Hide this for inner system use.
   * @since 14
   */
  function getOsuStatus(slotId: number): Promise<OsuStatus>;

  /**
   * Execute OS upgrade if current OS upgrade is not the latest one.
   * 
   * @permission ohos.permission.SET_TELEPHONY_ESIM_STATE
   * @param { number } slotId - Indicates the card slot index number.
   * @returns { Promise<OsuStatus> } Return the status of OS upgrade when OS upgrade status changed.
   * @throws { BusinessError } 201 - Permission denied.
   * @throws { BusinessError } 202 - Non-system applications use system APIs.
   * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified.
   * 2. Incorrect parameter types. 3. Invalid parameter value.
   * @throws { BusinessError } 801 - Capability not supported.
   * @throws { BusinessError } 3120001 - Service connection failed.
   * @throws { BusinessError } 3120002 - System internal error.
   * @syscap SystemCapability.Telephony.CoreService.Esim
   * @systemapi Hide this for inner system use.
   * @since 14
   */
  function startOsu(slotId: number): Promise<OsuStatus>;

  /**
   * Fills in and gets the metadata for a downloadable profile.
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
   * 2. Incorrect parameter types. 3. Invalid parameter value.
   * @throws { BusinessError } 801 - Capability not supported.
   * @throws { BusinessError } 3120001 - Service connection failed.
   * @throws { BusinessError } 3120002 - System internal error.
   * @syscap SystemCapability.Telephony.CoreService.Esim
   * @systemapi Hide this for inner system use.
   * @since 14
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
   * 2. Incorrect parameter types. 3. Invalid parameter value.
   * @throws { BusinessError } 801 - Capability not supported.
   * @throws { BusinessError } 3120001 - Service connection failed.
   * @throws { BusinessError } 3120002 - System internal error.
   * @syscap SystemCapability.Telephony.CoreService.Esim
   * @systemapi Hide this for inner system use.
   * @since 14
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
   * @param { DownloadConfiguration } configuration - Configuration information during downloading.
   * @returns { Promise<DownloadProfileResult> } Return the given downloadableProfile.
   * @throws { BusinessError } 201 - Permission denied.
   * @throws { BusinessError } 202 - Non-system applications use system APIs.
   * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified.
   * 2. Incorrect parameter types. 3. Invalid parameter value.
   * @throws { BusinessError } 801 - Capability not supported.
   * @throws { BusinessError } 3120001 - Service connection failed.
   * @throws { BusinessError } 3120002 - System internal error.
   * @syscap SystemCapability.Telephony.CoreService.Esim
   * @systemapi Hide this for inner system use.
   * @since 14
   */
  function downloadProfile(slotId: number, portIndex: number, profile: DownloadableProfile,
    configuration: DownloadConfiguration): Promise<DownloadProfileResult>;

  /**
   * Returns a list of all eUICC profile information.
   *
   * @permission ohos.permission.GET_TELEPHONY_ESIM_STATE
   * @param { number } slotId - Indicates the card slot index number.
   * @returns { Promise<GetEuiccProfileInfoListResult> } Return a list of eUICC profile information.
   * @throws { BusinessError } 201 - Permission denied.
   * @throws { BusinessError } 202 - Non-system applications use system APIs.
   * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified.
   * 2. Incorrect parameter types. 3. Invalid parameter value.
   * @throws { BusinessError } 801 - Capability not supported.
   * @throws { BusinessError } 3120001 - Service connection failed.
   * @throws { BusinessError } 3120002 - System internal error.
   * @syscap SystemCapability.Telephony.CoreService.Esim
   * @systemapi Hide this for inner system use.
   * @since 14
   */
  function getEuiccProfileInfoList(slotId: number): Promise<GetEuiccProfileInfoListResult>;

  /**
   * Returns the eUICC Information.
   *
   * @permission ohos.permission.GET_TELEPHONY_ESIM_STATE
   * @param { number } slotId - Indicates the card slot index number.
   * @returns { Promise<EuiccInfo> } Returns the eUICC information to obtain. When eUICC is not ready,
   * the return value may be null.
   * @throws { BusinessError } 201 - Permission denied.
   * @throws { BusinessError } 202 - Non-system applications use system APIs.
   * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified.
   * 2. Incorrect parameter types. 3. Invalid parameter value.
   * @throws { BusinessError } 801 - Capability not supported.
   * @throws { BusinessError } 3120001 - Service connection failed.
   * @throws { BusinessError } 3120002 - System internal error.
   * @syscap SystemCapability.Telephony.CoreService.Esim
   * @systemapi Hide this for inner system use.
   * @since 14
   */
  function getEuiccInfo(slotId: number): Promise<EuiccInfo>;

  /**
   * Deletes the given profile from eUICC.
   *
   * @permission ohos.permission.SET_TELEPHONY_ESIM_STATE
   * @param { number } slotId - Indicates the card slot index number.
   * @param { string } iccid - The iccid of the profile.
   * @returns { Promise<ResultCode> } Returns the response to deletes the given profile.
   * @throws { BusinessError } 201 - Permission denied.
   * @throws { BusinessError } 202 - Non-system applications use system APIs.
   * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified.
   * 2. Incorrect parameter types. 3. Invalid parameter value.
   * @throws { BusinessError } 801 - Capability not supported.
   * @throws { BusinessError } 3120001 - Service connection failed.
   * @throws { BusinessError } 3120002 - System internal error.
   * @syscap SystemCapability.Telephony.CoreService.Esim
   * @systemapi Hide this for inner system use.
   * @since 14
   */
  function deleteProfile(slotId: number, iccid: string): Promise<ResultCode>;

  /**
   * Switch to (enable) the given profile on the eUICC.
   *
   * @permission ohos.permission.SET_TELEPHONY_ESIM_STATE
   * @param { number } slotId - Indicates the card slot index number.
   * @param { number } portIndex - Index of the port for the slot.
   * @param { string } iccid - The iccid of the profile to switch to.
   * @param { boolean } forceDisableProfile - If true, the active profile must be disabled in order to perform the
   * operation. Otherwise, the resultCode should return {@link RESULT_MUST_DISABLE_PROFILE} to allow
   * the user to agree to this operation first.
   * @returns { Promise<ResultCode> } Returns the response to switch profile.
   * @throws { BusinessError } 201 - Permission denied.
   * @throws { BusinessError } 202 - Non-system applications use system APIs.
   * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified.
   * 2. Incorrect parameter types. 3. Invalid parameter value.
   * @throws { BusinessError } 801 - Capability not supported.
   * @throws { BusinessError } 3120001 - Service connection failed.
   * @throws { BusinessError } 3120002 - System internal error.
   * @syscap SystemCapability.Telephony.CoreService.Esim
   * @systemapi Hide this for inner system use.
   * @since 14
   */
  function switchToProfile(slotId: number, portIndex: number, iccid: string,
    forceDisableProfile: boolean): Promise<ResultCode>;

  /**
   * Adds or updates the given profile nickname.
   *
   * @permission ohos.permission.SET_TELEPHONY_ESIM_STATE
   * @param { number } slotId - Indicates the card slot index number.
   * @param { string } iccid - The iccid of the profile.
   * @param { string } nickname - The nickname of the profile.
   * @returns { Promise<ResultCode> } Returns the result of the set nickname operation.
   * @throws { BusinessError } 201 - Permission denied.
   * @throws { BusinessError } 202 - Non-system applications use system APIs.
   * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified.
   * 2. Incorrect parameter types. 3. Invalid parameter value.
   * @throws { BusinessError } 801 - Capability not supported.
   * @throws { BusinessError } 3120001 - Service connection failed.
   * @throws { BusinessError } 3120002 - System internal error.
   * @syscap SystemCapability.Telephony.CoreService.Esim
   * @systemapi Hide this for inner system use.
   * @since 14
   */
  function setProfileNickname(slotId: number, iccid: string, nickname: string): Promise<ResultCode>;

  /**
   * Erase all specific profiles and reset the eUICC.
   *
   * @permission ohos.permission.SET_TELEPHONY_ESIM_STATE
   * @param { number } slotId - Indicates the card slot index number.
   * @param { ResetOption } options - Options for resetting eUICC memory.
   * @returns { Promise<ResultCode> } Returns the result of the reset operation.
   * @throws { BusinessError } 201 - Permission denied.
   * @throws { BusinessError } 202 - Non-system applications use system APIs.
   * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified.
   * 2. Incorrect parameter types. 3. Invalid parameter value.
   * @throws { BusinessError } 801 - Capability not supported.
   * @throws { BusinessError } 3120001 - Service connection failed.
   * @throws { BusinessError } 3120002 - System internal error.
   * @syscap SystemCapability.Telephony.CoreService.Esim
   * @systemapi Hide this for inner system use.
   * @since 14
   */
  function resetMemory(slotId: number, options?:ResetOption): Promise<ResultCode>;

  /**
   * Ensure that profiles will be retained on the next factory reset.
   *
   * @permission ohos.permission.SET_TELEPHONY_ESIM_STATE
   * @param { number } slotId - Indicates the card slot index number.
   * @returns { Promise<ResultCode> } Returns the result code.
   * @throws { BusinessError } 201 - Permission denied.
   * @throws { BusinessError } 202 - Non-system applications use system APIs.
   * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified.
   * 2. Incorrect parameter types. 3. Invalid parameter value.
   * @throws { BusinessError } 801 - Capability not supported.
   * @throws { BusinessError } 3120001 - Service connection failed.
   * @throws { BusinessError } 3120002 - System internal error.
   * @syscap SystemCapability.Telephony.CoreService.Esim
   * @systemapi Hide this for inner system use.
   * @since 14
   */
  function reserveProfilesForFactoryRestore(slotId: number): Promise<ResultCode>;

  /**
   * Set or update the default SM-DP+ address stored in an eUICC.
   *
   * @permission ohos.permission.SET_TELEPHONY_ESIM_STATE
   * @param { number } slotId - Indicates the card slot index number.
   * @param { string } address -  The default SM-DP+ address to set.
   * @returns { Promise<ResultCode> } Returns the result code.
   * @throws { BusinessError } 201 - Permission denied.
   * @throws { BusinessError } 202 - Non-system applications use system APIs.
   * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified.
   * 2. Incorrect parameter types. 3. Invalid parameter value.
   * @throws { BusinessError } 801 - Capability not supported.
   * @throws { BusinessError } 3120001 - Service connection failed.
   * @throws { BusinessError } 3120002 - System internal error.
   * @syscap SystemCapability.Telephony.CoreService.Esim
   * @systemapi Hide this for inner system use.
   * @since 14
   */
  function setDefaultSmdpAddress(slotId: number, address: string): Promise<ResultCode>;

  /**
   * Gets the default SM-DP+ address stored in an eUICC.
   *
   * @permission ohos.permission.GET_TELEPHONY_ESIM_STATE
   * @param { number } slotId - Indicates the card slot index number.
   * @returns { Promise<string> } Returns the default SM-DP+ address.
   * @throws { BusinessError } 201 - Permission denied.
   * @throws { BusinessError } 202 - Non-system applications use system APIs.
   * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified.
   * 2. Incorrect parameter types. 3. Invalid parameter value.
   * @throws { BusinessError } 801 - Capability not supported.
   * @throws { BusinessError } 3120001 - Service connection failed.
   * @throws { BusinessError } 3120002 - System internal error.
   * @syscap SystemCapability.Telephony.CoreService.Esim
   * @systemapi Hide this for inner system use.
   * @since 14
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
   * @returns { Promise<ResultCode> } Returns the result code.
   * @throws { BusinessError } 201 - Permission denied.
   * @throws { BusinessError } 202 - Non-system applications use system APIs.
   * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified.
   * 2. Incorrect parameter types. 3. Invalid parameter value.
   * @throws { BusinessError } 801 - Capability not supported.
   * @throws { BusinessError } 3120001 - Service connection failed.
   * @throws { BusinessError } 3120002 - System internal error.
   * @syscap SystemCapability.Telephony.CoreService.Esim
   * @systemapi Hide this for inner system use.
   * @since 14
   */
  function cancelSession(slotId: number, transactionId: string, cancelReason: CancelReason): Promise<ResultCode>;

  /**
   * Establishes a single UICC access rule pursuant to the GlobalPlatform Secure Element Access Control specification.
   *
   * @interface AccessRule
   * @syscap SystemCapability.Telephony.CoreService.Esim
   * @systemapi Hide this for inner system use.
   * @since 14
   */
  export interface AccessRule {
    /**
     * Certificate hash hexadecimal string.
     * 
     * @type { string }
     * @syscap SystemCapability.Telephony.CoreService.Esim
     * @systemapi Hide this for inner system use.
     * @since 14
     */
    certificateHashHexStr: string;

    /**
     * The name of package.
     * 
     * @type { string }
     * @syscap SystemCapability.Telephony.CoreService.Esim
     * @systemapi Hide this for inner system use.
     * @since 14
     */
    packageName: string;

    /**
     * The type of access.
     * 
     * @type { number }
     * @syscap SystemCapability.Telephony.CoreService.Esim
     * @systemapi Hide this for inner system use.
     * @since 14
     */
    accessType: number;
  }

  /**
   * Information about a profile which is downloadable to an eUICC using.
   *
   * @interface DownloadableProfile
   * @syscap SystemCapability.Telephony.CoreService.Esim
   * @systemapi Hide this for inner system use.
   * @since 14
   */
  export interface DownloadableProfile {
    /**
     * Activation code.
     *
     * @type { string }
     * @syscap SystemCapability.Telephony.CoreService.Esim
     * @systemapi Hide this for inner system use.
     * @since 14
     */
    activationCode: string;

    /**
     * Confirmation code.
     * 
     * @type { ?string }
     * @syscap SystemCapability.Telephony.CoreService.Esim
     * @systemapi Hide this for inner system use.
     * @since 14
     */
    confirmationCode?: string;

    /**
     * Carrier name.
     * 
     * @type { ?string }
     * @syscap SystemCapability.Telephony.CoreService.Esim
     * @systemapi Hide this for inner system use.
     * @since 14
     */
    carrierName?: string;

    /**
     * Gets the accessRules.
     * 
     * @type { ?Array<AccessRule> }
     * @syscap SystemCapability.Telephony.CoreService.Esim
     * @systemapi Hide this for inner system use.
     * @since 14
     */
    accessRules?: Array<AccessRule>;
  }

  /**
   * Result the metadata for a downloadableProfile.
   *
   * @interface GetDownloadableProfileMetadataResult
   * @syscap SystemCapability.Telephony.CoreService.Esim
   * @systemapi Hide this for inner system use.
   * @since 14
   */
  export interface GetDownloadableProfileMetadataResult {
    /**
     * Information about a profile which is downloadable to an eUICC using.
     * 
     * @type { DownloadableProfile }
     * @syscap SystemCapability.Telephony.CoreService.Esim
     * @systemapi Hide this for inner system use.
     * @since 14
     */
    downloadableProfile: DownloadableProfile;

    /**
     * The type of profile policy rule.
     * 
     * @type { number }
     * @syscap SystemCapability.Telephony.CoreService.Esim
     * @systemapi Hide this for inner system use.
     * @since 14
     */
    pprType: number;

    /** 
     * The flag of profile policy rule.
     * 
     * @type { boolean }
     * @syscap SystemCapability.Telephony.CoreService.Esim
     * @systemapi Hide this for inner system use.
     * @since 14
     */
    pprFlag: boolean;

    /**
     * The iccid of the profile.
     * 
     * @type { string }
     * @syscap SystemCapability.Telephony.CoreService.Esim
     * @systemapi Hide this for inner system use.
     * @since 14
     */
     iccid: string;

     /**
      * The service provider name for the profile.
      * 
      * @type { string }
      * @syscap SystemCapability.Telephony.CoreService.Esim
      * @systemapi Hide this for inner system use.
      * @since 14
      */
     serviceProviderName: string;

     /**
      * The profile name.
      * 
      * @type { string }
      * @syscap SystemCapability.Telephony.CoreService.Esim
      * @systemapi Hide this for inner system use.
      * @since 14
      */
     profileName: string;

     /**
      * Profile class for the profile.
      *
      * @type { ProfileClass }
      * @syscap SystemCapability.Telephony.CoreService.Esim
      * @systemapi Hide this for inner system use.
      * @since 14
      */
     profileClass: ProfileClass;

    /**
     * Gets the solvable errors.
     * 
     * @type { SolvableErrors }
     * @syscap SystemCapability.Telephony.CoreService.Esim
     * @systemapi Hide this for inner system use.
     * @since 14
     */
    solvableErrors: SolvableErrors;

    /**
     * Gets the result of the operation.
     * 
     * @type { ResultCode }
     * @syscap SystemCapability.Telephony.CoreService.Esim
     * @systemapi Hide this for inner system use.
     * @since 14
     */
    responseResult: ResultCode;
  }

  /**
   * Result of downloadable Profile list.
   *
   * @interface GetDownloadableProfilesResult
   * @syscap SystemCapability.Telephony.CoreService.Esim
   * @systemapi Hide this for inner system use.
   * @since 14
   */
  export interface GetDownloadableProfilesResult {
    /**
     * Gets the result of the operation.
     * 
     * @type { ResultCode }
     * @syscap SystemCapability.Telephony.CoreService.Esim
     * @systemapi Hide this for inner system use.
     * @since 14
     */
    responseResult: ResultCode;

    /**
     * Gets the downloadable Profiles with filled-in metadata.
     * 
     * @type { Array<DownloadableProfile> }
     * @syscap SystemCapability.Telephony.CoreService.Esim
     * @systemapi Hide this for inner system use.
     * @since 14
     */
    downloadableProfiles: Array<DownloadableProfile>;
  }

  /**
   * Result of the given downloadable Profile.
   *
   * @interface DownloadProfileResult
   * @syscap SystemCapability.Telephony.CoreService.Esim
   * @systemapi Hide this for inner system use.
   * @since 14
   */
  export interface DownloadProfileResult {
    /**
     * Gets the result of the operation.
     * 
     * @type { ResultCode }
     * @syscap SystemCapability.Telephony.CoreService.Esim
     * @systemapi Hide this for inner system use.
     * @since 14
     */
    responseResult: ResultCode;

    /**
     * Gets the solvable errors.
     * 
     * @type { SolvableErrors }
     * @syscap SystemCapability.Telephony.CoreService.Esim
     * @systemapi Hide this for inner system use.
     * @since 14
     */
    solvableErrors: SolvableErrors;

    /**
     * Gets the card Id. This value comes from EuiccService and is used when resolving solvable errors.
     * 
     * @type { number }
     * @syscap SystemCapability.Telephony.CoreService.Esim
     * @systemapi Hide this for inner system use.
     * @since 14
     */
    cardId: number;
  }

  /**
   * Result of all eUICC profile information.
   *
   * @interface GetEuiccProfileInfoListResult
   * @syscap SystemCapability.Telephony.CoreService.Esim
   * @systemapi Hide this for inner system use.
   * @since 14
   */
  export interface GetEuiccProfileInfoListResult {
    /**
     * Gets the result of the operation.
     * 
     * @type { ResultCode }
     * @syscap SystemCapability.Telephony.CoreService.Esim
     * @systemapi Hide this for inner system use.
     * @since 14
     */
    responseResult: ResultCode;

    /**
     * Gets the profile list (only upon success).
     * 
     * @type { Array<EuiccProfile> }
     * @syscap SystemCapability.Telephony.CoreService.Esim
     * @systemapi Hide this for inner system use.
     * @since 14
     */
    profiles: Array<EuiccProfile>;

    /**
     * Gets whether the eUICC can be removed.
     * 
     * @type { boolean }
     * @syscap SystemCapability.Telephony.CoreService.Esim
     * @systemapi Hide this for inner system use.
     * @since 14
     */
    isRemovable: boolean;
  }

  /**
   * Information about the eUICC chip/device.
   *
   * @interface OperatorId
   * @syscap SystemCapability.Telephony.CoreService.Esim
   * @systemapi Hide this for inner system use.
   * @since 14
   */
  export interface OperatorId {
    /**
     * Mobile country code.
     * 
     * @type { string }
     * @syscap SystemCapability.Telephony.CoreService.Esim
     * @systemapi Hide this for inner system use.
     * @since 14
     */
    mcc: string;

    /**
     * Mobile network code.
     * 
     * @type { string }
     * @syscap SystemCapability.Telephony.CoreService.Esim
     * @systemapi Hide this for inner system use.
     * @since 14
     */
    mnc: string;

    /**
     * Group id level 1.
     * 
     * @type { string }
     * @syscap SystemCapability.Telephony.CoreService.Esim
     * @systemapi Hide this for inner system use.
     * @since 14
     */
    gid1: string;

    /**
     * Group id level 2.
     * 
     * @type { string }
     * @syscap SystemCapability.Telephony.CoreService.Esim
     * @systemapi Hide this for inner system use.
     * @since 14
     */
    gid2: string;
  }

  /**
   * Information about an embedded profile (subscription) on an eUICC.
   *
   * @interface EuiccProfile
   * @syscap SystemCapability.Telephony.CoreService.Esim
   * @systemapi Hide this for inner system use.
   * @since 14
   */
  export interface EuiccProfile {
    /**
     * The iccid of the profile.
     * 
     * @type { string }
     * @syscap SystemCapability.Telephony.CoreService.Esim
     * @systemapi Hide this for inner system use.
     * @since 14
     */
    iccid: string;

    /**
     * An optional nickname for the profile.
     * 
     * @type { string }
     * @syscap SystemCapability.Telephony.CoreService.Esim
     * @systemapi Hide this for inner system use.
     * @since 14
     */
    nickName: string;

    /**
     * The service provider name for the profile.
     * 
     * @type { string }
     * @syscap SystemCapability.Telephony.CoreService.Esim
     * @systemapi Hide this for inner system use.
     * @since 14
     */
    serviceProviderName: string;

    /**
     * The profile name.
     * 
     * @type { string }
     * @syscap SystemCapability.Telephony.CoreService.Esim
     * @systemapi Hide this for inner system use.
     * @since 14
     */
    profileName: string;

    /**
     * The profile state.
     *
     * @type { ProfileState }
     * @syscap SystemCapability.Telephony.CoreService.Esim
     * @systemapi Hide this for inner system use.
     * @since 14
     */
    state: ProfileState;

    /**
     * Profile class for the profile.
     *
     * @type { ProfileClass }
     * @syscap SystemCapability.Telephony.CoreService.Esim
     * @systemapi Hide this for inner system use.
     * @since 14
     */
    profileClass: ProfileClass;

    /**
     * The operator Id of the profile.
     * 
     * @type { OperatorId }
     * @syscap SystemCapability.Telephony.CoreService.Esim
     * @systemapi Hide this for inner system use.
     * @since 14
     */
    operatorId: OperatorId;

    /**
     * The policy rules of the profile.
     *
     * @type { PolicyRules }
     * @syscap SystemCapability.Telephony.CoreService.Esim
     * @systemapi Hide this for inner system use.
     * @since 14
     */
    policyRules: PolicyRules;

    /**
     * Optional access rules that specify which apps can manage this profile. Default platform management when not set.
     * 
     * @type { Array<AccessRule> }
     * @syscap SystemCapability.Telephony.CoreService.Esim
     * @systemapi Hide this for inner system use.
     * @since 14
     */
    accessRules: Array<AccessRule>;
  }

  /**
   * Information related to eUICC chips/devices.
   * 
   * @interface EuiccInfo
   * @syscap SystemCapability.Telephony.CoreService.Esim
   * @systemapi Hide this for inner system use.
   * @since 14
   */
  export interface EuiccInfo {
    /**
     * Operating system version.
     * 
     * @type { string }
     * @syscap SystemCapability.Telephony.CoreService.Esim
     * @systemapi Hide this for inner system use.
     * @since 14
     */
    osVersion: string;
  }

  /**
   * Options for resetting eUICC memory.
   *
   * @enum { number }
   * @syscap SystemCapability.Telephony.CoreService.Esim
   * @systemapi Hide this for inner system use.
   * @since 14
   */
  export enum ResetOption {
    /**
     * Deletes all operational profiles on reset.
     *
     * @syscap SystemCapability.Telephony.CoreService.Esim
     * @systemapi Hide this for inner system use.
     * @since 14
     */
    DELETE_OPERATIONAL_PROFILES = 1,

    /**
     * Deletes all field-loaded testing profiles on reset.
     *
     * @syscap SystemCapability.Telephony.CoreService.Esim
     * @systemapi Hide this for inner system use.
     * @since 14
     */
    DELETE_FIELD_LOADED_TEST_PROFILES = 1 << 1,

    /**
     * Resets the default SM-DP+ address on reset.
     *
     * @syscap SystemCapability.Telephony.CoreService.Esim
     * @systemapi Hide this for inner system use.
     * @since 14
     */
    RESET_DEFAULT_SMDP_ADDRESS = 1 << 2,
  }

  /**
   * Euicc OS upgrade status.
   *
   * @enum { number }
   * @syscap SystemCapability.Telephony.CoreService.Esim
   * @systemapi Hide this for inner system use.
   * @since 14
   */
  export enum OsuStatus {
    /**
     * The OS upgrade is in progress.
     *
     * @syscap SystemCapability.Telephony.CoreService.Esim
     * @systemapi Hide this for inner system use.
     * @since 14
     */
    EUICC_UPGRADE_IN_PROGRESS = 1,

    /**
     * The OS upgrade failed.
     *
     * @syscap SystemCapability.Telephony.CoreService.Esim
     * @systemapi Hide this for inner system use.
     * @since 14
     */
    EUICC_UPGRADE_FAILED = 2,

    /**
     * The OS upgrade successful.
     *
     * @syscap SystemCapability.Telephony.CoreService.Esim
     * @systemapi Hide this for inner system use.
     * @since 14
     */
    EUICC_UPGRADE_SUCCESSFUL = 3,

    /**
     * The OS upgrade not needed since current eUICC OS is latest.
     *
     * @syscap SystemCapability.Telephony.CoreService.Esim
     * @systemapi Hide this for inner system use.
     * @since 14
     */
    EUICC_UPGRADE_ALREADY_LATEST = 4,

    /**
     * The OS upgrade status is unavailable since eUICC service is unavailable.
     *
     * @syscap SystemCapability.Telephony.CoreService.Esim
     * @systemapi Hide this for inner system use.
     * @since 14
     */
    EUICC_UPGRADE_SERVICE_UNAVAILABLE = 5,
  }

  /**
   * Result state.
   *
   * @enum { number }
   * @syscap SystemCapability.Telephony.CoreService.Esim
   * @systemapi Hide this for inner system use.
   * @since 14
   */
  export enum ResultCode {
    /**
     * Indicates that the user must resolve a solvable error.
     *
     * @syscap SystemCapability.Telephony.CoreService.Esim
     * @systemapi Hide this for inner system use.
     * @since 14
     */
    RESULT_SOLVABLE_ERRORS = -2,

    /**
     * Indicates that the active profile must be disabled to perform the operation.
     *
     * @syscap SystemCapability.Telephony.CoreService.Esim
     * @systemapi Hide this for inner system use.
     * @since 14
     */
    RESULT_MUST_DISABLE_PROFILE = -1,

    /**
     * Operation succeeded.
     *
     * @syscap SystemCapability.Telephony.CoreService.Esim
     * @systemapi Hide this for inner system use.
     * @since 14
     */
    RESULT_OK = 0,

    /**
     * Failed to obtain the EID.
     *
     * @syscap SystemCapability.Telephony.CoreService.Esim
     * @systemapi Hide this for inner system use.
     * @since 14
     */
    RESULT_GET_EID_FAILED = 201,

    /**
     * The activation code is changed after the end user confirms the operation.
     *
     * @syscap SystemCapability.Telephony.CoreService.Esim
     * @systemapi Hide this for inner system use.
     * @since 14
     */
    RESULT_ACTIVATION_CODE_CHANGED = 203,

    /**
     * The activation code is invalid.
     *
     * @syscap SystemCapability.Telephony.CoreService.Esim
     * @systemapi Hide this for inner system use.
     * @since 14
     */
    RESULT_ACTIVATION_CODE_INVALID = 204,

    /**
     * The SM-DP+ server address is invalid.
     *
     * @syscap SystemCapability.Telephony.CoreService.Esim
     * @systemapi Hide this for inner system use.
     * @since 14
     */
    RESULT_SMDP_ADDRESS_INVALID = 205,

    /**
     * Invalid eUICC information.
     *
     * @syscap SystemCapability.Telephony.CoreService.Esim
     * @systemapi Hide this for inner system use.
     * @since 14
     */
    RESULT_EUICC_INFO_INVALID = 206,

    /**
     * TLS handshake fails.
     *
     * @syscap SystemCapability.Telephony.CoreService.Esim
     * @systemapi Hide this for inner system use.
     * @since 14
     */
    RESULT_TLS_HANDSHAKE_FAILED = 207,

    /**
     * Certificate network connection error.
     *
     * @syscap SystemCapability.Telephony.CoreService.Esim
     * @systemapi Hide this for inner system use.
     * @since 14
     */
    RESULT_CERTIFICATE_IO_ERROR = 208,

    /**
     * The certificate address is invalid or the response times out.
     *
     * @syscap SystemCapability.Telephony.CoreService.Esim
     * @systemapi Hide this for inner system use.
     * @since 14
     */
    RESULT_CERTIFICATE_RESPONSE_TIMEOUT = 209,

    /**
     * Authentication fails.
     *
     * @syscap SystemCapability.Telephony.CoreService.Esim
     * @systemapi Hide this for inner system use.
     * @since 14
     */
    RESULT_AUTHENTICATION_FAILED = 210,

    /**
     * HTTP response fails.
     *
     * @syscap SystemCapability.Telephony.CoreService.Esim
     * @systemapi Hide this for inner system use.
     * @since 14
     */
    RESULT_RESPONSE_HTTP_FAILED = 211,

    /**
     * Incorrect confirmation code.
     *
     * @syscap SystemCapability.Telephony.CoreService.Esim
     * @systemapi Hide this for inner system use.
     * @since 14
     */
    RESULT_CONFIRMATION_CODE_INCORRECT = 212,

    /**
     * The maximum number of confirmation code attempts is reached.
     *
     * @syscap SystemCapability.Telephony.CoreService.Esim
     * @systemapi Hide this for inner system use.
     * @since 14
     */
    RESULT_EXCEEDED_CONFIRMATION_CODE_TRY_LIMIT = 213,

    /**
     * There is no profile on the server for download.
     *
     * @syscap SystemCapability.Telephony.CoreService.Esim
     * @systemapi Hide this for inner system use.
     * @since 14
     */
    RESULT_NO_PROFILE_ON_SERVER = 214,

    /**
     * The transaction ID is invalid.
     *
     * @syscap SystemCapability.Telephony.CoreService.Esim
     * @systemapi Hide this for inner system use.
     * @since 14
     */
    RESULT_TRANSACTION_ID_INVALID = 215,

    /**
     * The server address is invalid.
     *
     * @syscap SystemCapability.Telephony.CoreService.Esim
     * @systemapi Hide this for inner system use.
     * @since 14
     */
    RESULT_SERVER_ADDRESS_INVALID = 216,

    /**
     * Failed to obtain the bound profile package.
     *
     * @syscap SystemCapability.Telephony.CoreService.Esim
     * @systemapi Hide this for inner system use.
     * @since 14
     */
    RESULT_GET_BOUND_PROFILE_PACKAGE_FAILED = 217,

    /**
     * The download is canceled by the end user.
     *
     * @syscap SystemCapability.Telephony.CoreService.Esim
     * @systemapi Hide this for inner system use.
     * @since 14
     */
    RESULT_USER_CANCEL_DOWNLOAD = 218,

    /**
     * The carrier server is unavailable.
     *
     * @syscap SystemCapability.Telephony.CoreService.Esim
     * @systemapi Hide this for inner system use.
     * @since 14
     */
    RESULT_SERVER_UNAVAILABLE = 220,

    /**
     * The profile is attached to a non-delete profile policy rule.
     *
     * @syscap SystemCapability.Telephony.CoreService.Esim
     * @systemapi Hide this for inner system use.
     * @since 14
     */
    RESULT_PROFILE_NON_DELETE = 223,

    /**
     * The authentication response server address does not match.
     *
     * @syscap SystemCapability.Telephony.CoreService.Esim
     * @systemapi Hide this for inner system use.
     * @since 14
     */
    RESULT_SMDP_ADDRESS_INCORRECT = 226,

    /**
     * Failed to analyze the authentication server response.
     *
     * @syscap SystemCapability.Telephony.CoreService.Esim
     * @systemapi Hide this for inner system use.
     * @since 14
     */
    RESULT_ANALYZE_AUTHENTICATION_SERVER_RESPONSE_FAILED = 228,

    /**
     * Failed to analyze the authentication client response.
     *
     * @syscap SystemCapability.Telephony.CoreService.Esim
     * @systemapi Hide this for inner system use.
     * @since 14
     */
    RESULT_ANALYZE_AUTHENTICATION_CLIENT_RESPONSE_FAILED = 229,

    /**
     * Failed to analyze the authentication client response because the matching ID is rejected.
     *
     * @syscap SystemCapability.Telephony.CoreService.Esim
     * @systemapi Hide this for inner system use.
     * @since 14
     */
    RESULT_ANALYZE_AUTHENTICATION_CLIENT_MATCHING_ID_REFUSED = 231,

    /**
     * Authentication stopped due to an error in the profile type.
     *
     * @syscap SystemCapability.Telephony.CoreService.Esim
     * @systemapi Hide this for inner system use.
     * @since 14
     */
    RESULT_PROFILE_TYPE_ERROR_AUTHENTICATION_STOPPED = 233,

    /**
     * The carrier server refused errors of which the reason code is 3.8.
     *
     * @syscap SystemCapability.Telephony.CoreService.Esim
     * @systemapi Hide this for inner system use.
     * @since 14
     */
    RESULT_CARRIER_SERVER_REFUSED_ERRORS = 249,

    /**
     * The certificate is invalid.
     *
     * @syscap SystemCapability.Telephony.CoreService.Esim
     * @systemapi Hide this for inner system use.
     * @since 14
     */
    RESULT_CERTIFICATE_INVALID = 251,

    /**
     * Profile installation failed due to insufficient memory.
     *
     * @syscap SystemCapability.Telephony.CoreService.Esim
     * @systemapi Hide this for inner system use.
     * @since 14
     */
    RESULT_OUT_OF_MEMORY = 263,

    /**
     * The profile policy rule prohibits this operation during download.
     *
     * @syscap SystemCapability.Telephony.CoreService.Esim
     * @systemapi Hide this for inner system use.
     * @since 14
     */
    RESULT_PPR_FORBIDDEN = 268,

    /**
     * Nothing is to be deleted.
     * 
     * @syscap SystemCapability.Telephony.CoreService.Esim
     * @systemapi Hide this for inner system use.
     * @since 14
     */
    RESULT_NOTHING_TO_DELETE = 270,

    /**
     * The profile policy rule does not match.
     *
     * @syscap SystemCapability.Telephony.CoreService.Esim
     * @systemapi Hide this for inner system use.
     * @since 14
     */
    RESULT_PPR_NOT_MATCH = 276,

    /**
     * A session is ongoing.
     * 
     * @syscap SystemCapability.Telephony.CoreService.Esim
     * @systemapi Hide this for inner system use.
     * @since 14
     */
    RESULT_CAT_BUSY = 283,

    /**
     * This eSIM profile is already in use or is invalid.
     *
     * @syscap SystemCapability.Telephony.CoreService.Esim
     * @systemapi Hide this for inner system use.
     * @since 14
     */
    RESULT_PROFILE_EID_INVALID = 284,

    /**
     * Download times out.
     *
     * @syscap SystemCapability.Telephony.CoreService.Esim
     * @systemapi Hide this for inner system use.
     * @since 14
     */
    RESULT_DOWNLOAD_TIMEOUT = 287,

    /**
     * Other errors defined in SGP.22.
     *
     * @syscap SystemCapability.Telephony.CoreService.Esim
     * @systemapi Hide this for inner system use.
     * @since 14
     */
    RESULT_SGP_22_OTHER = 400,
  }

  /**
   * The reason for canceling a profile download session.
   *
   * @enum { number }
   * @syscap SystemCapability.Telephony.CoreService.Esim
   * @systemapi Hide this for inner system use.
   * @since 14
   */
  export enum CancelReason {
    /**
     * The end user has rejected the download.
     *
     * @syscap SystemCapability.Telephony.CoreService.Esim
     * @systemapi Hide this for inner system use.
     * @since 14
     */
    CANCEL_REASON_END_USER_REJECTION = 0,

    /**
     * The download has been postponed and you can try again later.
     *
     * @syscap SystemCapability.Telephony.CoreService.Esim
     * @systemapi Hide this for inner system use.
     * @since 14
     */
    CANCEL_REASON_POSTPONED = 1,

    /**
     * The download has been timed out and you can try again later.
     *
     * @syscap SystemCapability.Telephony.CoreService.Esim
     * @systemapi Hide this for inner system use.
     * @since 14
     */
    CANCEL_REASON_TIMEOUT = 2,

    /**
     * The profile to be downloaded cannot be installed because profile policy rules are not allowed.
     *
     * @syscap SystemCapability.Telephony.CoreService.Esim
     * @systemapi Hide this for inner system use.
     * @since 14
     */
    CANCEL_REASON_PPR_NOT_ALLOWED = 3,
  }

  /**
   * The profile state.
   *
   * @enum { number }
   * @syscap SystemCapability.Telephony.CoreService.Esim
   * @systemapi Hide this for inner system use.
   * @since 14
   */
  export enum ProfileState {
    /**
     * Profile state not specified.
     *
     * @syscap SystemCapability.Telephony.CoreService.Esim
     * @systemapi Hide this for inner system use.
     * @since 14
     */
    PROFILE_STATE_UNSPECIFIED = -1,

    /**
     * Disabled profiles.
     *
     * @syscap SystemCapability.Telephony.CoreService.Esim
     * @systemapi Hide this for inner system use.
     * @since 14
     */
    PROFILE_STATE_DISABLED = 0,

    /**
     * Enabled profile.
     *
     * @syscap SystemCapability.Telephony.CoreService.Esim
     * @systemapi Hide this for inner system use.
     * @since 14
     */
    PROFILE_STATE_ENABLED = 1,
  }

  /**
   * The Profile class.
   *
   * @enum { number }
   * @syscap SystemCapability.Telephony.CoreService.Esim
   * @systemapi Hide this for inner system use.
   * @since 14
   */
  export enum ProfileClass {
    /**
     * Profile class not specified.
     *
     * @syscap SystemCapability.Telephony.CoreService.Esim
     * @systemapi Hide this for inner system use.
     * @since 14
     */
    PROFILE_CLASS_UNSPECIFIED = -1,

    /**
     * Testing profiles.
     *
     * @syscap SystemCapability.Telephony.CoreService.Esim
     * @systemapi Hide this for inner system use.
     * @since 14
     */
    PROFILE_CLASS_TEST = 0,

    /**
     * Provisioning profiles that preloaded on the eUICC.
     *
     * @syscap SystemCapability.Telephony.CoreService.Esim
     * @systemapi Hide this for inner system use.
     * @since 14
     */
    PROFILE_CLASS_PROVISIONING = 1,

    /**
     * Operational profiles that can be preloaded or downloaded.
     *
     * @syscap SystemCapability.Telephony.CoreService.Esim
     * @systemapi Hide this for inner system use.
     * @since 14
     */
    PROFILE_CLASS_OPERATIONAL = 2,
  }

  /**
   * The policy rules of the profile.
   *
   * @enum { number }
   * @syscap SystemCapability.Telephony.CoreService.Esim
   * @systemapi Hide this for inner system use.
   * @since 14
   */
  export enum PolicyRules {
    /**
     * Disabling of this Profile is not allowed.
     *
     * @syscap SystemCapability.Telephony.CoreService.Esim
     * @systemapi Hide this for inner system use.
     * @since 14
     */
    POLICY_RULE_DISABLE_NOT_ALLOWED = 1,

    /**
     * Deletion of this Profile is not allowed.
     *
     * @syscap SystemCapability.Telephony.CoreService.Esim
     * @systemapi Hide this for inner system use.
     * @since 14
     */
    POLICY_RULE_DELETE_NOT_ALLOWED = 1 << 1,

    /**
     * This profile should be deleted when disabled.
     *
     * @syscap SystemCapability.Telephony.CoreService.Esim
     * @systemapi Hide this for inner system use.
     * @since 14
     */
    POLICY_RULE_DISABLE_AND_DELETE = 1 << 2,
  }

  /**
   * The solvable errors.
   *
   * @enum { number }
   * @syscap SystemCapability.Telephony.CoreService.Esim
   * @systemapi Hide this for inner system use.
   * @since 14
   */
  export enum SolvableErrors {
    /**
     * Indicates that the user needs to input a confirmation code during the download.
     *
     * @syscap SystemCapability.Telephony.CoreService.Esim
     * @systemapi Hide this for inner system use.
     * @since 14
     */
    SOLVABLE_ERROR_NEED_CONFIRMATION_CODE = 1 << 0,

    /**
     * Indicates that the download process requires user consent to allow profile policy rules.
     *
     * @syscap SystemCapability.Telephony.CoreService.Esim
     * @systemapi Hide this for inner system use.
     * @since 14
     */
    SOLVABLE_ERROR_NEED_POLICY_RULE = 1 << 1,
  }

  /**
   * Specifies the download configuration.
   *
   * @interface DownloadConfiguration
   * @syscap SystemCapability.Telephony.CoreService.Esim
   * @systemapi Hide this for inner system use.
   * @since 14
   */
  export interface DownloadConfiguration {
    /**
     * Specifies whether to enable the profile after successful download.
     *
     * @type { boolean }
     * @syscap SystemCapability.Telephony.CoreService.Esim
     * @systemapi Hide this for inner system use.
     * @since 14
     */
    switchAfterDownload: boolean;

    /**
     * Specifies whether to forcibly disable the profile. If true, the active profile is disabled in order to perform
     * the operation. Otherwise, {@link RESULT_MUST_DISABLE_PROFILE} is returned in resultCode to ask for the user's
     * agreement to the operation.
     *
     * @type { boolean }
     * @syscap SystemCapability.Telephony.CoreService.Esim
     * @systemapi Hide this for inner system use.
     * @since 14
     */
    forceDisableProfile: boolean;

    /**
     * Specifies whether the user allows the service provider to enforce this Profile Policy Rule (PPR)
     * after being informed of its restrictions.
     *
     * @type { boolean }
     * @syscap SystemCapability.Telephony.CoreService.Esim
     * @systemapi Hide this for inner system use.
     * @since 14
     */
    isPprAllowed: boolean;
  }
}

export default eSIM;
