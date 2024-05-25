/*
 * Copyright (C) 2021-2023 Huawei Device Co., Ltd.
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
 * Provides applications with APIs for obtaining SIM card status, card file information, and card specifications.
 * SIM cards include SIM, USIM, and CSIM cards.
 *
 * @namespace sim
 * @syscap SystemCapability.Telephony.CoreService
 * @since 6
 */
declare namespace sim {
  /**
   * Checks whether the SIM card in a specified slot is activated.
   *
   * @param { number } slotId - Indicates the card slot index number,
   * ranging from {@code 0} to the maximum card slot index number supported by the device.
   * @param { AsyncCallback<boolean> } callback - Indicates the callback for checking
   * whether the SIM card in a specified slot is activated.
   * Returns {@code true} if the SIM card is activated; returns {@code false} otherwise.
   * @syscap SystemCapability.Telephony.CoreService
   * @since 7
   */
  function isSimActive(slotId: number, callback: AsyncCallback<boolean>): void;

  /**
   * Checks whether the SIM card in a specified slot is activated.
   *
   * @param { number } slotId - Indicates the card slot index number,
   * ranging from {@code 0} to the maximum card slot index number supported by the device.
   * @returns { Promise<boolean> } Returns {@code true} if the SIM card is activated; returns {@code false} otherwise.
   * @syscap SystemCapability.Telephony.CoreService
   * @since 7
   */
  function isSimActive(slotId: number): Promise<boolean>;

  /**
   * Checks whether the SIM card in a specified slot is activated.
   *
   * @param { number } slotId - Indicates the card slot index number,
   * ranging from 0 to the maximum card slots supported by the device.
   * @returns { boolean } Returns {@code true} if the SIM card is activated; returns {@code false} otherwise.
   * @syscap SystemCapability.Telephony.CoreService
   * @since 10
   */
  function isSimActiveSync(slotId: number): boolean;

  /**
   * Obtains the default card slot for the voice service.
   *
   * @param { AsyncCallback<number> } callback - Indicates the callback for getting
   * the default card slot for the voice service.
   * Returns {@code 0} if card 1 is used as the default card slot for the voice service;
   * returns {@code 1} if card 2 is used as the default card slot for the voice service;
   * returns {@code -1} if no card is available for the voice service.
   * @syscap SystemCapability.Telephony.CoreService
   * @since 7
   */
  function getDefaultVoiceSlotId(callback: AsyncCallback<number>): void;

  /**
   * Obtains the default card slot for the voice service.
   *
   * @returns { Promise<number> } Returns {@code 0} if card 1 is used as the default card slot for the voice service;
   * returns {@code 1} if card 2 is used as the default card slot for the voice service;
   * returns {@code -1} if no card is available for the voice service.
   * @syscap SystemCapability.Telephony.CoreService
   * @since 7
   */
  function getDefaultVoiceSlotId(): Promise<number>;

  /**
   * Checks whether your application (the caller) has been granted the operator permissions.
   *
   * @param { number } slotId - Indicates the card slot index number,
   * ranging from {@code 0} to the maximum card slot index number supported by the device.
   * @param { AsyncCallback<boolean> } callback - Indicates the callback of hasOperatorPrivileges.
   * Returns {@code true} if your application has been granted the operator permissions; returns {@code false} otherwise.
   * If no SIM card is inserted or the SIM card is deactivated will be return {@code false}.
   * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified.
   * 2. Incorrect parameter types.
   * @throws { BusinessError } 8300001 - Invalid parameter value.
   * @throws { BusinessError } 8300002 - Operation failed. Cannot connect to service.
   * @throws { BusinessError } 8300003 - System internal error.
   * @throws { BusinessError } 8300999 - Unknown error code.
   * @syscap SystemCapability.Telephony.CoreService
   * @since 7
   */
  function hasOperatorPrivileges(slotId: number, callback: AsyncCallback<boolean>): void;

  /**
   * Checks whether your application (the caller) has been granted the operator permissions.
   *
   * @param { number } slotId - Indicates the card slot index number,
   * ranging from {@code 0} to the maximum card slot index number supported by the device.
   * @returns { Promise<boolean> } Returns {@code true} if your application has been granted the operator permissions;
   * returns {@code false} otherwise. If no SIM card is inserted or the SIM card is deactivated will be
   * return {@code false}.
   * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified.
   * 2. Incorrect parameter types.
   * @throws { BusinessError } 8300001 - Invalid parameter value.
   * @throws { BusinessError } 8300002 - Operation failed. Cannot connect to service.
   * @throws { BusinessError } 8300003 - System internal error.
   * @throws { BusinessError } 8300999 - Unknown error code.
   * @syscap SystemCapability.Telephony.CoreService
   * @since 7
   */
  function hasOperatorPrivileges(slotId: number): Promise<boolean>;

  /**
   * Obtains the ISO country code of the SIM card in a specified slot.
   *
   * @param { number } slotId - Indicates the card slot index number,
   * ranging from 0 to the maximum card slot index number supported by the device.
   * @param { AsyncCallback<string> } callback - Indicates the callback for getting the country code defined
   * in ISO 3166-2; returns an empty string if no SIM card is inserted.
   * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified.
   * 2. Incorrect parameter types.
   * @throws { BusinessError } 8300001 - Invalid parameter value.
   * @throws { BusinessError } 8300002 - Operation failed. Cannot connect to service.
   * @throws { BusinessError } 8300003 - System internal error.
   * @throws { BusinessError } 8300004 - Do not have sim card.
   * @throws { BusinessError } 8300999 - Unknown error code.
   * @syscap SystemCapability.Telephony.CoreService
   * @since 6
   */
  function getISOCountryCodeForSim(slotId: number, callback: AsyncCallback<string>): void;

  /**
   * Obtains the ISO country code of the SIM card in a specified slot.
   *
   * @param { number } slotId - Indicates the card slot index number,
   * ranging from 0 to the maximum card slot index number supported by the device.
   * @returns { Promise<string> } Returns the country code defined in ISO 3166-2;
   * returns an empty string if no SIM card is inserted.
   * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified.
   * 2. Incorrect parameter types.
   * @throws { BusinessError } 8300001 - Invalid parameter value.
   * @throws { BusinessError } 8300002 - Operation failed. Cannot connect to service.
   * @throws { BusinessError } 8300003 - System internal error.
   * @throws { BusinessError } 8300004 - Do not have sim card.
   * @throws { BusinessError } 8300999 - Unknown error code.
   * @syscap SystemCapability.Telephony.CoreService
   * @since 6
   */
  function getISOCountryCodeForSim(slotId: number): Promise<string>;

  /**
   * Obtains the ISO country code of the SIM card in a specified slot.
   *
   * @param { number } slotId - Indicates the card slot index number,
   * ranging from 0 to the maximum card slots supported by the device.
   * @returns { string } Returns the country code defined in ISO 3166-2; returns an empty string if no SIM card
   * is inserted.
   * @syscap SystemCapability.Telephony.CoreService
   * @since 10
   */
  function getISOCountryCodeForSimSync(slotId: number): string;

  /**
   * Obtains the home PLMN number of the SIM card in a specified slot.
   *
   * <p>The value is recorded in the SIM card and is irrelevant to the network
   * with which the SIM card is currently registered.
   *
   * @param { number } slotId - Indicates the card slot index number,
   * ranging from 0 to the maximum card slot index number supported by the device.
   * @param { AsyncCallback<string> } callback - Indicates the callback for getting the PLMN number;
   * returns an empty string if no SIM card is inserted.
   * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified.
   * 2. Incorrect parameter types.
   * @throws { BusinessError } 8300001 - Invalid parameter value.
   * @throws { BusinessError } 8300002 - Operation failed. Cannot connect to service.
   * @throws { BusinessError } 8300003 - System internal error.
   * @throws { BusinessError } 8300004 - Do not have sim card.
   * @throws { BusinessError } 8300999 - Unknown error code.
   * @syscap SystemCapability.Telephony.CoreService
   * @since 6
   */
  function getSimOperatorNumeric(slotId: number, callback: AsyncCallback<string>): void;

  /**
   * Obtains the home PLMN number of the SIM card in a specified slot.
   *
   * <p>The value is recorded in the SIM card and is irrelevant to the network
   * with which the SIM card is currently registered.
   *
   * @param { number } slotId - Indicates the card slot index number,
   * ranging from 0 to the maximum card slot index number supported by the device.
   * @returns { Promise<string> } Returns the PLMN number; returns an empty string if no SIM card is inserted.
   * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified.
   * 2. Incorrect parameter types.
   * @throws { BusinessError } 8300001 - Invalid parameter value.
   * @throws { BusinessError } 8300002 - Operation failed. Cannot connect to service.
   * @throws { BusinessError } 8300003 - System internal error.
   * @throws { BusinessError } 8300004 - Do not have sim card.
   * @throws { BusinessError } 8300999 - Unknown error code.
   * @syscap SystemCapability.Telephony.CoreService
   * @since 6
   */
  function getSimOperatorNumeric(slotId: number): Promise<string>;

  /**
   * Obtains the home PLMN number of the SIM card in a specified slot.
   *
   * <p>The value is recorded in the SIM card and is irrelevant to the network
   * with which the SIM card is currently registered.
   *
   * @param { number } slotId - Indicates the card slot index number,
   * ranging from 0 to the maximum card slots supported by the device.
   * @returns { string } Returns the PLMN number; returns an empty string if no SIM card is inserted.
   * @syscap SystemCapability.Telephony.CoreService
   * @since 10
   */
  function getSimOperatorNumericSync(slotId: number): string;

  /**
   * Obtains the service provider name (SPN) of the SIM card in a specified slot.
   *
   * <p>The value is recorded in the EFSPN file of the SIM card and is irrelevant to the network
   * with which the SIM card is currently registered.
   *
   * @param { number } slotId - Indicates the card slot index number,
   * ranging from 0 to the maximum card slot index number supported by the device.
   * @param { AsyncCallback<string> } callback - Indicates the callback for getting the SPN;
   * returns an empty string if no SIM card is inserted or no EFSPN file in the SIM card.
   * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified.
   * 2. Incorrect parameter types.
   * @throws { BusinessError } 8300001 - Invalid parameter value.
   * @throws { BusinessError } 8300002 - Operation failed. Cannot connect to service.
   * @throws { BusinessError } 8300003 - System internal error.
   * @throws { BusinessError } 8300004 - Do not have sim card.
   * @throws { BusinessError } 8300999 - Unknown error code.
   * @syscap SystemCapability.Telephony.CoreService
   * @since 6
   */
  function getSimSpn(slotId: number, callback: AsyncCallback<string>): void;

  /**
   * Obtains the service provider name (SPN) of the SIM card in a specified slot.
   *
   * <p>The value is recorded in the EFSPN file of the SIM card and is irrelevant to the network
   * with which the SIM card is currently registered.
   *
   * @param { number } slotId - Indicates the card slot index number,
   * ranging from 0 to the maximum card slot index number supported by the device.
   * @returns { Promise<string> } Returns the SPN; returns an empty string if no SIM card is inserted or
   * no EFSPN file in the SIM card.
   * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified.
   * 2. Incorrect parameter types.
   * @throws { BusinessError } 8300001 - Invalid parameter value.
   * @throws { BusinessError } 8300002 - Operation failed. Cannot connect to service.
   * @throws { BusinessError } 8300003 - System internal error.
   * @throws { BusinessError } 8300004 - Do not have sim card.
   * @throws { BusinessError } 8300999 - Unknown error code.
   * @syscap SystemCapability.Telephony.CoreService
   * @since 6
   */
  function getSimSpn(slotId: number): Promise<string>;

  /**
   * Obtains the service provider name (SPN) of the SIM card in a specified slot.
   *
   * <p>The value is recorded in the EFSPN file of the SIM card and is irrelevant to the network
   * with which the SIM card is currently registered.
   *
   * @param { number } slotId - Indicates the card slot index number,
   * ranging from 0 to the maximum card slots supported by the device.
   * @returns { string } Returns the SPN; returns an empty string if no EFSPN file is configured for the SIM card.
   * in the SIM card.
   * @syscap SystemCapability.Telephony.CoreService
   * @since 10
   */
  function getSimSpnSync(slotId: number): string;

  /**
   * Obtains the state of the SIM card in a specified slot.
   *
   * @param { number } slotId - Indicates the card slot index number,
   * ranging from {@code 0} to the maximum card slot index number supported by the device.
   * @param { AsyncCallback<SimState> } callback - Indicates the callback for getting one of the following SIM card states:
   * <ul>
   * <li>{@code SimState#SIM_STATE_UNKNOWN}
   * <li>{@code SimState#SIM_STATE_NOT_PRESENT}
   * <li>{@code SimState#SIM_STATE_LOCKED}
   * <li>{@code SimState#SIM_STATE_NOT_READY}
   * <li>{@code SimState#SIM_STATE_READY}
   * <li>{@code SimState#SIM_STATE_LOADED}
   * </ul>
   * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified.
   * 2. Incorrect parameter types.
   * @throws { BusinessError } 8300001 - Invalid parameter value.
   * @throws { BusinessError } 8300002 - Operation failed. Cannot connect to service.
   * @throws { BusinessError } 8300003 - System internal error.
   * @throws { BusinessError } 8300999 - Unknown error code.
   * @syscap SystemCapability.Telephony.CoreService
   * @since 6
   */
  function getSimState(slotId: number, callback: AsyncCallback<SimState>): void;

  /**
   * Obtains the state of the SIM card in a specified slot.
   *
   * @param { number } slotId - Indicates the card slot index number,
   * ranging from {@code 0} to the maximum card slot index number supported by the device.
   * @returns { Promise<SimState> } Returns one of the following SIM card states:
   * <ul>
   * <li>{@code SimState#SIM_STATE_UNKNOWN}
   * <li>{@code SimState#SIM_STATE_NOT_PRESENT}
   * <li>{@code SimState#SIM_STATE_LOCKED}
   * <li>{@code SimState#SIM_STATE_NOT_READY}
   * <li>{@code SimState#SIM_STATE_READY}
   * <li>{@code SimState#SIM_STATE_LOADED}
   * </ul>
   * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified.
   * 2. Incorrect parameter types.
   * @throws { BusinessError } 8300001 - Invalid parameter value.
   * @throws { BusinessError } 8300002 - Operation failed. Cannot connect to service.
   * @throws { BusinessError } 8300003 - System internal error.
   * @throws { BusinessError } 8300999 - Unknown error code.
   * @syscap SystemCapability.Telephony.CoreService
   * @since 6
   */
  function getSimState(slotId: number): Promise<SimState>;

  /**
   * Obtains the state of the SIM card in a specified slot.
   *
   * @param { number } slotId - Indicates the card slot index number,
   * ranging from 0 to the maximum card slots supported by the device.
   * @returns { SimState } Returns one of the following SIM card states:
   * <ul>
   * <li>{@code SimState#SIM_STATE_UNKNOWN}
   * <li>{@code SimState#SIM_STATE_NOT_PRESENT}
   * <li>{@code SimState#SIM_STATE_LOCKED}
   * <li>{@code SimState#SIM_STATE_NOT_READY}
   * <li>{@code SimState#SIM_STATE_READY}
   * <li>{@code SimState#SIM_STATE_LOADED}
   * </ul>
   * @syscap SystemCapability.Telephony.CoreService
   * @since 10
   */
  function getSimStateSync(slotId: number): SimState;

  /**
   * Obtains the type of the SIM card installed in a specified slot.
   *
   * @param { number } slotId - Indicates the card slot index number,
   * ranging from {@code 0} to the maximum card slot index number supported by the device.
   * @param { AsyncCallback<CardType> } callback - Indicates the callback for getting the SIM card type.
   * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified.
   * 2. Incorrect parameter types.
   * @throws { BusinessError } 8300001 - Invalid parameter value.
   * @throws { BusinessError } 8300002 - Operation failed. Cannot connect to service.
   * @throws { BusinessError } 8300003 - System internal error.
   * @throws { BusinessError } 8300004 - Do not have sim card.
   * @throws { BusinessError } 8300999 - Unknown error code.
   * @syscap SystemCapability.Telephony.CoreService
   * @since 7
   */
  function getCardType(slotId: number, callback: AsyncCallback<CardType>): void;

  /**
   * Obtains the type of the SIM card installed in a specified slot.
   *
   * @param { number } slotId - Indicates the card slot index number,
   * ranging from {@code 0} to the maximum card slot index number supported by the device.
   * @returns { Promise<CardType> } Returns the SIM card type.
   * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified.
   * 2. Incorrect parameter types.
   * @throws { BusinessError } 8300001 - Invalid parameter value.
   * @throws { BusinessError } 8300002 - Operation failed. Cannot connect to service.
   * @throws { BusinessError } 8300003 - System internal error.
   * @throws { BusinessError } 8300004 - Do not have sim card.
   * @throws { BusinessError } 8300999 - Unknown error code.
   * @syscap SystemCapability.Telephony.CoreService
   * @since 7
   */
  function getCardType(slotId: number): Promise<CardType>;

  /**
   * Obtains the type of the SIM card inserted in a specified slot.
   *
   * @param { number } slotId - Indicates the card slot index number,
   * ranging from 0 to the maximum card slots supported by the device.
   * @returns { CardType } Returns the SIM card type.
   * @syscap SystemCapability.Telephony.CoreService
   * @since 10
   */
  function getCardTypeSync(slotId: number): CardType;

  /**
   * Obtains the ICCID of the SIM card in a specified slot.
   *
   * <p>The ICCID is a unique identifier of a SIM card. It consists of 20 digits
   * and is recorded in the EFICCID file of the SIM card.
   *
   * @permission ohos.permission.GET_TELEPHONY_STATE
   * @param { number } slotId - Indicates the card slot index number,
   * ranging from 0 to the maximum card slot index number supported by the device.
   * @param { AsyncCallback<string> } callback - Indicates the callback for getting the ICCID;
   * returns an empty string if no SIM card is inserted.
   * @throws { BusinessError } 201 - Permission denied.
   * @throws { BusinessError } 202 - Non-system applications use system APIs.
   * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified.
   * 2. Incorrect parameter types.
   * @throws { BusinessError } 8300001 - Invalid parameter value.
   * @throws { BusinessError } 8300002 - Operation failed. Cannot connect to service.
   * @throws { BusinessError } 8300003 - System internal error.
   * @throws { BusinessError } 8300004 - Do not have sim card.
   * @throws { BusinessError } 8300999 - Unknown error code.
   * @syscap SystemCapability.Telephony.CoreService
   * @systemapi Hide this for inner system use.
   * @since 7
   */
  function getSimIccId(slotId: number, callback: AsyncCallback<string>): void;

  /**
   * Obtains the ICCID of the SIM card in a specified slot.
   *
   * <p>The ICCID is a unique identifier of a SIM card. It consists of 20 digits
   * and is recorded in the EFICCID file of the SIM card.
   *
   * @permission ohos.permission.GET_TELEPHONY_STATE
   * @param { number } slotId - Indicates the card slot index number,
   * ranging from 0 to the maximum card slot index number supported by the device.
   * @returns { Promise<string> } Returns the ICCID; returns an empty string if no SIM card is inserted.
   * @throws { BusinessError } 201 - Permission denied.
   * @throws { BusinessError } 202 - Non-system applications use system APIs.
   * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified.
   * 2. Incorrect parameter types.
   * @throws { BusinessError } 8300001 - Invalid parameter value.
   * @throws { BusinessError } 8300002 - Operation failed. Cannot connect to service.
   * @throws { BusinessError } 8300003 - System internal error.
   * @throws { BusinessError } 8300004 - Do not have sim card.
   * @throws { BusinessError } 8300999 - Unknown error code.
   * @syscap SystemCapability.Telephony.CoreService
   * @systemapi Hide this for inner system use.
   * @since 7
   */
  function getSimIccId(slotId: number): Promise<string>;

  /**
   * Obtains the alpha identifier of the voice mailbox of the SIM card in a specified slot.
   *
   * @permission ohos.permission.GET_TELEPHONY_STATE
   * @param { number } slotId - Indicates the card slot index number,
   * ranging from {@code 0} to the maximum card slot index number supported by the device.
   * @param { AsyncCallback<string> } callback - Indicates the callback for getting the voice mailbox alpha identifier;
   * returns an empty string if no voice mailbox alpha identifier is written into the SIM card.
   * @throws { BusinessError } 201 - Permission denied.
   * @throws { BusinessError } 202 - Non-system applications use system APIs.
   * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified.
   * 2. Incorrect parameter types.
   * @throws { BusinessError } 8300001 - Invalid parameter value.
   * @throws { BusinessError } 8300002 - Operation failed. Cannot connect to service.
   * @throws { BusinessError } 8300003 - System internal error.
   * @throws { BusinessError } 8300004 - Do not have sim card.
   * @throws { BusinessError } 8300999 - Unknown error code.
   * @syscap SystemCapability.Telephony.CoreService
   * @systemapi Hide this for inner system use.
   * @since 8
   */
  function getVoiceMailIdentifier(slotId: number, callback: AsyncCallback<string>): void;

  /**
   * Obtains the alpha identifier of the voice mailbox of the SIM card in a specified slot.
   *
   * @permission ohos.permission.GET_TELEPHONY_STATE
   * @param { number } slotId - Indicates the card slot index number,
   * ranging from {@code 0} to the maximum card slot index number supported by the device.
   * @returns { Promise<string> } Returns the voice mailbox alpha identifier;
   * returns an empty string if no voice mailbox alpha identifier is written into the SIM card.
   * @throws { BusinessError } 201 - Permission denied.
   * @throws { BusinessError } 202 - Non-system applications use system APIs.
   * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified.
   * 2. Incorrect parameter types.
   * @throws { BusinessError } 8300001 - Invalid parameter value.
   * @throws { BusinessError } 8300002 - Operation failed. Cannot connect to service.
   * @throws { BusinessError } 8300003 - System internal error.
   * @throws { BusinessError } 8300004 - Do not have sim card.
   * @throws { BusinessError } 8300999 - Unknown error code.
   * @syscap SystemCapability.Telephony.CoreService
   * @systemapi Hide this for inner system use.
   * @since 8
   */
  function getVoiceMailIdentifier(slotId: number): Promise<string>;

  /**
   * Obtains the voice mailbox number of the SIM card in a specified slot.
   *
   * @permission ohos.permission.GET_TELEPHONY_STATE
   * @param { number } slotId - Indicates the card slot index number,
   * ranging from {@code 0} to the maximum card slot index number supported by the device.
   * @param { AsyncCallback<string> } callback - Indicates the callback for getting the voice mailbox number;
   * returns an empty string if no voice mailbox number is written into the SIM card.
   * @throws { BusinessError } 201 - Permission denied.
   * @throws { BusinessError } 202 - Non-system applications use system APIs.
   * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified.
   * 2. Incorrect parameter types.
   * @throws { BusinessError } 8300001 - Invalid parameter value.
   * @throws { BusinessError } 8300002 - Operation failed. Cannot connect to service.
   * @throws { BusinessError } 8300003 - System internal error.
   * @throws { BusinessError } 8300004 - Do not have sim card.
   * @throws { BusinessError } 8300999 - Unknown error code.
   * @syscap SystemCapability.Telephony.CoreService
   * @systemapi Hide this for inner system use.
   * @since 8
   */
  function getVoiceMailNumber(slotId: number, callback: AsyncCallback<string>): void;

  /**
   * Obtains the voice mailbox number of the SIM card in a specified slot.
   *
   * @permission ohos.permission.GET_TELEPHONY_STATE
   * @param { number } slotId - Indicates the card slot index number,
   * ranging from {@code 0} to the maximum card slot index number supported by the device.
   * @returns { Promise<string> } Returns the voice mailbox number.
   * returns an empty string if no voice mailbox number is written into the SIM card.
   * @throws { BusinessError } 201 - Permission denied.
   * @throws { BusinessError } 202 - Non-system applications use system APIs.
   * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified.
   * 2. Incorrect parameter types.
   * @throws { BusinessError } 8300001 - Invalid parameter value.
   * @throws { BusinessError } 8300002 - Operation failed. Cannot connect to service.
   * @throws { BusinessError } 8300003 - System internal error.
   * @throws { BusinessError } 8300004 - Do not have sim card.
   * @throws { BusinessError } 8300999 - Unknown error code.
   * @syscap SystemCapability.Telephony.CoreService
   * @systemapi Hide this for inner system use.
   * @since 8
   */
  function getVoiceMailNumber(slotId: number): Promise<string>;

  /**
   * Sets the voice mail information.
   *
   * @permission ohos.permission.SET_TELEPHONY_STATE
   * @param { number } slotId - Indicates the card slot index number,
   * ranging from {@code 0} to the maximum card slot index number supported by the device.
   * @param { string } mailName - Indicates the name of voice mail.
   * @param { string } mailNumber - Indicates the number of voice mail.
   * @param { AsyncCallback<void> } callback - The callback of setVoiceMailInfo.
   * @throws { BusinessError } 201 - Permission denied.
   * @throws { BusinessError } 202 - Non-system applications use system APIs.
   * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified.
   * 2. Incorrect parameter types.
   * @throws { BusinessError } 8300001 - Invalid parameter value.
   * @throws { BusinessError } 8300002 - Operation failed. Cannot connect to service.
   * @throws { BusinessError } 8300003 - System internal error.
   * @throws { BusinessError } 8300004 - Do not have sim card.
   * @throws { BusinessError } 8300999 - Unknown error code.
   * @throws { BusinessError } 8301002 - SIM card operation error.
   * @syscap SystemCapability.Telephony.CoreService
   * @systemapi Hide this for inner system use.
   * @since 8
   */
  function setVoiceMailInfo(slotId: number, mailName: string, mailNumber: string, callback: AsyncCallback<void>): void;

  /**
   * Sets the voice mail information.
   *
   * @permission ohos.permission.SET_TELEPHONY_STATE
   * @param { number } slotId - Indicates the card slot index number,
   * ranging from {@code 0} to the maximum card slot index number supported by the device.
   * @param { string } mailName - Indicates the name of voice mail.
   * @param { string } mailNumber - Indicates the number of voice mail.
   * @returns { Promise<void> } The promise returned by the setVoiceMailInfo.
   * @throws { BusinessError } 201 - Permission denied.
   * @throws { BusinessError } 202 - Non-system applications use system APIs.
   * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified.
   * 2. Incorrect parameter types.
   * @throws { BusinessError } 8300001 - Invalid parameter value.
   * @throws { BusinessError } 8300002 - Operation failed. Cannot connect to service.
   * @throws { BusinessError } 8300003 - System internal error.
   * @throws { BusinessError } 8300004 - Do not have sim card.
   * @throws { BusinessError } 8300999 - Unknown error code.
   * @throws { BusinessError } 8301002 - SIM card operation error.
   * @syscap SystemCapability.Telephony.CoreService
   * @systemapi Hide this for inner system use.
   * @since 8
   */
  function setVoiceMailInfo(slotId: number, mailName: string, mailNumber: string): Promise<void>;

  /**
   * Obtains the MSISDN of the SIM card in a specified slot.
   * The MSISDN is recorded in the EFMSISDN file of the SIM card.
   *
   * @permission ohos.permission.GET_PHONE_NUMBERS
   * @param { number } slotId - Indicates the card slot index number,
   * ranging from 0 to the maximum card slot index number supported by the device.
   * @param { AsyncCallback<string> } callback - Indicates the callback for getting the MSISDN;
   * Returns an empty string if no SIM card is inserted or
   * no MSISDN is recorded in the EFMSISDN file.
   * @throws { BusinessError } 201 - Permission denied.
   * @throws { BusinessError } 202 - Non-system applications use system APIs.
   * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified.
   * 2. Incorrect parameter types.
   * @throws { BusinessError } 8300001 - Invalid parameter value.
   * @throws { BusinessError } 8300002 - Operation failed. Cannot connect to service.
   * @throws { BusinessError } 8300003 - System internal error.
   * @throws { BusinessError } 8300004 - Do not have sim card.
   * @throws { BusinessError } 8300999 - Unknown error code.
   * @syscap SystemCapability.Telephony.CoreService
   * @systemapi Hide this for inner system use.
   * @since 8
   */
  function getSimTelephoneNumber(slotId: number, callback: AsyncCallback<string>): void;

  /**
   * Obtains the MSISDN of the SIM card in a specified slot.
   * The MSISDN is recorded in the EFMSISDN file of the SIM card.
   *
   * @permission ohos.permission.GET_PHONE_NUMBERS
   * @param { number } slotId - Indicates the card slot index number,
   * ranging from 0 to the maximum card slot index number supported by the device.
   * @returns { Promise<string> } Returns the MSISDN; returns an empty string if no SIM card is inserted or
   * no MSISDN is recorded in the EFMSISDN file.
   * @throws { BusinessError } 201 - Permission denied.
   * @throws { BusinessError } 202 - Non-system applications use system APIs.
   * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified.
   * 2. Incorrect parameter types.
   * @throws { BusinessError } 8300001 - Invalid parameter value.
   * @throws { BusinessError } 8300002 - Operation failed. Cannot connect to service.
   * @throws { BusinessError } 8300003 - System internal error.
   * @throws { BusinessError } 8300004 - Do not have sim card.
   * @throws { BusinessError } 8300999 - Unknown error code.
   * @syscap SystemCapability.Telephony.CoreService
   * @systemapi Hide this for inner system use.
   * @since 8
   */
  function getSimTelephoneNumber(slotId: number): Promise<string>;

  /**
   * Obtains the Group Identifier Level 1 (GID1) of the SIM card in a specified slot.
   * The GID1 is recorded in the EFGID1 file of the SIM card.
   *
   * @permission ohos.permission.GET_TELEPHONY_STATE
   * @param { number } slotId - Indicates the card slot index number,
   * ranging from 0 to the maximum card slot index number supported by the device.
   * @param { AsyncCallback<string> } callback - Indicates the callback for getting the GID1;
   * Returns an empty string if no SIM card is inserted or no GID1 in the SIM card.
   * @throws { BusinessError } 201 - Permission denied.
   * @throws { BusinessError } 202 - Non-system applications use system APIs.
   * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified.
   * 2. Incorrect parameter types.
   * @throws { BusinessError } 8300001 - Invalid parameter value.
   * @throws { BusinessError } 8300002 - Operation failed. Cannot connect to service.
   * @throws { BusinessError } 8300003 - System internal error.
   * @throws { BusinessError } 8300004 - Do not have sim card.
   * @throws { BusinessError } 8300999 - Unknown error code.
   * @syscap SystemCapability.Telephony.CoreService
   * @systemapi Hide this for inner system use.
   * @since 7
   */
  function getSimGid1(slotId: number, callback: AsyncCallback<string>): void;

  /**
   * Obtains the Group Identifier Level 1 (GID1) of the SIM card in a specified slot.
   * The GID1 is recorded in the EFGID1 file of the SIM card.
   *
   * @permission ohos.permission.GET_TELEPHONY_STATE
   * @param { number } slotId - Indicates the card slot index number,
   * ranging from 0 to the maximum card slot index number supported by the device.
   * @returns { Promise<string> } Returns the GID1; returns an empty string if no SIM card is inserted or
   * no GID1 in the SIM card.
   * @throws { BusinessError } 201 - Permission denied.
   * @throws { BusinessError } 202 - Non-system applications use system APIs.
   * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified.
   * 2. Incorrect parameter types.
   * @throws { BusinessError } 8300001 - Invalid parameter value.
   * @throws { BusinessError } 8300002 - Operation failed. Cannot connect to service.
   * @throws { BusinessError } 8300003 - System internal error.
   * @throws { BusinessError } 8300004 - Do not have sim card.
   * @throws { BusinessError } 8300999 - Unknown error code.
   * @syscap SystemCapability.Telephony.CoreService
   * @systemapi Hide this for inner system use.
   * @since 7
   */
  function getSimGid1(slotId: number): Promise<string>;

  /**
   * Obtains the maximum number of SIM cards that can be used simultaneously on the device,
   * that is, the maximum number of SIM card slots.
   *
   * @returns { number } Returns the maximum number of SIM card slots.
   * @syscap SystemCapability.Telephony.CoreService
   * @since 7
   */
  function getMaxSimCount(): number;

  /**
   * Get the international mobile subscriber ID.
   *
   * @permission ohos.permission.GET_TELEPHONY_STATE
   * @param { number } slotId - Indicates the card slot index number,
   * ranging from 0 to the maximum card slot index number supported by the device.
   * @param { AsyncCallback<string> } callback - Indicates the callback for getting
   * the international mobile subscriber ID.
   * @throws { BusinessError } 201 - Permission denied.
   * @throws { BusinessError } 202 - Non-system applications use system APIs.
   * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified.
   * 2. Incorrect parameter types.
   * @throws { BusinessError } 8300001 - Invalid parameter value.
   * @throws { BusinessError } 8300002 - Operation failed. Cannot connect to service.
   * @throws { BusinessError } 8300003 - System internal error.
   * @throws { BusinessError } 8300004 - Do not have sim card.
   * @throws { BusinessError } 8300999 - Unknown error code.
   * @syscap SystemCapability.Telephony.CoreService
   * @systemapi Hide this for inner system use.
   * @since 6
   */
  function getIMSI(slotId: number, callback: AsyncCallback<string>): void;

  /**
   * Get the international mobile subscriber ID.
   *
   * @permission ohos.permission.GET_TELEPHONY_STATE
   * @param { number } slotId - Indicates the card slot index number,
   * ranging from 0 to the maximum card slot index number supported by the device.
   * @returns { Promise<string> } Returns the international mobile subscriber ID.
   * @throws { BusinessError } 201 - Permission denied.
   * @throws { BusinessError } 202 - Non-system applications use system APIs.
   * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified.
   * 2. Incorrect parameter types.
   * @throws { BusinessError } 8300001 - Invalid parameter value.
   * @throws { BusinessError } 8300002 - Operation failed. Cannot connect to service.
   * @throws { BusinessError } 8300003 - System internal error.
   * @throws { BusinessError } 8300004 - Do not have sim card.
   * @throws { BusinessError } 8300999 - Unknown error code.
   * @syscap SystemCapability.Telephony.CoreService
   * @systemapi Hide this for inner system use.
   * @since 6
   */
  function getIMSI(slotId: number): Promise<string>;

  /**
   * Indicates whether the SIM card in a specified slot is a specified operator.
   *
   * @param { number } slotId - Indicates the card slot index number,
   * ranging from 0 to the maximum card slot index number supported by the device.
   * @param { OperatorSimCard } operator - Indicates the operator of sim.
   * @returns { boolean } Returns {@code true} if the SIM card is specified operator; return {@code false} otherwise.
   * @throws { BusinessError } 202 - Non-system applications use system APIs.
   * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified.
   * 2. Incorrect parameter types.
   * @throws { BusinessError } 8300001 - Invalid parameter value.
   * @throws { BusinessError } 8300002 - Operation failed. Cannot connect to service.
   * @throws { BusinessError } 8300003 - System internal error.
   * @throws { BusinessError } 8300004 - Do not have sim card.
   * @throws { BusinessError } 8300999 - Unknown error code.
   * @syscap SystemCapability.Telephony.CoreService
   * @systemapi Hide this for inner system use.
   * @since 11
   */
  function isOperatorSimCard(slotId: number, operator: OperatorSimCard): boolean;

  /**
   * Checks whether a SIM card is inserted in a specified slot.
   *
   * @param { number } slotId - Indicates the card slot index number,
   * ranging from 0 to the maximum card slot index number supported by the device.
   * @param { AsyncCallback<boolean> } callback - Indicates the callback for hasSimCard.
   * Returns {@code true} if a SIM card is inserted; return {@code false} otherwise.
   * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified.
   * 2. Incorrect parameter types.
   * @throws { BusinessError } 8300001 - Invalid parameter value.
   * @throws { BusinessError } 8300002 - Operation failed. Cannot connect to service.
   * @throws { BusinessError } 8300003 - System internal error.
   * @throws { BusinessError } 8300999 - Unknown error code.
   * @syscap SystemCapability.Telephony.CoreService
   * @since 7
   */
  function hasSimCard(slotId: number, callback: AsyncCallback<boolean>): void;

  /**
   * Checks whether a SIM card is inserted in a specified slot.
   *
   * @param { number } slotId - Indicates the card slot index number,
   * ranging from 0 to the maximum card slot index number supported by the device.
   * @returns { Promise<boolean> } Returns {@code true} if a SIM card is inserted; return {@code false} otherwise.
   * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified.
   * 2. Incorrect parameter types.
   * @throws { BusinessError } 8300001 - Invalid parameter value.
   * @throws { BusinessError } 8300002 - Operation failed. Cannot connect to service.
   * @throws { BusinessError } 8300003 - System internal error.
   * @throws { BusinessError } 8300999 - Unknown error code.
   * @syscap SystemCapability.Telephony.CoreService
   * @since 7
   */
  function hasSimCard(slotId: number): Promise<boolean>;

  /**
   * Checks whether a SIM card is inserted in a specified slot.
   *
   * @param { number } slotId - Indicates the card slot index number,
   * ranging from 0 to the maximum card slots supported by the device.
   * @returns { boolean } Returns {@code true} if a SIM card is inserted; return {@code false} otherwise.
   * @syscap SystemCapability.Telephony.CoreService
   * @since 10
   */
  function hasSimCardSync(slotId: number): boolean;

  /**
   * Get account information of SIM card.
   *
   * @permission ohos.permission.GET_TELEPHONY_STATE
   * @param { number } slotId - Indicates the card slot index number,
   * ranging from 0 to the maximum card slot index number supported by the device.
   * @param { AsyncCallback<IccAccountInfo> } callback - Indicates the callback for
   * getting a {@code IccAccountInfo} object. The ICCID and phone number will be null
   * if has no ohos.permission.GET_TELEPHONY_STATE.
   * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified.
   * 2. Incorrect parameter types.
   * @throws { BusinessError } 8300001 - Invalid parameter value.
   * @throws { BusinessError } 8300002 - Operation failed. Cannot connect to service.
   * @throws { BusinessError } 8300003 - System internal error.
   * @throws { BusinessError } 8300004 - Do not have sim card.
   * @throws { BusinessError } 8300999 - Unknown error code.
   * @throws { BusinessError } 8301002 - SIM card operation error.
   * @syscap SystemCapability.Telephony.CoreService
   * @since 10
   */
  function getSimAccountInfo(slotId: number, callback: AsyncCallback<IccAccountInfo>): void;

  /**
   * Get account information of SIM card.
   *
   * @permission ohos.permission.GET_TELEPHONY_STATE
   * @param { number } slotId - Indicates the card slot index number,
   * ranging from 0 to the maximum card slot index number supported by the device.
   * @returns { Promise<IccAccountInfo> } Returns a {@code IccAccountInfo} object. The ICCID and phone number
   * will be null if has no ohos.permission.GET_TELEPHONY_STATE.
   * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified.
   * 2. Incorrect parameter types.
   * @throws { BusinessError } 8300001 - Invalid parameter value.
   * @throws { BusinessError } 8300002 - Operation failed. Cannot connect to service.
   * @throws { BusinessError } 8300003 - System internal error.
   * @throws { BusinessError } 8300004 - Do not have sim card.
   * @throws { BusinessError } 8300999 - Unknown error code.
   * @throws { BusinessError } 8301002 - SIM card operation error.
   * @syscap SystemCapability.Telephony.CoreService
   * @since 10
   */
  function getSimAccountInfo(slotId: number): Promise<IccAccountInfo>;

  /**
   * Get the list of active SIM card account information.
   *
   * @permission ohos.permission.GET_TELEPHONY_STATE
   * @param { AsyncCallback<Array<IccAccountInfo>> } callback - The callback is used to
   * return the array of {@link IccAccountInfo}. The ICCID and phone number will be null
   * if has no ohos.permission.GET_TELEPHONY_STATE.
   * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified.
   * 2. Incorrect parameter types.
   * @throws { BusinessError } 8300001 - Invalid parameter value.
   * @throws { BusinessError } 8300002 - Operation failed. Cannot connect to service.
   * @throws { BusinessError } 8300003 - System internal error.
   * @throws { BusinessError } 8300004 - Do not have sim card.
   * @throws { BusinessError } 8300999 - Unknown error code.
   * @syscap SystemCapability.Telephony.CoreService
   * @since 10
   */
  function getActiveSimAccountInfoList(callback: AsyncCallback<Array<IccAccountInfo>>): void;

  /**
   * Get the list of active SIM card account information.
   *
   * @permission ohos.permission.GET_TELEPHONY_STATE
   * @returns { Promise<Array<IccAccountInfo>> } Returns the array of {@link IccAccountInfo}. The ICCID
   * and phone number will be null if has no ohos.permission.GET_TELEPHONY_STATE.
   * @throws { BusinessError } 8300002 - Operation failed. Cannot connect to service.
   * @throws { BusinessError } 8300003 - System internal error.
   * @throws { BusinessError } 8300004 - Do not have sim card.
   * @throws { BusinessError } 8300999 - Unknown error code.
   * @syscap SystemCapability.Telephony.CoreService
   * @since 10
   */
  function getActiveSimAccountInfoList(): Promise<Array<IccAccountInfo>>;

  /**
   * Set the card slot ID of the default voice service.
   *
   * @permission ohos.permission.SET_TELEPHONY_STATE
   * @param { number } slotId - Indicates the card slot index number,
   * ranging from 0 to the maximum card slot index number supported by the device.
   * @param { AsyncCallback<void> } callback - The callback of setDefaultVoiceSlotId.
   * @throws { BusinessError } 201 - Permission denied.
   * @throws { BusinessError } 202 - Non-system applications use system APIs.
   * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified.
   * 2. Incorrect parameter types.
   * @throws { BusinessError } 8300001 - Invalid parameter value.
   * @throws { BusinessError } 8300002 - Operation failed. Cannot connect to service.
   * @throws { BusinessError } 8300003 - System internal error.
   * @throws { BusinessError } 8300004 - Do not have sim card.
   * @throws { BusinessError } 8300999 - Unknown error code.
   * @throws { BusinessError } 8301001 - SIM card is not activated.
   * @syscap SystemCapability.Telephony.CoreService
   * @systemapi Hide this for inner system use.
   * @since 7
   */
  function setDefaultVoiceSlotId(slotId: number, callback: AsyncCallback<void>): void;

  /**
   * Set the card slot ID of the default voice service.
   *
   * @permission ohos.permission.SET_TELEPHONY_STATE
   * @param { number } slotId - Indicates the card slot index number,
   * ranging from 0 to the maximum card slot index number supported by the device.
   * @returns { Promise<void> } The promise returned by the setVoiceMailInfo.
   * @throws { BusinessError } 201 - Permission denied.
   * @throws { BusinessError } 202 - Non-system applications use system APIs.
   * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified.
   * 2. Incorrect parameter types.
   * @throws { BusinessError } 8300001 - Invalid parameter value.
   * @throws { BusinessError } 8300002 - Operation failed. Cannot connect to service.
   * @throws { BusinessError } 8300003 - System internal error.
   * @throws { BusinessError } 8300004 - Do not have sim card.
   * @throws { BusinessError } 8300999 - Unknown error code.
   * @throws { BusinessError } 8301001 - SIM card is not activated.
   * @syscap SystemCapability.Telephony.CoreService
   * @systemapi Hide this for inner system use.
   * @since 7
   */
  function setDefaultVoiceSlotId(slotId: number): Promise<void>;

  /**
   * Activate the SIM card in the specified slot.
   *
   * @permission ohos.permission.SET_TELEPHONY_STATE
   * @param { number } slotId - Indicates the card slot index number,
   * ranging from 0 to the maximum card slot index number supported by the device.
   * @param { AsyncCallback<void> } callback - The callback of activateSim.
   * @throws { BusinessError } 201 - Permission denied.
   * @throws { BusinessError } 202 - Non-system applications use system APIs.
   * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified.
   * 2. Incorrect parameter types.
   * @throws { BusinessError } 8300001 - Invalid parameter value.
   * @throws { BusinessError } 8300002 - Operation failed. Cannot connect to service.
   * @throws { BusinessError } 8300003 - System internal error.
   * @throws { BusinessError } 8300004 - Do not have sim card.
   * @throws { BusinessError } 8300999 - Unknown error code.
   * @syscap SystemCapability.Telephony.CoreService
   * @systemapi Hide this for inner system use.
   * @since 8
   */
  function activateSim(slotId: number, callback: AsyncCallback<void>): void;

  /**
   * Activate the SIM card in the specified slot.
   *
   * @permission ohos.permission.SET_TELEPHONY_STATE
   * @param { number } slotId - Indicates the card slot index number,
   * ranging from 0 to the maximum card slot index number supported by the device.
   * @returns { Promise<void> } The promise returned by the activateSim.
   * @throws { BusinessError } 201 - Permission denied.
   * @throws { BusinessError } 202 - Non-system applications use system APIs.
   * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified.
   * 2. Incorrect parameter types.
   * @throws { BusinessError } 8300001 - Invalid parameter value.
   * @throws { BusinessError } 8300002 - Operation failed. Cannot connect to service.
   * @throws { BusinessError } 8300003 - System internal error.
   * @throws { BusinessError } 8300004 - Do not have sim card.
   * @throws { BusinessError } 8300999 - Unknown error code.
   * @syscap SystemCapability.Telephony.CoreService
   * @systemapi Hide this for inner system use.
   * @since 8
   */
  function activateSim(slotId: number): Promise<void>;

  /**
   * Disable SIM card in specified slot.
   *
   * @permission ohos.permission.SET_TELEPHONY_STATE
   * @param { number } slotId - Indicates the card slot index number,
   * ranging from 0 to the maximum card slot index number supported by the device.
   * @param { AsyncCallback<void> } callback - The callback of deactivateSim.
   * @throws { BusinessError } 201 - Permission denied.
   * @throws { BusinessError } 202 - Non-system applications use system APIs.
   * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified.
   * 2. Incorrect parameter types.
   * @throws { BusinessError } 8300001 - Invalid parameter value.
   * @throws { BusinessError } 8300002 - Operation failed. Cannot connect to service.
   * @throws { BusinessError } 8300003 - System internal error.
   * @throws { BusinessError } 8300004 - Do not have sim card.
   * @throws { BusinessError } 8300999 - Unknown error code.
   * @syscap SystemCapability.Telephony.CoreService
   * @systemapi Hide this for inner system use.
   * @since 8
   */
  function deactivateSim(slotId: number, callback: AsyncCallback<void>): void;

  /**
   * Disable SIM card in specified slot.
   *
   * @permission ohos.permission.SET_TELEPHONY_STATE
   * @param { number } slotId - Indicates the card slot index number,
   * ranging from 0 to the maximum card slot index number supported by the device.
   * @returns { Promise<void> } The promise returned by the deactivateSim.
   * @throws { BusinessError } 201 - Permission denied.
   * @throws { BusinessError } 202 - Non-system applications use system APIs.
   * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified.
   * 2. Incorrect parameter types.
   * @throws { BusinessError } 8300001 - Invalid parameter value.
   * @throws { BusinessError } 8300002 - Operation failed. Cannot connect to service.
   * @throws { BusinessError } 8300003 - System internal error.
   * @throws { BusinessError } 8300004 - Do not have sim card.
   * @throws { BusinessError } 8300999 - Unknown error code.
   * @syscap SystemCapability.Telephony.CoreService
   * @systemapi Hide this for inner system use.
   * @since 8
   */
  function deactivateSim(slotId: number): Promise<void>;

  /**
   * Set the SIM card display name of the specified card slot.
   *
   * @permission ohos.permission.SET_TELEPHONY_STATE
   * @param { number } slotId - Indicates the card slot index number,
   * ranging from 0 to the maximum card slot index number supported by the device.
   * @param { string } name - Indicates SIM card name.
   * @param { AsyncCallback<void> } callback - The callback of setShowName.
   * @throws { BusinessError } 201 - Permission denied.
   * @throws { BusinessError } 202 - Non-system applications use system APIs.
   * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified.
   * 2. Incorrect parameter types.
   * @throws { BusinessError } 8300001 - Invalid parameter value.
   * @throws { BusinessError } 8300002 - Operation failed. Cannot connect to service.
   * @throws { BusinessError } 8300003 - System internal error.
   * @throws { BusinessError } 8300004 - Do not have sim card.
   * @throws { BusinessError } 8300999 - Unknown error code.
   * @syscap SystemCapability.Telephony.CoreService
   * @systemapi Hide this for inner system use.
   * @since 8
   */
  function setShowName(slotId: number, name: string, callback: AsyncCallback<void>): void;

  /**
   * Set the SIM card display name of the specified card slot.
   *
   * @permission ohos.permission.SET_TELEPHONY_STATE
   * @param { number } slotId - Indicates the card slot index number,
   * ranging from 0 to the maximum card slot index number supported by the device.
   * @param { string } name - Indicates SIM card name.
   * @returns { Promise<void> } The promise returned by the setShowName.
   * @throws { BusinessError } 201 - Permission denied.
   * @throws { BusinessError } 202 - Non-system applications use system APIs.
   * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified.
   * 2. Incorrect parameter types.
   * @throws { BusinessError } 8300001 - Invalid parameter value.
   * @throws { BusinessError } 8300002 - Operation failed. Cannot connect to service.
   * @throws { BusinessError } 8300003 - System internal error.
   * @throws { BusinessError } 8300004 - Do not have sim card.
   * @throws { BusinessError } 8300999 - Unknown error code.
   * @syscap SystemCapability.Telephony.CoreService
   * @systemapi Hide this for inner system use.
   * @since 8
   */
  function setShowName(slotId: number, name: string): Promise<void>;

  /**
   * Gets the name of the SIM card in the specified slot.
   *
   * @permission ohos.permission.GET_TELEPHONY_STATE
   * @param { number } slotId - Indicates the card slot index number,
   * ranging from 0 to the maximum card slot index number supported by the device.
   * @param { AsyncCallback<string> } callback - Indicates the callback for getting the SIM card name.
   * @throws { BusinessError } 201 - Permission denied.
   * @throws { BusinessError } 202 - Non-system applications use system APIs.
   * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified.
   * 2. Incorrect parameter types.
   * @throws { BusinessError } 8300001 - Invalid parameter value.
   * @throws { BusinessError } 8300002 - Operation failed. Cannot connect to service.
   * @throws { BusinessError } 8300003 - System internal error.
   * @throws { BusinessError } 8300004 - Do not have sim card.
   * @throws { BusinessError } 8300999 - Unknown error code.
   * @syscap SystemCapability.Telephony.CoreService
   * @systemapi Hide this for inner system use.
   * @since 8
   */
  function getShowName(slotId: number, callback: AsyncCallback<string>): void;

  /**
   * Gets the name of the SIM card in the specified slot.
   *
   * @permission ohos.permission.GET_TELEPHONY_STATE
   * @param { number } slotId - Indicates the card slot index number,
   * ranging from 0 to the maximum card slot index number supported by the device.
   * @returns { Promise<string> } Returns the SIM card name.
   * @throws { BusinessError } 201 - Permission denied.
   * @throws { BusinessError } 202 - Non-system applications use system APIs.
   * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified.
   * 2. Incorrect parameter types.
   * @throws { BusinessError } 8300001 - Invalid parameter value.
   * @throws { BusinessError } 8300002 - Operation failed. Cannot connect to service.
   * @throws { BusinessError } 8300003 - System internal error.
   * @throws { BusinessError } 8300004 - Do not have sim card.
   * @throws { BusinessError } 8300999 - Unknown error code.
   * @syscap SystemCapability.Telephony.CoreService
   * @systemapi Hide this for inner system use.
   * @since 8
   */
  function getShowName(slotId: number): Promise<string>;

  /**
   * Set the SIM card number in the specified slot.
   *
   * @permission ohos.permission.SET_TELEPHONY_STATE
   * @param { number } slotId - Indicates the card slot index number,
   * ranging from 0 to the maximum card slot index number supported by the device.
   * @param { string } number - Indicates SIM card number.
   * @param { AsyncCallback<void> } callback - The callback of setShowNumber.
   * @throws { BusinessError } 201 - Permission denied.
   * @throws { BusinessError } 202 - Non-system applications use system APIs.
   * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified.
   * 2. Incorrect parameter types.
   * @throws { BusinessError } 8300001 - Invalid parameter value.
   * @throws { BusinessError } 8300002 - Operation failed. Cannot connect to service.
   * @throws { BusinessError } 8300003 - System internal error.
   * @throws { BusinessError } 8300004 - Do not have sim card.
   * @throws { BusinessError } 8300999 - Unknown error code.
   * @syscap SystemCapability.Telephony.CoreService
   * @systemapi Hide this for inner system use.
   * @since 8
   */
  function setShowNumber(slotId: number, number: string, callback: AsyncCallback<void>): void;

  /**
   * Set the SIM card number in the specified slot.
   *
   * @permission ohos.permission.SET_TELEPHONY_STATE
   * @param { number } slotId - Indicates the card slot index number,
   * ranging from 0 to the maximum card slot index number supported by the device.
   * @param { string } number - Indicates SIM card number.
   * @returns { Promise<void> } The promise returned by the setShowNumber.
   * @throws { BusinessError } 201 - Permission denied.
   * @throws { BusinessError } 202 - Non-system applications use system APIs.
   * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified.
   * 2. Incorrect parameter types.
   * @throws { BusinessError } 8300001 - Invalid parameter value.
   * @throws { BusinessError } 8300002 - Operation failed. Cannot connect to service.
   * @throws { BusinessError } 8300003 - System internal error.
   * @throws { BusinessError } 8300004 - Do not have sim card.
   * @throws { BusinessError } 8300999 - Unknown error code.
   * @syscap SystemCapability.Telephony.CoreService
   * @systemapi Hide this for inner system use.
   * @since 8
   */
  function setShowNumber(slotId: number, number: string): Promise<void>;

  /**
   * Get the SIM card number of the specified card slot.
   *
   * @permission ohos.permission.GET_TELEPHONY_STATE
   * @param { number } slotId - Indicates the card slot index number,
   * ranging from 0 to the maximum card slot index number supported by the device.
   * @param { AsyncCallback<string> } callback - Indicates the callback for getting the SIM card number.
   * @throws { BusinessError } 201 - Permission denied.
   * @throws { BusinessError } 202 - Non-system applications use system APIs.
   * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified.
   * 2. Incorrect parameter types.
   * @throws { BusinessError } 8300001 - Invalid parameter value.
   * @throws { BusinessError } 8300002 - Operation failed. Cannot connect to service.
   * @throws { BusinessError } 8300003 - System internal error.
   * @throws { BusinessError } 8300004 - Do not have sim card.
   * @throws { BusinessError } 8300999 - Unknown error code.
   * @syscap SystemCapability.Telephony.CoreService
   * @systemapi Hide this for inner system use.
   * @since 8
   */
  function getShowNumber(slotId: number, callback: AsyncCallback<string>): void;

  /**
   * Get the SIM card number of the specified card slot.
   *
   * @permission ohos.permission.GET_TELEPHONY_STATE
   * @param { number } slotId - Indicates the card slot index number,
   * ranging from 0 to the maximum card slot index number supported by the device.
   * @returns { Promise<string> } Returns the SIM card number.
   * @throws { BusinessError } 201 - Permission denied.
   * @throws { BusinessError } 202 - Non-system applications use system APIs.
   * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified.
   * 2. Incorrect parameter types.
   * @throws { BusinessError } 8300001 - Invalid parameter value.
   * @throws { BusinessError } 8300002 - Operation failed. Cannot connect to service.
   * @throws { BusinessError } 8300003 - System internal error.
   * @throws { BusinessError } 8300004 - Do not have sim card.
   * @throws { BusinessError } 8300999 - Unknown error code.
   * @syscap SystemCapability.Telephony.CoreService
   * @systemapi Hide this for inner system use.
   * @since 8
   */
  function getShowNumber(slotId: number): Promise<string>;

  /**
   * Obtains the operatorconfigs of the SIM card in a specified slot.
   *
   * @permission ohos.permission.GET_TELEPHONY_STATE
   * @param { number } slotId - Indicates the card slot index number,
   * ranging from 0 to the maximum card slot index number supported by the device.
   * @param { AsyncCallback<Array<OperatorConfig>> } callback - Indicates the callback for
   * getting the operatorconfigs in a specified slot;
   * returns empty OperatorConfig if no SIM card is inserted.
   * @throws { BusinessError } 201 - Permission denied.
   * @throws { BusinessError } 202 - Non-system applications use system APIs.
   * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified.
   * 2. Incorrect parameter types.
   * @throws { BusinessError } 8300001 - Invalid parameter value.
   * @throws { BusinessError } 8300002 - Operation failed. Cannot connect to service.
   * @throws { BusinessError } 8300003 - System internal error.
   * @throws { BusinessError } 8300999 - Unknown error code.
   * @syscap SystemCapability.Telephony.CoreService
   * @systemapi Hide this for inner system use.
   * @since 8
   */
  function getOperatorConfigs(slotId: number, callback: AsyncCallback<Array<OperatorConfig>>): void;

  /**
   * Obtains the operatorconfigs of the SIM card in a specified slot.
   *
   * @permission ohos.permission.GET_TELEPHONY_STATE
   * @param { number } slotId - Indicates the card slot index number,
   * ranging from 0 to the maximum card slot index number supported by the device.
   * @returns { Promise<Array<OperatorConfig>> } Returns the operatorconfigs in a specified slot;
   * returns empty OperatorConfig if no SIM card is inserted.
   * @throws { BusinessError } 201 - Permission denied.
   * @throws { BusinessError } 202 - Non-system applications use system APIs.
   * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified.
   * 2. Incorrect parameter types.
   * @throws { BusinessError } 8300001 - Invalid parameter value.
   * @throws { BusinessError } 8300002 - Operation failed. Cannot connect to service.
   * @throws { BusinessError } 8300003 - System internal error.
   * @throws { BusinessError } 8300999 - Unknown error code.
   * @syscap SystemCapability.Telephony.CoreService
   * @systemapi Hide this for inner system use.
   * @since 8
   */
  function getOperatorConfigs(slotId: number): Promise<Array<OperatorConfig>>;

  /**
   * Unlock the SIM card password of the specified card slot.
   *
   * @permission ohos.permission.SET_TELEPHONY_STATE
   * @param { number } slotId - Indicates the card slot index number,
   * ranging from 0 to the maximum card slot index number supported by the device.
   * @param { string } pin - Indicates the password of the SIM card.
   * @param { AsyncCallback<LockStatusResponse> } callback - Indicates the callback for getting
   * the response to obtain the SIM card lock status of the specified card slot.
   * @throws { BusinessError } 201 - Permission denied.
   * @throws { BusinessError } 202 - Non-system applications use system APIs.
   * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified.
   * 2. Incorrect parameter types.
   * @throws { BusinessError } 8300001 - Invalid parameter value.
   * @throws { BusinessError } 8300002 - Operation failed. Cannot connect to service.
   * @throws { BusinessError } 8300003 - System internal error.
   * @throws { BusinessError } 8300004 - Do not have sim card.
   * @throws { BusinessError } 8300999 - Unknown error code.
   * @throws { BusinessError } 8301002 - SIM card operation error.
   * @syscap SystemCapability.Telephony.CoreService
   * @systemapi Hide this for inner system use.
   * @since 7
   */
  function unlockPin(slotId: number, pin: string, callback: AsyncCallback<LockStatusResponse>): void;

  /**
   * Unlock the SIM card password of the specified card slot.
   *
   * @permission ohos.permission.SET_TELEPHONY_STATE
   * @param { number } slotId - Indicates the card slot index number,
   * ranging from 0 to the maximum card slot index number supported by the device.
   * @param { string } pin - Indicates the password of the SIM card.
   * @returns { Promise<LockStatusResponse> } Returns the response to obtain
   * the SIM card lock status of the specified card slot.
   * @throws { BusinessError } 201 - Permission denied.
   * @throws { BusinessError } 202 - Non-system applications use system APIs.
   * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified.
   * 2. Incorrect parameter types.
   * @throws { BusinessError } 8300001 - Invalid parameter value.
   * @throws { BusinessError } 8300002 - Operation failed. Cannot connect to service.
   * @throws { BusinessError } 8300003 - System internal error.
   * @throws { BusinessError } 8300004 - Do not have sim card.
   * @throws { BusinessError } 8300999 - Unknown error code.
   * @throws { BusinessError } 8301002 - SIM card operation error.
   * @syscap SystemCapability.Telephony.CoreService
   * @systemapi Hide this for inner system use.
   * @since 7
   */
  function unlockPin(slotId: number, pin: string): Promise<LockStatusResponse>;

  /**
   * Unlock the SIM card password in the specified card slot.
   *
   * @permission ohos.permission.SET_TELEPHONY_STATE
   * @param { number } slotId - Indicates the card slot index number,
   * ranging from 0 to the maximum card slot index number supported by the device.
   * @param { string } newPin - Indicates to reset the SIM card password.
   * @param { string } puk - Indicates the unlock password of the SIM card password.
   * @param { AsyncCallback<LockStatusResponse> } callback - Indicates the callback for getting
   * the response to obtain the SIM card lock status of the specified card slot.
   * @throws { BusinessError } 201 - Permission denied.
   * @throws { BusinessError } 202 - Non-system applications use system APIs.
   * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified.
   * 2. Incorrect parameter types.
   * @throws { BusinessError } 8300001 - Invalid parameter value.
   * @throws { BusinessError } 8300002 - Operation failed. Cannot connect to service.
   * @throws { BusinessError } 8300003 - System internal error.
   * @throws { BusinessError } 8300004 - Do not have sim card.
   * @throws { BusinessError } 8300999 - Unknown error code.
   * @throws { BusinessError } 8301002 - SIM card operation error.
   * @syscap SystemCapability.Telephony.CoreService
   * @systemapi Hide this for inner system use.
   * @since 7
   */
  function unlockPuk(slotId: number, newPin: string, puk: string, callback: AsyncCallback<LockStatusResponse>): void;

  /**
   * Unlock the SIM card password in the specified card slot.
   *
   * @permission ohos.permission.SET_TELEPHONY_STATE
   * @param { number } slotId - Indicates the card slot index number,
   * ranging from 0 to the maximum card slot index number supported by the device.
   * @param { string } newPin - Indicates to reset the SIM card password.
   * @param { string } puk - Indicates the unlock password of the SIM card password.
   * @returns { Promise<LockStatusResponse> } Returns the response to obtain
   * the SIM card lock status of the specified card slot.
   * @throws { BusinessError } 201 - Permission denied.
   * @throws { BusinessError } 202 - Non-system applications use system APIs.
   * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified.
   * 2. Incorrect parameter types.
   * @throws { BusinessError } 8300001 - Invalid parameter value.
   * @throws { BusinessError } 8300002 - Operation failed. Cannot connect to service.
   * @throws { BusinessError } 8300003 - System internal error.
   * @throws { BusinessError } 8300004 - Do not have sim card.
   * @throws { BusinessError } 8300999 - Unknown error code.
   * @throws { BusinessError } 8301002 - SIM card operation error.
   * @syscap SystemCapability.Telephony.CoreService
   * @systemapi Hide this for inner system use.
   * @since 7
   */
  function unlockPuk(slotId: number, newPin: string, puk: string): Promise<LockStatusResponse>;

  /**
   * Change Pin Password.
   *
   * @permission ohos.permission.SET_TELEPHONY_STATE
   * @param { number } slotId - Indicates the card slot index number,
   * ranging from 0 to the maximum card slot index number supported by the device.
   * @param { string } newPin - Indicates a new password.
   * @param { string } oldPin - Indicates old password.
   * @param { AsyncCallback<LockStatusResponse> } callback - Indicates the callback for getting
   * the response to obtain the SIM card lock status of the specified card slot.
   * @throws { BusinessError } 201 - Permission denied.
   * @throws { BusinessError } 202 - Non-system applications use system APIs.
   * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified.
   * 2. Incorrect parameter types.
   * @throws { BusinessError } 8300001 - Invalid parameter value.
   * @throws { BusinessError } 8300002 - Operation failed. Cannot connect to service.
   * @throws { BusinessError } 8300003 - System internal error.
   * @throws { BusinessError } 8300004 - Do not have sim card.
   * @throws { BusinessError } 8300999 - Unknown error code.
   * @throws { BusinessError } 8301002 - SIM card operation error.
   * @syscap SystemCapability.Telephony.CoreService
   * @systemapi Hide this for inner system use.
   * @since 7
   */
  function alterPin(slotId: number, newPin: string, oldPin: string, callback: AsyncCallback<LockStatusResponse>): void;

  /**
   * Change Pin Password.
   *
   * @permission ohos.permission.SET_TELEPHONY_STATE
   * @param { number } slotId - Indicates the card slot index number,
   * ranging from 0 to the maximum card slot index number supported by the device.
   * @param { string } newPin - Indicates a new password.
   * @param { string } oldPin - Indicates old password.
   * @returns { Promise<LockStatusResponse> } Returns the response to obtain
   * the SIM card lock status of the specified card slot.
   * @throws { BusinessError } 201 - Permission denied.
   * @throws { BusinessError } 202 - Non-system applications use system APIs.
   * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified.
   * 2. Incorrect parameter types.
   * @throws { BusinessError } 8300001 - Invalid parameter value.
   * @throws { BusinessError } 8300002 - Operation failed. Cannot connect to service.
   * @throws { BusinessError } 8300003 - System internal error.
   * @throws { BusinessError } 8300004 - Do not have sim card.
   * @throws { BusinessError } 8300999 - Unknown error code.
   * @throws { BusinessError } 8301002 - SIM card operation error.
   * @syscap SystemCapability.Telephony.CoreService
   * @systemapi Hide this for inner system use.
   * @since 7
   */
  function alterPin(slotId: number, newPin: string, oldPin: string): Promise<LockStatusResponse>;

  /**
   * Set the lock status of the SIM card in the specified slot.
   *
   * @permission ohos.permission.SET_TELEPHONY_STATE
   * @param { number } slotId - Indicates the card slot index number,
   * ranging from 0 to the maximum card slot index number supported by the device.
   * @param { LockInfo } options - Indicates lock information.
   * @param { AsyncCallback<LockStatusResponse> } callback - Indicates the callback for getting
   * the response to obtain the SIM card lock status of the specified card slot.
   * @throws { BusinessError } 201 - Permission denied.
   * @throws { BusinessError } 202 - Non-system applications use system APIs.
   * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified.
   * 2. Incorrect parameter types.
   * @throws { BusinessError } 8300001 - Invalid parameter value.
   * @throws { BusinessError } 8300002 - Operation failed. Cannot connect to service.
   * @throws { BusinessError } 8300003 - System internal error.
   * @throws { BusinessError } 8300004 - Do not have sim card.
   * @throws { BusinessError } 8300999 - Unknown error code.
   * @throws { BusinessError } 8301002 - SIM card operation error.
   * @syscap SystemCapability.Telephony.CoreService
   * @systemapi Hide this for inner system use.
   * @since 7
   */
  function setLockState(slotId: number, options: LockInfo, callback: AsyncCallback<LockStatusResponse>): void;

  /**
   * Set the lock status of the SIM card in the specified slot.
   *
   * @permission ohos.permission.SET_TELEPHONY_STATE
   * @param { number } slotId - Indicates the card slot index number,
   * ranging from 0 to the maximum card slot index number supported by the device.
   * @param { LockInfo } options - Indicates lock information.
   * @returns { Promise<LockStatusResponse> } Returns the response to obtain
   * the SIM card lock status of the specified card slot.
   * @throws { BusinessError } 201 - Permission denied.
   * @throws { BusinessError } 202 - Non-system applications use system APIs.
   * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified.
   * 2. Incorrect parameter types.
   * @throws { BusinessError } 8300001 - Invalid parameter value.
   * @throws { BusinessError } 8300002 - Operation failed. Cannot connect to service.
   * @throws { BusinessError } 8300003 - System internal error.
   * @throws { BusinessError } 8300004 - Do not have sim card.
   * @throws { BusinessError } 8300999 - Unknown error code.
   * @throws { BusinessError } 8301002 - SIM card operation error.
   * @syscap SystemCapability.Telephony.CoreService
   * @systemapi Hide this for inner system use.
   * @since 7
   */
  function setLockState(slotId: number, options: LockInfo): Promise<LockStatusResponse>;

  /**
   * Unlock the SIM card password of the specified card slot.
   *
   * @permission ohos.permission.SET_TELEPHONY_STATE
   * @param { number } slotId - Indicates the card slot index number,
   * ranging from 0 to the maximum card slot index number supported by the device.
   * @param { string } pin2 - Indicates the password of the SIM card.
   * @param { AsyncCallback<LockStatusResponse> } callback - Indicates the callback for getting
   * the response to obtain the SIM card lock status of the specified card slot.
   * @throws { BusinessError } 201 - Permission denied.
   * @throws { BusinessError } 202 - Non-system applications use system APIs.
   * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified.
   * 2. Incorrect parameter types.
   * @throws { BusinessError } 8300001 - Invalid parameter value.
   * @throws { BusinessError } 8300002 - Operation failed. Cannot connect to service.
   * @throws { BusinessError } 8300003 - System internal error.
   * @throws { BusinessError } 8300004 - Do not have sim card.
   * @throws { BusinessError } 8300999 - Unknown error code.
   * @throws { BusinessError } 8301002 - SIM card operation error.
   * @syscap SystemCapability.Telephony.CoreService
   * @systemapi Hide this for inner system use.
   * @since 8
   */
  function unlockPin2(slotId: number, pin2: string, callback: AsyncCallback<LockStatusResponse>): void;

  /**
   * Unlock the SIM card password of the specified card slot.
   *
   * @permission ohos.permission.SET_TELEPHONY_STATE
   * @param { number } slotId - Indicates the card slot index number,
   * ranging from 0 to the maximum card slot index number supported by the device.
   * @param { string } pin2 - Indicates the password of the SIM card.
   * @returns { Promise<LockStatusResponse> } Returns the response to obtain
   * the SIM card lock status of the specified card slot.
   * @throws { BusinessError } 201 - Permission denied.
   * @throws { BusinessError } 202 - Non-system applications use system APIs.
   * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified.
   * 2. Incorrect parameter types.
   * @throws { BusinessError } 8300001 - Invalid parameter value.
   * @throws { BusinessError } 8300002 - Operation failed. Cannot connect to service.
   * @throws { BusinessError } 8300003 - System internal error.
   * @throws { BusinessError } 8300004 - Do not have sim card.
   * @throws { BusinessError } 8300999 - Unknown error code.
   * @throws { BusinessError } 8301002 - SIM card operation error.
   * @syscap SystemCapability.Telephony.CoreService
   * @systemapi Hide this for inner system use.
   * @since 8
   */
  function unlockPin2(slotId: number, pin2: string): Promise<LockStatusResponse>;

  /**
   * Unlock the SIM card password in the specified card slot.
   *
   * @permission ohos.permission.SET_TELEPHONY_STATE
   * @param { number } slotId - Indicates the card slot index number,
   * ranging from 0 to the maximum card slot index number supported by the device.
   * @param { string } newPin2 - Indicates to reset the SIM card password.
   * @param { string } puk2 - Indicates the unlock password of the SIM card password.
   * @param { AsyncCallback<LockStatusResponse> } callback - Indicates the callback for getting
   * the response to obtain the SIM card lock status of the specified card slot.
   * @throws { BusinessError } 201 - Permission denied.
   * @throws { BusinessError } 202 - Non-system applications use system APIs.
   * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified.
   * 2. Incorrect parameter types.
   * @throws { BusinessError } 8300001 - Invalid parameter value.
   * @throws { BusinessError } 8300002 - Operation failed. Cannot connect to service.
   * @throws { BusinessError } 8300003 - System internal error.
   * @throws { BusinessError } 8300004 - Do not have sim card.
   * @throws { BusinessError } 8300999 - Unknown error code.
   * @throws { BusinessError } 8301002 - SIM card operation error.
   * @syscap SystemCapability.Telephony.CoreService
   * @systemapi Hide this for inner system use.
   * @since 8
   */
  function unlockPuk2(slotId: number, newPin2: string, puk2: string, callback: AsyncCallback<LockStatusResponse>): void;

  /**
   * Unlock the SIM card password in the specified card slot.
   *
   * @permission ohos.permission.SET_TELEPHONY_STATE
   * @param { number } slotId - Indicates the card slot index number,
   * ranging from 0 to the maximum card slot index number supported by the device.
   * @param { string } newPin2 - Indicates to reset the SIM card password.
   * @param { string } puk2 - Indicates the unlock password of the SIM card password.
   * @returns { Promise<LockStatusResponse> } Returns the response to obtain
   * the SIM card lock status of the specified card slot.
   * @throws { BusinessError } 201 - Permission denied.
   * @throws { BusinessError } 202 - Non-system applications use system APIs.
   * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified.
   * 2. Incorrect parameter types.
   * @throws { BusinessError } 8300001 - Invalid parameter value.
   * @throws { BusinessError } 8300002 - Operation failed. Cannot connect to service.
   * @throws { BusinessError } 8300003 - System internal error.
   * @throws { BusinessError } 8300004 - Do not have sim card.
   * @throws { BusinessError } 8300999 - Unknown error code.
   * @throws { BusinessError } 8301002 - SIM card operation error.
   * @syscap SystemCapability.Telephony.CoreService
   * @systemapi Hide this for inner system use.
   * @since 8
   */
  function unlockPuk2(slotId: number, newPin2: string, puk2: string): Promise<LockStatusResponse>;

  /**
   * Change Pin2 password.
   *
   * @permission ohos.permission.SET_TELEPHONY_STATE
   * @param { number } slotId - Indicates the card slot index number,
   * ranging from 0 to the maximum card slot index number supported by the device.
   * @param { string } newPin2 - Indicates a new password.
   * @param { string } oldPin2 - Indicates old password.
   * @param { AsyncCallback<LockStatusResponse> } callback - Indicates the callback for getting
   * the response to obtain the SIM card lock status of the specified card slot.
   * @throws { BusinessError } 201 - Permission denied.
   * @throws { BusinessError } 202 - Non-system applications use system APIs.
   * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified.
   * 2. Incorrect parameter types.
   * @throws { BusinessError } 8300001 - Invalid parameter value.
   * @throws { BusinessError } 8300002 - Operation failed. Cannot connect to service.
   * @throws { BusinessError } 8300003 - System internal error.
   * @throws { BusinessError } 8300004 - Do not have sim card.
   * @throws { BusinessError } 8300999 - Unknown error code.
   * @throws { BusinessError } 8301002 - SIM card operation error.
   * @syscap SystemCapability.Telephony.CoreService
   * @systemapi Hide this for inner system use.
   * @since 8
   */
  function alterPin2(slotId: number, newPin2: string, oldPin2: string, callback: AsyncCallback<LockStatusResponse>): void;

  /**
   * Change Pin2 password.
   *
   * @permission ohos.permission.SET_TELEPHONY_STATE
   * @param { number } slotId - Indicates the card slot index number,
   * ranging from 0 to the maximum card slot index number supported by the device.
   * @param { string } newPin2 - Indicates a new password.
   * @param { string } oldPin2 - Indicates old password.
   * @returns { Promise<LockStatusResponse> } Returns the response to obtain
   * the SIM card lock status of the specified card slot.
   * @throws { BusinessError } 201 - Permission denied.
   * @throws { BusinessError } 202 - Non-system applications use system APIs.
   * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified.
   * 2. Incorrect parameter types.
   * @throws { BusinessError } 8300001 - Invalid parameter value.
   * @throws { BusinessError } 8300002 - Operation failed. Cannot connect to service.
   * @throws { BusinessError } 8300003 - System internal error.
   * @throws { BusinessError } 8300004 - Do not have sim card.
   * @throws { BusinessError } 8300999 - Unknown error code.
   * @throws { BusinessError } 8301002 - SIM card operation error.
   * @syscap SystemCapability.Telephony.CoreService
   * @systemapi Hide this for inner system use.
   * @since 8
   */
  function alterPin2(slotId: number, newPin2: string, oldPin2: string): Promise<LockStatusResponse>;

  /**
   * Query dialing number information on SIM card.
   *
   * @permission ohos.permission.READ_CONTACTS
   * @param { number } slotId - Indicates the card slot index number,
   * ranging from 0 to the maximum card slot index number supported by the device.
   * @param { ContactType } type - Indicates contact type.
   * @param { AsyncCallback<Array<DiallingNumbersInfo>> } callback - Indicates the callback for
   * getting the dialing number information.
   * @throws { BusinessError } 201 - Permission denied.
   * @throws { BusinessError } 202 - Non-system applications use system APIs.
   * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified.
   * 2. Incorrect parameter types.
   * @throws { BusinessError } 8300001 - Invalid parameter value.
   * @throws { BusinessError } 8300002 - Operation failed. Cannot connect to service.
   * @throws { BusinessError } 8300003 - System internal error.
   * @throws { BusinessError } 8300004 - Do not have sim card.
   * @throws { BusinessError } 8300999 - Unknown error code.
   * @throws { BusinessError } 8301002 - SIM card operation error.
   * @syscap SystemCapability.Telephony.CoreService
   * @systemapi Hide this for inner system use.
   * @since 8
   */
  function queryIccDiallingNumbers(slotId: number, type: ContactType, callback: AsyncCallback<Array<DiallingNumbersInfo>>): void;

  /**
   * Query dialing number information on SIM card.
   *
   * @permission ohos.permission.READ_CONTACTS
   * @param { number } slotId - Indicates the card slot index number,
   * ranging from 0 to the maximum card slot index number supported by the device.
   * @param { ContactType } type - Indicates contact type.
   * @returns { Promise<Array<DiallingNumbersInfo>> } Returns the dialing number information.
   * @throws { BusinessError } 201 - Permission denied.
   * @throws { BusinessError } 202 - Non-system applications use system APIs.
   * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified.
   * 2. Incorrect parameter types.
   * @throws { BusinessError } 8300001 - Invalid parameter value.
   * @throws { BusinessError } 8300002 - Operation failed. Cannot connect to service.
   * @throws { BusinessError } 8300003 - System internal error.
   * @throws { BusinessError } 8300004 - Do not have sim card.
   * @throws { BusinessError } 8300999 - Unknown error code.
   * @throws { BusinessError } 8301002 - SIM card operation error.
   * @syscap SystemCapability.Telephony.CoreService
   * @systemapi Hide this for inner system use.
   * @since 8
   */
  function queryIccDiallingNumbers(slotId: number, type: ContactType): Promise<Array<DiallingNumbersInfo>>;

  /**
   * Add dialing number information to SIM card.
   *
   * @permission ohos.permission.WRITE_CONTACTS
   * @param { number } slotId - Indicates the card slot index number,
   * ranging from 0 to the maximum card slot index number supported by the device.
   * @param { ContactType } type - Indicates contact type.
   * @param { DiallingNumbersInfo } diallingNumbers - Indicates dialing number information.
   * @param { AsyncCallback<void> } callback - The callback of addIccDiallingNumbers.
   * @throws { BusinessError } 201 - Permission denied.
   * @throws { BusinessError } 202 - Non-system applications use system APIs.
   * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified.
   * 2. Incorrect parameter types.
   * @throws { BusinessError } 8300001 - Invalid parameter value.
   * @throws { BusinessError } 8300002 - Operation failed. Cannot connect to service.
   * @throws { BusinessError } 8300003 - System internal error.
   * @throws { BusinessError } 8300004 - Do not have sim card.
   * @throws { BusinessError } 8300999 - Unknown error code.
   * @throws { BusinessError } 8301002 - SIM card operation error.
   * @syscap SystemCapability.Telephony.CoreService
   * @systemapi Hide this for inner system use.
   * @since 8
   */
  function addIccDiallingNumbers(slotId: number, type: ContactType, diallingNumbers: DiallingNumbersInfo, callback: AsyncCallback<void>): void;

  /**
   * Add dialing number information to SIM card.
   *
   * @permission ohos.permission.WRITE_CONTACTS
   * @param { number } slotId - Indicates the card slot index number,
   * ranging from 0 to the maximum card slot index number supported by the device.
   * @param { ContactType } type - Indicates contact type.
   * @param { DiallingNumbersInfo } diallingNumbers - Indicates dialing number information.
   * @returns { Promise<void> } The promise returned by the addIccDiallingNumbers.
   * @throws { BusinessError } 201 - Permission denied.
   * @throws { BusinessError } 202 - Non-system applications use system APIs.
   * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified.
   * 2. Incorrect parameter types.
   * @throws { BusinessError } 8300001 - Invalid parameter value.
   * @throws { BusinessError } 8300002 - Operation failed. Cannot connect to service.
   * @throws { BusinessError } 8300003 - System internal error.
   * @throws { BusinessError } 8300004 - Do not have sim card.
   * @throws { BusinessError } 8300999 - Unknown error code.
   * @throws { BusinessError } 8301002 - SIM card operation error.
   * @syscap SystemCapability.Telephony.CoreService
   * @systemapi Hide this for inner system use.
   * @since 8
   */
  function addIccDiallingNumbers(slotId: number, type: ContactType, diallingNumbers: DiallingNumbersInfo): Promise<void>;

  /**
   * Delete dialing number information on SIM card.
   *
   * @permission ohos.permission.WRITE_CONTACTS
   * @param { number } slotId - Indicates the card slot index number,
   * ranging from 0 to the maximum card slot index number supported by the device.
   * @param { ContactType } type - Indicates contact type.
   * @param { DiallingNumbersInfo } diallingNumbers - Indicates dialing number information.
   * @param { AsyncCallback<void> } callback - The callback of delIccDiallingNumbers.
   * @throws { BusinessError } 201 - Permission denied.
   * @throws { BusinessError } 202 - Non-system applications use system APIs.
   * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified.
   * 2. Incorrect parameter types.
   * @throws { BusinessError } 8300001 - Invalid parameter value.
   * @throws { BusinessError } 8300002 - Operation failed. Cannot connect to service.
   * @throws { BusinessError } 8300003 - System internal error.
   * @throws { BusinessError } 8300004 - Do not have sim card.
   * @throws { BusinessError } 8300999 - Unknown error code.
   * @throws { BusinessError } 8301002 - SIM card operation error.
   * @syscap SystemCapability.Telephony.CoreService
   * @systemapi Hide this for inner system use.
   * @since 8
   */
  function delIccDiallingNumbers(slotId: number, type: ContactType, diallingNumbers: DiallingNumbersInfo, callback: AsyncCallback<void>): void;

  /**
   * Delete dialing number information on SIM card.
   *
   * @permission ohos.permission.WRITE_CONTACTS
   * @param { number } slotId - Indicates the card slot index number,
   * ranging from 0 to the maximum card slot index number supported by the device.
   * @param { ContactType } type - Indicates contact type.
   * @param { DiallingNumbersInfo } diallingNumbers - Indicates dialing number information.
   * @returns { Promise<void> } The promise returned by the delIccDiallingNumbers.
   * @throws { BusinessError } 201 - Permission denied.
   * @throws { BusinessError } 202 - Non-system applications use system APIs.
   * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified.
   * 2. Incorrect parameter types.
   * @throws { BusinessError } 8300001 - Invalid parameter value.
   * @throws { BusinessError } 8300002 - Operation failed. Cannot connect to service.
   * @throws { BusinessError } 8300003 - System internal error.
   * @throws { BusinessError } 8300004 - Do not have sim card.
   * @throws { BusinessError } 8300999 - Unknown error code.
   * @throws { BusinessError } 8301002 - SIM card operation error.
   * @syscap SystemCapability.Telephony.CoreService
   * @systemapi Hide this for inner system use.
   * @since 8
   */
  function delIccDiallingNumbers(slotId: number, type: ContactType, diallingNumbers: DiallingNumbersInfo): Promise<void>;

  /**
   * Update dialing number information on SIM card.
   *
   * @permission ohos.permission.WRITE_CONTACTS
   * @param { number } slotId - Indicates the card slot index number,
   * ranging from 0 to the maximum card slot index number supported by the device.
   * @param { ContactType } type - Indicates contact type.
   * @param { DiallingNumbersInfo } diallingNumbers - Indicates dialing number information.
   * @param { AsyncCallback<void> } callback - The callback of updateIccDiallingNumbers.
   * @throws { BusinessError } 201 - Permission denied.
   * @throws { BusinessError } 202 - Non-system applications use system APIs.
   * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified.
   * 2. Incorrect parameter types.
   * @throws { BusinessError } 8300001 - Invalid parameter value.
   * @throws { BusinessError } 8300002 - Operation failed. Cannot connect to service.
   * @throws { BusinessError } 8300003 - System internal error.
   * @throws { BusinessError } 8300004 - Do not have sim card.
   * @throws { BusinessError } 8300999 - Unknown error code.
   * @throws { BusinessError } 8301002 - SIM card operation error.
   * @syscap SystemCapability.Telephony.CoreService
   * @systemapi Hide this for inner system use.
   * @since 8
   */
  function updateIccDiallingNumbers(slotId: number, type: ContactType, diallingNumbers: DiallingNumbersInfo, callback: AsyncCallback<void>): void;

  /**
   * Update dialing number information on SIM card.
   *
   * @permission ohos.permission.WRITE_CONTACTS
   * @param { number } slotId - Indicates the card slot index number,
   * ranging from 0 to the maximum card slot index number supported by the device.
   * @param { ContactType } type - Indicates contact type.
   * @param { DiallingNumbersInfo } diallingNumbers - Indicates dialing number information.
   * @returns { Promise<void> } The promise returned by the updateIccDiallingNumbers.
   * @throws { BusinessError } 201 - Permission denied.
   * @throws { BusinessError } 202 - Non-system applications use system APIs.
   * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified.
   * 2. Incorrect parameter types.
   * @throws { BusinessError } 8300001 - Invalid parameter value.
   * @throws { BusinessError } 8300002 - Operation failed. Cannot connect to service.
   * @throws { BusinessError } 8300003 - System internal error.
   * @throws { BusinessError } 8300004 - Do not have sim card.
   * @throws { BusinessError } 8300999 - Unknown error code.
   * @throws { BusinessError } 8301002 - SIM card operation error.
   * @syscap SystemCapability.Telephony.CoreService
   * @systemapi Hide this for inner system use.
   * @since 8
   */
  function updateIccDiallingNumbers(slotId: number, type: ContactType, diallingNumbers: DiallingNumbersInfo): Promise<void>;

  /**
   * Get the lock status of the SIM card in the specified slot.
   *
   * @permission ohos.permission.GET_TELEPHONY_STATE
   * @param { number } slotId - Indicates the card slot index number,
   * ranging from 0 to the maximum card slot index number supported by the device.
   * @param { LockType } lockType - Indicates the lock type.
   * @param { AsyncCallback<LockState> } callback - Indicates the callback for getting the sim card lock status.
   * @throws { BusinessError } 201 - Permission denied.
   * @throws { BusinessError } 202 - Non-system applications use system APIs.
   * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified.
   * 2. Incorrect parameter types.
   * @throws { BusinessError } 8300001 - Invalid parameter value.
   * @throws { BusinessError } 8300002 - Operation failed. Cannot connect to service.
   * @throws { BusinessError } 8300003 - System internal error.
   * @throws { BusinessError } 8300004 - Do not have sim card.
   * @throws { BusinessError } 8300999 - Unknown error code.
   * @throws { BusinessError } 8301002 - SIM card operation error.
   * @syscap SystemCapability.Telephony.CoreService
   * @systemapi Hide this for inner system use.
   * @since 8
   */
  function getLockState(slotId: number, lockType: LockType, callback: AsyncCallback<LockState>): void;

  /**
   * Get the lock status of the SIM card in the specified slot.
   *
   * @permission ohos.permission.GET_TELEPHONY_STATE
   * @param { number } slotId - Indicates the card slot index number,
   * ranging from 0 to the maximum card slot index number supported by the device.
   * @param { LockType } lockType - Indicates the lock type.
   * @returns { Promise<LockState> } Returns the sim card lock status.
   * @throws { BusinessError } 201 - Permission denied.
   * @throws { BusinessError } 202 - Non-system applications use system APIs.
   * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified.
   * 2. Incorrect parameter types.
   * @throws { BusinessError } 8300001 - Invalid parameter value.
   * @throws { BusinessError } 8300002 - Operation failed. Cannot connect to service.
   * @throws { BusinessError } 8300003 - System internal error.
   * @throws { BusinessError } 8300004 - Do not have sim card.
   * @throws { BusinessError } 8300999 - Unknown error code.
   * @throws { BusinessError } 8301002 - SIM card operation error.
   * @syscap SystemCapability.Telephony.CoreService
   * @systemapi Hide this for inner system use.
   * @since 8
   */
  function getLockState(slotId: number, lockType: LockType): Promise<LockState>;

  /**
   * Send envelope command to SIM card.
   *
   * @permission ohos.permission.SET_TELEPHONY_STATE
   * @param { number } slotId - Indicates the card slot index number,
   * ranging from 0 to the maximum card slot index number supported by the device.
   * @param { string } cmd - Indicates sending command.
   * @param { AsyncCallback<void> } callback - The callback of sendEnvelopeCmd.
   * @throws { BusinessError } 201 - Permission denied.
   * @throws { BusinessError } 202 - Non-system applications use system APIs.
   * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified.
   * 2. Incorrect parameter types.
   * @throws { BusinessError } 8300001 - Invalid parameter value.
   * @throws { BusinessError } 8300002 - Operation failed. Cannot connect to service.
   * @throws { BusinessError } 8300003 - System internal error.
   * @throws { BusinessError } 8300004 - Do not have sim card.
   * @throws { BusinessError } 8300999 - Unknown error code.
   * @syscap SystemCapability.Telephony.CoreService
   * @systemapi Hide this for inner system use.
   * @since 8
   */
  function sendEnvelopeCmd(slotId: number, cmd: string, callback: AsyncCallback<void>): void;

  /**
   * Send envelope command to SIM card.
   *
   * @permission ohos.permission.SET_TELEPHONY_STATE
   * @param { number } slotId - Indicates the card slot index number,
   * ranging from 0 to the maximum card slot index number supported by the device.
   * @param { string } cmd - Indicates sending command.
   * @returns { Promise<void> } The promise returned by the sendEnvelopeCmd.
   * @throws { BusinessError } 201 - Permission denied.
   * @throws { BusinessError } 202 - Non-system applications use system APIs.
   * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified.
   * 2. Incorrect parameter types.
   * @throws { BusinessError } 8300001 - Invalid parameter value.
   * @throws { BusinessError } 8300002 - Operation failed. Cannot connect to service.
   * @throws { BusinessError } 8300003 - System internal error.
   * @throws { BusinessError } 8300004 - Do not have sim card.
   * @throws { BusinessError } 8300999 - Unknown error code.
   * @syscap SystemCapability.Telephony.CoreService
   * @systemapi Hide this for inner system use.
   * @since 8
   */
  function sendEnvelopeCmd(slotId: number, cmd: string): Promise<void>;

  /**
   * Send terminal response command to SIM card.
   *
   * @permission ohos.permission.SET_TELEPHONY_STATE
   * @param { number } slotId - Indicates the card slot index number,
   * ranging from 0 to the maximum card slot index number supported by the device.
   * @param { string } cmd - Indicates sending command.
   * @param { AsyncCallback<void> } callback - The callback of sendTerminalResponseCmd.
   * @throws { BusinessError } 201 - Permission denied.
   * @throws { BusinessError } 202 - Non-system applications use system APIs.
   * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified.
   * 2. Incorrect parameter types.
   * @throws { BusinessError } 8300001 - Invalid parameter value.
   * @throws { BusinessError } 8300002 - Operation failed. Cannot connect to service.
   * @throws { BusinessError } 8300003 - System internal error.
   * @throws { BusinessError } 8300004 - Do not have sim card.
   * @throws { BusinessError } 8300999 - Unknown error code.
   * @syscap SystemCapability.Telephony.CoreService
   * @systemapi Hide this for inner system use.
   * @since 8
   */
  function sendTerminalResponseCmd(slotId: number, cmd: string, callback: AsyncCallback<void>): void;

  /**
   * Send terminal response command to SIM card.
   *
   * @permission ohos.permission.SET_TELEPHONY_STATE
   * @param { number } slotId - Indicates the card slot index number,
   * ranging from 0 to the maximum card slot index number supported by the device.
   * @param { string } cmd - Indicates sending command.
   * @returns { Promise<void> } The promise returned by the sendTerminalResponseCmd.
   * @throws { BusinessError } 201 - Permission denied.
   * @throws { BusinessError } 202 - Non-system applications use system APIs.
   * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified.
   * 2. Incorrect parameter types.
   * @throws { BusinessError } 8300001 - Invalid parameter value.
   * @throws { BusinessError } 8300002 - Operation failed. Cannot connect to service.
   * @throws { BusinessError } 8300003 - System internal error.
   * @throws { BusinessError } 8300004 - Do not have sim card.
   * @throws { BusinessError } 8300999 - Unknown error code.
   * @syscap SystemCapability.Telephony.CoreService
   * @systemapi Hide this for inner system use.
   * @since 8
   */
  function sendTerminalResponseCmd(slotId: number, cmd: string): Promise<void>;


  /**
   * Unlock SIM card.
   *
   * @permission ohos.permission.SET_TELEPHONY_STATE
   * @param { number } slotId - Indicates the card slot index number,
   * ranging from 0 to the maximum card slot index number supported by the device.
   * @param { PersoLockInfo } lockInfo - Indicates customized lock type information.
   * @param { AsyncCallback<LockStatusResponse> } callback - Indicates the callback used to obtain a response
   * to obtain the SIM card lock status for the specified card slot.
   * @throws { BusinessError } 201 - Permission denied.
   * @throws { BusinessError } 202 - Non-system applications use system APIs.
   * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified.
   * 2. Incorrect parameter types.
   * @throws { BusinessError } 8300001 - Invalid parameter value.
   * @throws { BusinessError } 8300002 - Operation failed. Cannot connect to service.
   * @throws { BusinessError } 8300003 - System internal error.
   * @throws { BusinessError } 8300004 - Do not have sim card.
   * @throws { BusinessError } 8300999 - Unknown error code.
   * @throws { BusinessError } 8301002 - SIM card operation error.
   * @syscap SystemCapability.Telephony.CoreService
   * @systemapi Hide this for inner system use.
   * @since 8
   */
  function unlockSimLock(slotId: number, lockInfo: PersoLockInfo, callback: AsyncCallback<LockStatusResponse>): void;

  /**
   * Unlock SIM card.
   *
   * @permission ohos.permission.SET_TELEPHONY_STATE
   * @param { number } slotId - Indicates the card slot index number,
   * ranging from 0 to the maximum card slot index number supported by the device.
   * @param { PersoLockInfo } lockInfo - Indicates customized lock type information.
   * @returns { Promise<LockStatusResponse> } Returns the response to obtain
   * the SIM card lock status of the specified card slot.
   * @throws { BusinessError } 201 - Permission denied.
   * @throws { BusinessError } 202 - Non-system applications use system APIs.
   * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified.
   * 2. Incorrect parameter types.
   * @throws { BusinessError } 8300001 - Invalid parameter value.
   * @throws { BusinessError } 8300002 - Operation failed. Cannot connect to service.
   * @throws { BusinessError } 8300003 - System internal error.
   * @throws { BusinessError } 8300004 - Do not have sim card.
   * @throws { BusinessError } 8300999 - Unknown error code.
   * @throws { BusinessError } 8301002 - SIM card operation error.
   * @syscap SystemCapability.Telephony.CoreService
   * @systemapi Hide this for inner system use.
   * @since 8
   */
  function unlockSimLock(slotId: number, lockInfo: PersoLockInfo): Promise<LockStatusResponse>;

  /**
   * Obtains the operator key of the SIM card in a specified slot.
   *
   * @param { number } slotId - Indicates the card slot index number,
   * ranging from 0 to the maximum card slot index number supported by the device.
   * @param { AsyncCallback<string> } callback - Indicates the callback for getting the operator key;
   * Returns an empty string if no SIM card is inserted or no operator key matched.
   * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified.
   * 2. Incorrect parameter types.
   * @throws { BusinessError } 801 - Capability not supported.
   * @throws { BusinessError } 8300001 - Invalid parameter value.
   * @throws { BusinessError } 8300002 - Operation failed. Cannot connect to service.
   * @throws { BusinessError } 8300003 - System internal error.
   * @throws { BusinessError } 8300999 - Unknown error code.
   * @syscap SystemCapability.Telephony.CoreService
   * @since 9
   */
  function getOpKey(slotId: number, callback: AsyncCallback<string>): void;

  /**
   * Obtains the operator key of the SIM card in a specified slot.
   *
   * @param { number } slotId - Indicates the card slot index number,
   * ranging from 0 to the maximum card slot index number supported by the device.
   * @returns { Promise<string> } Returns the operator key;
   * Returns an empty string if no SIM card is inserted or no operator key matched.
   * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified.
   * 2. Incorrect parameter types.
   * @throws { BusinessError } 801 - Capability not supported.
   * @throws { BusinessError } 8300001 - Invalid parameter value.
   * @throws { BusinessError } 8300002 - Operation failed. Cannot connect to service.
   * @throws { BusinessError } 8300003 - System internal error.
   * @throws { BusinessError } 8300999 - Unknown error code.
   * @syscap SystemCapability.Telephony.CoreService
   * @since 9
   */
  function getOpKey(slotId: number): Promise<string>;

  /**
   * Obtains the operator key of the SIM card in a specified slot.
   *
   * @param { number } slotId - Indicates the card slot index number,
   * ranging from 0 to the maximum card slots supported by the device.
   * @returns { string } Returns the operator key; returns an empty string if no SIM card is inserted or
   * no operator key is matched.
   * @syscap SystemCapability.Telephony.CoreService
   * @since 10
   */
  function getOpKeySync(slotId: number): string;

  /**
   * Obtains the operator name of the SIM card in a specified slot.
   *
   * @param { number } slotId - Indicates the card slot index number,
   * ranging from 0 to the maximum card slot index number supported by the device.
   * @param { AsyncCallback<string> } callback - Indicates the callback for getting the operator name;
   * Returns an empty string if no SIM card is inserted or no operator name matched.
   * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified.
   * 2. Incorrect parameter types.
   * @throws { BusinessError } 801 - Capability not supported.
   * @throws { BusinessError } 8300001 - Invalid parameter value.
   * @throws { BusinessError } 8300002 - Operation failed. Cannot connect to service.
   * @throws { BusinessError } 8300003 - System internal error.
   * @throws { BusinessError } 8300999 - Unknown error code.
   * @syscap SystemCapability.Telephony.CoreService
   * @since 9
   */
  function getOpName(slotId: number, callback: AsyncCallback<string>): void;

  /**
   * Obtains the operator name of the SIM card in a specified slot.
   *
   * @param { number } slotId - Indicates the card slot index number,
   * ranging from 0 to the maximum card slot index number supported by the device.
   * @returns { Promise<string> } Returns the operator name; returns an empty string if no SIM card is inserted or
   * no operator name matched.
   * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified.
   * 2. Incorrect parameter types.
   * @throws { BusinessError } 801 - Capability not supported.
   * @throws { BusinessError } 8300001 - Invalid parameter value.
   * @throws { BusinessError } 8300002 - Operation failed. Cannot connect to service.
   * @throws { BusinessError } 8300003 - System internal error.
   * @throws { BusinessError } 8300999 - Unknown error code.
   * @syscap SystemCapability.Telephony.CoreService
   * @since 9
   */
  function getOpName(slotId: number): Promise<string>;

  /**
   * Obtains the operator name of the SIM card in a specified slot.
   *
   * @param { number } slotId - Indicates the card slot index number,
   * ranging from 0 to the maximum card slots supported by the device.
   * @returns { string } Returns the operator name; returns an empty string if no SIM card is inserted or
   * no operator name is matched.
   * @syscap SystemCapability.Telephony.CoreService
   * @since 10
   */
  function getOpNameSync(slotId: number): string;

  /**
   * Obtains the default SIM ID for the voice service.
   *
   * @param { AsyncCallback<number> } callback - Returns the SIM ID of the default voice sim
   * and SIM ID will increase from 1.
   * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified.
   * 2. Incorrect parameter types.
   * @throws { BusinessError } 8300001 - Invalid parameter value.
   * @throws { BusinessError } 8300002 - Operation failed. Cannot connect to service.
   * @throws { BusinessError } 8300003 - System internal error.
   * @throws { BusinessError } 8300004 - Do not have sim card.
   * @throws { BusinessError } 8300999 - Unknown error code.
   * @throws { BusinessError } 8301001 - SIM card is not activated.
   * @syscap SystemCapability.Telephony.CoreService
   * @since 10
   */
  function getDefaultVoiceSimId(callback: AsyncCallback<number>): void;

  /**
   * Obtains the default SIM ID for the voice service.
   *
   * @returns { Promise<number> } Returns the SIM ID of the default voice sim
   * and SIM ID will increase from 1.
   * @throws { BusinessError } 8300001 - Invalid parameter value.
   * @throws { BusinessError } 8300002 - Operation failed. Cannot connect to service.
   * @throws { BusinessError } 8300003 - System internal error.
   * @throws { BusinessError } 8300004 - Do not have sim card.
   * @throws { BusinessError } 8300999 - Unknown error code.
   * @throws { BusinessError } 8301001 - SIM card is not activated.
   * @syscap SystemCapability.Telephony.CoreService
   * @since 10
   */
  function getDefaultVoiceSimId(): Promise<number>;

  /**
   * Obtains the value of dsds mode.
   *
   * @permission ohos.permission.GET_TELEPHONY_STATE
   * @param { AsyncCallback<DsdsMode> } callback - Indicates the callback for
   *     getting one of the following dsds mode states:
   * <ul>
   * <li>{@code DsdsMode#DSDS_MODE_V2}
   * <li>{@code DsdsMode#DSDS_MODE_V3}
   * <li>{@code DsdsMode#DSDS_MODE_V5_TDM}
   * <li>{@code DsdsMode#DSDS_MODE_V5_DSDA}
   * </ul>
   * @throws { BusinessError } 201 - Permission denied.
   * @throws { BusinessError } 202 - Non-system applications use system APIs.
   * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified.
   * 2. Incorrect parameter types.
   * @throws { BusinessError } 8300002 - Operation failed. Cannot connect to
   *     service.
   * @throws { BusinessError } 8300003 - System internal error.
   * @throws { BusinessError } 8300999 - Unknown error code.
   * @syscap SystemCapability.Telephony.CoreService
   * @systemapi Hide this for inner system use.
   * @since 11
   */
  function getDsdsMode(callback: AsyncCallback<DsdsMode>): void;

  /**
   * Obtains the value of dsds mode.
   *
   * @permission ohos.permission.GET_TELEPHONY_STATE
   * @returns { Promise<DsdsMode> } Returns one of the following dsds mode
   *     states:
   * <ul>
   * <li>{@code DsdsMode#DSDS_MODE_V2}
   * <li>{@code DsdsMode#DSDS_MODE_V3}
   * <li>{@code DsdsMode#DSDS_MODE_V5_TDM}
   * <li>{@code DsdsMode#DSDS_MODE_V5_DSDA}
   * </ul>
   * @throws { BusinessError } 201 - Permission denied.
   * @throws { BusinessError } 202 - Non-system applications use system APIs.
   * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified.
   * 2. Incorrect parameter types.
   * @throws { BusinessError } 8300002 - Operation failed. Cannot connect to
   *     service.
   * @throws { BusinessError } 8300003 - System internal error.
   * @throws { BusinessError } 8300999 - Unknown error code.
   * @syscap SystemCapability.Telephony.CoreService
   * @systemapi Hide this for inner system use.
   * @since 11
   */
  function getDsdsMode(): Promise<DsdsMode>;

  /**
   * Defines the carrier configuration.
   *
   * @interface OperatorConfig
   * @syscap SystemCapability.Telephony.CoreService
   * @systemapi Hide this for inner system use.
   * @since 8
   */
  export interface OperatorConfig {
    /**
     * Indicates the field.
     *
     * @type { string }
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 8
     */
    field: string;

    /**
     * Indicates the value.
     *
     * @type { string }
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 8
     */
    value: string;
  }

  /**
   * Defines the ICC account information.
   *
   * @interface IccAccountInfo
   * @syscap SystemCapability.Telephony.CoreService
   * @since 10
   */
  export interface IccAccountInfo {
    /**
     * Indicates the sim Id for card.
     *
     * @type { number }
     * @syscap SystemCapability.Telephony.CoreService
     * @since 10
     */
    simId: number;

    /**
     * Indicates the card slot index number,
     * ranging from 0 to the maximum card slot index number supported by the device.
     *
     * @type { number }
     * @syscap SystemCapability.Telephony.CoreService
     * @since 10
     */
    slotIndex: number;

    /**
     * Indicates the mark card is eSim or not.
     *
     * @type { boolean }
     * @syscap SystemCapability.Telephony.CoreService
     * @since 10
     */
    isEsim: boolean;

    /**
     * Indicates the active status for card.
     *
     * @type { boolean }
     * @syscap SystemCapability.Telephony.CoreService
     * @since 10
     */
    isActive: boolean;

    /**
     * Indicates the iccId for card.
     *
     * @type { string }
     * @syscap SystemCapability.Telephony.CoreService
     * @since 10
     */
    iccId: string;

    /**
     * Indicates the display name for card.
     *
     * @type { string }
     * @syscap SystemCapability.Telephony.CoreService
     * @since 10
     */
    showName: string;

    /**
     * Indicates the display number for card.
     *
     * @type { string }
     * @syscap SystemCapability.Telephony.CoreService
     * @since 10
     */
    showNumber: string;
  }

  /**
   * Defines the personalized lock information.
   *
   * @interface LockStatusResponse
   * @syscap SystemCapability.Telephony.CoreService
   * @systemapi Hide this for inner system use.
   * @since 7
   */
  export interface LockStatusResponse {
    /**
     * Indicates the current operation result.
     *
     * @type { number }
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 7
     */
    result: number;

    /**
     * Indicates the operations remaining.
     *
     * @type { ?number }
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 7
     */
    remain?: number;
  }

  /**
   * Defines the contact number information.
   *
   * @interface DiallingNumbersInfo
   * @syscap SystemCapability.Telephony.CoreService
   * @systemapi Hide this for inner system use.
   * @since 8
   */
  export interface DiallingNumbersInfo {
    /**
     * Indicates the tag.
     *
     * @type { string }
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 8
     */
    alphaTag: string;

    /**
     * Indicates the call transfer number.
     *
     * @type { string }
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 8
     */
    number: string;

    /**
     * Indicates the record number.
     *
     * @type { ?number }
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 8
     */
    recordNumber?: number;

    /**
     * Indicates the PIN 2.
     *
     * @type { ?string }
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 8
     */
    pin2?: string;
  }

  /**
   * Defines the personalized lock information.
   *
   * @interface LockInfo
   * @syscap SystemCapability.Telephony.CoreService
   * @systemapi Hide this for inner system use.
   * @since 8
   */
  export interface LockInfo {
    /**
     * Indicates the lock type.
     *
     * @type { LockType }
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 8
     */
    lockType: LockType;

    /**
     * Indicates the password.
     *
     * @type { string }
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 8
     */
    password: string;

    /**
     * Indicates the lock state.
     *
     * @type { LockState }
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 8
     */
    state: LockState;
  }

  /**
   * Defines the personalized lock information.
   *
   * @interface PersoLockInfo
   * @syscap SystemCapability.Telephony.CoreService
   * @systemapi Hide this for inner system use.
   * @since 8
   */
  export interface PersoLockInfo {
    /**
     * Indicates the personalized lock type.
     *
     * @type { PersoLockType }
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 8
     */
    lockType: PersoLockType;

    /**
     * Indicates the password.
     *
     * @type { string }
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 8
     */
    password: string;
  }

  /**
   * Indicates the lock types.
   *
   * @enum { number }
   * @syscap SystemCapability.Telephony.CoreService
   * @systemapi Hide this for inner system use.
   * @since 8
   */
  export enum LockType {
    /**
     * Indicates the SIM card password lock.
     *
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 8
     */
    PIN_LOCK = 1,

    /**
     * Indicates the fixed dialing lock.
     *
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 8
     */
    FDN_LOCK = 2,
  }

  /**
   * Indicates the SIM card types.
   *
   * @enum { number }
   * @syscap SystemCapability.Telephony.CoreService
   * @since 7
   */
  export enum CardType {
    /**
     * Icc card type: unknown type Card.
     *
     * @syscap SystemCapability.Telephony.CoreService
     * @since 7
     */
    UNKNOWN_CARD = -1,

    /**
     * Icc card type: Single sim card type.
     *
     * @syscap SystemCapability.Telephony.CoreService
     * @since 7
     */
    SINGLE_MODE_SIM_CARD = 10,

    /**
     * Icc card type: Single usim card type.
     *
     * @syscap SystemCapability.Telephony.CoreService
     * @since 7
     */
    SINGLE_MODE_USIM_CARD = 20,

    /**
     * Icc card type: Single ruim card type.
     *
     * @syscap SystemCapability.Telephony.CoreService
     * @since 7
     */
    SINGLE_MODE_RUIM_CARD = 30,

    /**
     * Icc card type: Double card C+G.
     *
     * @syscap SystemCapability.Telephony.CoreService
     * @since 7
     */
    DUAL_MODE_CG_CARD = 40,

    /**
     * Icc card type: China Telecom Internal Roaming Card (Dual Mode).
     *
     * @syscap SystemCapability.Telephony.CoreService
     * @since 7
     */
    CT_NATIONAL_ROAMING_CARD = 41,

    /**
     * Icc card type: China Unicom Dual Mode Card.
     *
     * @syscap SystemCapability.Telephony.CoreService
     * @since 7
     */
    CU_DUAL_MODE_CARD = 42,

    /**
     * Icc card type: China Telecom LTE Card (Dual Mode).
     *
     * @syscap SystemCapability.Telephony.CoreService
     * @since 7
     */
    DUAL_MODE_TELECOM_LTE_CARD = 43,

    /**
     * Icc card type: Double card U+G.
     *
     * @syscap SystemCapability.Telephony.CoreService
     * @since 7
     */
    DUAL_MODE_UG_CARD = 50,

    /**
     * Icc card type: Single isim card type.
     * @syscap SystemCapability.Telephony.CoreService
     * @since 8
     */
    SINGLE_MODE_ISIM_CARD = 60
  }

  /**
   * Indicates the SIM card states.
   *
   * @enum { number }
   * @syscap SystemCapability.Telephony.CoreService
   * @since 6
   */
  export enum SimState {
    /**
     * Indicates unknown SIM card state, that is, the accurate status cannot be
     * obtained.
     *
     * @syscap SystemCapability.Telephony.CoreService
     * @since 6
     */
    SIM_STATE_UNKNOWN,

    /**
     * Indicates that the SIM card is in the <b>not present</b> state, that is,
     * no SIM card is inserted into the card slot.
     *
     * @syscap SystemCapability.Telephony.CoreService
     * @since 6
     */
    SIM_STATE_NOT_PRESENT,

    /**
     * Indicates that the SIM card is in the <b>locked</b> state, that is, the
     * SIM card is locked by the personal identification number (PIN)/PIN
     * unblocking key (PUK) or network.
     *
     * @syscap SystemCapability.Telephony.CoreService
     * @since 6
     */
    SIM_STATE_LOCKED,

    /**
     * Indicates that the SIM card is in the <b>not ready</b> state, that is,
     * the SIM card is in position but cannot work properly.
     *
     * @syscap SystemCapability.Telephony.CoreService
     * @since 6
     */
    SIM_STATE_NOT_READY,

    /**
     * Indicates that the SIM card is in the <b>ready</b> state, that is, the
     * SIM card is in position and is working properly.
     *
     * @syscap SystemCapability.Telephony.CoreService
     * @since 6
     */
    SIM_STATE_READY,

    /**
     * Indicates that the SIM card is in the <b>loaded</b> state, that is, the
     * SIM card is in position and is working properly.
     *
     * @syscap SystemCapability.Telephony.CoreService
     * @since 6
     */
    SIM_STATE_LOADED
  }

  /**
   * Indicates the lock states.
   *
   * @enum { number }
   * @syscap SystemCapability.Telephony.CoreService
   * @systemapi Hide this for inner system use.
   * @since 8
   */
  export enum LockState {
    /**
     * Indicates that the lock state card is in the <b>off</b> state.
     *
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 8
     */
    LOCK_OFF = 0,

    /**
     * Indicates that the lock state card is in the <b>on</b> state.
     *
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 8
     */
    LOCK_ON = 1,
  }

  /**
   * Indicates the contact types.
   *
   * @enum { number }
   * @syscap SystemCapability.Telephony.CoreService
   * @systemapi Hide this for inner system use.
   * @since 8
   */
  export enum ContactType {
    /**
     * Indicates the common contact number.
     *
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 8
     */
    GENERAL_CONTACT = 1,

    /**
     * Indicates the fixed dialing number.
     *
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 8
     */
    FIXED_DIALING = 2,
  }

  /**
   * Indicates the personalized lock types.
   *
   * @enum { number }
   * @syscap SystemCapability.Telephony.CoreService
   * @systemapi Hide this for inner system use.
   * @since 8
   */
  export enum PersoLockType {
    /**
     * Indicates network personalization of PIN lock(refer 3GPP TS 22.022 [33]).
     *
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 8
     */
    PN_PIN_LOCK,

    /**
     * Indicates network personalization of PUK lock(refer 3GPP TS 22.022 [33]).
     *
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 8
     */
    PN_PUK_LOCK,

    /**
     * Indicates network subset personalization of PIN lock(refer 3GPP TS 22.022 [33]).
     *
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 8
     */
    PU_PIN_LOCK,

    /**
     * Indicates network subset personalization of PUK lock(refer 3GPP TS 22.022 [33]).
     *
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 8
     */
    PU_PUK_LOCK,

    /**
     * Indicates service provider personalization of PIN lock(refer 3GPP TS 22.022 [33]).
     *
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 8
     */
    PP_PIN_LOCK,

    /**
     * Indicates service provider personalization of PUK lock(refer 3GPP TS 22.022 [33]).
     *
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 8
     */
    PP_PUK_LOCK,

    /**
     * Indicates corporate personalization of PIN lock(refer 3GPP TS 22.022 [33]).
     *
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 8
     */
    PC_PIN_LOCK,

    /**
     * Indicates corporate personalization of PUK lock(refer 3GPP TS 22.022 [33]).
     *
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 8
     */
    PC_PUK_LOCK,

    /**
     * Indicates SIM/USIM personalization of PIN lock(refer 3GPP TS 22.022 [33]).
     *
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 8
     */
    SIM_PIN_LOCK,

    /**
     * Indicates SIM/USIM personalization of PUK lock(refer 3GPP TS 22.022 [33]).
     *
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 8
     */
    SIM_PUK_LOCK,
  }

  /**
   * Indicates the carrier configuration keys.
   *
   * @enum { string }
   * @syscap SystemCapability.Telephony.CoreService
   * @systemapi Hide this for inner system use.
   * @since 9
   */
  export enum OperatorConfigKey {
    /**
     * Indicates the voice mail number.
     *
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 9
     */
    KEY_VOICE_MAIL_NUMBER_STRING = 'voice_mail_number_string',

    /**
     * Indicates the status of ims switch.
     *
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 9
     */
    KEY_IMS_SWITCH_ON_BY_DEFAULT_BOOL = 'ims_switch_on_by_default_bool',

    /**
     * Indicates whether the ims switch status is hidden.
     *
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 9
     */
    KEY_HIDE_IMS_SWITCH_BOOL = 'hide_ims_switch_bool',

    /**
     * Indicates whether volte mode is supported.
     *
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 9
     */
    KEY_VOLTE_SUPPORTED_BOOL = 'volte_supported_bool',

    /**
     * Indicates the list supported by nr mode.
     *
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 9
     */
    KEY_NR_MODE_SUPPORTED_LIST_INT_ARRAY = 'nr_mode_supported_list_int_array',

    /**
     * Indicates whether VOLTE supports configuration.
     *
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 9
     */
    KEY_VOLTE_PROVISIONING_SUPPORTED_BOOL = 'volte_provisioning_supported_bool',

    /**
     * Indicates whether SS service supports UT.
     *
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 9
     */
    KEY_SS_OVER_UT_SUPPORTED_BOOL = 'ss_over_ut_supported_bool',

    /**
     * Indicates whether the IMS requires GBA.
     *
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 9
     */
    KEY_IMS_GBA_REQUIRED_BOOL = 'ims_gba_required_bool',

    /**
     * Indicates whether UT configuration is supported.
     *
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 9
     */
    KEY_UT_PROVISIONING_SUPPORTED_BOOL = 'ut_provisioning_supported_bool',

    /**
     * Indicates the ims emergency preference.
     *
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 9
     */
    KEY_IMS_PREFER_FOR_EMERGENCY_BOOL = 'ims_prefer_for_emergency_bool',

    /**
     * Indicates call waiting service.
     *
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 9
     */
    KEY_CALL_WAITING_SERVICE_CLASS_INT = 'call_waiting_service_class_int',

    /**
     * Indicates call forwarding visibility.
     *
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 9
     */
    KEY_CALL_TRANSFER_VISIBILITY_BOOL = 'call_transfer_visibility_bool',

    /**
     * Indicates the list of ims call end reasons.
     *
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 9
     */
    KEY_IMS_CALL_DISCONNECT_REASON_INFO_MAPPING_STRING_ARRAY =
    'ims_call_disconnect_reason_info_mapping_string_array',

    /**
     * Indicates the forced Volte switch on state.
     *
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 9
     */
    KEY_FORCE_VOLTE_SWITCH_ON_BOOL = 'force_volte_switch_on_bool',

    /**
     * Indicates whether the operator name is displayed.
     *
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 9
     */
    KEY_ENABLE_OPERATOR_NAME_CUST_BOOL = 'enable_operator_name_cust_bool',

    /**
     * Indicates the name of the operator.
     *
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 9
     */
    KEY_OPERATOR_NAME_CUST_STRING = 'operator_name_cust_string',

    /**
     * Indicates the spn display rule.
     *
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 9
     */
    KEY_SPN_DISPLAY_CONDITION_CUST_INT = 'spn_display_condition_cust_int',

    /**
     * Indicates the PLMN name.
     *
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 9
     */
    KEY_PNN_CUST_STRING_ARRAY = 'pnn_cust_string_array',

    /**
     * Indicates operator PLMN information.
     *
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 9
     */
    KEY_OPL_CUST_STRING_ARRAY = 'opl_cust_string_array',

    /**
     * Indicates the emergency call list.
     *
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 9
     */
    KEY_EMERGENCY_CALL_STRING_ARRAY = 'emergency_call_string_array',
  }

  /**
   * Indicates the Dsds Mode.
   *
   * @enum { number }
   * @syscap SystemCapability.Telephony.CoreService
   * @systemapi Hide this for inner system use.
   * @since 11
   */
  export enum DsdsMode {
    /**
     * Indicates the DSDS 2.0 Mode.
     *
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 11
     */
    DSDS_MODE_V2 = 0,

    /**
     * Indicates the DSDS 3.0 Mode.
     *
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 11
     */
    DSDS_MODE_V3 = 1,

    /**
     * Indicates the DSDS 5.0 TDM Mode.
     *
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 11
     */
    DSDS_MODE_V5_TDM = 2,

    /**
     * Indicates the DSDS 5.0 DSDA Mode.
     *
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 11
     */
    DSDS_MODE_V5_DSDA = 3,
  }

  /**
   * Indicates the operator of SIM.
   *
   * @enum { string }
   * @syscap SystemCapability.Telephony.CoreService
   * @systemapi Hide this for inner system use.
   * @since 11
   */
  export enum OperatorSimCard {
    /**
     * Indicates the China Telecom card.
     *
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 11
     */
    CHINA_TELECOM_CARD = 'china_telecom_card',
  }
}

export default sim;
