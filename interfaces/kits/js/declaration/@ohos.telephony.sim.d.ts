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

import {AsyncCallback} from "./basic";

/**
 * Provides applications with APIs for obtaining SIM card status, card file information, and card specifications.
 * SIM cards include SIM, USIM, and CSIM cards.
 *
 * @since 6
 * @sysCap SystemCapability.Telephony.Telephony
 */
declare namespace sim {
    /**
   * Checks whether a SIM card is inserted in a specified slot.
   *
   * @param slotId Indicates the card slot index number,
   * ranging from 0 to the maximum card slot index number supported by the device.
   * @param callback Returns true if a SIM card is inserted; return false otherwise.
   */
  function hasSimCard(slotId: number, callback: AsyncCallback<boolean>): void;
  function hasSimCard(slotId: number): Promise<boolean>;

  /**
   * Obtains the default card slot for the voice service.
   *
   * @param callback Returns {@code 0} if card 1 is used as the default card slot for the voice service;
   * returns {@code 1} if card 2 is used as the default card slot for the voice service;
   * returns {@code -1} if no card is available for the voice service.
   * @since 7
   */
  function getDefaultVoiceSlotId(callback: AsyncCallback<number>): void;
  function getDefaultVoiceSlotId(): Promise<number>;

  /**
   * Obtains the ISO country code of the SIM card in a specified slot.
   *
   * @param slotId Indicates the card slot index number,
   * ranging from 0 to the maximum card slot index number supported by the device.
   * @param callback Returns the country code defined in ISO 3166-2; returns an empty string if no SIM card is inserted.
   */
  function getISOCountryCodeForSim(slotId: number, callback: AsyncCallback<string>): void;
  function getISOCountryCodeForSim(slotId: number): Promise<string>;

  /**
   * Obtains the home PLMN number of the SIM card in a specified slot.
   *
   * <p>The value is recorded in the SIM card and is irrelevant to the network
   * with which the SIM card is currently registered.
   *
   * @param slotId Indicates the card slot index number,
   * ranging from 0 to the maximum card slot index number supported by the device.
   * @param callback Returns the PLMN number; returns an empty string if no SIM card is inserted.
   */
  function getSimOperatorNumeric(slotId: number, callback: AsyncCallback<string>): void;
  function getSimOperatorNumeric(slotId: number): Promise<string>;

  /**
   * Obtains the service provider name (SPN) of the SIM card in a specified slot.
   *
   * <p>The value is recorded in the EFSPN file of the SIM card and is irrelevant to the network
   * with which the SIM card is currently registered.
   *
   * @param slotId Indicates the card slot index number,
   * ranging from 0 to the maximum card slot index number supported by the device.
   * @param callback Returns the SPN; returns an empty string if no SIM card is inserted or
   * no EFSPN file in the SIM card.
   */
  function getSimSpn(slotId: number, callback: AsyncCallback<string>): void;
  function getSimSpn(slotId: number): Promise<string>;

  /**
   * Obtains the state of the SIM card in a specified slot.
   *
   * @param slotId Indicates the card slot index number,
   * ranging from {@code 0} to the maximum card slot index number supported by the device.
   * @param callback Returns one of the following SIM card states:
   * <ul>
   * <li>{@code SimState#SIM_STATE_UNKNOWN}
   * <li>{@code SimState#SIM_STATE_NOT_PRESENT}
   * <li>{@code SimState#SIM_STATE_LOCKED}
   * <li>{@code SimState#SIM_STATE_NOT_READY}
   * <li>{@code SimState#SIM_STATE_READY}
   * <li>{@code SimState#SIM_STATE_LOADED}
   * </ul>
   */
  function getSimState(slotId: number, callback: AsyncCallback<SimState>): void;
  function getSimState(slotId: number): Promise<SimState>;

  /**
   * Obtains the ICCID of the SIM card in a specified slot.
   *
   * <p>The ICCID is a unique identifier of a SIM card. It consists of 20 digits
   * and is recorded in the EFICCID file of the SIM card.
   *
   * <p>Requires Permission: {@code ohos.permission.GET_TELEPHONY_STATE}.
   *
   * @param slotId Indicates the card slot index number,
   * ranging from 0 to the maximum card slot index number supported by the device.
   * @param callback Returns the ICCID; returns an empty string if no SIM card is inserted.
   * @permission ohos.permission.GET_TELEPHONY_STATE
   */
  function getSimIccId(slotId: number, callback: AsyncCallback<string>): void;
  function getSimIccId(slotId: number): Promise<string>;

  /**
   * Obtains the Group Identifier Level 1 (GID1) of the SIM card in a specified slot.
   * The GID1 is recorded in the EFGID1 file of the SIM card.
   *
   * <p>Requires Permission: {@code ohos.permission.GET_TELEPHONY_STATE}.
   *
   * @param slotId Indicates the card slot index number,
   * ranging from 0 to the maximum card slot index number supported by the device.
   * @param callback Returns the GID1; returns an empty string if no SIM card is inserted or
   * no GID1 in the SIM card.
   * @permission ohos.permission.GET_TELEPHONY_STATE
   */
  function getSimGid1(slotId: number, callback: AsyncCallback<string>): void;
  function getSimGid1(slotId: number): Promise<string>;

  /**
   * @permission ohos.permission.GET_TELEPHONY_STATE
   * @systemapi Hide this for inner system use.
   */
  function getIMSI(slotId: number, callback: AsyncCallback<string>): void;
  function getIMSI(slotId: number): Promise<string>;

  /**
   * @permission ohos.permission.GET_TELEPHONY_STATE
   * @systemapi Hide this for inner system use.
   * @since 7
   */
  function getSimAccountInfo(slotId: number, callback: AsyncCallback<IccAccountInfo>): void;
  function getSimAccountInfo(slotId: number): Promise<IccAccountInfo>;

  /**
   * @permission ohos.permission.SET_TELEPHONY_STATE
   * @systemapi Hide this for inner system use.
   * @since 7
   */
  function setDefaultVoiceSlotId(slotId: number, callback: AsyncCallback<void>): void;
  function setDefaultVoiceSlotId(slotId: number): Promise<void>;

  /**
   * @permission ohos.permission.SET_TELEPHONY_STATE
   * @systemapi Hide this for inner system use.
   * @since 7
   */
  function unlockPin(slotId: number, pin: string, callback: AsyncCallback<LockStatusResponse>): void;
  function unlockPin(slotId: number, pin: string): Promise<LockStatusResponse>;

  /**
   * @permission ohos.permission.SET_TELEPHONY_STATE
   * @systemapi Hide this for inner system use.
   * @since 7
   */
  function unlockPuk(slotId: number, newPin: string, puk: string, callback: AsyncCallback<LockStatusResponse>): void;
  function unlockPuk(slotId: number, newPin: string, puk: string): Promise<LockStatusResponse>;

  /**
   * @permission ohos.permission.SET_TELEPHONY_STATE
   * @systemapi Hide this for inner system use.
   * @since 7
   */
  function alterPin(slotId: number, newPin: string, oldPin: string, callback: AsyncCallback<LockStatusResponse>): void;
  function alterPin(slotId: number, newPin: string, oldPin: string): Promise<LockStatusResponse>;

  /**
   * @permission ohos.permission.SET_TELEPHONY_STATE
   * @systemapi Hide this for inner system use.
   * @since 7
   */
  function setLockState(slotId: number, pin: string, enable: number, callback: AsyncCallback<LockStatusResponse>): void;
  function setLockState(slotId: number, pin: string, enable: number): Promise<LockStatusResponse>;

  /**
   * Obtains the MSISDN of the SIM card in a specified slot.
   * The MSISDN is recorded in the EFMSISDN file of the SIM card.
   *
   * <p>Requires Permission: {@code ohos.permission.GET_TELEPHONY_STATE}.
   *
   * @param slotId Indicates the card slot index number,
   * ranging from 0 to the maximum card slot index number supported by the device.
   * @param callback Returns the MSISDN; returns an empty string if no SIM card is inserted or
   * no MSISDN is recorded in the EFMSISDN file.
   * @permission ohos.permission.GET_TELEPHONY_STATE
   */
  function getSimTelephoneNumber(slotId: number, callback: AsyncCallback<string>): void;
  function getSimTelephoneNumber(slotId: number): Promise<string>;

  /**
   * @systemapi Hide this for inner system use.
   */
  function queryIccDiallingNumbers(slotId: number, type: number, callback: AsyncCallback<Array<DiallingNumbersInfo>>): void
  function queryIccDiallingNumbers(slotId: number, type: number): Promise<Array<DiallingNumbersInfo>>;

   /**
    * @systemapi Hide this for inner system use.
    */
  function addIccDiallingNumbers(slotId: number, type: number, diallingNumbers: DiallingNumbersInfo, callback: AsyncCallback<void>): void;
  function addIccDiallingNumbers(slotId: number, type: number, diallingNumbers: DiallingNumbersInfo): Promise<void>;

   /**
    * @systemapi Hide this for inner system use.
    */
  function delIccDiallingNumbers(slotId: number, type: number, index: number, callback :AsyncCallback<void>): void;
  function delIccDiallingNumbers(slotId: number, type: number, index: number): Promise<void>;

   /**
    * @systemapi Hide this for inner system use.
    */
  function updateIccDiallingNumbers(slotId: number, type: number, diallingNumbers: DiallingNumbersInfo, index: number, callback: AsyncCallback<void>): void;
  function updateIccDiallingNumbers(slotId: number, type: number, diallingNumbers: DiallingNumbersInfo, index: number): Promise<void>;

  /**
   * @systemapi Hide this for inner system use.
   * @since 7
   */
  export interface IccAccountInfo {
    slotIndex: number,              /* slot id */
    showName: string,               /* display name for card */
    showNumber: string,             /* display number for card */
  }

  /**
   * @systemapi Hide this for inner system use.
   * @since 7
   */
  export interface LockStatusResponse {
    result: number,                 /* Current operation result */
    remain?: number,                /* Operations remaining */
  }

  /**
   * @systemapi Hide this for inner system use.
   */
   export interface DiallingNumbersInfo {
    recordNumber: number,
    alphaTag: string,
    number: string,
  }

  export enum SimState {
    /**
     * Indicates unknown SIM card state, that is, the accurate status cannot be obtained.
     */
    SIM_STATE_UNKNOWN,

    /**
     * Indicates that the SIM card is in the <b>not present</b> state, that is, no SIM card is inserted
     * into the card slot.
     */
    SIM_STATE_NOT_PRESENT,

    /**
     * Indicates that the SIM card is in the <b>locked</b> state, that is, the SIM card is locked by the
     * personal identification number (PIN)/PIN unblocking key (PUK) or network.
     */
    SIM_STATE_LOCKED,

    /**
     * Indicates that the SIM card is in the <b>not ready</b> state, that is, the SIM card is in position
     * but cannot work properly.
     */
    SIM_STATE_NOT_READY,

    /**
     * Indicates that the SIM card is in the <b>ready</b> state, that is, the SIM card is in position and
     * is working properly.
     */
    SIM_STATE_READY,

    /**
     * Indicates that the SIM card is in the <b>loaded</b> state, that is, the SIM card is in position and
     * is working properly.
     */
    SIM_STATE_LOADED
  }
}

export default sim;