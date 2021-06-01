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
 * Provides interfaces for applications to obtain the network state, cell information, signal information,
 * and device ID of the wireless cellular network (WCN), and provides a callback registration mechanism to
 * listen for changes of the network, cell, and signal status of the WCN.
 *
 * @since 6
 */
declare namespace radio {
  // RadioTechnology, need ohos.permission.GET_NETWORK_INFO
  function getRadioTech(slotId: number, callback: AsyncCallback<{psRadioTech: RadioTechnology,
                        csRadioTech: RadioTechnology}>): void;
  function getRadioTech(slotId: number): Promise<{psRadioTech: RadioTechnology, csRadioTech: RadioTechnology}>;

  // NetworkState, need ohos.permission.GET_NETWORK_INFO
  function getNetworkState(callback: AsyncCallback<NetworkState>): void;
  function getNetworkState(slotId: number, callback: AsyncCallback<NetworkState>): void;
  function getNetworkState(slotId?: number): Promise<NetworkState>;

  // SignalInformation
  function getSignalInformation(slotId: number, callback: AsyncCallback<Array<SignalInformation>>): void;
  function getSignalInformation(slotId: number): Promise<Array<SignalInformation>>;

  export enum RadioTechnology {
    RADIO_TECHNOLOGY_UNKNOWN,
    RADIO_TECHNOLOGY_GSM,
    RADIO_TECHNOLOGY_1XRTT,
    RADIO_TECHNOLOGY_WCDMA,
    RADIO_TECHNOLOGY_HSPA,
    RADIO_TECHNOLOGY_HSPAP,
    RADIO_TECHNOLOGY_TD_SCDMA,
    RADIO_TECHNOLOGY_EVDO,
    RADIO_TECHNOLOGY_EHRPD,
    RADIO_TECHNOLOGY_LTE,
    RADIO_TECHNOLOGY_LTE_CA,
    RADIO_TECHNOLOGY_IWLAN,
    RADIO_TECHNOLOGY_NR
  }

  /**
   * Describes the radio access technology.
   *
   * @devices phone, tablet
   * @version 5
   */
  export enum RatType {
    /**
     * Indicates unknown radio access technology (RAT).
     */
    RADIO_TECHNOLOGY_UNKNOWN = 0,

    /**
     * Indicates that RAT is global system for mobile communications (GSM), including GSM, general packet
     * radio system (GPRS), and enhanced data rates for GSM evolution (EDGE).
     */
    RADIO_TECHNOLOGY_GSM = 1,

    /**
     * Indicates that RAT is code division multiple access (CDMA), including Interim Standard 95 (IS95) and
     * Single-Carrier Radio Transmission Technology (1xRTT).
     */
    RADIO_TECHNOLOGY_1XRTT = 2,

    /**
     * Indicates that RAT is wideband code division multiple address (WCDMA).
     */
    RADIO_TECHNOLOGY_WCDMA = 3,

    /**
     * Indicates that RAT is high-speed packet access (HSPA), including HSPA, high-speed downlink packet
     * access (HSDPA), and high-speed uplink packet access (HSUPA).
     */
    RADIO_TECHNOLOGY_HSPA = 4,

    /**
     * Indicates that RAT is evolved high-speed packet access (HSPA+), including HSPA+ and dual-carrier
     * HSPA+ (DC-HSPA+).
     */
    RADIO_TECHNOLOGY_HSPAP = 5,

    /**
     * Indicates that RAT is time division-synchronous code division multiple access (TD-SCDMA).
     */
    RADIO_TECHNOLOGY_TD_SCDMA = 6,

    /**
     * Indicates that RAT is evolution data only (EVDO), including EVDO Rev.0, EVDO Rev.A, and EVDO Rev.B.
     */
    RADIO_TECHNOLOGY_EVDO = 7,

    /**
     * Indicates that RAT is evolved high rate packet data (EHRPD).
     */
    RADIO_TECHNOLOGY_EHRPD = 8,

    /**
     * Indicates that RAT is long term evolution (LTE).
     */
    RADIO_TECHNOLOGY_LTE = 9,

    /**
     * Indicates that RAT is LTE carrier aggregation (LTE-CA).
     */
    RADIO_TECHNOLOGY_LTE_CA = 10,

    /**
     * Indicates that RAT is interworking WLAN (I-WLAN).
     */
    RADIO_TECHNOLOGY_IWLAN = 11,

    /**
     * Indicates that RAT is 5G new radio (NR).
     */
    RADIO_TECHNOLOGY_NR = 12
  }

  export interface SignalInformation {
    /**
     * Obtains the network type corresponding to the signal.
     */
    signalType: NetworkType;

    /**
     * Obtains the signal level of the current network.
     */
    signalLevel: number;
  }

  /**
   * Describes the network type.
   *
   * @devices phone, tablet
   * @version 5
   */
  export enum NetworkType {
    /**
     * Indicates unknown network type.
     */
    NETWORK_TYPE_UNKNOWN,

    /**
     * Indicates that the network type is GSM.
     */
    NETWORK_TYPE_GSM,

    /**
     * Indicates that the network type is CDMA.
     */
    NETWORK_TYPE_CDMA,

    /**
     * Indicates that the network type is WCDMA.
     */
    NETWORK_TYPE_WCDMA,

    /**
     * Indicates that the network type is TD-SCDMA.
     */
    NETWORK_TYPE_TDSCDMA,

    /**
     * Indicates that the network type is LTE.
     */
    NETWORK_TYPE_LTE,

    /**
     * Indicates that the network type is 5G NR.
     */
    NETWORK_TYPE_NR
  }

  export interface NetworkState {
    /**
     * Obtains the operator name in the long alphanumeric format of the registered network.
     *
     * @return Returns the operator name in the long alphanumeric format as a string;
     * returns an empty string if no operator name is obtained.
     * @version 5
     */
    longOperatorName: string;

    /**
     * Obtains the operator name in the short alphanumeric format of the registered network.
     *
     * @return Returns the operator name in the short alphanumeric format as a string;
     * returns an empty string if no operator name is obtained.
     * @version 5
     */
    shortOperatorName: string;

    /**
     * Obtains the PLMN code of the registered network.
     *
     * @return Returns the PLMN code as a string; returns an empty string if no operator name is obtained.
     * @version 5
     */
    plmnNumeric: string;

    /**
     * Checks whether the device is roaming.
     *
     * @return Returns {@code true} if the device is roaming; returns {@code false} otherwise.
     * @version 5
     */
    isRoaming: boolean;

    /**
     * Obtains the network registration status of the device.
     *
     * @return Returns the network registration status {@code RegStatus}.
     * @version 5
     */
    regStatus: RegStatus;

    /**
     * Obtains the NSA network registration status of the device.
     *
     * @return Returns the NSA network registration status {@code NsaState}.
     * @version 5
     */
    nsaState: NsaState;

    /**
     * Obtains the status of CA.
     *
     * @return Returns {@code true} if CA is actived; returns {@code false} otherwise.
     * @version 5
     */
    isCaActive: boolean;

    /**
     * Checks whether this device is allowed to make emergency calls only.
     *
     * @return Returns {@code true} if this device is allowed to make emergency calls only;
     * returns {@code false} otherwise.
     * @version 5
     */
    isEmergency: boolean;
  }

  /**
   * Describes the network registration state.
   *
   * @devices phone, tablet
   * @version 5
   */
  export enum RegStatus {
    /**
     * Indicates a state in which a device cannot use any service.
     */
    REG_STATE_NO_SERVICE = 0,

    /**
     * Indicates a state in which a device can use services properly.
     */
    REG_STATE_IN_SERVICE = 1,

    /**
     * Indicates a state in which a device can use only the emergency call service.
     */
    REG_STATE_EMERGENCY_CALL_ONLY = 2,

    /**
     * Indicates that the cellular radio is powered off.
     */
    REG_STATE_POWER_OFF = 3
  }
}

export default radio;