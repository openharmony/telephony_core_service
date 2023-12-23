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

import {AsyncCallback, Callback} from "./basic";

/**
 * Provides interfaces for applications to obtain the network state, cell information, signal information,
 * and device ID of the wireless cellular network (WCN), and provides a callback registration mechanism to
 * listen for changes of the network, cell, and signal status of the WCN.
 *
 * @namespace radio
 * @syscap SystemCapability.Telephony.CoreService
 * @since 6
 */
declare namespace radio {
  /**
   * Obtains radio access technology (RAT) of the registered network. The system
   * returns RAT of the packet service (PS) and circuit service (CS) domain.
   *
   * @permission ohos.permission.GET_NETWORK_INFO
   * @param { number } slotId - Indicates the card slot index number,
   * ranging from 0 to the maximum card slot index number supported by the device.
   * @param { AsyncCallback<{psRadioTech: RadioTechnology, csRadioTech: RadioTechnology}> } callback - Returns
   * an integer indicating the RAT in use. The values are as follows:
   * <ul>
   * <li>{@code RadioTechnology#RADIO_TECHNOLOGY_UNKNOWN}
   * <li>{@code RadioTechnology#RADIO_TECHNOLOGY_GSM}
   * <li>{@code RadioTechnology#RADIO_TECHNOLOGY_1XRTT}
   * <li>{@code RadioTechnology#RADIO_TECHNOLOGY_WCDMA}
   * <li>{@code RadioTechnology#RADIO_TECHNOLOGY_HSPA}
   * <li>{@code RadioTechnology#RADIO_TECHNOLOGY_HSPAP}
   * <li>{@code RadioTechnology#RADIO_TECHNOLOGY_TD_SCDMA}
   * <li>{@code RadioTechnology#RADIO_TECHNOLOGY_EVDO}
   * <li>{@code RadioTechnology#RADIO_TECHNOLOGY_EHRPD}
   * <li>{@code RadioTechnology#RADIO_TECHNOLOGY_LTE}
   * <li>{@code RadioTechnology#RADIO_TECHNOLOGY_LTE_CA}
   * <li>{@code RadioTechnology#RADIO_TECHNOLOGY_IWLAN}
   * <li>{@code RadioTechnology#RADIO_TECHNOLOGY_NR}
   * </ul>
   * @throws { BusinessError } 201 - Permission denied.
   * @throws { BusinessError } 401 - Parameter error.
   * @throws { BusinessError } 8300001 - Invalid parameter value.
   * @throws { BusinessError } 8300002 - Operation failed. Cannot connect to service.
   * @throws { BusinessError } 8300003 - System internal error.
   * @throws { BusinessError } 8300999 - Unknown error code.
   * @syscap SystemCapability.Telephony.CoreService
   * @since 6
   */
  /**
   * Obtains radio access technology (RAT) of the registered network. The system
   * returns RAT of the packet service (PS) and circuit service (CS) domain.
   *
   * @permission ohos.permission.GET_NETWORK_INFO
   * @param { number } slotId - Indicates the card slot index number,
   * ranging from 0 to the maximum card slot index number supported by the device.
   * @param { AsyncCallback<NetworkRadioTech> } callback - Returns
   * the RAT of PS domain and CS domain of registered network.
   * The values of RAT are as follows:
   * <ul>
   * <li>{@code RadioTechnology#RADIO_TECHNOLOGY_UNKNOWN}
   * <li>{@code RadioTechnology#RADIO_TECHNOLOGY_GSM}
   * <li>{@code RadioTechnology#RADIO_TECHNOLOGY_1XRTT}
   * <li>{@code RadioTechnology#RADIO_TECHNOLOGY_WCDMA}
   * <li>{@code RadioTechnology#RADIO_TECHNOLOGY_HSPA}
   * <li>{@code RadioTechnology#RADIO_TECHNOLOGY_HSPAP}
   * <li>{@code RadioTechnology#RADIO_TECHNOLOGY_TD_SCDMA}
   * <li>{@code RadioTechnology#RADIO_TECHNOLOGY_EVDO}
   * <li>{@code RadioTechnology#RADIO_TECHNOLOGY_EHRPD}
   * <li>{@code RadioTechnology#RADIO_TECHNOLOGY_LTE}
   * <li>{@code RadioTechnology#RADIO_TECHNOLOGY_LTE_CA}
   * <li>{@code RadioTechnology#RADIO_TECHNOLOGY_IWLAN}
   * <li>{@code RadioTechnology#RADIO_TECHNOLOGY_NR}
   * </ul>
   * @throws { BusinessError } 201 - Permission denied.
   * @throws { BusinessError } 401 - Parameter error.
   * @throws { BusinessError } 8300001 - Invalid parameter value.
   * @throws { BusinessError } 8300002 - Operation failed. Cannot connect to service.
   * @throws { BusinessError } 8300003 - System internal error.
   * @throws { BusinessError } 8300999 - Unknown error code.
   * @syscap SystemCapability.Telephony.CoreService
   * @since 11
   */
  function getRadioTech(slotId: number, callback: AsyncCallback<NetworkRadioTech>): void;

  /**
   * Obtains radio access technology (RAT) of the registered network. The system
   * returns RAT of the packet service (PS) and circuit service (CS) domain.
   *
   * @permission ohos.permission.GET_NETWORK_INFO
   * @param { number } slotId - Indicates the card slot index number,
   * ranging from 0 to the maximum card slot index number supported by the device.
   * @returns { Promise<{psRadioTech: RadioTechnology, csRadioTech: RadioTechnology}> } Returns
   * the enumeration of RadioTechnology. The values are as follows:
   * <ul>
   * <li>{@code RadioTechnology#RADIO_TECHNOLOGY_UNKNOWN}
   * <li>{@code RadioTechnology#RADIO_TECHNOLOGY_GSM}
   * <li>{@code RadioTechnology#RADIO_TECHNOLOGY_1XRTT}
   * <li>{@code RadioTechnology#RADIO_TECHNOLOGY_WCDMA}
   * <li>{@code RadioTechnology#RADIO_TECHNOLOGY_HSPA}
   * <li>{@code RadioTechnology#RADIO_TECHNOLOGY_HSPAP}
   * <li>{@code RadioTechnology#RADIO_TECHNOLOGY_TD_SCDMA}
   * <li>{@code RadioTechnology#RADIO_TECHNOLOGY_EVDO}
   * <li>{@code RadioTechnology#RADIO_TECHNOLOGY_EHRPD}
   * <li>{@code RadioTechnology#RADIO_TECHNOLOGY_LTE}
   * <li>{@code RadioTechnology#RADIO_TECHNOLOGY_LTE_CA}
   * <li>{@code RadioTechnology#RADIO_TECHNOLOGY_IWLAN}
   * <li>{@code RadioTechnology#RADIO_TECHNOLOGY_NR}
   * </ul>
   * @throws { BusinessError } 201 - Permission denied.
   * @throws { BusinessError } 401 - Parameter error.
   * @throws { BusinessError } 8300001 - Invalid parameter value.
   * @throws { BusinessError } 8300002 - Operation failed. Cannot connect to service.
   * @throws { BusinessError } 8300003 - System internal error.
   * @throws { BusinessError } 8300999 - Unknown error code.
   * @syscap SystemCapability.Telephony.CoreService
   * @since 6
   */
  /**
   * Obtains radio access technology (RAT) of the registered network. The system
   * returns RAT of the packet service (PS) and circuit service (CS) domain.
   *
   * @permission ohos.permission.GET_NETWORK_INFO
   * @param { number } slotId - Indicates the card slot index number,
   * ranging from 0 to the maximum card slot index number supported by the device.
   * @returns { Promise<NetworkRadioTech> } Returns the RAT of PS domain and CS domain of registered network.
   * The values of RAT are as follows:
   * <ul>
   * <li>{@code RadioTechnology#RADIO_TECHNOLOGY_UNKNOWN}
   * <li>{@code RadioTechnology#RADIO_TECHNOLOGY_GSM}
   * <li>{@code RadioTechnology#RADIO_TECHNOLOGY_1XRTT}
   * <li>{@code RadioTechnology#RADIO_TECHNOLOGY_WCDMA}
   * <li>{@code RadioTechnology#RADIO_TECHNOLOGY_HSPA}
   * <li>{@code RadioTechnology#RADIO_TECHNOLOGY_HSPAP}
   * <li>{@code RadioTechnology#RADIO_TECHNOLOGY_TD_SCDMA}
   * <li>{@code RadioTechnology#RADIO_TECHNOLOGY_EVDO}
   * <li>{@code RadioTechnology#RADIO_TECHNOLOGY_EHRPD}
   * <li>{@code RadioTechnology#RADIO_TECHNOLOGY_LTE}
   * <li>{@code RadioTechnology#RADIO_TECHNOLOGY_LTE_CA}
   * <li>{@code RadioTechnology#RADIO_TECHNOLOGY_IWLAN}
   * <li>{@code RadioTechnology#RADIO_TECHNOLOGY_NR}
   * </ul>
   * @throws { BusinessError } 201 - Permission denied.
   * @throws { BusinessError } 401 - Parameter error.
   * @throws { BusinessError } 8300001 - Invalid parameter value.
   * @throws { BusinessError } 8300002 - Operation failed. Cannot connect to service.
   * @throws { BusinessError } 8300003 - System internal error.
   * @throws { BusinessError } 8300999 - Unknown error code.
   * @syscap SystemCapability.Telephony.CoreService
   * @since 11
   */
  function getRadioTech(slotId: number): Promise<NetworkRadioTech>;

  /**
   * Obtains the network state of the registered network.
   *
   * @permission ohos.permission.GET_NETWORK_INFO
   * @param { number } slotId - Indicates the card slot index number,
   * ranging from 0 to the maximum card slot index number supported by the device.
   * @param { AsyncCallback<NetworkState> } callback - Indicates the callback for getting network registration state.
   * @throws { BusinessError } 201 - Permission denied.
   * @throws { BusinessError } 401 - Parameter error.
   * @throws { BusinessError } 8300001 - Invalid parameter value.
   * @throws { BusinessError } 8300002 - Operation failed. Cannot connect to service.
   * @throws { BusinessError } 8300003 - System internal error.
   * @throws { BusinessError } 8300999 - Unknown error code.
   * @syscap SystemCapability.Telephony.CoreService
   * @since 6
   */
  function getNetworkState(slotId: number, callback: AsyncCallback<NetworkState>): void;

  /**
   * Obtains the network state of the registered network.
   *
   * @permission ohos.permission.GET_NETWORK_INFO
   * @param { number } slotId - Indicates the card slot index number,
   * ranging from 0 to the maximum card slot index number supported by the device.
   * @returns { Promise<NetworkState> } Returns the NetworkState object.
   * @throws { BusinessError } 201 - Permission denied.
   * @throws { BusinessError } 401 - Parameter error.
   * @throws { BusinessError } 8300001 - Invalid parameter value.
   * @throws { BusinessError } 8300002 - Operation failed. Cannot connect to service.
   * @throws { BusinessError } 8300003 - System internal error.
   * @throws { BusinessError } 8300999 - Unknown error code.
   * @syscap SystemCapability.Telephony.CoreService
   * @since 6
   */
  function getNetworkState(slotId?: number): Promise<NetworkState>;

  /**
   * Obtains the network state of the registered network.
   *
   * @permission ohos.permission.GET_NETWORK_INFO
   * @param { AsyncCallback<NetworkState> } callback - Indicates the callback for getting network registration state.
   * @throws { BusinessError } 201 - Permission denied.
   * @throws { BusinessError } 401 - Parameter error.
   * @throws { BusinessError } 8300001 - Invalid parameter value.
   * @throws { BusinessError } 8300002 - Operation failed. Cannot connect to service.
   * @throws { BusinessError } 8300003 - System internal error.
   * @throws { BusinessError } 8300999 - Unknown error code.
   * @syscap SystemCapability.Telephony.CoreService
   * @since 6
   */
  function getNetworkState(callback: AsyncCallback<NetworkState>): void;

  /**
   * Actively requests to update location information.
   *
   * @permission ohos.permission.LOCATION and ohos.permission.APPROXIMATELY_LOCATION
   * @param { number } slotId - Indicates the card slot index number, ranging from 0 to the maximum card slot
   * index number supported by the device.
   * @param { AsyncCallback<void> } callback - The callback of sendUpdateCellLocationRequest.
   * @throws { BusinessError } 201 - Permission denied.
   * @throws { BusinessError } 202 - Non-system applications use system APIs.
   * @throws { BusinessError } 401 - Parameter error.
   * @throws { BusinessError } 8300001 - Invalid parameter value.
   * @throws { BusinessError } 8300002 - Operation failed. Cannot connect to service.
   * @throws { BusinessError } 8300003 - System internal error.
   * @throws { BusinessError } 8300999 - Unknown error code.
   * @syscap SystemCapability.Telephony.CoreService
   * @systemapi Hide this for inner system use.
   * @since 8
   */
  function sendUpdateCellLocationRequest(slotId: number, callback: AsyncCallback<void>): void;

  /**
   * Actively requests to update location information.
   *
   * @permission ohos.permission.LOCATION and ohos.permission.APPROXIMATELY_LOCATION
   * @param { number } slotId - Indicates the card slot index number, ranging from 0 to the maximum card slot
   * index number supported by the device.
   * @returns { Promise<void> } The promise returned by the sendUpdateCellLocationRequest.
   * @throws { BusinessError } 201 - Permission denied.
   * @throws { BusinessError } 202 - Non-system applications use system APIs.
   * @throws { BusinessError } 401 - Parameter error.
   * @throws { BusinessError } 8300001 - Invalid parameter value.
   * @throws { BusinessError } 8300002 - Operation failed. Cannot connect to service.
   * @throws { BusinessError } 8300003 - System internal error.
   * @throws { BusinessError } 8300999 - Unknown error code.
   * @syscap SystemCapability.Telephony.CoreService
   * @systemapi Hide this for inner system use.
   * @since 8
   */
  function sendUpdateCellLocationRequest(slotId?: number): Promise<void>;

  /**
   * Actively requests to update location information.
   *
   * @permission ohos.permission.LOCATION and ohos.permission.APPROXIMATELY_LOCATION
   * @param { AsyncCallback<void> } callback - The callback of sendUpdateCellLocationRequest.
   * @throws { BusinessError } 201 - Permission denied.
   * @throws { BusinessError } 202 - Non-system applications use system APIs.
   * @throws { BusinessError } 401 - Parameter error.
   * @throws { BusinessError } 8300001 - Invalid parameter value.
   * @throws { BusinessError } 8300002 - Operation failed. Cannot connect to service.
   * @throws { BusinessError } 8300003 - System internal error.
   * @throws { BusinessError } 8300999 - Unknown error code.
   * @syscap SystemCapability.Telephony.CoreService
   * @systemapi Hide this for inner system use.
   * @since 8
   */
  function sendUpdateCellLocationRequest(callback: AsyncCallback<void>): void;

  /**
   * Get the current cell information.
   *
   * @permission ohos.permission.LOCATION and ohos.permission.APPROXIMATELY_LOCATION
   * @param { number } slotId - Indicates the card slot index number, ranging from 0 to the maximum card slot
   * index number supported by the device.
   * @param { AsyncCallback<Array<CellInformation>> } callback - Indicates the callback for getting cell information.
   * @throws { BusinessError } 201 - Permission denied.
   * @throws { BusinessError } 202 - Non-system applications use system APIs.
   * @throws { BusinessError } 401 - Parameter error.
   * @throws { BusinessError } 8300001 - Invalid parameter value.
   * @throws { BusinessError } 8300002 - Operation failed. Cannot connect to service.
   * @throws { BusinessError } 8300003 - System internal error.
   * @throws { BusinessError } 8300999 - Unknown error code.
   * @syscap SystemCapability.Telephony.CoreService
   * @systemapi Hide this for inner system use.
   * @since 8
   */
  function getCellInformation(slotId: number, callback: AsyncCallback<Array<CellInformation>>): void;

  /**
   * Get the current cell information.
   *
   * @permission ohos.permission.LOCATION and ohos.permission.APPROXIMATELY_LOCATION
   * @param { number } slotId - Indicates the card slot index number, ranging from 0 to the maximum card slot
   * index number supported by the device.
   * @returns { Promise<Array<CellInformation>> } Returns the current cell information.
   * @throws { BusinessError } 201 - Permission denied.
   * @throws { BusinessError } 202 - Non-system applications use system APIs.
   * @throws { BusinessError } 401 - Parameter error.
   * @throws { BusinessError } 8300001 - Invalid parameter value.
   * @throws { BusinessError } 8300002 - Operation failed. Cannot connect to service.
   * @throws { BusinessError } 8300003 - System internal error.
   * @throws { BusinessError } 8300999 - Unknown error code.
   * @syscap SystemCapability.Telephony.CoreService
   * @systemapi Hide this for inner system use.
   * @since 8
   */
  function getCellInformation(slotId?: number): Promise<Array<CellInformation>>;

  /**
   * Get the current cell information.
   *
   * @permission ohos.permission.LOCATION and ohos.permission.APPROXIMATELY_LOCATION
   * @param { AsyncCallback<Array<CellInformation>> } callback - Indicates the callback for getting cell information.
   * @throws { BusinessError } 201 - Permission denied.
   * @throws { BusinessError } 202 - Non-system applications use system APIs.
   * @throws { BusinessError } 401 - Parameter error.
   * @throws { BusinessError } 8300001 - Invalid parameter value.
   * @throws { BusinessError } 8300002 - Operation failed. Cannot connect to service.
   * @throws { BusinessError } 8300003 - System internal error.
   * @throws { BusinessError } 8300999 - Unknown error code.
   * @syscap SystemCapability.Telephony.CoreService
   * @systemapi Hide this for inner system use.
   * @since 8
   */
  function getCellInformation(callback: AsyncCallback<Array<CellInformation>>): void;

  /**
   * Obtains the network search mode of the SIM card in a specified slot.
   *
   * @param { number } slotId - Indicates the card slot index number, ranging from 0 to the maximum card slot
   * index number supported by the device.
   * @param { AsyncCallback<NetworkSelectionMode> } callback - Indicates the callback for getting
   * the network search mode of the SIM card. Available values are as follows:
   * <ul>
   * <li>{@link NetworkSelectionMode#NETWORK_SELECTION_UNKNOWN}
   * <li>{@link NetworkSelectionMode#NETWORK_SELECTION_AUTOMATIC}
   * <li>{@link NetworkSelectionMode#NETWORK_SELECTION_MANUAL}
   * <ul>
   * @throws { BusinessError } 401 - Parameter error.
   * @throws { BusinessError } 8300001 - Invalid parameter value.
   * @throws { BusinessError } 8300002 - Operation failed. Cannot connect to service.
   * @throws { BusinessError } 8300003 - System internal error.
   * @throws { BusinessError } 8300999 - Unknown error code.
   * @syscap SystemCapability.Telephony.CoreService
   * @since 6
   */
  function getNetworkSelectionMode(slotId: number, callback: AsyncCallback<NetworkSelectionMode>): void;

  /**
   * Obtains the network search mode of the SIM card in a specified slot.
   *
   * @param { number } slotId - Indicates the card slot index number, ranging from 0 to the maximum card slot
   * index number supported by the device.
   * @returns { Promise<NetworkSelectionMode> } Returns the network search mode of the SIM card.
   * Available values are as follows:
   * <ul>
   * <li>{@link NetworkSelectionMode#NETWORK_SELECTION_UNKNOWN}
   * <li>{@link NetworkSelectionMode#NETWORK_SELECTION_AUTOMATIC}
   * <li>{@link NetworkSelectionMode#NETWORK_SELECTION_MANUAL}
   * <ul>
   * @throws { BusinessError } 401 - Parameter error.
   * @throws { BusinessError } 8300001 - Invalid parameter value.
   * @throws { BusinessError } 8300002 - Operation failed. Cannot connect to service.
   * @throws { BusinessError } 8300003 - System internal error.
   * @throws { BusinessError } 8300999 - Unknown error code.
   * @syscap SystemCapability.Telephony.CoreService
   * @since 6
   */
  function getNetworkSelectionMode(slotId: number): Promise<NetworkSelectionMode>;

  /**
   * Set the current network selection mode.
   *
   * @permission ohos.permission.SET_TELEPHONY_STATE
   * @param { NetworkSelectionModeOptions } options Indicates the network selection mode option.
   * @param { AsyncCallback<void> } callback - The callback of setNetworkSelectionMode.
   * @throws { BusinessError } 201 - Permission denied.
   * @throws { BusinessError } 202 - Non-system applications use system APIs.
   * @throws { BusinessError } 401 - Parameter error.
   * @throws { BusinessError } 8300001 - Invalid parameter value.
   * @throws { BusinessError } 8300002 - Operation failed. Cannot connect to service.
   * @throws { BusinessError } 8300003 - System internal error.
   * @throws { BusinessError } 8300999 - Unknown error code.
   * @syscap SystemCapability.Telephony.CoreService
   * @systemapi Hide this for inner system use.
   * @since 6
   */
  function setNetworkSelectionMode(options: NetworkSelectionModeOptions, callback: AsyncCallback<void>): void;

  /**
   * Set the current network selection mode.
   *
   * @permission ohos.permission.SET_TELEPHONY_STATE
   * @param { NetworkSelectionModeOptions } options Indicates the network selection mode option.
   * @returns { Promise<void> } The promise returned by the setNetworkSelectionMode.
   * @throws { BusinessError } 201 - Permission denied.
   * @throws { BusinessError } 202 - Non-system applications use system APIs.
   * @throws { BusinessError } 401 - Parameter error.
   * @throws { BusinessError } 8300001 - Invalid parameter value.
   * @throws { BusinessError } 8300002 - Operation failed. Cannot connect to service.
   * @throws { BusinessError } 8300003 - System internal error.
   * @throws { BusinessError } 8300999 - Unknown error code.
   * @syscap SystemCapability.Telephony.CoreService
   * @systemapi Hide this for inner system use.
   * @since 6
   */
  function setNetworkSelectionMode(options: NetworkSelectionModeOptions): Promise<void>;

  /**
   * Get network search information.
   *
   * @permission ohos.permission.GET_TELEPHONY_STATE
   * @param { number } slotId - Indicates the card slot index number, ranging from 0 to the maximum card slot
   * index number supported by the device.
   * @param { AsyncCallback<NetworkSearchResult> } callback - Indicates the callback for getting
   * the search results of the network.
   * @throws { BusinessError } 201 - Permission denied.
   * @throws { BusinessError } 202 - Non-system applications use system APIs.
   * @throws { BusinessError } 401 - Parameter error.
   * @throws { BusinessError } 8300001 - Invalid parameter value.
   * @throws { BusinessError } 8300002 - Operation failed. Cannot connect to service.
   * @throws { BusinessError } 8300003 - System internal error.
   * @throws { BusinessError } 8300999 - Unknown error code.
   * @syscap SystemCapability.Telephony.CoreService
   * @systemapi Hide this for inner system use.
   * @since 6
   */
  function getNetworkSearchInformation(slotId: number, callback: AsyncCallback<NetworkSearchResult>): void;

  /**
   * Get network search information.
   *
   * @permission ohos.permission.GET_TELEPHONY_STATE
   * @param { number } slotId - Indicates the card slot index number, ranging from 0 to the maximum card slot
   * index number supported by the device.
   * @returns { Promise<NetworkSearchResult> } Returns the search results of the network.
   * @throws { BusinessError } 201 - Permission denied.
   * @throws { BusinessError } 202 - Non-system applications use system APIs.
   * @throws { BusinessError } 401 - Parameter error.
   * @throws { BusinessError } 8300001 - Invalid parameter value.
   * @throws { BusinessError } 8300002 - Operation failed. Cannot connect to service.
   * @throws { BusinessError } 8300003 - System internal error.
   * @throws { BusinessError } 8300999 - Unknown error code.
   * @syscap SystemCapability.Telephony.CoreService
   * @systemapi Hide this for inner system use.
   * @since 6
   */
  function getNetworkSearchInformation(slotId: number): Promise<NetworkSearchResult>;

  /**
   * Obtains the ISO-defined country code of the country where the registered network is deployed.
   *
   * @param { number } slotId - Indicates the card slot index number,
   * ranging from 0 to the maximum card slot index number supported by the device.
   * @param { AsyncCallback<string> } callback - Indicates the callback for getting the country code
   * defined in ISO 3166-2; returns an empty string if the device is not registered with any network.
   * @throws { BusinessError } 401 - Parameter error.
   * @throws { BusinessError } 8300001 - Invalid parameter value.
   * @throws { BusinessError } 8300002 - Operation failed. Cannot connect to service.
   * @throws { BusinessError } 8300003 - System internal error.
   * @throws { BusinessError } 8300999 - Unknown error code.
   * @syscap SystemCapability.Telephony.CoreService
   * @since 7
   */
  function getISOCountryCodeForNetwork(slotId: number, callback: AsyncCallback<string>): void;

  /**
   * Obtains the ISO-defined country code of the country where the registered network is deployed.
   *
   * @param { number } slotId - Indicates the card slot index number,
   * ranging from 0 to the maximum card slot index number supported by the device.
   * @returns { Promise<string> } Returns the country code defined in ISO 3166-2.
   * Returns an empty string if the device is not registered with any network.
   * @throws { BusinessError } 401 - Parameter error.
   * @throws { BusinessError } 8300001 - Invalid parameter value.
   * @throws { BusinessError } 8300002 - Operation failed. Cannot connect to service.
   * @throws { BusinessError } 8300003 - System internal error.
   * @throws { BusinessError } 8300999 - Unknown error code.
   * @syscap SystemCapability.Telephony.CoreService
   * @since 7
   */
  function getISOCountryCodeForNetwork(slotId: number): Promise<string>;

  /**
   * Obtains the ISO-defined country code of the country where the registered network is deployed.
   *
   * @param { number } slotId - Indicates the card slot index number,
   * ranging from 0 to the maximum card slots supported by the device.
   * @returns { string } Returns the country code defined in ISO 3166-2.
   * Returns an empty string if the device is not registered with any network.
   * @syscap SystemCapability.Telephony.CoreService
   * @since 10
   */
  function getISOCountryCodeForNetworkSync(slotId: number): string;

  /**
   * Get the option mode of NR.
   *
   * @param { number } slotId - Indicates the card slot index number, ranging from 0 to the maximum card slot
   * index number supported by the device.
   * @param { AsyncCallback<NrOptionMode> } callback - Indicates the callback for getting the selection mode of NR.
   * @throws { BusinessError } 202 - Non-system applications use system APIs.
   * @throws { BusinessError } 401 - Parameter error.
   * @throws { BusinessError } 8300001 - Invalid parameter value.
   * @throws { BusinessError } 8300002 - Operation failed. Cannot connect to service.
   * @throws { BusinessError } 8300003 - System internal error.
   * @throws { BusinessError } 8300999 - Unknown error code.
   * @syscap SystemCapability.Telephony.CoreService
   * @systemapi Hide this for inner system use.
   * @since 8
   * @deprecated since 10
   * @useinstead telephony.radio#getNROptionMode
   */
  function getNrOptionMode(slotId: number, callback: AsyncCallback<NrOptionMode>): void;

  /**
   * Get the option mode of NR.
   *
   * @param { number } slotId - Indicates the card slot index number, ranging from 0 to the maximum card slot
   * index number supported by the device.
   * @returns { Promise<NrOptionMode> } Returns the selection mode of NR.
   * @throws { BusinessError } 202 - Non-system applications use system APIs.
   * @throws { BusinessError } 401 - Parameter error.
   * @throws { BusinessError } 8300001 - Invalid parameter value.
   * @throws { BusinessError } 8300002 - Operation failed. Cannot connect to service.
   * @throws { BusinessError } 8300003 - System internal error.
   * @throws { BusinessError } 8300999 - Unknown error code.
   * @syscap SystemCapability.Telephony.CoreService
   * @systemapi Hide this for inner system use.
   * @since 8
   * @deprecated since 10
   * @useinstead telephony.radio#getNROptionMode
   */
  function getNrOptionMode(slotId?: number): Promise<NrOptionMode>;

  /**
   * Get the option mode of NR.
   *
   * @param { AsyncCallback<NrOptionMode> } callback - Indicates the callback for getting the selection mode of NR.
   * @throws { BusinessError } 202 - Non-system applications use system APIs.
   * @throws { BusinessError } 401 - Parameter error.
   * @throws { BusinessError } 8300001 - Invalid parameter value.
   * @throws { BusinessError } 8300002 - Operation failed. Cannot connect to service.
   * @throws { BusinessError } 8300003 - System internal error.
   * @throws { BusinessError } 8300999 - Unknown error code.
   * @syscap SystemCapability.Telephony.CoreService
   * @systemapi Hide this for inner system use.
   * @since 8
   * @deprecated since 10
   * @useinstead telephony.radio#getNROptionMode
   */
  function getNrOptionMode(callback: AsyncCallback<NrOptionMode>): void;

  /**
   * Obtains the IMEI of a specified card slot of the device.
   *
   * @permission ohos.permission.GET_TELEPHONY_STATE
   * @param { number } slotId - Indicates the card slot index number, ranging from 0 to the maximum card slot
   * index number supported by the device.
   * @param { AsyncCallback<string> } callback - Indicates the callback for getting the IMEI.
   * Returns an empty string if the IMEI does not exist.
   * @throws { BusinessError } 201 - Permission denied.
   * @throws { BusinessError } 202 - Non-system applications use system APIs.
   * @throws { BusinessError } 401 - Parameter error.
   * @throws { BusinessError } 8300001 - Invalid parameter value.
   * @throws { BusinessError } 8300002 - Operation failed. Cannot connect to service.
   * @throws { BusinessError } 8300003 - System internal error.
   * @throws { BusinessError } 8300999 - Unknown error code.
   * @syscap SystemCapability.Telephony.CoreService
   * @systemapi Hide this for inner system use.
   * @since 8
   */
  function getIMEI(slotId: number, callback: AsyncCallback<string>): void;

  /**
   * Obtains the IMEI of a specified card slot of the device.
   *
   * @permission ohos.permission.GET_TELEPHONY_STATE
   * @param { number } slotId - Indicates the card slot index number, ranging from 0 to the maximum card slot
   * index number supported by the device.
   * @returns { Promise<string> } Returns the IMEI. Returns an empty string if the IMEI does not exist.
   * @throws { BusinessError } 201 - Permission denied.
   * @throws { BusinessError } 202 - Non-system applications use system APIs.
   * @throws { BusinessError } 401 - Parameter error.
   * @throws { BusinessError } 8300001 - Invalid parameter value.
   * @throws { BusinessError } 8300002 - Operation failed. Cannot connect to service.
   * @throws { BusinessError } 8300003 - System internal error.
   * @throws { BusinessError } 8300999 - Unknown error code.
   * @syscap SystemCapability.Telephony.CoreService
   * @systemapi Hide this for inner system use.
   * @since 8
   */
  function getIMEI(slotId?: number): Promise<string>;

  /**
   * Obtains the IMEI of a specified card slot of the device.
   *
   * @permission ohos.permission.GET_TELEPHONY_STATE
   * @param { AsyncCallback<string> } callback - Indicates the callback for getting the IMEI.
   * Returns an empty string if the IMEI does not exist.
   * @throws { BusinessError } 201 - Permission denied.
   * @throws { BusinessError } 202 - Non-system applications use system APIs.
   * @throws { BusinessError } 401 - Parameter error.
   * @throws { BusinessError } 8300001 - Invalid parameter value.
   * @throws { BusinessError } 8300002 - Operation failed. Cannot connect to service.
   * @throws { BusinessError } 8300003 - System internal error.
   * @throws { BusinessError } 8300999 - Unknown error code.
   * @syscap SystemCapability.Telephony.CoreService
   * @systemapi Hide this for inner system use.
   * @since 8
   */
  function getIMEI(callback: AsyncCallback<string>): void;

  /**
   * Obtains the MEID of a specified card slot of the device.
   *
   * @permission ohos.permission.GET_TELEPHONY_STATE
   * @param { number } slotId - Indicates the card slot index number, ranging from 0 to the maximum card slot
   * index number supported by the device.
   * @param { AsyncCallback<string> } callback - Indicates the callback for getting the MEID.
   * Returns an empty string if the MEID does not exist.
   * @throws { BusinessError } 201 - Permission denied.
   * @throws { BusinessError } 202 - Non-system applications use system APIs.
   * @throws { BusinessError } 401 - Parameter error.
   * @throws { BusinessError } 8300001 - Invalid parameter value.
   * @throws { BusinessError } 8300002 - Operation failed. Cannot connect to service.
   * @throws { BusinessError } 8300003 - System internal error.
   * @throws { BusinessError } 8300999 - Unknown error code.
   * @syscap SystemCapability.Telephony.CoreService
   * @systemapi Hide this for inner system use.
   * @since 8
   */
  function getMEID(slotId: number, callback: AsyncCallback<string>): void;

  /**
   * Obtains the MEID of a specified card slot of the device.
   *
   * @permission ohos.permission.GET_TELEPHONY_STATE
   * @param { number } slotId - Indicates the card slot index number, ranging from 0 to the maximum card slot
   * index number supported by the device.
   * @returns { Promise<string> } Returns the MEID. Returns an empty string if the MEID does not exist.
   * @throws { BusinessError } 201 - Permission denied.
   * @throws { BusinessError } 202 - Non-system applications use system APIs.
   * @throws { BusinessError } 401 - Parameter error.
   * @throws { BusinessError } 8300001 - Invalid parameter value.
   * @throws { BusinessError } 8300002 - Operation failed. Cannot connect to service.
   * @throws { BusinessError } 8300003 - System internal error.
   * @throws { BusinessError } 8300999 - Unknown error code.
   * @syscap SystemCapability.Telephony.CoreService
   * @systemapi Hide this for inner system use.
   * @since 8
   */
  function getMEID(slotId?: number): Promise<string>;

  /**
   * Obtains the MEID of a specified card slot of the device.
   *
   * @permission ohos.permission.GET_TELEPHONY_STATE
   * @param { AsyncCallback<string> } callback - Indicates the callback for getting the MEID.
   * Returns an empty string if the MEID does not exist.
   * @throws { BusinessError } 201 - Permission denied.
   * @throws { BusinessError } 202 - Non-system applications use system APIs.
   * @throws { BusinessError } 401 - Parameter error.
   * @throws { BusinessError } 8300001 - Invalid parameter value.
   * @throws { BusinessError } 8300002 - Operation failed. Cannot connect to service.
   * @throws { BusinessError } 8300003 - System internal error.
   * @throws { BusinessError } 8300999 - Unknown error code.
   * @syscap SystemCapability.Telephony.CoreService
   * @systemapi Hide this for inner system use.
   * @since 8
   */
  function getMEID(callback: AsyncCallback<string>): void;

  /**
   * Obtains the unique device ID of a specified card slot of the device.
   *
   * If the device is registered with a 3GPP-compliant network, the international mobile equipment identity
   * (IMEI) is returned. If the device is registered with a 3GPP2-compliant network, the mobile equipment identifier
   * (MEID) is returned.
   *
   * @permission ohos.permission.GET_TELEPHONY_STATE
   * @param { number } slotId - Indicates the card slot index number, ranging from 0 to the maximum card slot
   * index number supported by the device.
   * @param { AsyncCallback<string> } callback - Indicates the callback for getting the unique device ID.
   * Returns an empty string if the unique device ID does not exist.
   * @throws { BusinessError } 201 - Permission denied.
   * @throws { BusinessError } 202 - Non-system applications use system APIs.
   * @throws { BusinessError } 401 - Parameter error.
   * @throws { BusinessError } 8300001 - Invalid parameter value.
   * @throws { BusinessError } 8300002 - Operation failed. Cannot connect to service.
   * @throws { BusinessError } 8300003 - System internal error.
   * @throws { BusinessError } 8300999 - Unknown error code.
   * @syscap SystemCapability.Telephony.CoreService
   * @systemapi Hide this for inner system use.
   * @since 8
   */
  function getUniqueDeviceId(slotId: number, callback: AsyncCallback<string>): void;

  /**
   * Obtains the unique device ID of a specified card slot of the device.
   *
   * If the device is registered with a 3GPP-compliant network, the international mobile equipment identity
   * (IMEI) is returned. If the device is registered with a 3GPP2-compliant network, the mobile equipment identifier
   * (MEID) is returned.
   *
   * @permission ohos.permission.GET_TELEPHONY_STATE
   * @param { number } slotId - Indicates the card slot index number, ranging from 0 to the maximum card slot
   * index number supported by the device.
   * @returns { Promise<string> } Returns the unique device ID.
   * Returns an empty string if the unique device ID does not exist.
   * @throws { BusinessError } 201 - Permission denied.
   * @throws { BusinessError } 202 - Non-system applications use system APIs.
   * @throws { BusinessError } 401 - Parameter error.
   * @throws { BusinessError } 8300001 - Invalid parameter value.
   * @throws { BusinessError } 8300002 - Operation failed. Cannot connect to service.
   * @throws { BusinessError } 8300003 - System internal error.
   * @throws { BusinessError } 8300999 - Unknown error code.
   * @syscap SystemCapability.Telephony.CoreService
   * @systemapi Hide this for inner system use.
   * @since 8
   */
  function getUniqueDeviceId(slotId?: number): Promise<string>;

  /**
   * Obtains the unique device ID of a specified card slot of the device.
   *
   * If the device is registered with a 3GPP-compliant network, the international mobile equipment identity
   * (IMEI) is returned. If the device is registered with a 3GPP2-compliant network, the mobile equipment identifier
   * (MEID) is returned.
   *
   * @permission ohos.permission.GET_TELEPHONY_STATE
   * @param { AsyncCallback<string> } callback - Indicates the callback for getting the unique device ID.
   * Returns an empty string if the unique device ID does not exist.
   * @throws { BusinessError } 201 - Permission denied.
   * @throws { BusinessError } 202 - Non-system applications use system APIs.
   * @throws { BusinessError } 401 - Parameter error.
   * @throws { BusinessError } 8300001 - Invalid parameter value.
   * @throws { BusinessError } 8300002 - Operation failed. Cannot connect to service.
   * @throws { BusinessError } 8300003 - System internal error.
   * @throws { BusinessError } 8300999 - Unknown error code.
   * @syscap SystemCapability.Telephony.CoreService
   * @systemapi Hide this for inner system use.
   * @since 8
   */
  function getUniqueDeviceId(callback: AsyncCallback<string>): void;

  /**
   * Obtains the index number of the card slot where the primary card is located if multiple SIM cards are inserted.
   *
   * The primary card is the SIM card inserted in the card slot that uses data services by default.
   *
   * @param { AsyncCallback<number> } callback - Indicates the callback for getting the index number of
   * the primary card slot.
   * @throws { BusinessError } 401 - Parameter error.
   * @throws { BusinessError } 8300001 - Invalid parameter value.
   * @throws { BusinessError } 8300002 - Operation failed. Cannot connect to service.
   * @throws { BusinessError } 8300003 - System internal error.
   * @throws { BusinessError } 8300999 - Unknown error code.
   * @syscap SystemCapability.Telephony.CoreService
   * @since 7
   */
  function getPrimarySlotId(callback: AsyncCallback<number>): void;

  /**
   * Obtains the index number of the card slot where the primary card is located if multiple SIM cards are inserted.
   *
   * The primary card is the SIM card inserted in the card slot that uses data services by default.
   *
   * @returns { Promise<number> } Returns the index number of the primary card slot.
   * @throws { BusinessError } 8300002 - Operation failed. Cannot connect to service.
   * @throws { BusinessError } 8300003 - System internal error.
   * @throws { BusinessError } 8300999 - Unknown error code.
   * @syscap SystemCapability.Telephony.CoreService
   * @since 7
   */
  function getPrimarySlotId(): Promise<number>;

  /**
   * Set the index number of the main SIM card slot.
   *
   * @permission ohos.permission.SET_TELEPHONY_STATE
   * @param { number } slotId - Indicates the card slot index number, ranging from 0 to the maximum card slot
   * index number supported by the device.
   * @param { AsyncCallback<void> } callback - The callback of setPrimarySlotId.
   * @throws { BusinessError } 201 - Permission denied.
   * @throws { BusinessError } 202 - Non-system applications use system APIs.
   * @throws { BusinessError } 401 - Parameter error.
   * @throws { BusinessError } 8300001 - Invalid parameter value.
   * @throws { BusinessError } 8300002 - Operation failed. Cannot connect to service.
   * @throws { BusinessError } 8300003 - System internal error.
   * @throws { BusinessError } 8300004 - Do not have sim card.
   * @throws { BusinessError } 8300999 - Unknown error code.
   * @syscap SystemCapability.Telephony.CoreService
   * @systemapi Hide this for inner system use.
   * @since 8
   */
  function setPrimarySlotId(slotId: number, callback: AsyncCallback<void>): void;

  /**
   * Set the index number of the main SIM card slot.
   *
   * @permission ohos.permission.SET_TELEPHONY_STATE
   * @param { number } slotId - Indicates the card slot index number, ranging from 0 to the maximum card slot
   * index number supported by the device.
   * @returns { Promise<void> } The promise returned by the setPrimarySlotId.
   * @throws { BusinessError } 201 - Permission denied.
   * @throws { BusinessError } 202 - Non-system applications use system APIs.
   * @throws { BusinessError } 401 - Parameter error.
   * @throws { BusinessError } 8300001 - Invalid parameter value.
   * @throws { BusinessError } 8300002 - Operation failed. Cannot connect to service.
   * @throws { BusinessError } 8300003 - System internal error.
   * @throws { BusinessError } 8300004 - Do not have sim card.
   * @throws { BusinessError } 8300999 - Unknown error code.
   * @syscap SystemCapability.Telephony.CoreService
   * @systemapi Hide this for inner system use.
   * @since 8
   */
  function setPrimarySlotId(slotId: number): Promise<void>;

  /**
   * Obtains the list of signal strength information of the registered network corresponding to a specified SIM card.
   *
   * @param { number } slotId - Indicates the card slot index number, ranging from 0 to the maximum card slot
   * index number supported by the device.
   * @param { AsyncCallback<Array<SignalInformation>> } callback - Indicates the callback for getting
   * the instance list of the child classes derived from {@link SignalInformation}.
   * @throws { BusinessError } 401 - Parameter error.
   * @throws { BusinessError } 8300001 - Invalid parameter value.
   * @throws { BusinessError } 8300002 - Operation failed. Cannot connect to service.
   * @throws { BusinessError } 8300003 - System internal error.
   * @throws { BusinessError } 8300999 - Unknown error code.
   * @syscap SystemCapability.Telephony.CoreService
   * @since 7
   */
  function getSignalInformation(slotId: number, callback: AsyncCallback<Array<SignalInformation>>): void;

  /**
   * Obtains the list of signal strength information of the registered network corresponding to a specified SIM card.
   *
   * @param { number } slotId - Indicates the card slot index number, ranging from 0 to the maximum card slot
   * index number supported by the device.
   * @returns { Promise<Array<SignalInformation>> } Returns the callback for getting the instance list of
   * the child classes derived from {@link SignalInformation}.
   * @throws { BusinessError } 401 - Parameter error.
   * @throws { BusinessError } 8300001 - Invalid parameter value.
   * @throws { BusinessError } 8300002 - Operation failed. Cannot connect to service.
   * @throws { BusinessError } 8300003 - System internal error.
   * @throws { BusinessError } 8300999 - Unknown error code.
   * @syscap SystemCapability.Telephony.CoreService
   * @since 7
   */
  function getSignalInformation(slotId: number): Promise<Array<SignalInformation>>;

  /**
   * Obtains the list of signal strength information of the registered network corresponding to a specified SIM card.
   *
   * @param { number } slotId - Indicates the card slot index number, ranging from 0 to the maximum
   * card slots supported by the device.
   * @returns { Array<SignalInformation> } Returns the callback for getting the instance list of
   * the child classes derived from {@link SignalInformation}.
   * @syscap SystemCapability.Telephony.CoreService
   * @since 10
   */
  function getSignalInformationSync(slotId: number): Array<SignalInformation>;

  /**
   * Checks whether the device supports 5G New Radio (NR).
   *
   * @returns { boolean } Returns {@code true} if the device supports 5G NR; returns {@code false} otherwise.
   * @syscap SystemCapability.Telephony.CoreService
   * @since 7
   * @deprecated since 9
   * @useinstead telephony.radio#isNRSupported
   */
  function isNrSupported(): boolean;

  /**
   * Checks whether the device supports 5G New Radio (NR) by according card slot.
   *
   * @param { number } slotId - Indicates the card slot index number, ranging from 0 to the maximum card slot
   * index number supported by the device.
   * @returns { boolean } Returns {@code true} if the device supports 5G NR; returns {@code false} otherwise.
   * @syscap SystemCapability.Telephony.CoreService
   * @since 8
   * @deprecated since 9
   * @useinstead telephony.radio#isNRSupported
   */
  function isNrSupported(slotId: number): boolean;

  /**
   * Checks whether the device supports 5G New Radio (NR).
   *
   * @returns { boolean } Returns {@code true} if the device supports 5G NR; returns {@code false} otherwise.
   * @syscap SystemCapability.Telephony.CoreService
   * @since 9
   */
  function isNRSupported(): boolean;

  /**
   * Checks whether the device supports 5G New Radio (NR) by according card slot.
   *
   * @param { number } slotId - Indicates the card slot index number, ranging from 0 to the maximum card slot
   * index number supported by the device.
   * @returns { boolean } Returns {@code true} if the device supports 5G NR; returns {@code false} otherwise.
   * @syscap SystemCapability.Telephony.CoreService
   * @since 9
   */
  function isNRSupported(slotId: number): boolean;

  /**
   * Checks whether the radio service is enabled.
   *
   * @permission ohos.permission.GET_NETWORK_INFO
   * @param { number } slotId - Indicates the card slot index number,
   * ranging from 0 to the maximum card slot index number supported by the device.
   * @param { AsyncCallback<boolean> } callback - Returns {@code true} If the radio service is enabled.
   * Returns {@code false} otherwise.
   * @throws { BusinessError } 201 - Permission denied.
   * @throws { BusinessError } 401 - Parameter error.
   * @throws { BusinessError } 8300001 - Invalid parameter value.
   * @throws { BusinessError } 8300002 - Operation failed. Cannot connect to service.
   * @throws { BusinessError } 8300003 - System internal error.
   * @throws { BusinessError } 8300999 - Unknown error code.
   * @syscap SystemCapability.Telephony.CoreService
   * @since 7
   */
  function isRadioOn(slotId: number, callback: AsyncCallback<boolean>): void;

  /**
   * Checks whether the radio service is enabled.
   *
   * @permission ohos.permission.GET_NETWORK_INFO
   * @param { number } slotId - Indicates the card slot index number,
   * ranging from 0 to the maximum card slot index number supported by the device.
   * @returns { Promise<boolean> } Returns {@code true} If the radio service is enabled; returns {@code false} otherwise.
   * @throws { BusinessError } 201 - Permission denied.
   * @throws { BusinessError } 401 - Parameter error.
   * @throws { BusinessError } 8300001 - Invalid parameter value.
   * @throws { BusinessError } 8300002 - Operation failed. Cannot connect to service.
   * @throws { BusinessError } 8300003 - System internal error.
   * @throws { BusinessError } 8300999 - Unknown error code.
   * @syscap SystemCapability.Telephony.CoreService
   * @since 7
   */
  function isRadioOn(slotId?: number): Promise<boolean>;

  /**
   * Checks whether the radio service is enabled.
   *
   * @permission ohos.permission.GET_NETWORK_INFO
   * @param { AsyncCallback<boolean> } callback - Returns {@code true} If the radio service is enabled.
   * Returns {@code false} otherwise.
   * @throws { BusinessError } 201 - Permission denied.
   * @throws { BusinessError } 401 - Parameter error.
   * @throws { BusinessError } 8300001 - Invalid parameter value.
   * @throws { BusinessError } 8300002 - Operation failed. Cannot connect to service.
   * @throws { BusinessError } 8300003 - System internal error.
   * @throws { BusinessError } 8300999 - Unknown error code.
   * @syscap SystemCapability.Telephony.CoreService
   * @since 7
   */
  function isRadioOn(callback: AsyncCallback<boolean>): void;

  /**
   * Turn on the radio service.
   *
   * @permission ohos.permission.SET_TELEPHONY_STATE
   * @param { number } slotId - Indicates the card slot index number,
   * ranging from 0 to the maximum card slot index number supported by the device.
   * @param { AsyncCallback<void> } callback - The callback of turnOnRadio.
   * @throws { BusinessError } 201 - Permission denied.
   * @throws { BusinessError } 202 - Non-system applications use system APIs.
   * @throws { BusinessError } 401 - Parameter error.
   * @throws { BusinessError } 8300001 - Invalid parameter value.
   * @throws { BusinessError } 8300002 - Operation failed. Cannot connect to service.
   * @throws { BusinessError } 8300003 - System internal error.
   * @throws { BusinessError } 8300999 - Unknown error code.
   * @syscap SystemCapability.Telephony.CoreService
   * @systemapi Hide this for inner system use.
   * @since 7
   */
  function turnOnRadio(slotId: number, callback: AsyncCallback<void>): void;

  /**
   * Turn on the radio service.
   *
   * @permission ohos.permission.SET_TELEPHONY_STATE
   * @param { number } slotId - Indicates the card slot index number,
   * ranging from 0 to the maximum card slot index number supported by the device.
   * @returns { Promise<void> } The promise returned by the turnOnRadio.
   * @throws { BusinessError } 201 - Permission denied.
   * @throws { BusinessError } 202 - Non-system applications use system APIs.
   * @throws { BusinessError } 401 - Parameter error.
   * @throws { BusinessError } 8300001 - Invalid parameter value.
   * @throws { BusinessError } 8300002 - Operation failed. Cannot connect to service.
   * @throws { BusinessError } 8300003 - System internal error.
   * @throws { BusinessError } 8300999 - Unknown error code.
   * @syscap SystemCapability.Telephony.CoreService
   * @systemapi Hide this for inner system use.
   * @since 7
   */
  function turnOnRadio(slotId?: number): Promise<void>;

  /**
   * Turn on the radio service.
   *
   * @permission ohos.permission.SET_TELEPHONY_STATE
   * @param { AsyncCallback<void> } callback - The callback of turnOnRadio.
   * @throws { BusinessError } 201 - Permission denied.
   * @throws { BusinessError } 202 - Non-system applications use system APIs.
   * @throws { BusinessError } 401 - Parameter error.
   * @throws { BusinessError } 8300001 - Invalid parameter value.
   * @throws { BusinessError } 8300002 - Operation failed. Cannot connect to service.
   * @throws { BusinessError } 8300003 - System internal error.
   * @throws { BusinessError } 8300999 - Unknown error code.
   * @syscap SystemCapability.Telephony.CoreService
   * @systemapi Hide this for inner system use.
   * @since 7
   */
  function turnOnRadio(callback: AsyncCallback<void>): void;

  /**
   * Turn off the radio service.
   *
   * @permission ohos.permission.SET_TELEPHONY_STATE
   * @param { number } slotId - Indicates the card slot index number,
   * ranging from 0 to the maximum card slot index number supported by the device.
   * @param { AsyncCallback<void> } callback - The callback of turnOffRadio.
   * @throws { BusinessError } 201 - Permission denied.
   * @throws { BusinessError } 202 - Non-system applications use system APIs.
   * @throws { BusinessError } 401 - Parameter error.
   * @throws { BusinessError } 8300001 - Invalid parameter value.
   * @throws { BusinessError } 8300002 - Operation failed. Cannot connect to service.
   * @throws { BusinessError } 8300003 - System internal error.
   * @throws { BusinessError } 8300999 - Unknown error code.
   * @syscap SystemCapability.Telephony.CoreService
   * @systemapi Hide this for inner system use.
   * @since 7
   */
  function turnOffRadio(slotId: number, callback: AsyncCallback<void>): void;

  /**
   * Turn off the radio service.
   *
   * @permission ohos.permission.SET_TELEPHONY_STATE
   * @param { number } slotId - Indicates the card slot index number,
   * ranging from 0 to the maximum card slot index number supported by the device.
   * @returns { Promise<void> } The promise returned by the turnOffRadio.
   * @throws { BusinessError } 201 - Permission denied.
   * @throws { BusinessError } 202 - Non-system applications use system APIs.
   * @throws { BusinessError } 401 - Parameter error.
   * @throws { BusinessError } 8300001 - Invalid parameter value.
   * @throws { BusinessError } 8300002 - Operation failed. Cannot connect to service.
   * @throws { BusinessError } 8300003 - System internal error.
   * @throws { BusinessError } 8300999 - Unknown error code.
   * @syscap SystemCapability.Telephony.CoreService
   * @systemapi Hide this for inner system use.
   * @since 7
   */
  function turnOffRadio(slotId?: number): Promise<void>;

  /**
   * Turn off the radio service.
   *
   * @permission ohos.permission.SET_TELEPHONY_STATE
   * @param { AsyncCallback<void> } callback - The callback of turnOffRadio.
   * @throws { BusinessError } 201 - Permission denied.
   * @throws { BusinessError } 202 - Non-system applications use system APIs.
   * @throws { BusinessError } 401 - Parameter error.
   * @throws { BusinessError } 8300001 - Invalid parameter value.
   * @throws { BusinessError } 8300002 - Operation failed. Cannot connect to service.
   * @throws { BusinessError } 8300003 - System internal error.
   * @throws { BusinessError } 8300999 - Unknown error code.
   * @syscap SystemCapability.Telephony.CoreService
   * @systemapi Hide this for inner system use.
   * @since 7
   */
  function turnOffRadio(callback: AsyncCallback<void>): void;

  /**
   * Get the operator name of the specified SIM card slot.
   *
   * @param { number } slotId - Indicates the card slot index number,
   * ranging from 0 to the maximum card slot index number supported by the device.
   * @param { AsyncCallback<string> } callback - Indicates the callback for getting the operator name.
   * @throws { BusinessError } 401 - Parameter error.
   * @throws { BusinessError } 8300001 - Invalid parameter value.
   * @throws { BusinessError } 8300002 - Operation failed. Cannot connect to service.
   * @throws { BusinessError } 8300003 - System internal error.
   * @throws { BusinessError } 8300999 - Unknown error code.
   * @syscap SystemCapability.Telephony.CoreService
   * @since 7
   */
  function getOperatorName(slotId: number, callback: AsyncCallback<string>): void;

  /**
   * Get the operator name of the specified SIM card slot.
   *
   * @param { number } slotId - Indicates the card slot index number,
   * ranging from 0 to the maximum card slot index number supported by the device.
   * @returns { Promise<string> } Returns the operator name.
   * @throws { BusinessError } 401 - Parameter error.
   * @throws { BusinessError } 8300001 - Invalid parameter value.
   * @throws { BusinessError } 8300002 - Operation failed. Cannot connect to service.
   * @throws { BusinessError } 8300003 - System internal error.
   * @throws { BusinessError } 8300999 - Unknown error code.
   * @syscap SystemCapability.Telephony.CoreService
   * @since 7
   */
  function getOperatorName(slotId: number): Promise<string>;

  /**
   * Get the operator name of the specified SIM card slot.
   *
   * @param { number } slotId - Indicates the card slot index number,
   * ranging from 0 to the maximum card slot index number supported by the device.
   * @returns { string } Returns the operator name.
   * @syscap SystemCapability.Telephony.CoreService
   * @since 10
   */
  function getOperatorNameSync(slotId: number): string;

  /**
   * Set the preferred network for the specified SIM card slot.
   *
   * @permission ohos.permission.SET_TELEPHONY_STATE
   * @param { number } slotId - Indicates the card slot index number,
   * ranging from 0 to the maximum card slot index number supported by the device.
   * @param { PreferredNetworkMode } networkMode - Indicates that you want to set the preferred network mode.
   * @param { AsyncCallback<void> } callback - The callback of setPreferredNetwork.
   * @throws { BusinessError } 201 - Permission denied.
   * @throws { BusinessError } 202 - Non-system applications use system APIs.
   * @throws { BusinessError } 401 - Parameter error.
   * @throws { BusinessError } 8300001 - Invalid parameter value.
   * @throws { BusinessError } 8300002 - Operation failed. Cannot connect to service.
   * @throws { BusinessError } 8300003 - System internal error.
   * @throws { BusinessError } 8300999 - Unknown error code.
   * @syscap SystemCapability.Telephony.CoreService
   * @systemapi Hide this for inner system use.
   * @since 8
   */
  function setPreferredNetwork(slotId: number, networkMode: PreferredNetworkMode, callback: AsyncCallback<void>): void;

  /**
   * Set the preferred network for the specified SIM card slot.
   *
   * @permission ohos.permission.SET_TELEPHONY_STATE
   * @param { number } slotId - Indicates the card slot index number,
   * ranging from 0 to the maximum card slot index number supported by the device.
   * @param { PreferredNetworkMode } networkMode - Indicates that you want to set the preferred network mode.
   * @returns { Promise<void> } The promise returned by the setPreferredNetwork.
   * @throws { BusinessError } 201 - Permission denied.
   * @throws { BusinessError } 202 - Non-system applications use system APIs.
   * @throws { BusinessError } 401 - Parameter error.
   * @throws { BusinessError } 8300001 - Invalid parameter value.
   * @throws { BusinessError } 8300002 - Operation failed. Cannot connect to service.
   * @throws { BusinessError } 8300003 - System internal error.
   * @throws { BusinessError } 8300999 - Unknown error code.
   * @syscap SystemCapability.Telephony.CoreService
   * @systemapi Hide this for inner system use.
   * @since 8
   */
  function setPreferredNetwork(slotId: number, networkMode: PreferredNetworkMode): Promise<void>;

  /**
   * Get the preferred network for the specified SIM card slot.
   *
   * @permission ohos.permission.GET_TELEPHONY_STATE
   * @param { number } slotId - Indicates the card slot index number,
   * ranging from 0 to the maximum card slot index number supported by the device.
   * @param { AsyncCallback<PreferredNetworkMode> } callback - Indicates the callback for getting
   * the preferred network mode to obtain.
   * @throws { BusinessError } 201 - Permission denied.
   * @throws { BusinessError } 202 - Non-system applications use system APIs.
   * @throws { BusinessError } 401 - Parameter error.
   * @throws { BusinessError } 8300001 - Invalid parameter value.
   * @throws { BusinessError } 8300002 - Operation failed. Cannot connect to service.
   * @throws { BusinessError } 8300003 - System internal error.
   * @throws { BusinessError } 8300999 - Unknown error code.
   * @syscap SystemCapability.Telephony.CoreService
   * @systemapi Hide this for inner system use.
   * @since 8
   */
  function getPreferredNetwork(slotId: number, callback: AsyncCallback<PreferredNetworkMode>): void;

  /**
   * Get the preferred network for the specified SIM card slot.
   *
   * @permission ohos.permission.GET_TELEPHONY_STATE
   * @param { number } slotId - Indicates the card slot index number,
   * ranging from 0 to the maximum card slot index number supported by the device.
   * @returns { Promise<PreferredNetworkMode> } Returns the callback for getting the preferred network mode to obtain.
   * @throws { BusinessError } 201 - Permission denied.
   * @throws { BusinessError } 202 - Non-system applications use system APIs.
   * @throws { BusinessError } 401 - Parameter error.
   * @throws { BusinessError } 8300001 - Invalid parameter value.
   * @throws { BusinessError } 8300002 - Operation failed. Cannot connect to service.
   * @throws { BusinessError } 8300003 - System internal error.
   * @throws { BusinessError } 8300999 - Unknown error code.
   * @syscap SystemCapability.Telephony.CoreService
   * @systemapi Hide this for inner system use.
   * @since 8
   */
  function getPreferredNetwork(slotId: number): Promise<PreferredNetworkMode>;

  /**
   * Set network capability.
   *
   * @permission ohos.permission.SET_TELEPHONY_STATE
   * @param { number } slotId - Indicates the card slot index number,
   * ranging from 0 to the maximum card slot index number supported by the device.
   * @param { NetworkCapabilityType } type - Indicates the service type of the {@link NetworkCapabilityType}.
   * @param { NetworkCapabilityState } state - Indicates the service ability of the {@link NetworkCapabilityState}.
   * @param { AsyncCallback<void> } callback - The callback of setNetworkCapability.
   * @throws { BusinessError } 201 - Permission denied.
   * @throws { BusinessError } 202 - Non-system applications use system APIs.
   * @throws { BusinessError } 401 - Parameter error.
   * @throws { BusinessError } 8300001 - Invalid parameter value.
   * @throws { BusinessError } 8300002 - Operation failed. Cannot connect to service.
   * @throws { BusinessError } 8300003 - System internal error.
   * @throws { BusinessError } 8300999 - Unknown error code.
   * @syscap SystemCapability.Telephony.CoreService
   * @systemapi Hide this for inner system use.
   * @since 10
   */
  function setNetworkCapability(slotId: number, type: NetworkCapabilityType, state: NetworkCapabilityState,
      callback: AsyncCallback<void>): void;

  /**
   * Set network ability switch.
   *
   * @permission ohos.permission.SET_TELEPHONY_STATE
   * @param { number } slotId - Indicates the card slot index number,
   * ranging from 0 to the maximum card slot index number supported by the device.
   * @param { NetworkCapabilityType } type - Indicates the service type of the {@link NetworkCapabilityType}.
   * @param { NetworkCapabilityState } state - Indicates the service ability of the {@link NetworkCapabilityState}.
   * @returns { Promise<void> } The promise returned by the setNetworkCapability.
   * @throws { BusinessError } 201 - Permission denied.
   * @throws { BusinessError } 202 - Non-system applications use system APIs.
   * @throws { BusinessError } 401 - Parameter error.
   * @throws { BusinessError } 8300001 - Invalid parameter value.
   * @throws { BusinessError } 8300002 - Operation failed. Cannot connect to service.
   * @throws { BusinessError } 8300003 - System internal error.
   * @throws { BusinessError } 8300999 - Unknown error code.
   * @syscap SystemCapability.Telephony.CoreService
   * @systemapi Hide this for inner system use.
   * @since 10
   */
  function setNetworkCapability(slotId: number, type: NetworkCapabilityType, state: NetworkCapabilityState): Promise<void>;

  /**
   * Get network capability.
   *
   * @permission ohos.permission.GET_TELEPHONY_STATE
   * @param { number } slotId - Indicates the card slot index number,
   * ranging from 0 to the maximum card slot index number supported by the device.
   * @param { NetworkCapabilityType } type - Indicates the service type of the {@link NetworkCapabilityType}.
   * @param { AsyncCallback<NetworkCapabilityState> } callback - Indicates the callback for getting
   * the network capability state.
   * @throws { BusinessError } 201 - Permission denied.
   * @throws { BusinessError } 202 - Non-system applications use system APIs.
   * @throws { BusinessError } 401 - Parameter error.
   * @throws { BusinessError } 8300001 - Invalid parameter value.
   * @throws { BusinessError } 8300002 - Operation failed. Cannot connect to service.
   * @throws { BusinessError } 8300003 - System internal error.
   * @throws { BusinessError } 8300999 - Unknown error code.
   * @syscap SystemCapability.Telephony.CoreService
   * @systemapi Hide this for inner system use.
   * @since 10
   */
  function getNetworkCapability(slotId: number, type: NetworkCapabilityType,
      callback: AsyncCallback<NetworkCapabilityState>): void;

  /**
   * Get network capability.
   *
   * @permission ohos.permission.GET_TELEPHONY_STATE
   * @param { number } slotId - Indicates the card slot index number,
   * ranging from 0 to the maximum card slot index number supported by the device.
   * @param { NetworkCapabilityType } type - Indicates the service type of the {@link NetworkCapabilityType}.
   * @returns { Promise<NetworkCapabilityState> } Returns the callback for getting the network capability state.
   * @throws { BusinessError } 201 - Permission denied.
   * @throws { BusinessError } 202 - Non-system applications use system APIs.
   * @throws { BusinessError } 401 - Parameter error.
   * @throws { BusinessError } 8300001 - Invalid parameter value.
   * @throws { BusinessError } 8300002 - Operation failed. Cannot connect to service.
   * @throws { BusinessError } 8300003 - System internal error.
   * @throws { BusinessError } 8300999 - Unknown error code.
   * @syscap SystemCapability.Telephony.CoreService
   * @systemapi Hide this for inner system use.
   * @since 10
   */
  function getNetworkCapability(slotId: number, type: NetworkCapabilityType): Promise<NetworkCapabilityState>;

  /**
   * Get the IMS registration state info of specified IMS service type.
   *
   * @permission ohos.permission.GET_TELEPHONY_STATE
   * @param { number } slotId - Indicates the card slot index number,
   * ranging from 0 to the maximum card slot index number supported by the device.
   * @param { ImsServiceType } imsType - Indicates the ims service type of the {@link ImsServiceType}.
   * @param { AsyncCallback<ImsRegInfo> } callback - Indicates an instance of the {@link ImsRegInfo} class.
   * @throws { BusinessError } 201 - Permission denied.
   * @throws { BusinessError } 202 - Non-system applications use system APIs.
   * @throws { BusinessError } 401 - Parameter error.
   * @throws { BusinessError } 8300001 - Invalid parameter value.
   * @throws { BusinessError } 8300002 - Operation failed. Cannot connect to service.
   * @throws { BusinessError } 8300003 - System internal error.
   * @throws { BusinessError } 8300999 - Unknown error code.
   * @syscap SystemCapability.Telephony.CoreService
   * @systemapi Hide this for inner system use.
   * @since 9
   */
  function getImsRegInfo(slotId: number, imsType: ImsServiceType, callback: AsyncCallback<ImsRegInfo>): void;

  /**
   * Get the IMS registration state info of specified IMS service type.
   *
   * @permission ohos.permission.GET_TELEPHONY_STATE
   * @param { number } slotId - Indicates the card slot index number,
   * ranging from 0 to the maximum card slot index number supported by the device.
   * @param { ImsServiceType } imsType - Indicates the ims service type of the {@link ImsServiceType}.
   * @returns { Promise<ImsRegInfo> } Returns an instance of the {@link ImsRegInfo} class.
   * @throws { BusinessError } 201 - Permission denied.
   * @throws { BusinessError } 202 - Non-system applications use system APIs.
   * @throws { BusinessError } 401 - Parameter error.
   * @throws { BusinessError } 8300001 - Invalid parameter value.
   * @throws { BusinessError } 8300002 - Operation failed. Cannot connect to service.
   * @throws { BusinessError } 8300003 - System internal error.
   * @throws { BusinessError } 8300999 - Unknown error code.
   * @syscap SystemCapability.Telephony.CoreService
   * @systemapi Hide this for inner system use.
   * @since 9
   */
  function getImsRegInfo(slotId: number, imsType: ImsServiceType): Promise<ImsRegInfo>;

  /**
   * Called when the IMS registration state of specified IMS service type corresponding to
   * a monitored {@code slotId} updates.
   *
   * @permission ohos.permission.GET_TELEPHONY_STATE
   * @param { 'imsRegStateChange' } type - Event type. Indicates the imsRegStateChange event to be subscribed to.
   * @param { number } slotId - Indicates the card slot index number,
   * ranging from 0 to the maximum card slot index number supported by the device.
   * @param { ImsServiceType } imsType - Indicates the ims service type of the {@link ImsServiceType}.
   * @param { Callback<ImsRegInfo> } callback - Indicates the callback for getting an instance of
   * the {@link ImsRegInfo} class.
   * @throws { BusinessError } 201 - Permission denied.
   * @throws { BusinessError } 202 - Non-system applications use system APIs.
   * @throws { BusinessError } 401 - Parameter error.
   * @throws { BusinessError } 8300001 - Invalid parameter value.
   * @throws { BusinessError } 8300002 - Operation failed. Cannot connect to service.
   * @throws { BusinessError } 8300003 - System internal error.
   * @throws { BusinessError } 8300999 - Unknown error code.
   * @syscap SystemCapability.Telephony.CoreService
   * @systemapi Hide this for inner system use.
   * @since 9
   */
  function on(type: 'imsRegStateChange', slotId: number, imsType: ImsServiceType, callback: Callback<ImsRegInfo>): void;

  /**
   * Unsubscribe from imsRegStateChange event.
   *
   * @permission ohos.permission.GET_TELEPHONY_STATE
   * @param { 'imsRegStateChange' } type - Event type. Indicates the imsRegStateChange event to unsubscribe from.
   * @param { number } slotId - Indicates the card slot index number,
   * ranging from 0 to the maximum card slot index number supported by the device.
   * @param { ImsServiceType } imsType - Indicates the ims service type of the {@link ImsServiceType}.
   * @param { Callback<ImsRegInfo> } callback - Indicates the callback for getting
   * an instance of the {@link ImsRegInfo} class.
   * @throws { BusinessError } 201 - Permission denied.
   * @throws { BusinessError } 202 - Non-system applications use system APIs.
   * @throws { BusinessError } 401 - Parameter error.
   * @throws { BusinessError } 8300001 - Invalid parameter value.
   * @throws { BusinessError } 8300002 - Operation failed. Cannot connect to service.
   * @throws { BusinessError } 8300003 - System internal error.
   * @throws { BusinessError } 8300999 - Unknown error code.
   * @syscap SystemCapability.Telephony.CoreService
   * @systemapi Hide this for inner system use.
   * @since 9
   */
  function off(type: 'imsRegStateChange', slotId: number, imsType: ImsServiceType, callback?: Callback<ImsRegInfo>): void;

  /**
   * Get the version of Baseband.
   *
   * @permission ohos.permission.GET_TELEPHONY_STATE
   * @param { number } slotId - Indicates the card slot index number, ranging from 0 to the maximum card slot index number
   * supported by the device.
   * @param { AsyncCallback<string> } callback - Indicates the callback for getting the baseband version.
   * @throws { BusinessError } 201 - Permission denied.
   * @throws { BusinessError } 202 - Non-system applications use system APIs.
   * @throws { BusinessError } 401 - Parameter error.
   * @throws { BusinessError } 8300001 - Invalid parameter value.
   * @throws { BusinessError } 8300002 - Operation failed. Cannot connect to service.
   * @throws { BusinessError } 8300003 - System internal error.
   * @throws { BusinessError } 8300999 - Unknown error code.
   * @syscap SystemCapability.Telephony.CoreService
   * @systemapi Hide this for inner system use.
   * @since 10
   */
  function getBasebandVersion(slotId: number, callback: AsyncCallback<string>): void;

  /**
   * Get the version of Baseband.
   *
   * @permission ohos.permission.GET_TELEPHONY_STATE
   * @param { number } slotId - Indicates the card slot index number, ranging from 0 to the maximum card slot index number
   * supported by the device.
   * @returns { Promise<string> } Returns the baseband version.
   * @throws { BusinessError } 201 - Permission denied.
   * @throws { BusinessError } 202 - Non-system applications use system APIs.
   * @throws { BusinessError } 401 - Parameter error.
   * @throws { BusinessError } 8300001 - Invalid parameter value.
   * @throws { BusinessError } 8300002 - Operation failed. Cannot connect to service.
   * @throws { BusinessError } 8300003 - System internal error.
   * @throws { BusinessError } 8300999 - Unknown error code.
   * @syscap SystemCapability.Telephony.CoreService
   * @systemapi Hide this for inner system use.
   * @since 10
   */
  function getBasebandVersion(slotId: number): Promise<string>;

  /**
   * Set the NR option mode.
   *
   * @permission ohos.permission.SET_TELEPHONY_STATE
   * @param { number } slotId - Indicates the card slot index number, ranging from 0 to the maximum card slot index
   * number supported by the device.
   * @param { NROptionMode } mode - Indicates the nr option mode to be set.
   * @param { AsyncCallback<void> } callback - Indicates the callback for getting the option result.
   * @throws { BusinessError } 201 - Permission denied.
   * @throws { BusinessError } 202 - Non-system applications use system APIs.
   * @throws { BusinessError } 401 - Parameter error.
   * @throws { BusinessError } 8300001 - Invalid parameter value.
   * @throws { BusinessError } 8300002 - Operation failed. Cannot connect to service.
   * @throws { BusinessError } 8300003 - System internal error.
   * @throws { BusinessError } 8300999 - Unknown error code.
   * @syscap SystemCapability.Telephony.CoreService
   * @systemapi Hide this for inner system use.
   * @since 10
   */
  function setNROptionMode(slotId: number, mode: NROptionMode, callback: AsyncCallback<void>): void;

  /**
   * Set the NR option mode.
   *
   * @permission ohos.permission.SET_TELEPHONY_STATE
   * @param { number } slotId - Indicates the card slot index number, ranging from 0 to the maximum card slot index
   * number supported by the device.
   * @param { NROptionMode } mode - Indicates the nr option mode to be set.
   * @returns { Promise<void> } Returns option result.
   * @throws { BusinessError } 201 - Permission denied.
   * @throws { BusinessError } 202 - Non-system applications use system APIs.
   * @throws { BusinessError } 401 - Parameter error.
   * @throws { BusinessError } 8300001 - Invalid parameter value.
   * @throws { BusinessError } 8300002 - Operation failed. Cannot connect to service.
   * @throws { BusinessError } 8300003 - System internal error.
   * @throws { BusinessError } 8300999 - Unknown error code.
   * @syscap SystemCapability.Telephony.CoreService
   * @systemapi Hide this for inner system use.
   * @since 10
   */
  function setNROptionMode(slotId: number, mode: NROptionMode): Promise<void>;

  /**
   * Get the option mode of NR.
   *
   * @param { number } slotId - Indicates the card slot index number, ranging from 0 to the maximum card slot
   * index number supported by the device.
   * @param { AsyncCallback<NROptionMode> } callback - Indicates the callback for getting the selection mode of NR.
   * @throws { BusinessError } 202 - Non-system applications use system APIs.
   * @throws { BusinessError } 401 - Parameter error.
   * @throws { BusinessError } 8300001 - Invalid parameter value.
   * @throws { BusinessError } 8300002 - Operation failed. Cannot connect to service.
   * @throws { BusinessError } 8300003 - System internal error.
   * @throws { BusinessError } 8300999 - Unknown error code.
   * @syscap SystemCapability.Telephony.CoreService
   * @systemapi Hide this for inner system use.
   * @since 10
   */
  function getNROptionMode(slotId: number, callback: AsyncCallback<NROptionMode>): void;

  /**
   * Get the option mode of NR.
   *
   * @param { number } slotId - Indicates the card slot index number, ranging from 0 to the maximum card slot
   * index number supported by the device.
   * @returns { Promise<NROptionMode> } Returns the selection mode of NR.
   * @throws { BusinessError } 202 - Non-system applications use system APIs.
   * @throws { BusinessError } 401 - Parameter error.
   * @throws { BusinessError } 8300001 - Invalid parameter value.
   * @throws { BusinessError } 8300002 - Operation failed. Cannot connect to service.
   * @throws { BusinessError } 8300003 - System internal error.
   * @throws { BusinessError } 8300999 - Unknown error code.
   * @syscap SystemCapability.Telephony.CoreService
   * @systemapi Hide this for inner system use.
   * @since 10
   */
  function getNROptionMode(slotId: number): Promise<NROptionMode>;

  /**
   * Reset all network settings of telephony.
   *
   * @permission ohos.permission.SET_TELEPHONY_STATE
   * @param { number } slotId - Indicates the card slot index number, ranging from 0 to the maximum card slot
   * index number supported by the device.
   * @returns { Promise<void> } The promise returned by the factoryReset.
   * @throws { BusinessError } 201 - Permission denied
   * @throws { BusinessError } 202 - Non-system applications use system APIs.
   * @throws { BusinessError } 401 - Parameter error.
   * @throws { BusinessError } 8300001 - Invalid parameter value.
   * @throws { BusinessError } 8300002 - Operation failed. Cannot connect to service.
   * @throws { BusinessError } 8300003 - System internal error.
   * @throws { BusinessError } 8300999 - Unknown error code.
   * @syscap SystemCapability.Telephony.CoreService
   * @systemapi Hide this for inner system use.
   * @since 11
   */
  function factoryReset(slotId: number): Promise<void>;

  /**
   * Indicates the preferred network.
   *
   * @enum { number }
   * @syscap SystemCapability.Telephony.CoreService
   * @systemapi Hide this for inner system use.
   * @since 8
   */
  export enum PreferredNetworkMode {
    /**
     * Preferred GSM network mode.
     *
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 8
     */
    PREFERRED_NETWORK_MODE_GSM = 1,

    /**
     * Preferred WCDMA network mode.
     *
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 8
     */
    PREFERRED_NETWORK_MODE_WCDMA = 2,

    /**
     * Preferred LTE mode.
     *
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 8
     */
    PREFERRED_NETWORK_MODE_LTE = 3,

    /**
     * Preferred LTE/WCDMA network mode.
     *
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 8
     */
    PREFERRED_NETWORK_MODE_LTE_WCDMA = 4,

    /**
     * Preferred LTE/WCDMA/GSM network mode.
     *
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 8
     */
    PREFERRED_NETWORK_MODE_LTE_WCDMA_GSM = 5,

    /**
     * Preferred WCDMA/GSM network mode.
     *
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 8
     */
    PREFERRED_NETWORK_MODE_WCDMA_GSM = 6,

    /**
     * Preferred CDMA network mode.
     *
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 8
     */
    PREFERRED_NETWORK_MODE_CDMA = 7,

    /**
     * Preferred EVDO network mode.
     *
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 8
     */
    PREFERRED_NETWORK_MODE_EVDO = 8,

    /**
     * Preferred EVDO/CDMA network mode.
     *
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 8
     */
    PREFERRED_NETWORK_MODE_EVDO_CDMA = 9,

    /**
     * Preferred WCDMA/GSM/EVDO/CDMA network mode.
     *
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 8
     */
    PREFERRED_NETWORK_MODE_WCDMA_GSM_EVDO_CDMA = 10,

    /**
     * Preferred LTE/EVDO/CDMA network mode.
     *
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 8
     */
    PREFERRED_NETWORK_MODE_LTE_EVDO_CDMA = 11,

    /**
     * Preferred LTE/WCDMA/GSM/EVDO/CDMA network mode.
     *
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 8
     */
    PREFERRED_NETWORK_MODE_LTE_WCDMA_GSM_EVDO_CDMA = 12,

    /**
     * Preferred TDSCDMA network mode.
     *
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 8
     */
    PREFERRED_NETWORK_MODE_TDSCDMA = 13,

    /**
     * Preferred TDSCDMA/GSM network mode.
     *
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 8
     */
    PREFERRED_NETWORK_MODE_TDSCDMA_GSM = 14,

    /**
     * Preferred TDSCDMA/WCDMA network mode.
     *
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 8
     */
    PREFERRED_NETWORK_MODE_TDSCDMA_WCDMA = 15,

    /**
     * Preferred TDSCDMA/WCDMA/GSM network mode.
     *
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 8
     */
    PREFERRED_NETWORK_MODE_TDSCDMA_WCDMA_GSM = 16,

    /**
     * Preferred LTE/TDSCDMA network mode.
     *
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 8
     */
    PREFERRED_NETWORK_MODE_LTE_TDSCDMA = 17,

    /**
     * Preferred LTE/TDSCDMA/GSM network mode.
     *
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 8
     */
    PREFERRED_NETWORK_MODE_LTE_TDSCDMA_GSM = 18,

    /**
     * Preferred LTE/TDSCDMA/WCDMA network mode.
     *
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 8
     */
    PREFERRED_NETWORK_MODE_LTE_TDSCDMA_WCDMA = 19,

    /**
     * Preferred LTE/TDSCDMA/WCDMA/GSM network mode.
     *
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 8
     */
    PREFERRED_NETWORK_MODE_LTE_TDSCDMA_WCDMA_GSM = 20,

    /**
     * Preferred TDSCDMA/WCDMA/GSM/EVDO/CDMA network mode.
     *
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 8
     */
    PREFERRED_NETWORK_MODE_TDSCDMA_WCDMA_GSM_EVDO_CDMA = 21,

    /**
     * Preferred LTE/TDSCDMA/WCDMA/GSM/EVDO/CDMA network mode.
     *
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 8
     */
    PREFERRED_NETWORK_MODE_LTE_TDSCDMA_WCDMA_GSM_EVDO_CDMA = 22,

    /**
     * Preferred NR network mode.
     *
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 8
     */
    PREFERRED_NETWORK_MODE_NR = 31,

    /**
     * Preferred NR/LTE network mode.
     *
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 8
     */
    PREFERRED_NETWORK_MODE_NR_LTE = 32,

    /**
     * Preferred NR/LTE/WCDMA network mode.
     *
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 8
     */
    PREFERRED_NETWORK_MODE_NR_LTE_WCDMA = 33,

    /**
     * Preferred NR/LTE/WCDMA/GSM network mode.
     *
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 8
     */
    PREFERRED_NETWORK_MODE_NR_LTE_WCDMA_GSM = 34,

    /**
     * Preferred NR/LTE/EVDO/CDMA network mode.
     *
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 8
     */
    PREFERRED_NETWORK_MODE_NR_LTE_EVDO_CDMA = 35,

    /**
     * Preferred NR/LTE/WCDMA/GSM/EVDO/CDMA network mode.
     *
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 8
     */
    PREFERRED_NETWORK_MODE_NR_LTE_WCDMA_GSM_EVDO_CDMA = 36,

    /**
     * Preferred NR/LTE/TDSCDMA network mode.
     *
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 8
     */
    PREFERRED_NETWORK_MODE_NR_LTE_TDSCDMA = 37,

    /**
     * Preferred NR/LTE/TDSCDMA/GSM network mode.
     *
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 8
     */
    PREFERRED_NETWORK_MODE_NR_LTE_TDSCDMA_GSM = 38,

    /**
     * Preferred NR/LTE/TDSCDMA/WCDMA network mode.
     *
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 8
     */
    PREFERRED_NETWORK_MODE_NR_LTE_TDSCDMA_WCDMA = 39,

    /**
     * Preferred NR/LTE/TDSCDMA/WCDMA/GSM network mode.
     *
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 8
     */
    PREFERRED_NETWORK_MODE_NR_LTE_TDSCDMA_WCDMA_GSM = 40,

    /**
     * Preferred NR/LTE/TDSCDMA/WCDMA/GSM/EVDO/CDMA network mode.
     *
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 8
     */
    PREFERRED_NETWORK_MODE_NR_LTE_TDSCDMA_WCDMA_GSM_EVDO_CDMA = 41,

    /**
     * Preferred network mode Maximum.
     *
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 8
     */
    PREFERRED_NETWORK_MODE_MAX_VALUE = 99,
  }

  /**
   * Describes the radio access technology (RAT) of registered network.
   *
   * @interface NetworkRadioTech
   * @syscap SystemCapability.Telephony.CoreService
   * @since 11
   */
  export interface NetworkRadioTech {
    /**
     * Indicates radio access technology (RAT) of packet service (PS) domain.
     *
     * @syscap SystemCapability.Telephony.CoreService
     * @since 11
     */
    psRadioTech: RadioTechnology;

    /**
     * Indicates radio access technology (RAT) of circuit service (CS) domain.
     *
     * @syscap SystemCapability.Telephony.CoreService
     * @since 11
     */
    csRadioTech: RadioTechnology;
  }

  /**
   * Describes the radio access technology.
   *
   * @enum { number }
   * @syscap SystemCapability.Telephony.CoreService
   * @since 6
   */
  export enum RadioTechnology {
    /**
     * Indicates unknown radio access technology (RAT).
     *
     * @syscap SystemCapability.Telephony.CoreService
     * @since 6
     */
    RADIO_TECHNOLOGY_UNKNOWN = 0,

    /**
     * Indicates that RAT is global system for mobile communications (GSM), including GSM, general packet
     * radio system (GPRS), and enhanced data rates for GSM evolution (EDGE).
     *
     * @syscap SystemCapability.Telephony.CoreService
     * @since 6
     */
    RADIO_TECHNOLOGY_GSM = 1,

    /**
     * Indicates that RAT is code division multiple access (CDMA), including Interim Standard 95 (IS95) and
     * Single-Carrier Radio Transmission Technology (1xRTT).
     *
     * @syscap SystemCapability.Telephony.CoreService
     * @since 6
     */
    RADIO_TECHNOLOGY_1XRTT = 2,

    /**
     * Indicates that RAT is wideband code division multiple address (WCDMA).
     *
     * @syscap SystemCapability.Telephony.CoreService
     * @since 6
     */
    RADIO_TECHNOLOGY_WCDMA = 3,

    /**
     * Indicates that RAT is high-speed packet access (HSPA), including HSPA, high-speed downlink packet
     * access (HSDPA), and high-speed uplink packet access (HSUPA).
     *
     * @syscap SystemCapability.Telephony.CoreService
     * @since 6
     */
    RADIO_TECHNOLOGY_HSPA = 4,

    /**
     * Indicates that RAT is evolved high-speed packet access (HSPA+), including HSPA+ and dual-carrier
     * HSPA+ (DC-HSPA+).
     *
     * @syscap SystemCapability.Telephony.CoreService
     * @since 6
     */
    RADIO_TECHNOLOGY_HSPAP = 5,

    /**
     * Indicates that RAT is time division-synchronous code division multiple access (TD-SCDMA).
     *
     * @syscap SystemCapability.Telephony.CoreService
     * @since 6
     */
    RADIO_TECHNOLOGY_TD_SCDMA = 6,

    /**
     * Indicates that RAT is evolution data only (EVDO), including EVDO Rev.0, EVDO Rev.A, and EVDO Rev.B.
     *
     * @syscap SystemCapability.Telephony.CoreService
     * @since 6
     */
    RADIO_TECHNOLOGY_EVDO = 7,

    /**
     * Indicates that RAT is evolved high rate packet data (EHRPD).
     *
     * @syscap SystemCapability.Telephony.CoreService
     * @since 6
     */
    RADIO_TECHNOLOGY_EHRPD = 8,

    /**
     * Indicates that RAT is long term evolution (LTE).
     *
     * @syscap SystemCapability.Telephony.CoreService
     * @since 6
     */
    RADIO_TECHNOLOGY_LTE = 9,

    /**
     * Indicates that RAT is LTE carrier aggregation (LTE-CA).
     *
     * @syscap SystemCapability.Telephony.CoreService
     * @since 6
     */
    RADIO_TECHNOLOGY_LTE_CA = 10,

    /**
     * Indicates that RAT is interworking WLAN (I-WLAN).
     *
     * @syscap SystemCapability.Telephony.CoreService
     * @since 6
     */
    RADIO_TECHNOLOGY_IWLAN = 11,

    /**
     * Indicates that RAT is 5G new radio (NR).
     *
     * @syscap SystemCapability.Telephony.CoreService
     * @since 6
     */
    RADIO_TECHNOLOGY_NR = 12
  }

  /**
   * Returns child class objects specific to the network type.
   *
   * @interface SignalInformation
   * @syscap SystemCapability.Telephony.CoreService
   * @since 6
   */
  export interface SignalInformation {
    /**
     * Obtains the network type corresponding to the signal.
     *
     * @type { NetworkType }
     * @syscap SystemCapability.Telephony.CoreService
     * @since 6
     */
    signalType: NetworkType;

    /**
     * Obtains the signal level of the current network.
     *
     * @type { number }
     * @syscap SystemCapability.Telephony.CoreService
     * @since 6
     */
    signalLevel: number;

    /**
     * rsrp for LTE and NR; dbm for CDMA and EVDO; rscp for WCDMA; rssi for GSM.
     *
     * @type { number }
     * @syscap SystemCapability.Telephony.CoreService
     * @since 9
     */
    dBm: number;
  }

  /**
   * Describes the network type.
   *
   * @enum { number }
   * @syscap SystemCapability.Telephony.CoreService
   * @since 6
   */
  export enum NetworkType {
    /**
     * Indicates unknown network type.
     *
     * @syscap SystemCapability.Telephony.CoreService
     * @since 6
     */
    NETWORK_TYPE_UNKNOWN,

    /**
     * Indicates that the network type is GSM.
     *
     * @syscap SystemCapability.Telephony.CoreService
     * @since 6
     */
    NETWORK_TYPE_GSM,

    /**
     * Indicates that the network type is CDMA.
     *
     * @syscap SystemCapability.Telephony.CoreService
     * @since 6
     */
    NETWORK_TYPE_CDMA,

    /**
     * Indicates that the network type is WCDMA.
     *
     * @syscap SystemCapability.Telephony.CoreService
     * @since 6
     */
    NETWORK_TYPE_WCDMA,

    /**
     * Indicates that the network type is TD-SCDMA.
     *
     * @syscap SystemCapability.Telephony.CoreService
     * @since 6
     */
    NETWORK_TYPE_TDSCDMA,

    /**
     * Indicates that the network type is LTE.
     *
     * @syscap SystemCapability.Telephony.CoreService
     * @since 6
     */
    NETWORK_TYPE_LTE,

    /**
     * Indicates that the network type is 5G NR.
     *
     * @syscap SystemCapability.Telephony.CoreService
     * @since 6
     */
    NETWORK_TYPE_NR
  }

  /**
   * Describes the network registration state.
   *
   * @interface NetworkState
   * @syscap SystemCapability.Telephony.CoreService
   * @since 6
   */
  export interface NetworkState {
    /**
     * Obtains the operator name in the long alphanumeric format of the registered network.
     *
     * Returns the operator name in the long alphanumeric format as a string;
     * returns an empty string if no operator name is obtained.
     *
     * @type { string }
     * @syscap SystemCapability.Telephony.CoreService
     * @since 6
     */
    longOperatorName: string;

    /**
     * Obtains the operator name in the short alphanumeric format of the registered network.
     *
     * Returns the operator name in the short alphanumeric format as a string;
     * returns an empty string if no operator name is obtained.
     *
     * @type { string }
     * @syscap SystemCapability.Telephony.CoreService
     * @since 6
     */
    shortOperatorName: string;

    /**
     * Obtains the PLMN code of the registered network.
     *
     * Returns the PLMN code as a string; returns an empty string if no operator name is obtained.
     *
     * @type { string }
     * @syscap SystemCapability.Telephony.CoreService
     * @since 6
     */
    plmnNumeric: string;

    /**
     * Checks whether the device is roaming.
     *
     * @type { boolean }
     * @syscap SystemCapability.Telephony.CoreService
     * @since 6
     */
    isRoaming: boolean;

    /**
     * Obtains the network registration status of the device.
     *
     * @type { RegState }
     * @syscap SystemCapability.Telephony.CoreService
     * @since 6
     */
    regState: RegState;

    /**
     * Obtains the radio Access technology after config conversion.
     *
     * @type { RadioTechnology }
     * @syscap SystemCapability.Telephony.CoreService
     * @since 8
     */
    cfgTech: RadioTechnology;

    /**
     * Obtains the NSA network registration status of the device.
     *
     * Returns the NSA network registration status {@code NsaState}.
     *
     * @type { NsaState }
     * @syscap SystemCapability.Telephony.CoreService
     * @since 6
     */
    nsaState: NsaState;

    /**
     * Obtains the status of CA.
     *
     * Returns {@code true} if CA is actived; returns {@code false} otherwise.
     *
     * @type { boolean }
     * @syscap SystemCapability.Telephony.CoreService
     * @since 6
     */
    isCaActive: boolean;

    /**
     * Checks whether this device is allowed to make emergency calls only.
     *
     * Returns {@code true} if this device is allowed to make emergency calls only;
     * returns {@code false} otherwise.
     *
     * @type { boolean }
     * @syscap SystemCapability.Telephony.CoreService
     * @since 6
     */
    isEmergency: boolean;
  }

  /**
   * Describes the network registration state.
   *
   * @enum { number }
   * @syscap SystemCapability.Telephony.CoreService
   * @since 6
   */
  export enum RegState {
    /**
     * Indicates a state in which a device cannot use any service.
     *
     * @syscap SystemCapability.Telephony.CoreService
     * @since 6
     */
    REG_STATE_NO_SERVICE = 0,

    /**
     * Indicates a state in which a device can use services properly.
     *
     * @syscap SystemCapability.Telephony.CoreService
     * @since 6
     */
    REG_STATE_IN_SERVICE = 1,

    /**
     * Indicates a state in which a device can use only the emergency call service.
     *
     * @syscap SystemCapability.Telephony.CoreService
     * @since 6
     */
    REG_STATE_EMERGENCY_CALL_ONLY = 2,

    /**
     * Indicates that the cellular radio is powered off.
     *
     * @syscap SystemCapability.Telephony.CoreService
     * @since 6
     */
    REG_STATE_POWER_OFF = 3
  }

  /**
   * Describes the nsa state.
   *
   * @enum { number }
   * @syscap SystemCapability.Telephony.CoreService
   * @since 6
   */
  export enum NsaState {
    /**
     * Indicates that a device is idle under or is connected to an LTE cell that does not support NSA.
     *
     * @syscap SystemCapability.Telephony.CoreService
     * @since 6
     */
    NSA_STATE_NOT_SUPPORT = 1,

    /**
     * Indicates that a device is idle under an LTE cell supporting NSA but not NR coverage detection.
     *
     * @syscap SystemCapability.Telephony.CoreService
     * @since 6
     */
    NSA_STATE_NO_DETECT = 2,

    /**
     * Indicates that a device is connected to an LTE network under an LTE cell
     * that supports NSA and NR coverage detection.
     *
     * @syscap SystemCapability.Telephony.CoreService
     * @since 6
     */
    NSA_STATE_CONNECTED_DETECT = 3,

    /**
     * Indicates that a device is idle under an LTE cell supporting NSA and NR coverage detection.
     *
     * @syscap SystemCapability.Telephony.CoreService
     * @since 6
     */
    NSA_STATE_IDLE_DETECT = 4,

    /**
     * Indicates that a device is connected to an LTE + NR network under an LTE cell that supports NSA.
     *
     * @syscap SystemCapability.Telephony.CoreService
     * @since 6
     */
    NSA_STATE_DUAL_CONNECTED = 5,

    /**
     * Indicates that a device is idle under or is connected to an NG-RAN cell while being attached to 5GC.
     *
     * @syscap SystemCapability.Telephony.CoreService
     * @since 6
     */
    NSA_STATE_SA_ATTACHED = 6
  }

  /**
   * Enum for network capability type.
   *
   * @syscap SystemCapability.Telephony.CoreService
   * @systemapi Hide this for inner system use.
   * @since 10
   */
  export enum NetworkCapabilityType {
    /**
     * Indicates LTE network switch type.
     *
     * @syscap SystemCapability.Telephony.CoreService
     * @since 10
     */
    SERVICE_TYPE_LTE,

    /**
     * Indicates NR network switch type.
     *
     * @syscap SystemCapability.Telephony.CoreService
     * @since 10
     */
    SERVICE_TYPE_NR,
  }

  /**
   * Enum for network capability state.
   *
   * @syscap SystemCapability.Telephony.CoreService
   * @systemapi Hide this for inner system use.
   * @since 10
   */
  export enum NetworkCapabilityState {
    /**
     * Indicates turn off network switch.
     *
     * @syscap SystemCapability.Telephony.CoreService
     * @since 10
     */
    SERVICE_CAPABILITY_OFF,

    /**
     * Indicates turn on network switch.
     *
     * @syscap SystemCapability.Telephony.CoreService
     * @since 10
     */
    SERVICE_CAPABILITY_ON,
  }

  /**
   * Obtains current cell information.
   *
   * @interface CellInformation
   * @syscap SystemCapability.Telephony.CoreService
   * @systemapi Hide this for inner system use.
   * @since 8
   */
  export interface CellInformation {
    /**
     * Obtains the network type of the serving cell.
     *
     * An application can call this method to determine the network type that the child class uses.
     *
     * @type { NetworkType }
     * @syscap SystemCapability.Telephony.CoreService
     * @since 8
     */
    networkType: NetworkType;

    /**
     * Obtains the camp-on status of the serving cell.
     *
     * Returns {@code true} if the user equipment (UE) is camped on the cell; returns {@code false} otherwise.
     *
     * @type { boolean }
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 8
     */
    isCamped: boolean;

    /**
     * Obtains the timestamp when the cell information is obtained.
     *
     * Returns a timestamp since boot, in nanoseconds.
     *
     * @type { number }
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 8
     */
    timeStamp: number;

    /**
     * An abstract method of the parent class whose implementation depends on the child classes.
     * Returned child class objects vary according to the network type.
     * Returns child class objects specific to the network type.
     *
     * @type { SignalInformation }
     * @syscap SystemCapability.Telephony.CoreService
     * @since 8
     */
    signalInformation: SignalInformation;

    /**
     * Obtains signal strength under different network formats.
     *
     * @type { CdmaCellInformation | GsmCellInformation | LteCellInformation | NrCellInformation
     * | TdscdmaCellInformation | WcdmaCellInformation }
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 8
     */
    data: CdmaCellInformation | GsmCellInformation | LteCellInformation | NrCellInformation | TdscdmaCellInformation
      | WcdmaCellInformation;
  }

  /**
   * Obtains CDMA cell information.
   *
   * @interface CdmaCellInformation
   * @syscap SystemCapability.Telephony.CoreService
   * @systemapi Hide this for inner system use.
   * @since 8
   */
  export interface CdmaCellInformation {
    /**
     * Indicates the base station Id.
     *
     * @type { number }
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 8
     */
    baseId: number;

    /**
     * Indicates the latitude.
     *
     * @type { number }
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 8
     */
    latitude: number;

    /**
     * Indicates the longitude.
     *
     * @type { number }
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 8
     */
    longitude: number;

    /**
     * Indicates the network identification code.
     *
     * @type { number }
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 8
     */
    nid: number;

    /**
     * Indicates the system identification code.
     *
     * @type { number }
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 8
     */
    sid: number;
  }

  /**
   * Obtains GSM cell information.
   *
   * @interface GsmCellInformation
   * @syscap SystemCapability.Telephony.CoreService
   * @systemapi Hide this for inner system use.
   * @since 8
   */
  export interface GsmCellInformation {
    /**
     * Indicates the location area code.
     *
     * @type { number }
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 8
     */
    lac: number;

    /**
     * Indicates the cell identification.
     *
     * @type { number }
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 8
     */
    cellId: number;

    /**
     * Indicates the ARFCN(absolute radio frequency channel number).
     *
     * @type { number }
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 8
     */
    arfcn: number;

    /**
     * Indicates the base station identification code.
     *
     * @type { number }
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 8
     */
    bsic: number;

    /**
     * Indicates the mobile country code.
     *
     * @type { string }
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 8
     */
    mcc: string;

    /**
     * Indicates the mobile network code.
     *
     * @type { string }
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 8
     */
    mnc: string;
  }

  /**
   * Obtains LTE cell information.
   *
   * @interface LteCellInformation
   * @syscap SystemCapability.Telephony.CoreService
   * @systemapi Hide this for inner system use.
   * @since 8
   */
  export interface LteCellInformation {
    /**
     * Indicates the cell global identification.
     *
     * @type { number }
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 8
     */
    cgi: number;

    /**
     * Indicates the physical cell identification.
     *
     * @type { number }
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 8
     */
    pci: number;

    /**
     * Indicates the tracking area code.
     *
     * @type { number }
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 8
     */
    tac: number;

    /**
     * Indicates the E-UTRA Absolute Radio Frequency Channel Number.
     *
     * @type { number }
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 8
     */
    earfcn: number;

    /**
     * Indicates the bandwidth.
     *
     * @type { number }
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 8
     */
    bandwidth: number;

    /**
     * Indicates the mobile country code.
     *
     * @type { string }
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 8
     */
    mcc: string;

    /**
     * Indicates the mobile network code.
     *
     * @type { string }
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 8
     */
    mnc: string;

    /**
     * Support for New Radio_Dual Connectivity.
     *
     * @type { boolean }
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 8
     */
    isSupportEndc: boolean;
  }

  /**
   * Obtains NR cell information.
   *
   * @interface NrCellInformation
   * @syscap SystemCapability.Telephony.CoreService
   * @systemapi Hide this for inner system use.
   * @since 8
   */
  export interface NrCellInformation {
    /**
     * Indicates the NR-ARFCN(NR Absolute Radio Frequency Channel Number).
     *
     * @type { number }
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 8
     */
    nrArfcn: number;

    /**
     * Indicates the physical cell identification.
     *
     * @type { number }
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 8
     */
    pci: number;

    /**
     * Indicates the tracking area code.
     *
     * @type { number }
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 8
     */
    tac: number;

    /**
     * Indicates the 5G network cell ID.
     *
     * @type { number }
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 8
     */
    nci: number;

    /**
     * Indicates the mobile country code.
     *
     * @type { string }
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 8
     */
    mcc: string;

    /**
     * Indicates the mobile network code.
     *
     * @type { string }
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 8
     */
    mnc: string;
  }

  /**
   * Obtains TDSCDMA cell information.
   *
   * @interface TdscdmaCellInformation
   * @syscap SystemCapability.Telephony.CoreService
   * @systemapi Hide this for inner system use.
   * @since 8
   */
  export interface TdscdmaCellInformation {
    /**
     * Indicates the location area code.
     *
     * @type { number }
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 8
     */
    lac: number;

    /**
     * Indicates the cell ID.
     *
     * @type { number }
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 8
     */
    cellId: number;

    /**
     * Indicates the cell parameter ID.
     *
     * @type { number }
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 8
     */
    cpid: number;

    /**
     * Indicates the absolute radio frequency number.
     *
     * @type { number }
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 8
     */
    uarfcn: number;

    /**
     * Indicates the mobile country code.
     *
     * @type { string }
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 8
     */
    mcc: string;

    /**
     * Indicates the mobile network code.
     *
     * @type { string }
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 8
     */
    mnc: string;
  }

  /**
   * Obtains WCDMA cell information.
   *
   * @interface WcdmaCellInformation
   * @syscap SystemCapability.Telephony.CoreService
   * @systemapi Hide this for inner system use.
   * @since 8
   */
  export interface WcdmaCellInformation {
    /**
     * Indicates the location area code.
     *
     * @type { number }
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 8
     */
    lac: number;

    /**
     * Indicates the cell ID.
     *
     * @type { number }
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 8
     */
    cellId: number;

    /**
     * Indicates the primary scrambling code.
     *
     * @type { number }
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 8
     */
    psc: number;

    /**
     * Indicates the absolute radio frequency number.
     *
     * @type { number }
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 8
     */
    uarfcn: number;

    /**
     * Indicates the mobile country code.
     *
     * @type { string }
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 8
     */
    mcc: string;

    /**
     * Indicates the mobile network code.
     *
     * @type { string }
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 8
     */
    mnc: string;
  }

  /**
   * Obtains the option mode of NR.
   *
   * @enum { number }
   * @syscap SystemCapability.Telephony.CoreService
   * @systemapi Hide this for inner system use.
   * @since 8
   * @deprecated since 10
   * @useinstead telephony.radio#NROptionMode
   */
  export enum NrOptionMode {
    /**
     * Indicates unknown NR networking mode.
     *
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 8
     */
    NR_OPTION_UNKNOWN,

    /**
     * Indicates that the NR networking mode is NSA only.
     *
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 8
     */
    NR_OPTION_NSA_ONLY,

    /**
     * Indicates that the NR networking mode is SA only.
     *
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 8
     */
    NR_OPTION_SA_ONLY,

    /**
     * Indicates that the NR networking mode is NSA and SA.
     *
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 8
     */
    NR_OPTION_NSA_AND_SA,
  }

  /**
   * Obtains the option mode of NR.
   *
   * @enum { number }
   * @syscap SystemCapability.Telephony.CoreService
   * @systemapi Hide this for inner system use.
   * @since 10
   */
  export enum NROptionMode {
    /**
     * Indicates unknown NR networking mode.
     *
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 10
     */
    NR_OPTION_UNKNOWN,

    /**
     * Indicates that the NR networking mode is NSA only.
     *
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 10
     */
    NR_OPTION_NSA_ONLY,

    /**
     * Indicates that the NR networking mode is SA only.
     *
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 10
     */
    NR_OPTION_SA_ONLY,

    /**
     * Indicates that the NR networking mode is NSA and SA.
     *
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 10
     */
    NR_OPTION_NSA_AND_SA,
  }

  /**
   * Obtains the network search results.
   *
   * @interface NetworkSearchResult
   * @syscap SystemCapability.Telephony.CoreService
   * @systemapi Hide this for inner system use.
   * @since 6
   */
  export interface NetworkSearchResult {
    /**
     * Indicates whether the network search was successful.
     *
     * @type { boolean }
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 6
     */
    isNetworkSearchSuccess: boolean;

    /**
     * Obtains the network search results.
     *
     * @type { Array<NetworkInformation> }
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 6
     */
    networkSearchResult: Array<NetworkInformation>;
  }

  /**
   * Obtains the network information.
   *
   * @interface NetworkInformation
   * @syscap SystemCapability.Telephony.CoreService
   * @systemapi Hide this for inner system use.
   * @since 6
   */
  export interface NetworkInformation {
    /**
     * Indicates the name of the operator.
     *
     * @type { string }
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 6
     */
    operatorName: string;

    /**
     * Indicates the number of the operator.
     *
     * @type { string }
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 6
     */
    operatorNumeric: string;

    /**
     * Indicates the status of network information.
     *
     * @type { NetworkInformationState }
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 6
     */
    state: NetworkInformationState;

    /**
     * Indicates the radio Technology.
     *
     * @type { string }
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 6
     */
    radioTech: string;
  }

  /**
   * Obtains network information status.
   *
   * @enum { number }
   * @syscap SystemCapability.Telephony.CoreService
   * @systemapi Hide this for inner system use.
   * @since 6
   */
  export enum NetworkInformationState {
    /**
     * Indicates that the network state is unknown.
     *
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 6
     */
    NETWORK_UNKNOWN,

    /**
     * Indicates that the network is available for registration.
     *
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 6
     */
    NETWORK_AVAILABLE,

    /**
     * Indicates that you have already registered with the network.
     *
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 6
     */
    NETWORK_CURRENT,

    /**
     * Indicates that the network is unavailable for registration.
     *
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 6
     */
    NETWORK_FORBIDDEN
  }

  /**
   * Obtains the network selection mode option.
   *
   * @interface NetworkSelectionModeOptions
   * @syscap SystemCapability.Telephony.CoreService
   * @systemapi Hide this for inner system use.
   * @since 6
   */
  export interface NetworkSelectionModeOptions {
    /**
     * Indicates the card slot index number, ranging from 0 to
     * the maximum card slot index number supported by the device.
     *
     * @type { number }
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 6
     */
    slotId: number;

    /**
     * Indicates the network search mode of the SIM card.
     *
     * @type { NetworkSelectionMode }
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 6
     */
    selectMode: NetworkSelectionMode;

    /**
     * Indicates the network information.
     *
     * @type { NetworkInformation }
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 6
     */
    networkInformation: NetworkInformation;

    /**
     * Indicates whether to continue selecting the network selection mode.
     *
     * @type { boolean }
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 6
     */
    resumeSelection: boolean;
  }

  /**
   * Obtains the network selection mode.
   *
   * @enum { number }
   * @syscap SystemCapability.Telephony.CoreService
   * @since 6
   */
  export enum NetworkSelectionMode {
    /**
     * Indicates that the network is unavailable for registration.
     *
     * @syscap SystemCapability.Telephony.CoreService
     * @since 6
     */
    NETWORK_SELECTION_UNKNOWN,

    /**
     * Indicates that the network is unavailable for registration.
     *
     * @syscap SystemCapability.Telephony.CoreService
     * @since 6
     */
    NETWORK_SELECTION_AUTOMATIC,

    /**
     * Manual network selection modes.
     *
     * @syscap SystemCapability.Telephony.CoreService
     * @since 6
     */
    NETWORK_SELECTION_MANUAL
  }

  /**
   * Obtains IMS registration status.
   *
   * @enum { number }
   * @syscap SystemCapability.Telephony.CoreService
   * @systemapi Hide this for inner system use.
   * @since 9
   */
  export enum ImsRegState {
    /**
     * Indicates that the ims service is not registered.
     *
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 9
     */
    IMS_UNREGISTERED,

    /**
     * Indicates that the ims service has been registered.
     *
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 9
     */
    IMS_REGISTERED,
  }

  /**
   * Indicates IMS registration technology.
   *
   * @enum { number }
   * @syscap SystemCapability.Telephony.CoreService
   * @systemapi Hide this for inner system use.
   * @since 9
   */
  export enum ImsRegTech {
    /**
     * Indicates that ims has no registered technology.
     *
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 9
     */
    REGISTRATION_TECH_NONE,

    /**
     * Indicates that ims registers LTE technology.
     *
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 9
     */
    REGISTRATION_TECH_LTE,

    /**
     * Indicates that ims registers IWLAN technology.
     *
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 9
     */
    REGISTRATION_TECH_IWLAN,

    /**
     * Indicates that ims registers NR technology.
     *
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 9
     */
    REGISTRATION_TECH_NR,
  }

  /**
   * Indicates IMS registration information.
   *
   * @interface ImsRegInfo
   * @syscap SystemCapability.Telephony.CoreService
   * @systemapi Hide this for inner system use.
   * @since 9
   */
  export interface ImsRegInfo {
    /**
     * Indicates the registration status of the ims service.
     *
     * @type { ImsRegState }
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 9
     */
    imsRegState: ImsRegState;

    /**
     * Indicates the mode of ims radio technology.
     *
     * @type { ImsRegTech }
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 9
     */
    imsRegTech: ImsRegTech;
  }

  /**
   * Indicates the type of IMS service.
   *
   * @enum { number }
   * @syscap SystemCapability.Telephony.CoreService
   * @systemapi Hide this for inner system use.
   * @since 9
   */
  export enum ImsServiceType {
    /**
     * Indicates voice service.
     *
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 9
     */
    TYPE_VOICE,

    /**
     * Indicates video service.
     *
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 9
     */
    TYPE_VIDEO,

    /**
     * Indicates UT service.
     *
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 9
     */
    TYPE_UT,

    /**
     * Indicates SMS service.
     *
     * @syscap SystemCapability.Telephony.CoreService
     * @systemapi Hide this for inner system use.
     * @since 9
     */
    TYPE_SMS,
  }
}

export default radio;
