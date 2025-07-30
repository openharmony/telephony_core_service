/*
 * Copyright (C) 2025-2025 Huawei Device Co., Ltd.
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
import type { AsyncCallback, Callback } from '@ohos.base';

export default namespace radio {
    loadLibrary("telephony_radio_ani")

    export native function nativeGetImsRegInfo(slotId: int, imsType: ImsServiceType): ImsRegInfo;

    export function getImsRegInfo(slotId: int, imsType: ImsServiceType, callback: AsyncCallback<ImsRegInfo>): void {
      let p1 = taskpool.execute((): ImsRegInfo => {
        return nativeGetImsRegInfo(slotId, imsType)
      })
      p1.then((content: NullishType) => {
          callback(new BusinessError(), content as ImsRegInfo)
      }, (err: Error): void => {
          callback(err as BusinessError, undefined)
      });
    }

    export function getImsRegInfo(slotId: int, imsType: ImsServiceType): Promise<ImsRegInfo> {
      return new Promise<ImsRegInfo>((resolve, reject) => {
        let p = taskpool.execute((): ImsRegInfo => {
          return nativeGetImsRegInfo(slotId, imsType)
        })
        p.then((e: NullishType) => {
            let r = e as ImsRegInfo
            resolve(r)
        }).catch((e: Error): void => {
            reject(e)
        })
      })
    }

    export native function nativeGetSignalInformation(slotId: int): Array<SignalInformation>;

    export function getSignalInformation(slotId: int, callback: AsyncCallback<Array<SignalInformation>>): void {
      let p1 = taskpool.execute((): Array<SignalInformation> => {
        return nativeGetSignalInformation(slotId)
      })
      p1.then((content: NullishType) => {
          callback(new BusinessError(), content as Array<SignalInformation>)
      }, (err: Error): void => {
          callback(err as BusinessError, undefined)
      });
    }

    export function getSignalInformation(slotId: int): Promise<Array<SignalInformation>> {
      return new Promise<Array<SignalInformation>>((resolve, reject) => {
        let p = taskpool.execute((): Array<SignalInformation> => {
          return nativeGetSignalInformation(slotId)
        })
        p.then((e: NullishType) => {
            let r = e as Array<SignalInformation>
            resolve(r)
        }).catch((e: Error): void => {
            reject(e)
        })
      })
    }

    export native function nativeGetPrimarySlotId(): int;

    export function getPrimarySlotId(callback: AsyncCallback<int>): void {
      let p1 = taskpool.execute((): int => {
        return nativeGetPrimarySlotId()
      })
      p1.then((content: NullishType) => {
          callback(new BusinessError(), content as int)
      }, (err: Error): void => {
          callback(err as BusinessError, undefined)
      });
    }

    export function getPrimarySlotId(): Promise<int> {
      return new Promise<int>((resolve, reject) => {
        let p = taskpool.execute((): int => {
          return nativeGetPrimarySlotId()
        })
        p.then((e: NullishType) => {
            let r = e as int
            resolve(r)
        }).catch((e: Error): void => {
            reject(e)
        })
      })
    }

    export native function nativeGetNetworkState(slotId?: int): NetworkState;

    export function getNetworkState(slotId: int, callback: AsyncCallback<NetworkState>): void {
      let p1 = taskpool.execute((): NetworkState => {
        return nativeGetNetworkState(slotId);
      })
      p1.then((content: NullishType) => {
          callback(new BusinessError(), content as NetworkState)
      }, (err: Error): void => {
          callback(err as BusinessError, undefined)
      });
    }
    
    export function getNetworkState(slotId?: int): Promise<NetworkState> {
      return new Promise<NetworkState>((resolve, reject) => {
        let p = taskpool.execute((): NetworkState => {
          return nativeGetNetworkState(slotId);
        })
        p.then((e: NullishType) => {
            let r = e as NetworkState
            resolve(r)
        }).catch((e: Error): void => {
            reject(e)
        })
      })
    }

    export function getNetworkState(callback: AsyncCallback<NetworkState>): void {
      let p1 = taskpool.execute((): NetworkState => {
        return nativeGetNetworkState();
      })
      p1.then((content: NullishType) => {
          callback(new BusinessError(), content as NetworkState)
      }, (err: Error): void => {
          callback(err as BusinessError, undefined)
      });
    }

    export native function nativeIsNRSupported(): boolean;

    export function isNRSupported(): boolean {
      return nativeIsNRSupported()
    }
    export function isNRSupported(slotId: int): boolean {
      return nativeIsNRSupported()
    }

    export native function onImsRegStateChange(type: string, slotId: int, imsType: ImsServiceType, callback: Callback<ImsRegInfo>): void;

    function on(type: 'imsRegStateChange', slotId: int, imsType: ImsServiceType, callback: Callback<ImsRegInfo>): void {
      return onImsRegStateChange(type, slotId, imsType, callback)
    }

    export native function offImsRegStateChange(type: string, slotId: int, imsType: ImsServiceType, callback?: Callback<ImsRegInfo>): void;

    function off(type: 'imsRegStateChange', slotId: int, imsType: ImsServiceType, callback?: Callback<ImsRegInfo>): void {
      return offImsRegStateChange(type, slotId, imsType, callback)
    }

    export enum ImsServiceType {
      TYPE_VOICE,
      TYPE_VIDEO,
      TYPE_UT,
      TYPE_SMS,
    }

    export enum ImsRegState {
      IMS_UNREGISTERED,
      IMS_REGISTERED,
    }

    export enum ImsRegTech {
      REGISTRATION_TECH_NONE,
      REGISTRATION_TECH_LTE,
      REGISTRATION_TECH_IWLAN,
      REGISTRATION_TECH_NR,
    }

    export enum NetworkType {
      NETWORK_TYPE_UNKNOWN,
      NETWORK_TYPE_GSM,
      NETWORK_TYPE_CDMA,
      NETWORK_TYPE_WCDMA,
      NETWORK_TYPE_TDSCDMA,
      NETWORK_TYPE_LTE,
      NETWORK_TYPE_NR
    }

    export enum RegState {
      REG_STATE_NO_SERVICE = 0,
      REG_STATE_IN_SERVICE = 1,
      REG_STATE_EMERGENCY_CALL_ONLY = 2,
      REG_STATE_POWER_OFF = 3
    }

    export enum RadioTechnology {
      RADIO_TECHNOLOGY_UNKNOWN = 0,
      RADIO_TECHNOLOGY_GSM = 1,
      RADIO_TECHNOLOGY_1XRTT = 2,
      RADIO_TECHNOLOGY_WCDMA = 3,
      RADIO_TECHNOLOGY_HSPA = 4,
      RADIO_TECHNOLOGY_HSPAP = 5,
      RADIO_TECHNOLOGY_TD_SCDMA = 6,
      RADIO_TECHNOLOGY_EVDO = 7,
      RADIO_TECHNOLOGY_EHRPD = 8,
      RADIO_TECHNOLOGY_LTE = 9,
      RADIO_TECHNOLOGY_LTE_CA = 10,
      RADIO_TECHNOLOGY_IWLAN = 11,
      RADIO_TECHNOLOGY_NR = 12
    }

    export enum NsaState {
      NSA_STATE_NOT_SUPPORT = 1,
      NSA_STATE_NO_DETECT = 2,
      NSA_STATE_CONNECTED_DETECT = 3,
      NSA_STATE_IDLE_DETECT = 4,
      NSA_STATE_DUAL_CONNECTED = 5,
      NSA_STATE_SA_ATTACHED = 6
    }

    export interface ImsRegInfo {
      imsRegState: ImsRegState;
      imsRegTech: ImsRegTech;
    }

    export class ImsRegInfoInner implements ImsRegInfo {
      imsRegState: ImsRegState;
      imsRegTech: ImsRegTech;
    }

    export interface SignalInformation {
      signalType: NetworkType;
      signalLevel: int;
      dBm: int;
    }

    export class SignalInformationInner implements SignalInformation {
      signalType: NetworkType;
      signalLevel: int;
      dBm: int;
    }

    export interface NetworkState {
      longOperatorName: string;
      shortOperatorName: string;
      plmnNumeric: string;
      isRoaming: boolean;
      regState: RegState;
      cfgTech: RadioTechnology;
      nsaState: NsaState;
      isEmergency: boolean;
    }

    export class NetworkStateInner implements NetworkState {
      longOperatorName: string;
      shortOperatorName: string;
      plmnNumeric: string;
      isRoaming: boolean;
      regState: RegState;
      cfgTech: RadioTechnology;
      nsaState: NsaState;
      isEmergency: boolean;
    }

    export interface CellInformation {
      networkType: NetworkType;
      signalInformation: SignalInformation;
    }

    export class CellInformationInner implements CellInformation {
      networkType: NetworkType;
      signalInformation: SignalInformation;
    }

    export interface NetworkRadioTech {
      psRadioTech: RadioTechnology;
    }

    export class NetworkRadioTechInner implements NetworkRadioTech {
      psRadioTech: RadioTechnology;
    }
}