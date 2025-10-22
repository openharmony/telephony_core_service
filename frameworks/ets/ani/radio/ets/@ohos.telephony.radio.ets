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

    export native function nativeGetRadioTech(slotId: int): NetworkRadioTech;

    export function getRadioTech(slotId: int, callback: AsyncCallback<NetworkRadioTech>): void {
      let p1 = taskpool.execute((): NetworkRadioTech => {
          return nativeGetRadioTech(slotId)
      })
      p1.then((content: NullishType) => {
          callback(new BusinessError(), content as NetworkRadioTech);
      }, (err: Error): void => {
          callback(err as BusinessError, undefined);
      });
    }

    export function getRadioTech(slotId: int): Promise<NetworkRadioTech> {
      return new Promise<NetworkRadioTech>((resolve, reject) => {
        let p = taskpool.execute((): NetworkRadioTech => {
            return nativeGetRadioTech(slotId)
        })
        p.then((e: NullishType) => {
            let r = e as NetworkRadioTech
            resolve(r)
        }).catch((e: Error): void => {
            reject(e)
        })
      })
    }

    export function getRadioTechSync(slotId: int): NetworkRadioTech {
      return nativeGetRadioTech(slotId);
    }

    export native function nativeSendUpdateCellLocationRequest(slotId?: int): void;

    export function sendUpdateCellLocationRequest(slotId: int, callback: AsyncCallback<void>): void {
      let p1 = taskpool.execute((): void => {
          return nativeSendUpdateCellLocationRequest(slotId)
      })
      p1.then((content: NullishType) => {
          callback(new BusinessError(), content as undefined);
      }, (err: Error): void => {
          callback(err as BusinessError, undefined);
      })
    }

    export function sendUpdateCellLocationRequest(slotId?: int): Promise<void> {
      return new Promise<void>((resolve, reject) => {
        let p = taskpool.execute((): void => {
            return nativeSendUpdateCellLocationRequest(slotId)
        })
        p.then((e: NullishType) => {
            resolve(e as undefined)
        }).catch((e: Error): void => {
            reject(e as Error)
        })
      })
    }

    export function sendUpdateCellLocationRequest(callback: AsyncCallback<void>): void {
      let p1 = taskpool.execute((): void => {
          return nativeSendUpdateCellLocationRequest()
      })
      p1.then((content: NullishType) => {
          callback(new BusinessError(), content as undefined);
      }, (err: Error): void => {
          callback(err as BusinessError, undefined);
      })
    }

    export native function nativeGetCellInformation(slotId?: int): Array<CellInformation>;

    export function getCellInformation(slotId: int, callback: AsyncCallback<Array<CellInformation>>): void {
      let p1 = taskpool.execute((): Array<CellInformation> => {
          return nativeGetCellInformation(slotId)
      })
      p1.then((content: NullishType) => {
          callback(new BusinessError(), content as Array<CellInformation>);
      }, (err: Error): void => {
          callback(err as BusinessError, new Array<CellInformation>());
      });
    }

    export function getCellInformation(slotId?: int): Promise<Array<CellInformation>> {
      return new Promise<Array<CellInformation>>((resolve, reject) => {
        let p = taskpool.execute((): Array<CellInformation> => {
            return nativeGetCellInformation(slotId)
        })
        p.then((e: NullishType) => {
            let r = e as Array<CellInformation>
            resolve(r)
        }).catch((e: Error): void => {
            reject(e)
        })
      })
    }

    export function getCellInformation(callback: AsyncCallback<Array<CellInformation>>): void {
      let p1 = taskpool.execute((): Array<CellInformation> => {
          return nativeGetCellInformation()
      })
      p1.then((content: NullishType) => {
          callback(new BusinessError(), content as Array<CellInformation>);
      }, (err: Error): void => {
          callback(err as BusinessError, new Array<CellInformation>());
      });
    }

    export native function nativeGetNetworkSelectionMode(slotId: int): NetworkSelectionMode;

    export function getNetworkSelectionMode(slotId: int, callback: AsyncCallback<NetworkSelectionMode>): void {
      let p1 = taskpool.execute((): NetworkSelectionMode => {
        return nativeGetNetworkSelectionMode(slotId);
      })
      p1.then((content: NullishType) => {
          callback(new BusinessError(), content as NetworkSelectionMode)
      }, (err: Error): void => {
          callback(err as BusinessError, undefined)
      });
    }
    
    export function getNetworkSelectionMode(slotId: int): Promise<NetworkSelectionMode> {
      return new Promise<NetworkSelectionMode>((resolve, reject) => {
        let p = taskpool.execute((): NetworkSelectionMode => {
          return nativeGetNetworkSelectionMode(slotId);
        })
        p.then((e: NullishType) => {
            let r = e as NetworkSelectionMode
            resolve(r)
        }).catch((e: Error): void => {
            reject(e)
        })
      })
    }

    export native function nativeSetNetworkSelectionMode(options: NetworkSelectionModeOptions): void;

    export function setNetworkSelectionMode(options: NetworkSelectionModeOptions, callback: AsyncCallback<void>): void {
      let p1 = taskpool.execute((): void => {
        return nativeSetNetworkSelectionMode(options)
      })
      p1.then((content: NullishType) => {
          callback(new BusinessError(), content as undefined)
      }, (err: Error): void => {
          callback(err as BusinessError, undefined)
      });
    }

    export function setNetworkSelectionMode(options: NetworkSelectionModeOptions): Promise<void> {
      return new Promise<void>((resolve, reject) => {
        let p = taskpool.execute((): void => {
          return nativeSetNetworkSelectionMode(options)
        })
        p.then((e: NullishType) => {
            let r = e as undefined
            resolve(r)
        }).catch((e: Error): void => {
            reject(e as Error)
        })
      })
    }

    export native function nativeGetNetworkSearchInformation(slotId: int): NetworkSearchResult;

    export function getNetworkSearchInformation(slotId: int, callback: AsyncCallback<NetworkSearchResult>): void {
      let p1 = taskpool.execute((): NetworkSearchResult => {
        return nativeGetNetworkSearchInformation(slotId)
      })
      p1.then((content: NullishType) => {
          callback(new BusinessError(), content as NetworkSearchResult)
      }, (err: Error): void => {
          callback(err as BusinessError, undefined)
      });
    }

    export function getNetworkSearchInformation(slotId: int): Promise<NetworkSearchResult> {
      return new Promise<NetworkSearchResult>((resolve, reject) => {
        let p = taskpool.execute((): NetworkSearchResult => {
          return nativeGetNetworkSearchInformation(slotId)
        })
        p.then((e: NullishType) => {
            let r = e as NetworkSearchResult
            resolve(r)
        }).catch((e: Error): void => {
            reject(e)
        })
      })
    }

    export native function nativeGetISOCountryCodeForNetwork(slotId: int): string;

    export function getISOCountryCodeForNetwork(slotId: int, callback: AsyncCallback<string>): void {
      let p1 = taskpool.execute((): string => {
          return nativeGetISOCountryCodeForNetwork(slotId)
      })
      p1.then((content: NullishType) => {
          callback(new BusinessError(), content as string);
      }, (err: Error): void => {
          callback(err as BusinessError, new string());
      });
    }

    export function getISOCountryCodeForNetwork(slotId: int): Promise<string> {
      return new Promise<string>((resolve, reject) => {
        let p = taskpool.execute((): string => {
            return nativeGetISOCountryCodeForNetwork(slotId)
        })
        p.then((e: NullishType) => {
            let r = e as string
            resolve(r)
        }).catch((e: Error): void => {
            reject(e)
        })
      })
    }

    export function getISOCountryCodeForNetworkSync(slotId: int): string {
      return nativeGetISOCountryCodeForNetwork(slotId);
    }

    export native function nativeGetIMEI(slotId?: int): string;

    export function getIMEI(slotId: int, callback: AsyncCallback<string>): void {
      let p1 = taskpool.execute((): string => {
          return nativeGetIMEI(slotId)
      })
      p1.then((content: NullishType) => {
          callback(new BusinessError(), content as string);
      }, (err: Error): void => {
          callback(err as BusinessError, new string());
      });
    }

    export function getIMEI(slotId?: int): Promise<string> {
      return new Promise<string>((resolve, reject) => {
        let p = taskpool.execute((): string => {
            return nativeGetIMEI(slotId)
        })
        p.then((e: NullishType) => {
            let r = e as string
            resolve(r)
        }).catch((e: Error): void => {
            reject(e)
        })
      })
    }

    export function getIMEI(callback: AsyncCallback<string>): void {
      let p1 = taskpool.execute((): string => {
          return nativeGetIMEI()
      })
      p1.then((content: NullishType) => {
          callback(new BusinessError(), content as string);
      }, (err: Error): void => {
          callback(err as BusinessError, new string());
      });
    }

    export native function nativeGetMEID(slotId?: int): string;

    export function getMEID(slotId: int, callback: AsyncCallback<string>): void {
      let p1 = taskpool.execute((): string => {
          return nativeGetMEID(slotId)
      })
      p1.then((content: NullishType) => {
          callback(new BusinessError(), content as string);
      }, (err: Error): void => {
          callback(err as BusinessError, new string());
      });
    }

    export function getMEID(slotId?: int): Promise<string> {
      return new Promise<string>((resolve, reject) => {
        let p = taskpool.execute((): string => {
            return nativeGetMEID(slotId)
        })
        p.then((e: NullishType) => {
            let r = e as string
            resolve(r)
        }).catch((e: Error): void => {
            reject(e)
        })
      })
    }

    export function getMEID(callback: AsyncCallback<string>): void {
      let p1 = taskpool.execute((): string => {
          return nativeGetMEID()
      })
      p1.then((content: NullishType) => {
          callback(new BusinessError(), content as string);
      }, (err: Error): void => {
          callback(err as BusinessError, new string());
      });
    }

    export native function nativeGetUniqueDeviceId(slotId?: int): string;

    export function getUniqueDeviceId(slotId: int, callback: AsyncCallback<string>): void {
      let p1 = taskpool.execute((): string => {
          return nativeGetUniqueDeviceId(slotId)
      })
      p1.then((content: NullishType) => {
          callback(new BusinessError(), content as string);
      }, (err: Error): void => {
          callback(err as BusinessError, new string());
      });
    }

    export function getUniqueDeviceId(slotId?: int): Promise<string> {
      return new Promise<string>((resolve, reject) => {
        let p = taskpool.execute((): string => {
            return nativeGetUniqueDeviceId(slotId)
        })
        p.then((e: NullishType) => {
            let r = e as string
            resolve(r)
        }).catch((e: Error): void => {
            reject(e)
        })
      })
    }

    export function getUniqueDeviceId(callback: AsyncCallback<string>): void {
      let p1 = taskpool.execute((): string => {
          return nativeGetUniqueDeviceId()
      })
      p1.then((content: NullishType) => {
          callback(new BusinessError(), content as string);
      }, (err: Error): void => {
          callback(err as BusinessError, new string());
      });
    }

    export native function nativeSetPrimarySlotId(slotId: int): void;

    export function setPrimarySlotId(slotId: int, callback: AsyncCallback<void>): void {
      let p1 = taskpool.execute(nativeSetPrimarySlotId, slotId);
      p1.then((content: NullishType) => {
          callback(new BusinessError(), content as undefined);
      }, (err: Error): void => {
          callback(err as BusinessError, undefined);
      })
    }

    export function setPrimarySlotId(slotId: int): Promise<void> {
      return new Promise<void>((resolve, reject) => {
        let p = taskpool.execute(nativeSetPrimarySlotId, slotId);
        p.then((e: NullishType) => {
            resolve(e as undefined)
        }).catch((e: Error): void => {
            reject(e as Error)
        })
      })
    }

    export native function nativeIsRadioOn(slotId?: int): boolean;

    export function isRadioOn(slotId: int, callback: AsyncCallback<boolean>): void {
      let p1 = taskpool.execute((): boolean => {
          return nativeIsRadioOn(slotId)
      })
      p1.then((content: NullishType) => {
          callback(new BusinessError(), content as boolean);
      }, (err: Error): void => {
          callback(err as BusinessError, false);
      });
    }

    export function isRadioOn(slotId?: int): Promise<boolean> {
      return new Promise<boolean>((resolve, reject) => {
        let p = taskpool.execute((): boolean => {
            return nativeIsRadioOn(slotId)
        })
        p.then((e: NullishType) => {
            let r = e as boolean
            resolve(r)
        }).catch((e: Error): void => {
            reject(e)
        })
      })
    }

    export function isRadioOn(callback: AsyncCallback<boolean>): void {
      let p1 = taskpool.execute((): boolean => {
          return nativeIsRadioOn()
      })
      p1.then((content: NullishType) => {
          callback(new BusinessError(), content as boolean);
      }, (err: Error): void => {
          callback(err as BusinessError, false);
      });
    }

    export native function nativeTurnOnRadio(slotId?: int): void;

    export function turnOnRadio(slotId: int, callback: AsyncCallback<void>): void {
      let p1 = taskpool.execute((): void => {
          return nativeTurnOnRadio(slotId)
      })
      p1.then((content: NullishType) => {
          callback(new BusinessError(), content as undefined);
      }, (err: Error): void => {
          callback(err as BusinessError, undefined);
      })
    }

    export function turnOnRadio(slotId?: int): Promise<void>{
      return new Promise<void>((resolve, reject) => {
        let p = taskpool.execute((): void => {
            return nativeTurnOnRadio(slotId)
        })
        p.then((e: NullishType) => {
            resolve(e as undefined)
        }).catch((e: Error): void => {
            reject(e as Error)
        })
      })
    }

    export function turnOnRadio(callback: AsyncCallback<void>): void {
      let p1 = taskpool.execute((): void => {
          return nativeTurnOnRadio()
      })
      p1.then((content: NullishType) => {
          callback(new BusinessError(), content as undefined);
      }, (err: Error): void => {
          callback(err as BusinessError, undefined);
      })
    }

    export native function nativeTurnOffRadio(slotId?: int): void;

    export function turnOffRadio(slotId: int, callback: AsyncCallback<void>): void {
      let p1 = taskpool.execute((): void => {
          return nativeTurnOffRadio(slotId)
      })
      p1.then((content: NullishType) => {
          callback(new BusinessError(), content as undefined);
      }, (err: Error): void => {
          callback(err as BusinessError, undefined);
      })
    }

    export function turnOffRadio(slotId?: int): Promise<void>{
      return new Promise<void>((resolve, reject) => {
        let p = taskpool.execute((): void => {
            return nativeTurnOffRadio(slotId);
        })
        p.then((e: NullishType) => {
            resolve(e as undefined)
        }).catch((e: Error): void => {
            reject(e as Error)
        })
      })
    }

    export function turnOffRadio(callback: AsyncCallback<void>): void {
      let p1 = taskpool.execute((): void => {
          return nativeTurnOffRadio()
      })
      p1.then((content: NullishType) => {
          callback(new BusinessError(), content as undefined);
      }, (err: Error): void => {
          callback(err as BusinessError, undefined);
      })
    }

    export native function nativeGetOperatorName(slotId: int): string;

    export function getOperatorName(slotId: int, callback: AsyncCallback<string>): void {
      let p1 = taskpool.execute((): string => {
            return nativeGetOperatorName(slotId)
      })
      p1.then((content: NullishType) => {
          callback(new BusinessError(), content as string);
      }, (err: Error): void => {
          callback(err as BusinessError, new string());
      });
    }

    export function getOperatorName(slotId: int): Promise<string> {
      return new Promise<string>((resolve, reject) => {
        let p = taskpool.execute((): string => {
            return nativeGetOperatorName(slotId)
        })
        p.then((e: NullishType) => {
            let r = e as string
            resolve(r)
        }).catch((e: Error): void => {
            reject(e)
        })
      })
    }

    export function getOperatorNameSync(slotId: int): string {
      return nativeGetOperatorName(slotId);
    }

    export native function nativeSetPreferredNetwork(slotId: int, networkMode: PreferredNetworkMode): void;

    export function setPreferredNetwork(slotId: int, networkMode: PreferredNetworkMode, callback: AsyncCallback<void>): void {
      let p1 = taskpool.execute(nativeSetPreferredNetwork, slotId, networkMode);
      p1.then((content: NullishType) => {
          callback(new BusinessError(), content as undefined);
      }, (err: Error): void => {
          callback(err as BusinessError, undefined);
      })
    }

    export function setPreferredNetwork(slotId: int, networkMode: PreferredNetworkMode): Promise<void> {
      return new Promise<void>((resolve, reject) => {
        let p = taskpool.execute(nativeSetPreferredNetwork, slotId, networkMode);
        p.then((e: NullishType) => {
            resolve(e as undefined)
        }).catch((e: Error): void => {
            reject(e as Error)
        })
      })
    }

    export native function nativeGetPreferredNetwork(slotId: int): PreferredNetworkMode;

    export function getPreferredNetwork(slotId: int, callback: AsyncCallback<PreferredNetworkMode>): void {
      let p1 = taskpool.execute((): PreferredNetworkMode => {
        return nativeGetPreferredNetwork(slotId)
      })
      p1.then((content: NullishType) => {
          callback(new BusinessError(), content as PreferredNetworkMode)
      }, (err: Error): void => {
          callback(err as BusinessError, undefined)
      });
    }

    export function getPreferredNetwork(slotId: int): Promise<PreferredNetworkMode> {
      return new Promise<PreferredNetworkMode>((resolve, reject) => {
        let p = taskpool.execute((): PreferredNetworkMode => {
          return nativeGetPreferredNetwork(slotId)
        })
        p.then((e: NullishType) => {
            let r = e as PreferredNetworkMode
            resolve(r)
        }).catch((e: Error): void => {
            reject(e)
        })
      })
    }

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

    export function getSignalInformationSync(slotId: int): Array<SignalInformation> {
      return nativeGetSignalInformation(slotId)
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

    export native function nativeGetBasebandVersion(slotId: int): string;

    export function getBasebandVersion(slotId: int, callback: AsyncCallback<string>): void {
      let p1 = taskpool.execute((): string => {
            return nativeGetBasebandVersion(slotId)
      })
      p1.then((content: NullishType) => {
          callback(new BusinessError(), content as string);
      }, (err: Error): void => {
          callback(err as BusinessError, new string());
      });
    }

    export function getBasebandVersion(slotId: int): Promise<string> {
      return new Promise<string>((resolve, reject) => {
        let p = taskpool.execute((): string => {
            return nativeGetBasebandVersion(slotId)
        })
        p.then((e: NullishType) => {
            let r = e as string
            resolve(r)
        }).catch((e: Error): void => {
            reject(e)
        })
      })
    }

    export native function nativeSetNROptionMode(slotId: int, mode: NROptionMode): void;

    export function setNROptionMode(slotId: int, mode: NROptionMode, callback: AsyncCallback<void>): void {
      let p1 = taskpool.execute(nativeSetNROptionMode, slotId, mode);
      p1.then((content: NullishType) => {
          callback(new BusinessError(), content as undefined);
      }, (err: Error): void => {
          callback(err as BusinessError, undefined);
      })
    }

    export function setNROptionMode(slotId: int, mode: NROptionMode): Promise<void> {
      return new Promise<void>((resolve, reject) => {
        let p = taskpool.execute(nativeSetNROptionMode, slotId, mode);
        p.then((e: NullishType) => {
            resolve(e as undefined)
        }).catch((e: Error): void => {
            reject(e as Error)
        })
      })
    }

    export native function nativeGetNROptionMode(slotId: int): NROptionMode;

    export function getNROptionMode(slotId: int, callback: AsyncCallback<NROptionMode>): void {
      let p1 = taskpool.execute((): NROptionMode => {
        return nativeGetNROptionMode(slotId)
      })
      p1.then((content: NullishType) => {
          callback(new BusinessError(), content as NROptionMode)
      }, (err: Error): void => {
          callback(err as BusinessError, undefined)
      });
    }

    export function getNROptionMode(slotId: int): Promise<NROptionMode> {
      return new Promise<NROptionMode>((resolve, reject) => {
        let p = taskpool.execute((): NROptionMode => {
          return nativeGetNROptionMode(slotId)
        })
        p.then((e: NullishType) => {
            let r = e as NROptionMode
            resolve(r)
        }).catch((e: Error): void => {
            reject(e)
        })
      })
    }

    export native function nativeSetNetworkCapability(slotId: int, type: NetworkCapabilityType, state: NetworkCapabilityState): void;

    export function setNetworkCapability(slotId: int, type: NetworkCapabilityType, state: NetworkCapabilityState,
      callback: AsyncCallback<void>): void {
      let p1 = taskpool.execute(nativeSetNetworkCapability, slotId, type, state);
      p1.then((content: NullishType) => {
          callback(new BusinessError(), content as undefined);
      }, (err: Error): void => {
          callback(err as BusinessError, undefined);
      })
    }

    export function setNetworkCapability(slotId: int, type: NetworkCapabilityType,
      state: NetworkCapabilityState): Promise<void> {
      return new Promise<void>((resolve, reject) => {
        let p = taskpool.execute(nativeSetNetworkCapability, slotId, type, state);
        p.then((e: NullishType) => {
            resolve(e as undefined)
        }).catch((e: Error): void => {
            reject(e as Error)
        })
      })
    }

    export native function nativeGetNetworkCapability(slotId: int, type: NetworkCapabilityType): NetworkCapabilityState;

    export function getNetworkCapability(slotId: int, type: NetworkCapabilityType,
      callback: AsyncCallback<NetworkCapabilityState>): void {
      let p1 = taskpool.execute((): NetworkCapabilityState => {
        return nativeGetNetworkCapability(slotId, type)
      })
      p1.then((content: NullishType) => {
          callback(new BusinessError(), content as NetworkCapabilityState)
      }, (err: Error): void => {
          callback(err as BusinessError, undefined)
      });
    }

    export function getNetworkCapability(slotId: int, type: NetworkCapabilityType):
      Promise<NetworkCapabilityState> {
      return new Promise<NetworkCapabilityState>((resolve, reject) => {
        let p = taskpool.execute((): NetworkCapabilityState => {
          return nativeGetNetworkCapability(slotId, type)
        })
        p.then((e: NullishType) => {
            let r = e as NetworkCapabilityState
            resolve(r)
        }).catch((e: Error): void => {
            reject(e)
        })
      })
    }

    export native function nativeFactoryReset(slotId: int): void;

    export function factoryReset(slotId: int): Promise<void> {
      return new Promise<void>((resolve, reject) => {
        let p = taskpool.execute(nativeFactoryReset, slotId);
        p.then((e: NullishType) => {
            resolve(e as undefined)
        }).catch((e: Error): void => {
            reject(e as Error)
        })
      })
    }

    export native function nativeGetIMEISV(slotId: int): string;

    export function getIMEISV(slotId: int): string {
      return nativeGetIMEISV(slotId)
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
      isCaActive: boolean;
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
      isCaActive: boolean;
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
      isCamped: boolean;
      timeStamp: long;
      signalInformation: SignalInformation;
      data: CdmaCellInformation | GsmCellInformation | LteCellInformation | NrCellInformation | TdscdmaCellInformation
      | WcdmaCellInformation;
    }

    export class CellInformationInner implements CellInformation {
      networkType: NetworkType;
      isCamped: boolean;
      timeStamp: long;
      signalInformation: SignalInformation;
      data: CdmaCellInformation | GsmCellInformation | LteCellInformation | NrCellInformation | TdscdmaCellInformation
      | WcdmaCellInformation;
    }

    export interface NetworkRadioTech {
      psRadioTech: RadioTechnology;
      csRadioTech: RadioTechnology;
    }

    export class NetworkRadioTechInner implements NetworkRadioTech {
      psRadioTech: RadioTechnology;
      csRadioTech: RadioTechnology;
    }

    export enum PreferredNetworkMode {
      PREFERRED_NETWORK_MODE_GSM = 1,
      PREFERRED_NETWORK_MODE_WCDMA = 2,
      PREFERRED_NETWORK_MODE_LTE = 3,
      PREFERRED_NETWORK_MODE_LTE_WCDMA = 4,
      PREFERRED_NETWORK_MODE_LTE_WCDMA_GSM = 5,
      PREFERRED_NETWORK_MODE_WCDMA_GSM = 6,
      PREFERRED_NETWORK_MODE_CDMA = 7,
      PREFERRED_NETWORK_MODE_EVDO = 8,
      PREFERRED_NETWORK_MODE_EVDO_CDMA = 9,
      PREFERRED_NETWORK_MODE_WCDMA_GSM_EVDO_CDMA = 10,
      PREFERRED_NETWORK_MODE_LTE_EVDO_CDMA = 11,
      PREFERRED_NETWORK_MODE_LTE_WCDMA_GSM_EVDO_CDMA = 12,
      PREFERRED_NETWORK_MODE_TDSCDMA = 13,
      PREFERRED_NETWORK_MODE_TDSCDMA_GSM = 14,
      PREFERRED_NETWORK_MODE_TDSCDMA_WCDMA = 15,
      PREFERRED_NETWORK_MODE_TDSCDMA_WCDMA_GSM = 16,
      PREFERRED_NETWORK_MODE_LTE_TDSCDMA = 17,
      PREFERRED_NETWORK_MODE_LTE_TDSCDMA_GSM = 18,
      PREFERRED_NETWORK_MODE_LTE_TDSCDMA_WCDMA = 19,
      PREFERRED_NETWORK_MODE_LTE_TDSCDMA_WCDMA_GSM = 20,
      PREFERRED_NETWORK_MODE_TDSCDMA_WCDMA_GSM_EVDO_CDMA = 21,
      PREFERRED_NETWORK_MODE_LTE_TDSCDMA_WCDMA_GSM_EVDO_CDMA = 22,
      PREFERRED_NETWORK_MODE_NR = 31,
      PREFERRED_NETWORK_MODE_NR_LTE = 32,
      PREFERRED_NETWORK_MODE_NR_LTE_WCDMA = 33,
      PREFERRED_NETWORK_MODE_NR_LTE_WCDMA_GSM = 34,
      PREFERRED_NETWORK_MODE_NR_LTE_EVDO_CDMA = 35,
      PREFERRED_NETWORK_MODE_NR_LTE_WCDMA_GSM_EVDO_CDMA = 36,
      PREFERRED_NETWORK_MODE_NR_LTE_TDSCDMA = 37,
      PREFERRED_NETWORK_MODE_NR_LTE_TDSCDMA_GSM = 38,
      PREFERRED_NETWORK_MODE_NR_LTE_TDSCDMA_WCDMA = 39,
      PREFERRED_NETWORK_MODE_NR_LTE_TDSCDMA_WCDMA_GSM = 40,
      PREFERRED_NETWORK_MODE_NR_LTE_TDSCDMA_WCDMA_GSM_EVDO_CDMA = 41,
      PREFERRED_NETWORK_MODE_MAX_VALUE = 99,
    }

    export enum NetworkInformationState {
      NETWORK_UNKNOWN,
      NETWORK_AVAILABLE,
      NETWORK_CURRENT,
      NETWORK_FORBIDDEN
    }

    export interface NetworkInformation {
      operatorName: string;
      operatorNumeric: string;
      state: NetworkInformationState;
      radioTech: string;
    }

    export class NetworkInformationInner implements NetworkInformation {
      operatorName: string;
      operatorNumeric: string;
      state: NetworkInformationState;
      radioTech: string;
    }

    export interface NetworkSearchResult {
      isNetworkSearchSuccess: boolean;
      networkSearchResult: Array<NetworkInformation>;
    }

    export class NetworkSearchResultInner implements NetworkSearchResult {
      isNetworkSearchSuccess: boolean;
      networkSearchResult: Array<NetworkInformation>;
    }

    export enum NetworkSelectionMode {
      NETWORK_SELECTION_UNKNOWN,
      NETWORK_SELECTION_AUTOMATIC,
      NETWORK_SELECTION_MANUAL
    }

    export interface NetworkSelectionModeOptions {
      slotId: int;
      selectMode: NetworkSelectionMode;
      networkInformation: NetworkInformation;
      resumeSelection: boolean;
    }

    export class NetworkSelectionModeOptionsInner implements NetworkSelectionModeOptions {
      slotId: int;
      selectMode: NetworkSelectionMode;
      networkInformation: NetworkInformation;
      resumeSelection: boolean;
    }

    export interface CdmaCellInformation {
      baseId: int;
      latitude: int;
      longitude: int;
      nid: int;
      sid: int;
    }

    export class CdmaCellInformationInner implements CdmaCellInformation {
      baseId: int;
      latitude: int;
      longitude: int;
      nid: int;
      sid: int;
    }

    export interface GsmCellInformation {
      lac: int;
      cellId: int;
      arfcn: int;
      bsic: int;
      mcc: string;
      mnc: string;
    }

    export class GsmCellInformationInner implements GsmCellInformation {
      lac: int;
      cellId: int;
      arfcn: int;
      bsic: int;
      mcc: string;
      mnc: string;
    }

    export interface LteCellInformation {
      cgi: long;
      pci: int;
      tac: int;
      earfcn: int;
      bandwidth: int;
      mcc: string;
      mnc: string;
      isSupportEndc: boolean;
    }

    export class LteCellInformationInner implements LteCellInformation {
      cgi: long;
      pci: int;
      tac: int;
      earfcn: int;
      bandwidth: int;
      mcc: string;
      mnc: string;
      isSupportEndc: boolean;
    }

    export interface NrCellInformation {
      nrArfcn: int;
      pci: int;
      tac: int;
      nci: int;
      mcc: string;
      mnc: string;
    }

    export class NrCellInformationInner implements NrCellInformation {
      nrArfcn: int;
      pci: int;
      tac: int;
      nci: int;
      mcc: string;
      mnc: string;
    }

    export interface TdscdmaCellInformation {
      lac: int;
      cellId: int;
      cpid: int;
      uarfcn: int;
      mcc: string;
      mnc: string;
    }

    export class TdscdmaCellInformationInner implements TdscdmaCellInformation {
      lac: int;
      cellId: int;
      cpid: int;
      uarfcn: int;
      mcc: string;
      mnc: string;
    }

    export interface WcdmaCellInformation {
      lac: int;
      cellId: int;
      psc: int;
      uarfcn: int;
      mcc: string;
      mnc: string;
    }

    export class WcdmaCellInformationInner implements WcdmaCellInformation {
      lac: int;
      cellId: int;
      psc: int;
      uarfcn: int;
      mcc: string;
      mnc: string;
    }

    export enum NetworkCapabilityType {
      SERVICE_TYPE_LTE,
      SERVICE_TYPE_NR,
    }

    export enum NetworkCapabilityState {
      SERVICE_CAPABILITY_OFF,
      SERVICE_CAPABILITY_ON,
    }

    export enum NROptionMode {
      NR_OPTION_UNKNOWN,
      NR_OPTION_NSA_ONLY,
      NR_OPTION_SA_ONLY,
      NR_OPTION_NSA_AND_SA,
    }
}