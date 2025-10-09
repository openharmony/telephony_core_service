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
import type { AsyncCallback } from '@ohos.base';

export default namespace sim {
  loadLibrary("sim_ani")

  export native function nativeGetLockState(slotId: int, lockType: LockType): LockState;

  export function getLockState(slotId: int, lockType: LockType, callback: AsyncCallback<LockState>): void {
    let p1 = taskpool.execute(nativeGetLockState, slotId, lockType)
    p1.then((content: NullishType) => {
        callback(new BusinessError(), content as LockState);
    }, (err: Error): void => {
        callback(err as BusinessError, LockState.LOCK_OFF);
    });
  }

  export function getLockState(slotId: int, lockType: LockType): Promise<LockState> {
    return new Promise<LockState>((resolve, reject) => {
      let p = taskpool.execute(nativeGetLockState, slotId, lockType)
      p.then((e: NullishType) => {
          let r = e as LockState
          resolve(r)
      }).catch((e: Error): void => {
          reject(e)
      })
    })
  }

  export native function nativeUnlockPuk(slotId: int, newPin: string, puk: string): LockStatusResponse;

  export function unlockPuk(slotId: int, newPin: string, puk: string, callback: AsyncCallback<LockStatusResponse>): void {
    let p1 = taskpool.execute(nativeUnlockPuk, slotId, newPin, puk)
    p1.then((content: NullishType) => {
        callback(new BusinessError(), content as LockStatusResponse);
    }, (err: Error): void => {
        callback(err as BusinessError, new LockStatusResponseInner());
    });
  }

  export function unlockPuk(slotId: int, newPin: string, puk: string): Promise<LockStatusResponse> {
    return new Promise<LockStatusResponse>((resolve, reject) => {
      let p = taskpool.execute(nativeUnlockPuk, slotId, newPin, puk)
      p.then((e: NullishType) => {
          let r = e as LockStatusResponse
          resolve(r)
      }).catch((e: Error): void => {
          reject(e)
      })
    })
  }

  export native function nativeunlockPin(slotId: int, pin: string): LockStatusResponse;

  export function unlockPin(slotId: int, pin: string, callback: AsyncCallback<LockStatusResponse>): void {
    let p1 = taskpool.execute(nativeunlockPin, slotId, pin)
    p1.then((content: NullishType) => {
        callback(new BusinessError(), content as LockStatusResponse);
    }, (err: Error): void => {
        callback(err as BusinessError, new LockStatusResponseInner());
    });
  }

  export function unlockPin(slotId: int, pin: string): Promise<LockStatusResponse> {
    return new Promise<LockStatusResponse>((resolve, reject) => {
      let p = taskpool.execute(nativeunlockPin, slotId, pin)
      p.then((e: NullishType) => {
          let r = e as LockStatusResponse
          resolve(r)
      }).catch((e: Error): void => {
          reject(e)
      })
    })
  }

  export native function nativeGetOperatorConfigs(slotId: int): Array<OperatorConfig>;

  export function getOperatorConfigs(slotId: int, callback: AsyncCallback<Array<OperatorConfig>>): void {
    let p1 = taskpool.execute(nativeGetOperatorConfigs, slotId)
    p1.then((content: NullishType) => {
        callback(new BusinessError(), content as Array<OperatorConfig>);
    }, (err: Error): void => {
        callback(err as BusinessError, new Array<OperatorConfig>());
    });
  }

  export function getOperatorConfigs(slotId: int): Promise<Array<OperatorConfig>> {
    return new Promise<Array<OperatorConfig>>((resolve, reject) => {
      let p = taskpool.execute(nativeGetOperatorConfigs, slotId)
      p.then((e: NullishType) => {
          let r = e as Array<OperatorConfig>
          resolve(r)
      }).catch((e: Error): void => {
          reject(e)
      })
    })
  }

  export native function nativeGetActiveSimAccountInfoList(): Array<IccAccountInfo>;

  export function getActiveSimAccountInfoList(callback: AsyncCallback<Array<IccAccountInfo>>): void {
    let p1 = taskpool.execute(nativeGetActiveSimAccountInfoList)
    p1.then((content: NullishType) => {
        callback(new BusinessError(), content as Array<IccAccountInfo>);
    }, (err: Error): void => {
        callback(err as BusinessError, new Array<IccAccountInfo>());
    });
  }

  export function getActiveSimAccountInfoList(): Promise<Array<IccAccountInfo>> {
    return new Promise<Array<IccAccountInfo>>((resolve, reject) => {
      let p = taskpool.execute(nativeGetActiveSimAccountInfoList)
      p.then((e: NullishType) => {
          let r = e as Array<IccAccountInfo>
          resolve(r)
      }).catch((e: Error): void => {
          reject(e)
      })
    })
  }

  export native function nativeGetSimAccountInfo(slotId: int): IccAccountInfo;

  export function getSimAccountInfo(slotId: int, callback: AsyncCallback<IccAccountInfo>): void {
    let p1 = taskpool.execute(nativeGetSimAccountInfo, slotId)
    p1.then((content: NullishType) => {
        callback(new BusinessError(), content as IccAccountInfo);
    }, (err: Error): void => {
        callback(err as BusinessError, new IccAccountInfoInner);
    });
  }

  export function getSimAccountInfo(slotId: int): Promise<IccAccountInfo> {
    return new Promise<IccAccountInfo>((resolve, reject) => {
      let p = taskpool.execute(nativeGetSimAccountInfo, slotId)
      p.then((e: NullishType) => {
          let r = e as IccAccountInfo
          resolve(r)
      }).catch((e: Error): void => {
          reject(e)
      })
    })
  }

  export native function nativeHasSimCard(slotId: int): boolean;

  export function hasSimCard(slotId: int, callback: AsyncCallback<boolean>): void {
    let p1 = taskpool.execute(nativeHasSimCard, slotId)
    p1.then((content: NullishType) => {
        callback(new BusinessError(), content as boolean);
    }, (err: Error): void => {
        callback(err as BusinessError, false);
    });
  }

  export function hasSimCard(slotId: int): Promise<boolean> {
    return new Promise<boolean>((resolve, reject) => {
      let p = taskpool.execute(nativeHasSimCard, slotId)
      p.then((e: NullishType) => {
          let r = e as boolean
          resolve(r)
      }).catch((e: Error): void => {
          reject(e)
      })
    })
  }

  export native function nativeGetSimState(slotId: int): SimState;

  export function getSimState(slotId: int, callback: AsyncCallback<SimState>): void {
    let p1 = taskpool.execute(nativeGetSimState, slotId)
    p1.then((content: NullishType) => {
        callback(new BusinessError(), content as SimState);
    }, (err: Error): void => {
        callback(err as BusinessError, SimState.SIM_STATE_UNKNOWN);
    });
  }

  export function getSimState(slotId: int): Promise<SimState> {
    return new Promise<SimState>((resolve, reject) => {
      let p = taskpool.execute(nativeGetSimState, slotId)
      p.then((e: NullishType) => {
          let r = e as SimState
          resolve(r)
      }).catch((e: Error): void => {
          reject(e)
      })
    })
  }

  export function getSimStateSync(slotId: int): SimState {
    return nativeGetSimState(slotId)
  }

  export native function nativeGetISOCountryCodeForSim(slotId: int): string;

  export function getISOCountryCodeForSim(slotId: int, callback: AsyncCallback<string>): void {
    let p1 = taskpool.execute(nativeGetISOCountryCodeForSim, slotId)
    p1.then((content: NullishType) => {
        callback(new BusinessError(), content as string);
    }, (err: Error): void => {
        callback(err as BusinessError, new string());
    });
  }

  export function getISOCountryCodeForSim(slotId: int): Promise<string> {
    return new Promise<string>((resolve, reject) => {
      let p = taskpool.execute(nativeGetISOCountryCodeForSim, slotId)
      p.then((e: NullishType) => {
          let r = e as string
          resolve(r)
      }).catch((e: Error): void => {
          reject(e)
      })
    })
  }

  export native function nativeGetMaxSimCount(): int;

  export function getMaxSimCount(): int {
    return nativeGetMaxSimCount();
  }

  export native function nativeGetDefaultVoiceSlotId(): int;

  export function getDefaultVoiceSlotId(callback: AsyncCallback<int>): void {
    let p1 = taskpool.execute(nativeGetDefaultVoiceSlotId)
    p1.then((content: NullishType) => {
        callback(new BusinessError(), content as int);
    }, (err: Error): void => {
        callback(err as BusinessError, 0);
    });
  }

  export function getDefaultVoiceSlotId(): Promise<int> {
    return new Promise<int>((resolve, reject) => {
      let p = taskpool.execute(nativeGetDefaultVoiceSlotId)
      p.then((e: NullishType) => {
          let r = e as int
          resolve(r)
      }).catch((e: Error): void => {
          reject(e)
      })
    })
  }

  export native function nativeIsSimActive(slotId: int): boolean;

  export function isSimActive(slotId: int, callback: AsyncCallback<boolean>): void {
    let p1 = taskpool.execute(nativeIsSimActive, slotId)
    p1.then((content: NullishType) => {
        callback(new BusinessError(), content as boolean);
    }, (err: Error): void => {
        callback(err as BusinessError, false);
    });
  }

  export function isSimActive(slotId: int): Promise<boolean> {
    return new Promise<boolean>((resolve, reject) => {
      let p = taskpool.execute(nativeIsSimActive, slotId)
      p.then((e: NullishType) => {
          let r = e as boolean
          resolve(r)
      }).catch((e: Error): void => {
          reject(e)
      })
    })
  }

  export function isSimActiveSync(slotId: int): boolean {
    return nativeIsSimActive(slotId)
  }

  export enum LockState {
    LOCK_OFF = 0,

    LOCK_ON = 1,
  }

  export enum LockType {
    PIN_LOCK = 1,

    FDN_LOCK = 2,
  }

  export interface LockStatusResponse {
    result: int;

    remain?: int;
  }

  export class LockStatusResponseInner implements LockStatusResponse {
    result: int;

    remain?: int;
  }

  export interface OperatorConfig {
    field: string;

    value: string;
  }

  export class OperatorConfigInner implements OperatorConfig {
    field: string;

    value: string;
  }

  export interface IccAccountInfo {
    simId: int;

    slotIndex: int;

    isEsim: boolean;

    isActive: boolean;

    iccId: string;

    showName: string;

    showNumber: string;
  }

  export class IccAccountInfoInner implements IccAccountInfo {
    simId: int;

    slotIndex: int;

    isEsim: boolean;

    isActive: boolean;

    iccId: string;

    showName: string;

    showNumber: string;
  }

  export enum SimState {
    SIM_STATE_UNKNOWN,

    SIM_STATE_NOT_PRESENT,

    SIM_STATE_LOCKED,

    SIM_STATE_NOT_READY,

    SIM_STATE_READY,

    SIM_STATE_LOADED
  }

  export enum CardType {
    UNKNOWN_CARD = -1,

    SINGLE_MODE_SIM_CARD = 10,

    SINGLE_MODE_USIM_CARD = 20,

    SINGLE_MODE_RUIM_CARD = 30,
    
    DUAL_MODE_CG_CARD = 40,

    CT_NATIONAL_ROAMING_CARD = 41,

    CU_DUAL_MODE_CARD = 42,

    DUAL_MODE_TELECOM_LTE_CARD = 43,

    DUAL_MODE_UG_CARD = 50,

    SINGLE_MODE_ISIM_CARD = 60
  }
}
