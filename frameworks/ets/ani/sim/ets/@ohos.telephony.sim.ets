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
    p1.then((content: Any) => {
        callback(new BusinessError(), content as LockState);
    }, (err: Error): void => {
        callback(err as BusinessError, LockState.LOCK_OFF);
    });
  }

  export function getLockState(slotId: int, lockType: LockType): Promise<LockState> {
    return new Promise<LockState>((resolve, reject) => {
      let p = taskpool.execute(nativeGetLockState, slotId, lockType)
      p.then((e: Any) => {
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
    p1.then((content: Any) => {
        callback(new BusinessError(), content as LockStatusResponse);
    }, (err: Error): void => {
        callback(err as BusinessError, new LockStatusResponseInner());
    });
  }

  export function unlockPuk(slotId: int, newPin: string, puk: string): Promise<LockStatusResponse> {
    return new Promise<LockStatusResponse>((resolve, reject) => {
      let p = taskpool.execute(nativeUnlockPuk, slotId, newPin, puk)
      p.then((e: Any) => {
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
    p1.then((content: Any) => {
        callback(new BusinessError(), content as LockStatusResponse);
    }, (err: Error): void => {
        callback(err as BusinessError, new LockStatusResponseInner());
    });
  }

  export function unlockPin(slotId: int, pin: string): Promise<LockStatusResponse> {
    return new Promise<LockStatusResponse>((resolve, reject) => {
      let p = taskpool.execute(nativeunlockPin, slotId, pin)
      p.then((e: Any) => {
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
    p1.then((content: Any) => {
        callback(new BusinessError(), content as Array<OperatorConfig>);
    }, (err: Error): void => {
        callback(err as BusinessError, new Array<OperatorConfig>());
    });
  }

  export function getOperatorConfigs(slotId: int): Promise<Array<OperatorConfig>> {
    return new Promise<Array<OperatorConfig>>((resolve, reject) => {
      let p = taskpool.execute(nativeGetOperatorConfigs, slotId)
      p.then((e: Any) => {
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
    p1.then((content: Any) => {
        callback(new BusinessError(), content as Array<IccAccountInfo>);
    }, (err: Error): void => {
        callback(err as BusinessError, new Array<IccAccountInfo>());
    });
  }

  export function getActiveSimAccountInfoList(): Promise<Array<IccAccountInfo>> {
    return new Promise<Array<IccAccountInfo>>((resolve, reject) => {
      let p = taskpool.execute(nativeGetActiveSimAccountInfoList)
      p.then((e: Any) => {
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
    p1.then((content: Any) => {
        callback(new BusinessError(), content as IccAccountInfo);
    }, (err: Error): void => {
        callback(err as BusinessError, new IccAccountInfoInner);
    });
  }

  export function getSimAccountInfo(slotId: int): Promise<IccAccountInfo> {
    return new Promise<IccAccountInfo>((resolve, reject) => {
      let p = taskpool.execute(nativeGetSimAccountInfo, slotId)
      p.then((e: Any) => {
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
    p1.then((content: Any) => {
        callback(new BusinessError(), content as boolean);
    }, (err: Error): void => {
        callback(err as BusinessError, false);
    });
  }

  export function hasSimCard(slotId: int): Promise<boolean> {
    return new Promise<boolean>((resolve, reject) => {
      let p = taskpool.execute(nativeHasSimCard, slotId)
      p.then((e: Any) => {
          let r = e as boolean
          resolve(r)
      }).catch((e: Error): void => {
          reject(e)
      })
    })
  }

  export function hasSimCardSync(slotId: int): boolean {
    return nativeHasSimCard(slotId);
  }

  export native function nativeGetSimState(slotId: int): SimState;

  export function getSimState(slotId: int, callback: AsyncCallback<SimState>): void {
    let p1 = taskpool.execute(nativeGetSimState, slotId)
    p1.then((content: Any) => {
        callback(new BusinessError(), content as SimState);
    }, (err: Error): void => {
        callback(err as BusinessError, SimState.SIM_STATE_UNKNOWN);
    });
  }

  export function getSimState(slotId: int): Promise<SimState> {
    return new Promise<SimState>((resolve, reject) => {
      let p = taskpool.execute(nativeGetSimState, slotId)
      p.then((e: Any) => {
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
    p1.then((content: Any) => {
        callback(new BusinessError(), content as string);
    }, (err: Error): void => {
        callback(err as BusinessError, new string());
    });
  }

  export function getISOCountryCodeForSim(slotId: int): Promise<string> {
    return new Promise<string>((resolve, reject) => {
      let p = taskpool.execute(nativeGetISOCountryCodeForSim, slotId)
      p.then((e: Any) => {
          let r = e as string
          resolve(r)
      }).catch((e: Error): void => {
          reject(e)
      })
    })
  }

  export function getISOCountryCodeForSimSync(slotId: int): string {
    return nativeGetISOCountryCodeForSim(slotId);
  }

  export native function nativeGetMaxSimCount(): int;

  export function getMaxSimCount(): int {
    return nativeGetMaxSimCount();
  }

  export native function nativeGetDefaultVoiceSlotId(): int;

  export function getDefaultVoiceSlotId(callback: AsyncCallback<int>): void {
    let p1 = taskpool.execute(nativeGetDefaultVoiceSlotId)
    p1.then((content: Any) => {
        callback(new BusinessError(), content as int);
    }, (err: Error): void => {
        callback(err as BusinessError, 0);
    });
  }

  export function getDefaultVoiceSlotId(): Promise<int> {
    return new Promise<int>((resolve, reject) => {
      let p = taskpool.execute(nativeGetDefaultVoiceSlotId)
      p.then((e: Any) => {
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
    p1.then((content: Any) => {
        callback(new BusinessError(), content as boolean);
    }, (err: Error): void => {
        callback(err as BusinessError, false);
    });
  }

  export function isSimActive(slotId: int): Promise<boolean> {
    return new Promise<boolean>((resolve, reject) => {
      let p = taskpool.execute(nativeIsSimActive, slotId)
      p.then((e: Any) => {
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

  export native function nativeHasOperatorPrivileges(slotId: int): boolean;

  export function hasOperatorPrivileges(slotId: int, callback: AsyncCallback<boolean>): void {
    let p1 = taskpool.execute(nativeHasOperatorPrivileges, slotId)
    p1.then((content: Any) => {
        callback(new BusinessError(), content as boolean);
    }, (err: Error): void => {
        callback(err as BusinessError, false);
    });
  }

  export function hasOperatorPrivileges(slotId: int): Promise<boolean> {
    return new Promise<boolean>((resolve, reject) => {
      let p = taskpool.execute(nativeHasOperatorPrivileges, slotId)
      p.then((e: Any) => {
          let r = e as boolean
          resolve(r)
      }).catch((e: Error): void => {
          reject(e)
      })
    })
  }

  export native function nativeGetSimOperatorNumeric(slotId: int): string;

  export function getSimOperatorNumeric(slotId: int, callback: AsyncCallback<string>): void {
    let p1 = taskpool.execute(nativeGetSimOperatorNumeric, slotId)
    p1.then((content: Any) => {
        callback(new BusinessError(), content as string);
    }, (err: Error): void => {
        callback(err as BusinessError, new string());
    });
  }

  export function getSimOperatorNumeric(slotId: int): Promise<string> {
    return new Promise<string>((resolve, reject) => {
      let p = taskpool.execute(nativeGetSimOperatorNumeric, slotId);
      p.then((e: Any) => {
          let r = e as string
          resolve(r)
      }).catch((e: Error): void => {
          reject(e)
      })
    })
  }

  export function getSimOperatorNumericSync(slotId: int): string {
    return nativeGetSimOperatorNumeric(slotId);
  }

  export native function nativeGetSimSpn(slotId: int): string;

  export function getSimSpn(slotId: int, callback: AsyncCallback<string>): void {
    let p1 = taskpool.execute(nativeGetSimSpn, slotId)
    p1.then((content: Any) => {
        callback(new BusinessError(), content as string);
    }, (err: Error): void => {
        callback(err as BusinessError, new string());
    });
  }

  export function getSimSpn(slotId: int): Promise<string> {
    return new Promise<string>((resolve, reject) => {
      let p = taskpool.execute(nativeGetSimSpn, slotId);
      p.then((e: Any) => {
          let r = e as string
          resolve(r)
      }).catch((e: Error): void => {
          reject(e)
      })
    })
  }

  export function getSimSpnSync(slotId: int): string {
    return nativeGetSimSpn(slotId);
  }

  export native function nativeGetCardType(slotId: int): CardType;

  export function getCardType(slotId: int, callback: AsyncCallback<CardType>): void {
    let p1 = taskpool.execute(nativeGetCardType, slotId)
    p1.then((content: Any) => {
        callback(new BusinessError(), content as CardType);
    }, (err: Error): void => {
        callback(err as BusinessError, CardType.UNKNOWN_CARD);
    });
  }

  export function getCardType(slotId: int): Promise<CardType> {
    return new Promise<CardType>((resolve, reject) => {
      let p = taskpool.execute(nativeGetCardType, slotId)
      p.then((e: Any) => {
          let r = e as CardType
          resolve(r)
      }).catch((e: Error): void => {
          reject(e)
      })
    })
  }

  export function getCardTypeSync(slotId: int): CardType {
    return nativeGetCardType(slotId);
  }

  export native function nativeGetSimIccId(slotId: int): string;

  export function getSimIccId(slotId: int, callback: AsyncCallback<string>): void {
    let p1 = taskpool.execute(nativeGetSimIccId, slotId)
    p1.then((content: Any) => {
        callback(new BusinessError(), content as string);
    }, (err: Error): void => {
        callback(err as BusinessError, new string());
    });
  }

  export function getSimIccId(slotId: int): Promise<string> {
    return new Promise<string>((resolve, reject) => {
      let p = taskpool.execute(nativeGetSimIccId, slotId);
      p.then((e: Any) => {
          let r = e as string
          resolve(r)
      }).catch((e: Error): void => {
          reject(e)
      })
    })
  }

  export native function nativeGetVoiceMailIdentifier(slotId: int): string;

  export function getVoiceMailIdentifier(slotId: int, callback: AsyncCallback<string>): void {
    let p1 = taskpool.execute(nativeGetVoiceMailIdentifier, slotId)
    p1.then((content: Any) => {
        callback(new BusinessError(), content as string);
    }, (err: Error): void => {
        callback(err as BusinessError, new string());
    });
  }

  export function getVoiceMailIdentifier(slotId: int): Promise<string> {
    return new Promise<string>((resolve, reject) => {
      let p = taskpool.execute(nativeGetVoiceMailIdentifier, slotId);
      p.then((e: Any) => {
          let r = e as string
          resolve(r)
      }).catch((e: Error): void => {
          reject(e)
      })
    })
  }

  export native function nativeGetVoiceMailNumber(slotId: int): string;

  export function getVoiceMailNumber(slotId: int, callback: AsyncCallback<string>): void {
    let p1 = taskpool.execute(nativeGetVoiceMailNumber, slotId)
    p1.then((content: Any) => {
        callback(new BusinessError(), content as string);
    }, (err: Error): void => {
        callback(err as BusinessError, new string());
    });
  }

  export function getVoiceMailNumber(slotId: int): Promise<string> {
    return new Promise<string>((resolve, reject) => {
      let p = taskpool.execute(nativeGetVoiceMailNumber, slotId);
      p.then((e: Any) => {
          let r = e as string
          resolve(r)
      }).catch((e: Error): void => {
          reject(e)
      })
    })
  }

  export native function nativeSetVoiceMailInfo(slotId: int, mailName: string, mailNumber: string): void;

  export function setVoiceMailInfo(slotId: int, mailName: string, mailNumber: string, callback: AsyncCallback<void>): void {
    let p1 = taskpool.execute(nativeSetVoiceMailInfo, slotId, mailName, mailNumber);
    p1.then((content: Any) => {
        callback(new BusinessError(), content as undefined);
    }, (err: Error): void => {
        callback(err as BusinessError, undefined);
    })
  }

  export function setVoiceMailInfo(slotId: int, mailName: string, mailNumber: string): Promise<void> {
    return new Promise<void>((resolve, reject) => {
      let p = taskpool.execute(nativeSetVoiceMailInfo, slotId, mailName, mailNumber);
      p.then((e: Any) => {
          let r = e as undefined
          resolve(r)
      }).catch((e: Error): void => {
          reject(e)
      })
    })
  }

  export native function nativeGetSimTelephoneNumber(slotId: int): string;

  export function getSimTelephoneNumber(slotId: int, callback: AsyncCallback<string>): void {
    let p1 = taskpool.execute(nativeGetSimTelephoneNumber, slotId)
    p1.then((content: Any) => {
        callback(new BusinessError(), content as string);
    }, (err: Error): void => {
        callback(err as BusinessError, new string());
    });
  }

  export function getSimTelephoneNumber(slotId: int): Promise<string> {
    return new Promise<string>((resolve, reject) => {
      let p = taskpool.execute(nativeGetSimTelephoneNumber, slotId);
      p.then((e: Any) => {
          let r = e as string
          resolve(r)
      }).catch((e: Error): void => {
          reject(e)
      })
    })
  }

  export native function nativeGetSimGid1(slotId: int): string;

  export function getSimGid1(slotId: int, callback: AsyncCallback<string>): void {
    let p1 = taskpool.execute(nativeGetSimGid1, slotId)
    p1.then((content: Any) => {
        callback(new BusinessError(), content as string);
    }, (err: Error): void => {
        callback(err as BusinessError, new string());
    });
  }

  export function getSimGid1(slotId: int): Promise<string> {
    return new Promise<string>((resolve, reject) => {
      let p = taskpool.execute(nativeGetSimGid1, slotId);
      p.then((e: Any) => {
          let r = e as string
          resolve(r)
      }).catch((e: Error): void => {
          reject(e)
      })
    })
  }

  export native function nativeGetIMSI(slotId: int): string;

  export function getIMSI(slotId: int, callback: AsyncCallback<string>): void {
    let p1 = taskpool.execute(nativeGetIMSI, slotId)
    p1.then((content: Any) => {
        callback(new BusinessError(), content as string);
    }, (err: Error): void => {
        callback(err as BusinessError, new string());
    });
  }

  export function getIMSI(slotId: int): Promise<string> {
    return new Promise<string>((resolve, reject) => {
      let p = taskpool.execute(nativeGetIMSI, slotId);
      p.then((e: Any) => {
          let r = e as string
          resolve(r)
      }).catch((e: Error): void => {
          reject(e)
      })
    })
  }

  export native function nativeIsOperatorSimCard(slotId: int, operator: OperatorSimCard): boolean;

  export function isOperatorSimCard(slotId: int, operator: OperatorSimCard): boolean {
    return nativeIsOperatorSimCard(slotId, operator);
  }

  export native function nativeSetDefaultVoiceSlotId(slotId: int): void;

  export function setDefaultVoiceSlotId(slotId: int, callback: AsyncCallback<void>): void {
    let p1 = taskpool.execute(nativeSetDefaultVoiceSlotId, slotId);
    p1.then((content: Any) => {
        callback(new BusinessError(), content as undefined);
    }, (err: Error): void => {
        callback(err as BusinessError, undefined);
    })
  }

  export function setDefaultVoiceSlotId(slotId: int): Promise<void> {
    return new Promise<void>((resolve, reject) => {
      let p = taskpool.execute(nativeSetDefaultVoiceSlotId, slotId);
      p.then((e: Any) => {
          let r = e as undefined
          resolve(r)
      }).catch((e: Error): void => {
          reject(e)
      })
    })
  }

  export native function nativeActivateSim(slotId: int): void;

  export function activateSim(slotId: int, callback: AsyncCallback<void>): void {
    let p1 = taskpool.execute(nativeActivateSim, slotId);
    p1.then((content: Any) => {
        callback(new BusinessError(), content as undefined);
    }, (err: Error): void => {
        callback(err as BusinessError, undefined);
    })
  }

  export function activateSim(slotId: int): Promise<void> {
    return new Promise<void>((resolve, reject) => {
      let p = taskpool.execute(nativeActivateSim, slotId);
      p.then((e: Any) => {
          let r = e as undefined
          resolve(r)
      }).catch((e: Error): void => {
          reject(e)
      })
    })
  }

  export native function nativeDeactivateSim(slotId: int): void;

  export function deactivateSim(slotId: int, callback: AsyncCallback<void>): void {
    let p1 = taskpool.execute(nativeDeactivateSim, slotId);
    p1.then((content: Any) => {
        callback(new BusinessError(), content as undefined);
    }, (err: Error): void => {
        callback(err as BusinessError, undefined);
    })
  }

  export function deactivateSim(slotId: int): Promise<void> {
    return new Promise<void>((resolve, reject) => {
      let p = taskpool.execute(nativeDeactivateSim, slotId);
      p.then((e: Any) => {
          let r = e as undefined
          resolve(r)
      }).catch((e: Error): void => {
          reject(e)
      })
    })
  }

  export native function nativeSetShowName(slotId: int, name: string): void;

  export function setShowName(slotId: int, name: string, callback: AsyncCallback<void>): void {
    let p1 = taskpool.execute(nativeSetShowName, slotId, name);
    p1.then((content: Any) => {
        callback(new BusinessError(), content as undefined);
    }, (err: Error): void => {
        callback(err as BusinessError, undefined);
    })
  }

  export function setShowName(slotId: int, name: string): Promise<void> {
    return new Promise<void>((resolve, reject) => {
      let p = taskpool.execute(nativeSetShowName, slotId, name);
      p.then((e: Any) => {
          let r = e as undefined
          resolve(r)
      }).catch((e: Error): void => {
          reject(e)
      })
    })
  }

  export native function nativeGetShowName(slotId: int): string;

  export function getShowName(slotId: int, callback: AsyncCallback<string>): void {
    let p1 = taskpool.execute(nativeGetShowName, slotId)
    p1.then((content: Any) => {
        callback(new BusinessError(), content as string);
    }, (err: Error): void => {
        callback(err as BusinessError, new string());
    });
  }

  export function getShowName(slotId: int): Promise<string> {
    return new Promise<string>((resolve, reject) => {
      let p = taskpool.execute(nativeGetShowName, slotId);
      p.then((e: Any) => {
          let r = e as string
          resolve(r)
      }).catch((e: Error): void => {
          reject(e)
      })
    })
  }

  export native function nativeSetShowNumber(slotId: int, number: string): void;

  export function setShowNumber(slotId: int, number: string, callback: AsyncCallback<void>): void {
    let p1 = taskpool.execute(nativeSetShowNumber, slotId, number);
    p1.then((content: Any) => {
        callback(new BusinessError(), content as undefined);
    }, (err: Error): void => {
        callback(err as BusinessError, undefined);
    })
  }

  export function setShowNumber(slotId: int, number: string): Promise<void> {
    return new Promise<void>((resolve, reject) => {
      let p = taskpool.execute(nativeSetShowNumber, slotId, number);
      p.then((e: Any) => {
          let r = e as undefined
          resolve(r)
      }).catch((e: Error): void => {
          reject(e)
      })
    })
  }

  export native function nativeGetShowNumber(slotId: int): string;

  export function getShowNumber(slotId: int, callback: AsyncCallback<string>): void {
    let p1 = taskpool.execute(nativeGetShowNumber, slotId)
    p1.then((content: Any) => {
        callback(new BusinessError(), content as string);
    }, (err: Error): void => {
        callback(err as BusinessError, new string());
    });
  }

  export function getShowNumber(slotId: int): Promise<string> {
    return new Promise<string>((resolve, reject) => {
      let p = taskpool.execute(nativeGetShowNumber, slotId);
      p.then((e: Any) => {
          let r = e as string
          resolve(r)
      }).catch((e: Error): void => {
          reject(e)
      })
    })
  }

  export native function nativeAlterPin(slotId: int, newPin: string, oldPin: string): LockStatusResponse;

  export function alterPin(slotId: int, newPin: string, oldPin: string, callback: AsyncCallback<LockStatusResponse>): void {
    let p1 = taskpool.execute(nativeAlterPin, slotId, newPin, oldPin)
    p1.then((content: Any) => {
        callback(new BusinessError(), content as LockStatusResponse);
    }, (err: Error): void => {
        callback(err as BusinessError, new LockStatusResponseInner());
    });
  }

  export function alterPin(slotId: int, newPin: string, oldPin: string): Promise<LockStatusResponse> {
    return new Promise<LockStatusResponse>((resolve, reject) => {
      let p = taskpool.execute(nativeAlterPin, slotId, newPin, oldPin)
      p.then((e: Any) => {
          let r = e as LockStatusResponse
          resolve(r)
      }).catch((e: Error): void => {
          reject(e)
      })
    })
  }

  export native function nativeSetLockState(slotId: int, options: LockInfo): LockStatusResponse;

  export function setLockState(slotId: int, options: LockInfo, callback: AsyncCallback<LockStatusResponse>): void {
    let p1 = taskpool.execute(nativeSetLockState, slotId, options)
    p1.then((content: Any) => {
        callback(new BusinessError(), content as LockStatusResponse);
    }, (err: Error): void => {
        callback(err as BusinessError, new LockStatusResponseInner());
    });
  }

  export function setLockState(slotId: int, options: LockInfo): Promise<LockStatusResponse> {
    return new Promise<LockStatusResponse>((resolve, reject) => {
      let p = taskpool.execute(nativeSetLockState, slotId, options)
      p.then((e: Any) => {
          let r = e as LockStatusResponse
          resolve(r)
      }).catch((e: Error): void => {
          reject(e)
      })
    })
  }

  export native function nativeUnlockPin2(slotId: int, Pin2: string): LockStatusResponse;

  export function unlockPin2(slotId: int, pin2: string, callback: AsyncCallback<LockStatusResponse>): void {
    let p1 = taskpool.execute(nativeUnlockPin2, slotId, pin2)
    p1.then((content: Any) => {
        callback(new BusinessError(), content as LockStatusResponse);
    }, (err: Error): void => {
        callback(err as BusinessError, new LockStatusResponseInner());
    });
  }

  export function unlockPin2(slotId: int, pin2: string): Promise<LockStatusResponse> {
    return new Promise<LockStatusResponse>((resolve, reject) => {
      let p = taskpool.execute(nativeUnlockPin2, slotId, pin2)
      p.then((e: Any) => {
          let r = e as LockStatusResponse
          resolve(r)
      }).catch((e: Error): void => {
          reject(e)
      })
    })
  }

  export native function nativeUnlockPuk2(slotId: int, newPin2: string, puk2: string): LockStatusResponse;

  export function unlockPuk2(slotId: int, newPin2: string, puk2: string, callback: AsyncCallback<LockStatusResponse>): void {
    let p1 = taskpool.execute(nativeUnlockPuk2, slotId, newPin2, puk2)
    p1.then((content: Any) => {
        callback(new BusinessError(), content as LockStatusResponse);
    }, (err: Error): void => {
        callback(err as BusinessError, new LockStatusResponseInner());
    });
  }

  export function unlockPuk2(slotId: int, newPin2: string, puk2: string): Promise<LockStatusResponse> {
    return new Promise<LockStatusResponse>((resolve, reject) => {
      let p = taskpool.execute(nativeUnlockPuk2, slotId, newPin2, puk2)
      p.then((e: Any) => {
          let r = e as LockStatusResponse
          resolve(r)
      }).catch((e: Error): void => {
          reject(e)
      })
    })
  }

  export native function nativeAlterPin2(slotId: int, newPin2: string, oldPin2: string): LockStatusResponse;

  export function alterPin2(slotId: int, newPin2: string, oldPin2: string, callback: AsyncCallback<LockStatusResponse>): void {
    let p1 = taskpool.execute(nativeAlterPin2, slotId, newPin2, oldPin2)
    p1.then((content: Any) => {
        callback(new BusinessError(), content as LockStatusResponse);
    }, (err: Error): void => {
        callback(err as BusinessError, new LockStatusResponseInner());
    });
  }

  export function alterPin2(slotId: int, newPin2: string, oldPin2: string): Promise<LockStatusResponse> {
    return new Promise<LockStatusResponse>((resolve, reject) => {
      let p = taskpool.execute(nativeAlterPin2, slotId, newPin2, oldPin2)
      p.then((e: Any) => {
          let r = e as LockStatusResponse
          resolve(r)
      }).catch((e: Error): void => {
          reject(e)
      })
    })
  }

  export native function nativeQueryIccDiallingNumbers(slotId: int, type: ContactType): Array<DiallingNumbersInfo>;

  export function queryIccDiallingNumbers(slotId: int, type: ContactType, callback: AsyncCallback<Array<DiallingNumbersInfo>>): void {
    let p1 = taskpool.execute(nativeQueryIccDiallingNumbers, slotId, type)
    p1.then((content: Any) => {
        callback(new BusinessError(), content as Array<DiallingNumbersInfo>);
    }, (err: Error): void => {
        callback(err as BusinessError, new Array<DiallingNumbersInfo>());
    });
  }

  export function queryIccDiallingNumbers(slotId: int, type: ContactType): Promise<Array<DiallingNumbersInfo>> {
    return new Promise<Array<DiallingNumbersInfo>>((resolve, reject) => {
      let p = taskpool.execute(nativeQueryIccDiallingNumbers, slotId, type)
      p.then((e: Any) => {
          let r = e as Array<DiallingNumbersInfo>
          resolve(r)
      }).catch((e: Error): void => {
          reject(e)
      })
    })
  }

  export native function nativeAddIccDiallingNumbers(slotId: int, type: ContactType, diallingNumbers: DiallingNumbersInfo): void;

  export function addIccDiallingNumbers(slotId: int, type: ContactType, diallingNumbers: DiallingNumbersInfo, callback: AsyncCallback<void>): void {
    let p1 = taskpool.execute(nativeAddIccDiallingNumbers, slotId, type, diallingNumbers);
    p1.then((content: Any) => {
        callback(new BusinessError(), content as undefined);
    }, (err: Error): void => {
        callback(err as BusinessError, undefined);
    })
  }

  export function addIccDiallingNumbers(slotId: int, type: ContactType, diallingNumbers: DiallingNumbersInfo): Promise<void> {
    return new Promise<void>((resolve, reject) => {
      let p = taskpool.execute(nativeAddIccDiallingNumbers, slotId, type, diallingNumbers)
      p.then((e: Any) => {
          let r = e as undefined
          resolve(r)
      }).catch((e: Error): void => {
          reject(e)
      })
    })
  }

  export native function nativeDelIccDiallingNumbers(slotId: int, type: ContactType, diallingNumbers: DiallingNumbersInfo): void;

  export function delIccDiallingNumbers(slotId: int, type: ContactType, diallingNumbers: DiallingNumbersInfo, callback: AsyncCallback<void>): void {
    let p1 = taskpool.execute(nativeDelIccDiallingNumbers, slotId, type, diallingNumbers);
    p1.then((content: Any) => {
        callback(new BusinessError(), content as undefined);
    }, (err: Error): void => {
        callback(err as BusinessError, undefined);
    })
  }

  export function delIccDiallingNumbers(slotId: int, type: ContactType, diallingNumbers: DiallingNumbersInfo): Promise<void> {
    return new Promise<void>((resolve, reject) => {
      let p = taskpool.execute(nativeDelIccDiallingNumbers, slotId, type, diallingNumbers)
      p.then((e: Any) => {
          let r = e as undefined
          resolve(r)
      }).catch((e: Error): void => {
          reject(e)
      })
    })
  }

  export native function nativeUpdateIccDiallingNumbers(slotId: int, type: ContactType, diallingNumbers: DiallingNumbersInfo): void;

  export function updateIccDiallingNumbers(slotId: int, type: ContactType, diallingNumbers: DiallingNumbersInfo, callback: AsyncCallback<void>): void {
    let p1 = taskpool.execute(nativeUpdateIccDiallingNumbers, slotId, type, diallingNumbers);
    p1.then((content: Any) => {
        callback(new BusinessError(), content as undefined);
    }, (err: Error): void => {
        callback(err as BusinessError, undefined);
    })
  }

  export function updateIccDiallingNumbers(slotId: int, type: ContactType, diallingNumbers: DiallingNumbersInfo): Promise<void> {
    return new Promise<void>((resolve, reject) => {
      let p = taskpool.execute(nativeUpdateIccDiallingNumbers, slotId, type, diallingNumbers)
      p.then((e: Any) => {
          let r = e as undefined
          resolve(r)
      }).catch((e: Error): void => {
          reject(e)
      })
    })
  }

  export native function nativeSendEnvelopeCmd(slotId: int, cmd: string): void;

  export function sendEnvelopeCmd(slotId: int, cmd: string, callback: AsyncCallback<void>): void {
    let p1 = taskpool.execute(nativeSendEnvelopeCmd, slotId, cmd);
    p1.then((content: Any) => {
        callback(new BusinessError(), content as undefined);
    }, (err: Error): void => {
        callback(err as BusinessError, undefined);
    })
  }

  export function sendEnvelopeCmd(slotId: int, cmd: string): Promise<void> {
    return new Promise<void>((resolve, reject) => {
      let p = taskpool.execute(nativeSendEnvelopeCmd, slotId, cmd)
      p.then((e: Any) => {
          let r = e as undefined
          resolve(r)
      }).catch((e: Error): void => {
          reject(e)
      })
    })
  }

  export native function nativeSendTerminalResponseCmd(slotId: int, cmd: string): void;

  export function sendTerminalResponseCmd(slotId: int, cmd: string, callback: AsyncCallback<void>): void {
    let p1 = taskpool.execute(nativeSendTerminalResponseCmd, slotId, cmd);
    p1.then((content: Any) => {
        callback(new BusinessError(), content as undefined);
    }, (err: Error): void => {
        callback(err as BusinessError, undefined);
    });
  }

  export function sendTerminalResponseCmd(slotId: int, cmd: string): Promise<void> {
    return new Promise<void>((resolve, reject) => {
      let p = taskpool.execute(nativeSendTerminalResponseCmd, slotId, cmd)
      p.then((e: Any) => {
          let r = e as undefined
          resolve(r)
      }).catch((e: Error): void => {
        reject(e)
      })
    })
  }

  export native function nativeUnlockSimLock(slotId: int, lockInfo: PersoLockInfo): LockStatusResponse;

  export function unlockSimLock(slotId: int, lockInfo: PersoLockInfo, callback: AsyncCallback<LockStatusResponse>): void {
    let p1 = taskpool.execute(nativeUnlockSimLock, slotId, lockInfo)
    p1.then((content: Any) => {
        callback(new BusinessError(), content as LockStatusResponse);
    }, (err: Error): void => {
        callback(err as BusinessError, new LockStatusResponseInner());
    });
  }

  export function unlockSimLock(slotId: int, lockInfo: PersoLockInfo): Promise<LockStatusResponse> {
    return new Promise<LockStatusResponse>((resolve, reject) => {
      let p = taskpool.execute(nativeUnlockSimLock, slotId, lockInfo)
      p.then((e: Any) => {
          let r = e as LockStatusResponse
          resolve(r)
      }).catch((e: Error): void => {
          reject(e)
      })
    })
  }

  export native function nativeGetOpKey(slotId: int): string;

  export function getOpKey(slotId: int, callback: AsyncCallback<string>): void {
    let p1 = taskpool.execute(nativeGetOpKey, slotId)
    p1.then((content: Any) => {
        callback(new BusinessError(), content as string);
    }, (err: Error): void => {
        callback(err as BusinessError, new string());
    });
  }

  export function getOpKey(slotId: int): Promise<string> {
    return new Promise<string>((resolve, reject) => {
      let p = taskpool.execute(nativeGetOpKey, slotId)
      p.then((e: Any) => {
          let r = e as string
          resolve(r)
      }).catch((e: Error): void => {
          reject(e)
      })
    })
  }

  export function getOpKeySync(slotId: int): string {
    return nativeGetOpKey(slotId);
  }

  export native function nativeGetOpName(slotId: int): string;

  export function getOpName(slotId: int, callback: AsyncCallback<string>): void {
    let p1 = taskpool.execute(nativeGetOpName, slotId)
    p1.then((content: Any) => {
        callback(new BusinessError(), content as string);
    }, (err: Error): void => {
        callback(err as BusinessError, new string());
    });
  }

  export function getOpName(slotId: int): Promise<string> {
    return new Promise<string>((resolve, reject) => {
      let p = taskpool.execute(nativeGetOpName, slotId)
      p.then((e: Any) => {
          let r = e as string
          resolve(r)
      }).catch((e: Error): void => {
          reject(e)
      })
    })
  }

  export function getOpNameSync(slotId: int): string {
    return nativeGetOpName(slotId);
  }

  export native function nativeGetDefaultVoiceSimId(): int;

  export function getDefaultVoiceSimId(callback: AsyncCallback<int>): void {
    let p1 = taskpool.execute(nativeGetDefaultVoiceSimId)
    p1.then((content: Any) => {
        callback(new BusinessError(), content as int);
    }, (err: Error): void => {
        callback(err as BusinessError, 0);
    });
  }

  export function getDefaultVoiceSimId(): Promise<int> {
    return new Promise<int>((resolve, reject) => {
      let p = taskpool.execute(nativeGetDefaultVoiceSimId)
      p.then((e: Any) => {
          let r = e as int
          resolve(r)
      }).catch((e: Error): void => {
          reject(e)
      })
    })
  }

export native function nativeGetDsdsMode(): DsdsMode;

  export function getDsdsMode(callback: AsyncCallback<DsdsMode>): void {
    let p1 = taskpool.execute(nativeGetDsdsMode)
    p1.then((content: Any) => {
        callback(new BusinessError(), content as DsdsMode);
    }, (err: Error): void => {
        callback(err as BusinessError, DsdsMode.DSDS_MODE_V2);
    });
  }

  export function getDsdsMode(): Promise<DsdsMode> {
    return new Promise<DsdsMode>((resolve, reject) => {
      let p = taskpool.execute(nativeGetDsdsMode)
      p.then((e: Any) => {
          let r = e as DsdsMode
          resolve(r)
      }).catch((e: Error): void => {
          reject(e)
      })
    })
  }

  export native function nativeGetSimAuthentication(slotId: int, authType: AuthType, authData: string): SimAuthenticationResponse;

  export function getSimAuthentication(slotId: int, authType: AuthType, authData: string): Promise<SimAuthenticationResponse> {
    return new Promise<SimAuthenticationResponse>((resolve, reject) => {
      let p = taskpool.execute(nativeGetSimAuthentication, slotId, authType, authData)
      p.then((e: Any) => {
          let r = e as SimAuthenticationResponse
          resolve(r)
      }).catch((e: Error): void => {
          reject(e)
      })
    })
  }

export native function nativeGetSimLabel(slotId: int): SimLabel;
 
  export function getSimLabel(slotId: int, callback: AsyncCallback<SimLabel>): void {
    let p1 = taskpool.execute(nativeGetSimLabel, slotId)
    p1.then((content: Any) => {
        callback(new BusinessError(), content as SimLabel);
    }, (err: Error): void => {
        callback(err as BusinessError, new SimLabelInner);
    });
  }
 
  export function getSimLabel(slotId: int): Promise<SimLabel> {
    return new Promise<SimLabel>((resolve, reject) => {
      let p = taskpool.execute(nativeGetSimLabel, slotId)
      p.then((e: Any) => {
          let r = e as SimLabel
          resolve(r)
      }).catch((e: Error): void => {
          reject(e)
      })
    })
  }
 
  export function getSimLabelSync(slotId: int): SimLabel {
    return nativeGetSimLabel(slotId)
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

  export enum PersoLockType {
    PN_PIN_LOCK,

    PN_PUK_LOCK,

    PU_PIN_LOCK,

    PU_PUK_LOCK,

    PP_PIN_LOCK,

    PP_PUK_LOCK,

    PC_PIN_LOCK,

    PC_PUK_LOCK,

    SIM_PIN_LOCK,

    SIM_PUK_LOCK,
  }

export enum SimType {
    PSIM = 0,
 
    ESIM = 1,
  }
 
  export interface SimLabel {
    simType: SimType;
 
    index: int;
  }
 
  export class SimLabelInner implements SimLabel {
    simType: SimType;
 
    index: int;
  }

  export interface PersoLockInfo {
    lockType: PersoLockType;

    password: string;
  }

  export class PersoLockInfoInner implements PersoLockInfo {
    lockType: PersoLockType;

    password: string;
  }

  export enum ContactType {
    GENERAL_CONTACT = 1,

    FIXED_DIALING = 2,
  }

  export interface DiallingNumbersInfo {
    alphaTag: string;

    teleNumber: string;

    recordNumber?: int;

    pin2?: string;
  }

  export class DiallingNumbersInfoInner implements DiallingNumbersInfo {
    alphaTag: string;

    teleNumber: string;

    recordNumber?: int;

    pin2?: string;
  }

export interface LockInfo {
  lockType: LockType;

  password: string;

  state: LockState;
}

export class LockInfoInner implements LockInfo {
  lockType: LockType;

  password: string;

  state: LockState;
}

export enum OperatorSimCard {
  CHINA_TELECOM_CARD = 'china_telecom_card',
}

export enum DsdsMode {
  DSDS_MODE_V2 = 0,

  DSDS_MODE_V3 = 1,

  DSDS_MODE_V5_TDM = 2,

  DSDS_MODE_V5_DSDA = 3,
}

export enum AuthType {
  SIM_AUTH_EAP_SIM_TYPE = 128,

  SIM_AUTH_EAP_AKA_TYPE = 129,
}


export interface SimAuthenticationResponse {
  simStatusWord1: int;

  simStatusWord2: int;

  response: string;
}

export class SimAuthenticationResponseInner implements SimAuthenticationResponse {
  simStatusWord1: int;

  simStatusWord2: int;

  response: string;
}
}
