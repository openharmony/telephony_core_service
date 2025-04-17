/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

export class BusinessError extends Error {
    constructor(code: int, message : string){
        super(message)
        this.code = code;
    }
    code: int;
}

type AsyncCallback = (err: BusinessError) => void;

let errMap: Map<int, string> = new Map<int, string>();
errMap.set(401, 'Parameter error. Possible causes: 1. Mandatory parameters are left unspecified. 2. Incorrect parameter types.');
errMap.set(8300001, 'Invalid parameter value.');
errMap.set(8300002, 'Operation failed. Cannot connect to service.');
errMap.set(8300003, 'System internal error.');
errMap.set(8300999, 'Unknown error code.');

export namespace SimAbility {
    loadLibrary("SIMABILITYNativeModule");

    export native function getDefaultVoiceSlotIdExecute(): int;
    export native function getISOCountryCodeForSimExecute(slotId: number): int;

    export function getDefaultVoiceSlotId(callback:AsyncCallback): void {
        console.info("getDefaultVoiceSlotId callback call.");
        let task = taskpool.execute(SimAbility.getDefaultVoiceSlotIdExecute);
        task.then((code: NullishType) => {
            let codeInt = code as int;
            let message = errMap.get(code as int) ?? 'Unknown error occurred.';
            let err: BusinessError = new BusinessError(codeInt, message);
            callback(err);
        });
    }

    export function getDefaultVoiceSlotId(): Promise<void> {
        console.info("getDefaultVoiceSlotId Promise call.");
        return new Promise<void>((resolve, reject) => {
            let p1 = taskpool.execute(SimAbility.getDefaultVoiceSlotIdExecute);
            p1.then((code: NullishType) => {
                let codeInt = code as int;
                let message = errMap.get(code as int) ?? 'Unknown error occurred.';
                let err: BusinessError = new BusinessError(codeInt, message);
                if (err.code !== 0) {
                    reject(err);
                } else {
                    resolve(undefined);
                }
            });
        });
    }

    export function getISOCountryCodeForSim(slotId: number, callback:AsyncCallback): void {
        console.info("getISOCountryCodeForSim callback call.");
        let task = taskpool.execute(SimAbility.getISOCountryCodeForSimExecute, slotId);
        task.then((code: NullishType) => {
            let codeInt = code as int;
            let message = errMap.get(code as int) ?? 'Unknown error occurred.';
            let err: BusinessError = new BusinessError(codeInt, message);
            callback(err);
        });
    }

    export function getISOCountryCodeForSim(slotId: number): Promise<void> {
        console.info("getISOCountryCodeForSim Promise call.");
        return new Promise<void>((resolve, reject) => {
            let p1 = taskpool.execute(SimAbility.getISOCountryCodeForSimExecute, slotId);
            p1.then((code: NullishType) => {
                let codeInt = code as int;
                let message = errMap.get(code as int) ?? 'Unknown error occurred.';
                let err: BusinessError = new BusinessError(codeInt, message);
                if (err.code !== 0) {
                    reject(err);
                } else {
                    resolve(undefined);
                }
            });
        });
    }
}