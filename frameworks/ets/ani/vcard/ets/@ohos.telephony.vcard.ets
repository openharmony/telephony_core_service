/*
 * Copyright (C) 2026-2026 Huawei Device Co., Ltd.
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
import BaseContext from 'application.BaseContext';
import dataSharePredicates from '@ohos.data.dataSharePredicates';

export default namespace vcard {
  loadLibrary("vcard_ani")

  export native function nativeImportVCard(context: BaseContext, filePath: string, accountId?: int): void;

  export function importVCard(context: BaseContext, filePath: string, accountId: int, callback: AsyncCallback<void>): void {
    let p1 = taskpool.execute(nativeImportVCard, context, filePath, accountId)
    p1.then((content: Any) => {
        callback(null, content as undefined)
    }, (err: Error): void => {
        callback(err as BusinessError, undefined)
    });
  }
    
  export function importVCard(context: BaseContext, filePath: string, accountId?: int): Promise<void> {
    return new Promise<void>((resolve, reject) => {
      let p = taskpool.execute(nativeImportVCard, context, filePath, accountId)
      p.then((e: Any) => {
          let r = e as undefined
          resolve(r)
      }).catch((e: Error): void => {
          reject(e)
      })
    })
  }

  export function importVCard(context: BaseContext, filePath: string, callback: AsyncCallback<void>): void {
    let p1 = taskpool.execute(nativeImportVCard, context, filePath)
    p1.then((content: Any) => {
        callback(null, content as undefined)
    }, (err: Error): void => {
        callback(err as BusinessError, undefined)
    });
  }

  export native function nativeExportVCard(context: BaseContext, predicates: dataSharePredicates.DataSharePredicates,
    options?: VCardBuilderOptions): string;

  export function exportVCard(context: BaseContext, predicates: dataSharePredicates.DataSharePredicates,
    options: VCardBuilderOptions, callback: AsyncCallback<string>): void {
    let p1 = taskpool.execute(nativeExportVCard, context, predicates, options)
    p1.then((content: Any) => {
        callback(null, content as string);
    }, (err: Error): void => {
        callback(err as BusinessError, undefined);
    })
  }

  export function exportVCard(context: BaseContext, predicates: dataSharePredicates.DataSharePredicates,
    options?: VCardBuilderOptions): Promise<string> {
    return new Promise<string>((resolve, reject) => {
      let p = taskpool.execute(nativeExportVCard, context, predicates, options)
      p.then((e: Any) => {
          resolve(e as string)
      }).catch((e: Error): void => {
          reject(e as Error)
      })
    })
  }

  export function exportVCard(context: BaseContext, predicates: dataSharePredicates.DataSharePredicates,
    callback: AsyncCallback<string>): void {
    let p1 = taskpool.execute(nativeExportVCard, context, predicates)
    p1.then((content: Any) => {
        callback(null, content as string);
    }, (err: Error): void => {
        callback(err as BusinessError, undefined);
    })
  }

  export enum VCardType {
    VERSION_21 = 0,
	  VERSION_30 = 1,
	  VERSION_40 = 2,
  }
  
  export interface VCardBuilderOptions {
    cardType?: VCardType;
	  charset?: string;
  }

  export class VCardBuilderOptionsInner implements VCardBuilderOptions {
    cardType?: VCardType;
	  charset?: string;
  }
}