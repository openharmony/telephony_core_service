/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#ifndef NETWORK_SEARCH_CALLBACK_BASE_H
#define NETWORK_SEARCH_CALLBACK_BASE_H

#include <string>

#include "refbase.h"

namespace OHOS {
namespace Telephony {
class NetworkSearchCallBackBase : public virtual RefBase {
public:
    virtual ~NetworkSearchCallBackBase() = default;

    virtual bool HasInternetCapability(int32_t slotId, int32_t cId)
    {
        return false;
    }
    virtual void ClearCellularDataConnections(int32_t slotId) {}
    virtual void ClearCellularCallList(int32_t slotId) {}
    virtual void SetReadyToCall(int32_t slotId, bool isReadyToCall) {}
};
} // namespace Telephony
} // namespace OHOS
#endif // NET_SUPPLIER_CALLBACK_BASE_H