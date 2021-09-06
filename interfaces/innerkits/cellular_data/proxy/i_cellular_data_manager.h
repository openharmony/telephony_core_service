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

#ifndef I_CELLULAR_DATA_MANAGER_H
#define I_CELLULAR_DATA_MANAGER_H

#include "iremote_broker.h"

namespace OHOS {
namespace Telephony {
class ICellularDataManager : public IRemoteBroker {
public:
    enum {
        IS_CELLULAR_DATA_ENABLED = 0,
        ENABLE_CELLULAR_DATA,
        GET_CELLULAR_DATA_STATE,
        IS_DATA_ROAMING_ENABLED,
        ENABLE_DATA_ROAMING,
        ADD_CELLULAR_DATA_OBSERVER,
        REMOVE_CELLULAR_DATA_OBSERVER,
        REQUEST_CELLULAR_DATA,
        RELEASE_CELLULAR_DATA,
    };

    virtual int32_t IsCellularDataEnabled(int32_t slotId) = 0;

    virtual int32_t EnableCellularData(int32_t slotId, bool enable) = 0;

    virtual int32_t GetCellularDataState(int32_t slotId) = 0;

    virtual int32_t IsDataRoamingEnabled(int32_t slotId) = 0;

    virtual int32_t EnableDataRoaming(int32_t slotId, bool enable) = 0;

    virtual int32_t ReleaseNet(std::string ident, uint32_t capability) = 0;

    virtual int32_t RequestNet(std::string ident, uint32_t capability) = 0;

public:
    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.telephony.ICellularDataManager");
};
} // namespace Telephony
} // namespace OHOS
#endif // I_CELLULAR_DATA_MANAGER_H
