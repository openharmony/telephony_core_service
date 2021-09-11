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

#ifndef CELLULAR_DATA_SERVICE_PROXY_H
#define CELLULAR_DATA_SERVICE_PROXY_H

#include "i_cellular_data_manager.h"
#include "iremote_proxy.h"

namespace OHOS {
namespace Telephony {
class CellularDataServiceProxy : public IRemoteProxy<ICellularDataManager> {
public:
    explicit CellularDataServiceProxy(const sptr<IRemoteObject> &impl) : IRemoteProxy<ICellularDataManager>(impl)
    {}

    ~CellularDataServiceProxy() = default;

    /**
     * Whether the cellular data user switch is enabled
     * @param slotId
     * @return return true User data switch on, false User data switch off.
     */
    virtual int32_t IsCellularDataEnabled(int32_t slotId);

    /**
     * Whether to enable cellular data user switch
     * @param slotId
     * @param enable allow or not
     * @return Returns 0 on failure, other on failure.
     */
    int32_t EnableCellularData(int32_t slotId, bool enable);

    /**
     * Cellular data connection status
     * @param slotId
     * @return
     *   DATA_STATE_DISCONNECTED = 11
     *   DATA_STATE_CONNECTING = 12
     *   DATA_STATE_CONNECTED = 13
     *   DATA_STATE_SUSPENDED = 14
     */
    int32_t GetCellularDataState(int32_t slotId);

    /**
     * Whether roaming is allowed
     * @param slotId
     * @return return true Allowed to roam, false not Allowed to roam.
     */
    int32_t IsDataRoamingEnabled(int32_t slotId);

    /**
     * Whether roaming switches are allowed
     * @param slotId
     * @param enable Whether roaming switches are allowed
     * @return Returns 0 on failure, other on failure.
     */
    int32_t EnableDataRoaming(int32_t slotId, bool enable);

    int32_t ReleaseNet(std::string ident, uint32_t capability);

    int32_t RequestNet(std::string ident, uint32_t capability);

private:
    static inline BrokerDelegator<CellularDataServiceProxy> delegator_;
};
} // namespace Telephony
} // namespace OHOS
#endif // CELLULAR_DATA_SERVICE_PROXY_H
