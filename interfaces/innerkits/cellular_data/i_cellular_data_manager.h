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
    enum class FuncCode {
        IS_CELLULAR_DATA_ENABLED = 0,
        ENABLE_CELLULAR_DATA,
        GET_CELLULAR_DATA_STATE,
        IS_DATA_ROAMING_ENABLED,
        ENABLE_DATA_ROAMING,
        ADD_CELLULAR_DATA_OBSERVER,
        REMOVE_CELLULAR_DATA_OBSERVER,
        REQUEST_CELLULAR_DATA,
        RELEASE_CELLULAR_DATA,
        STRATEGY_SWITCH,
        GET_DEFAULT_SLOT_ID,
        SET_DEFAULT_SLOT_ID,
        GET_FLOW_TYPE_ID,
        APN_DATA_CHANGED
    };

    /**
     * Whether the cellular data user switch is enabled
     *
     * @return return 84082688 invalid parameter, 1 enabled, 0 not enable
     */
    virtual int32_t IsCellularDataEnabled() = 0;

    /**
     * Whether to enable cellular data user switch
     *
     * @param enable allow or not
     * @return return 84082688 invalid parameter, 1 data enable success, 0 enable fail
     */
    virtual int32_t EnableCellularData(bool enable) = 0;

    /**
     * Cellular data connection status
     *
     * @return 84082688 Indicates that a cellular data link is unknown
     *         11 Indicates that a cellular data link is disconnected
     *         12 Indicates that a cellular data link is being connected
     *         13 Indicates that a cellular data link is connected
     *         14 Indicates that a cellular data link is suspended
     */
    virtual int32_t GetCellularDataState() = 0;

    /**
     * Whether roaming is allowed
     *
     * @param slotId card slot identification
     * @return return 84082688 invalid parameter, 0 roaming is not allowed, 1 roaming is allowed
     */
    virtual int32_t IsCellularDataRoamingEnabled(int32_t slotId) = 0;

    /**
     * Whether roaming switches are allowed
     *
     * @param slotId card slot identification
     * @param enable Whether roaming switches are allowed
     * @return Returns 0 on failure, 1 on failure. 84082688 invalid parameter
     */
    virtual int32_t EnableCellularDataRoaming(int32_t slotId, bool enable) = 0;

    /**
     * Release the connections for the specified network capability
     *
     * @param ident unique identifier
     * @param capability a network capability
     * @return 1 request success, 0 request fail, 84082688 invalid parameter
     */
    virtual int32_t ReleaseNet(std::string ident, uint64_t capability) = 0;

    /**
     * Request a connection that specifies the network capability
     *
     * @param ident unique identifier
     * @param capability a network capability
     * @return 1 release success, 0 release fail, 84082688 invalid parameter
     */
    virtual int32_t RequestNet(std::string ident, uint64_t capability) = 0;

    /**
     * Processing of APN content changes
     *
     * @param slotId card slot identification
     * @param apns changed apns
     * @return the number of apns created else 84082688 invalid parameter
     */
    virtual int32_t HandleApnChanged(int32_t slotId, std::string apns) = 0;

    /**
     * Get the slotId that uses the data traffic by default
     *
     * @return default settings data card, -1 error code
     */
    virtual int32_t GetDefaultCellularDataSlotId() = 0;

    /**
     * set the slotId that uses the data traffic by default
     *
     * @return 1 set success, 0 set fail, 84082688 invalid parameter
     */
    virtual int32_t SetDefaultCellularDataSlotId(int32_t slotId) = 0;

    /**
     * get data packet type
     *
     * @return 0 Indicates that there is no uplink or down link data,
     *         1 Indicates that there is only down link data,
     *         2 Indicates that there is only uplink data,
     *         3 Indicates that there is uplink and down link data
     *         4 Indicates that there is no uplink or down link data,
     *           and the bottom-layer link is in the dormant state
     *         84082688 Indicates invalid parameter
     */
    virtual int32_t GetCellularDataFlowType() = 0;

    /**
     * set the status of the data policy switch
     *
     * @param enable data policy switch status
     * @return if true set success else false
     */
    virtual int32_t StrategySwitch(bool enable) = 0;

public:
    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.telephony.ICellularDataManager");
};
} // namespace Telephony
} // namespace OHOS
#endif // I_CELLULAR_DATA_MANAGER_H
