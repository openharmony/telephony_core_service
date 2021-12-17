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

#ifndef CELLULAR_DATA_CLIENT_H
#define CELLULAR_DATA_CLIENT_H

#include <cstdint>
#include <iremote_object.h>
#include <singleton.h>

#include "i_cellular_data_manager.h"

namespace OHOS {
namespace Telephony {
class CellularDataClient : public DelayedRefSingleton<CellularDataClient> {
    DECLARE_DELAYED_REF_SINGLETON(CellularDataClient);

public:
    bool IsConnect() const;
    int32_t EnableCellularData(bool enable);
    int32_t IsCellularDataEnabled();
    int32_t GetCellularDataState();
    int32_t IsCellularDataRoamingEnabled(int32_t slotId);
    int32_t EnableCellularDataRoaming(int32_t slotId, bool enable);
    int32_t RequestNet(std::string ident, uint64_t capability);
    int32_t ReleaseNet(std::string ident, uint64_t capability);
    int32_t GetDefaultCellularDataSlotId();
    int32_t SetDefaultCellularDataSlotId(int32_t slotId);
    int32_t GetCellularDataFlowType();
    int32_t StrategySwitch(bool enable);
    sptr<ICellularDataManager> GetProxy();

private:
    class CellularDataDeathRecipient : public IRemoteObject::DeathRecipient {
    public:
        explicit CellularDataDeathRecipient(CellularDataClient &client) : client_(client) {}
        ~CellularDataDeathRecipient() override = default;
        void OnRemoteDied(const wptr<IRemoteObject> &remote) override
        {
            client_.OnRemoteDied(remote);
        }

    private:
        CellularDataClient &client_;
    };

    void OnRemoteDied(const wptr<IRemoteObject> &remote);

private:
    std::mutex mutexProxy_;
    sptr<ICellularDataManager> proxy_ {nullptr};
    sptr<IRemoteObject::DeathRecipient> deathRecipient_ {nullptr};
};
} // namespace Telephony
} // namespace OHOS
#endif // CELLULAR_DATA_CLIENT_H