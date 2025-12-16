/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#ifndef TELEPHONY_ESIM_CONTROLLER_H
#define TELEPHONY_ESIM_CONTROLLER_H

#include <singleton.h>
#include <string.h>
#include <atomic>
#include "ffrt.h"
#include "sim_rdb_helper.h"
#include "telephony_types.h"

namespace OHOS {
namespace Telephony {

typedef bool (*VerifyBind)(int slotId, const char* command, size_t commandLen);

class EsimController : public DelayedRefSingleton<EsimController> {
    DECLARE_DELAYED_REF_SINGLETON(EsimController);

public:
    bool ChecIsVerifyBindCommand(const std::string &cmdData);
    void ProcessCommandMessage(int slotId, const std::string &cmdData);
    void ProcessCommandByCa(int slotId, const std::string &cmdData);
    void SetVerifyResult(int slotId, bool isVerifySuccess);
    bool GetVerifyResult(int slotId);
private:
    ffrt::mutex caMutex_;
    ffrt::mutex setVerifyResultMutex_;
    std::unique_ptr<SimRdbHelper> simDbHelper_ = nullptr;
    std::atomic<bool> isVerifySuccess_[MAX_SLOT_COUNT] = {}; // use default value - false
};
} // namespace Telephony
} // namespace OHOS
#endif // TELEPHONY_ESIM_CONTROLLER_H
