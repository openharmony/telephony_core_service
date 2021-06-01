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
#include "phone.h"
#include <string>
#include <vector>
#include "network_search_manager.h"
#include "tel_ril_manager.h"
#include "sim_file_manager.h"
#include "sim_state_manager.h"

using namespace OHOS::SIM;

namespace OHOS {
Phone::Phone(int opt) : networkSearchManager_(nullptr), rilManager_(nullptr), phoneID_(opt) {}
void Phone::OnInit()
{
    TELEPHONY_INFO_LOG("Phone OnInit");
    rilManager_ = new RilManager();
    if (rilManager_ != nullptr) {
        rilManager_->TelRilSetParam(0, 1, phoneID_);
        rilManager_->OnInit();
    }
    simStateManager_ = std::make_shared<SimStateManager>();
    if (simStateManager_ != nullptr) {
        simStateManager_->Init();
    }
    simFileManager_ = std::make_shared<SimFileManager>(simStateManager_);
    if (simFileManager_ != nullptr) {
        simFileManager_->Init();
    }
    networkSearchManager_ = std::make_shared<NetworkSearchManager>();
    if (networkSearchManager_ != nullptr) {
        networkSearchManager_->Init();
    }
}
} // namespace OHOS