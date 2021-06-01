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

#ifndef IMPL_PHONE_H
#define IMPL_PHONE_H

#include "i_tel_ril_manager.h"

#include <unistd.h>
#include <mutex>
#include <string>
#include <thread>
#include "i_network_search.h"
#include "i_sim_file_manager.h"
#include "i_sim_state_manager.h"
#include "observer_handler.h"

namespace OHOS {
const int NUM_CIRCLES = 4;

class Phone {
public:
    Phone(int opt);

    ~Phone() = default;

    void OnInit();

public:
    std::shared_ptr<INetworkSearch> networkSearchManager_ = nullptr;
    IRilManager *rilManager_ = nullptr;
    std::shared_ptr<SIM::ISimFileManager> simFileManager_ = nullptr;
    std::shared_ptr<SIM::ISimStateManager> simStateManager_ = nullptr;
    int phoneID_;
};
} // namespace OHOS
#endif
