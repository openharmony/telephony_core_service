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
#ifndef OHOS_SIM_FILE_CONTROLLER_H
#define OHOS_SIM_FILE_CONTROLLER_H

#include <stdlib.h>
#include <cstring>
#include <string>
#include "sim_constant.h"
#include "icc_file_controller.h"

namespace OHOS {
namespace SIM {
class SimFileController : public IccFileController {
public:
    SimFileController(const std::shared_ptr<AppExecFwk::EventRunner> &runner);
    ~SimFileController();
    std::string ObtainElementFilePath(int efId);
};
} // namespace SIM
} // namespace OHOS
#endif // OHOS_SIM_FILE_CONTROLLER_H