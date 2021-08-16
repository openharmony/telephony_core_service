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
#ifndef OHOS_USIM_FILE_CONTROLLER_H
#define OHOS_USIM_FILE_CONTROLLER_H

#include <stdlib.h>
#include <cstring>
#include <string>
#include "sim_constant.h"
#include "icc_file_controller.h"

namespace OHOS {
namespace Telephony {
class UsimFileController : public IccFileController {
public:
    UsimFileController(const std::shared_ptr<AppExecFwk::EventRunner> &runner);
    ~UsimFileController();
    std::string ObtainElementFilePath(int efId);

private:
    std::string ObtainUsimElementFilePath(int efId);
};
} // namespace Telephony
} // namespace OHOS

#endif // OHOS_USIM_FILE_CONTROLLER_H