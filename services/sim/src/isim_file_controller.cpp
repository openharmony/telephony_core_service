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

#include "isim_file_controller.h"

namespace OHOS {
namespace Telephony {
IsimFileController::IsimFileController(int slotId) : IccFileController("IsimFileController", slotId) {}

std::string IsimFileController::ObtainElementFilePath(int efId)
{
    if (efId == ELEMENTARY_FILE_IMPI || efId == ELEMENTARY_FILE_IMPU || efId == ELEMENTARY_FILE_DOMAIN ||
        efId == ELEMENTARY_FILE_IST || efId == ELEMENTARY_FILE_PCSCF) {
        return std::string(MASTER_FILE_SIM) + std::string(DEDICATED_FILE_ADF);
    }
    std::string path = ObtainElementFileForPublic(efId);
    if (path.empty()) {
        TELEPHONY_LOGE("Error: IsimFileController ElementFile Path get null string");
    }
    return path;
}

IsimFileController::~IsimFileController() {}
} // namespace Telephony
} // namespace OHOS
