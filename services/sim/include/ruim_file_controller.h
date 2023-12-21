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

#ifndef OHOS_RUIM_FILE_CONTROLLER_H
#define OHOS_RUIM_FILE_CONTROLLER_H

#include "icc_file_controller.h"

namespace OHOS {
namespace Telephony {
class RuimFileController : public IccFileController {
public:
    explicit RuimFileController(int slotId);
    ~RuimFileController();
    std::string ObtainElementFilePath(int efId);
    void ObtainTransparentImg(
        int fileId, int highOffset, int lowOffset, int length, AppExecFwk::InnerEvent::Pointer &onLoaded);

private:
    const std::string DEDICATED_FILE_CDMA = "7F25";
};
} // namespace Telephony
} // namespace OHOS

#endif // OHOS_RUIM_FILE_CONTROLLER_H