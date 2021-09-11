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

#ifndef OHOS_SIM_DATA_TYPE_H
#define OHOS_SIM_DATA_TYPE_H

#include <iostream>
#include <string>
#include <vector>
#include "event_handler.h"
#include "event_runner.h"
#include "sim_constant.h"

#define Ef_RESULT_NUM 3

namespace OHOS {
namespace Telephony {
struct IccControllerHolder {
    int fileId = 0;
    int fileNum = 0;
    int fileSize = 0;
    int countFiles = 0;
    bool getAllFile = false;
    std::string filePath = "";
    AppExecFwk::InnerEvent::Pointer fileLoaded = AppExecFwk::InnerEvent::Pointer(nullptr, nullptr);
    std::vector<std::string> fileResults;
    IccControllerHolder(int efId, int recordNum) : fileId(efId), fileNum(recordNum), getAllFile(false) {}
    IccControllerHolder(int efId, int recordNum, std::string path)
        : fileId(efId), fileNum(recordNum), getAllFile(false), filePath(path)
    {}
    IccControllerHolder(int efId, std::string path) : fileId(efId), fileNum(1), getAllFile(true), filePath(path) {}
    IccControllerHolder(int efId) : fileId(efId), fileNum(1), getAllFile(true) {}
};

struct IccFileData {
    int32_t sw1 = 0;
    int32_t sw2 = 0;
    std::string resultData = "";
    std::shared_ptr<void> exception = nullptr;
};

struct FileToControllerMsg {
    int arg1 = INVALID_VALUE;
    int arg2 = INVALID_VALUE;
    std::shared_ptr<void> iccLoader = nullptr;
};

struct ControllerToFileMsg : public FileToControllerMsg, IccFileData {
    ControllerToFileMsg(const FileToControllerMsg *cmd, const IccFileData *fd)
    {
        if (cmd != nullptr) {
            arg1 = cmd->arg1;
            arg2 = cmd->arg2;
            iccLoader = cmd->iccLoader;
        }
        if (fd != nullptr) {
            sw1 = fd->sw1;
            sw2 = fd->sw2;
            resultData = fd->resultData;
            exception = fd->exception;
        }
    }
};

struct IccToRilMsg {
    IccToRilMsg(std::shared_ptr<IccControllerHolder> holder) : controlHolder(holder) {}
    std::shared_ptr<IccControllerHolder> controlHolder;
    int arg1 = INVALID_VALUE;
    int arg2 = INVALID_VALUE;
};

struct IccFromRilMsg : public IccToRilMsg {
    IccFromRilMsg(std::shared_ptr<IccControllerHolder> &holder) : IccToRilMsg(holder) {}
    IccFileData fileData;
};

struct EfLinearResult {
    int valueData[Ef_RESULT_NUM] = {0};
};

struct MultiRecordResult {
    std::vector<std::string> fileResults;
    int resultLength = 0;
    std::shared_ptr<void> exception = nullptr;
};

struct PbLoadHolder {
    int fileID = 0;
    int index = 0;
    std::shared_ptr<void> adn = nullptr;
};

using EventPointer = AppExecFwk::InnerEvent::Pointer;
} // namespace Telephony
} // namespace OHOS
#endif // OHOS_SIM_DATA_TYPE_H
