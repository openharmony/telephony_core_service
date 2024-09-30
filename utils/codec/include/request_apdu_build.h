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

#ifndef REQUEST_APDU_BUILD_H
#define REQUEST_APDU_BUILD_H

#include <list>
#include <mutex>
#include "apdu_command.h"

namespace OHOS {
namespace Telephony {
class RequestApduBuild {
public:
    explicit RequestApduBuild(int32_t channelId): channelId_(channelId) {}
    void BuildStoreData(const std::string &cmdHex);
    std::list<std::unique_ptr<ApduCommand>> GetCommands();

private:
    void AddApdu(const ApduData &apduData);
    void ConstructApduData(uint32_t packetTag, uint32_t packetIndex, uint32_t packetLen,
        const std::string &cmdHex, ApduData &apduData);
    int32_t channelId_ = 0;
    std::list<std::unique_ptr<ApduCommand>> apduCommandLst_;
    std::mutex mutex_;
};
} // namespace Telephony
} // namespace OHOS
#endif