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

#include "request_apdu_build.h"
#include "asn1_constants.h"
#include "asn1_utils.h"

namespace OHOS {
namespace Telephony {
namespace {
const uint32_t CLA_STORE_DATA = 0x80;
const uint32_t INS_STORE_DATA = 0xE2;
const uint32_t P1_STORE_DATA_INTERM = 0x11;
const uint32_t P1_STORE_DATA_END = 0x91;
}

std::list<std::unique_ptr<ApduCommand>> RequestApduBuild::GetCommands()
{
    std::lock_guard<std::mutex> lock(mutex_);
    std::list<std::unique_ptr<ApduCommand>> apduCommandTempLst(std::move(apduCommandLst_));
    apduCommandLst_.clear();
    return apduCommandTempLst;
}

void RequestApduBuild::AddApdu(const ApduData &apduData)
{
    std::unique_ptr<ApduCommand> apduCommand = std::make_unique<ApduCommand>(channelId_, apduData);
    apduCommandLst_.push_back(std::move(apduCommand));
}

void RequestApduBuild::ConstructApduData(uint32_t packetTag, uint32_t packetIndex, uint32_t packetLen,
    const std::string &cmdHex, ApduData &apduData)
{
    apduData.cla = CLA_STORE_DATA;
    apduData.ins = INS_STORE_DATA;
    apduData.p1 = packetTag;
    apduData.p2 = packetIndex;
    apduData.p3 = packetLen;
    apduData.cmdHex = cmdHex;
}

void RequestApduBuild::BuildStoreData(const std::string &cmdHex)
{
    int32_t cmdLen = MAX_UINT8 * BYTE_TO_HEX_LEN;
    int32_t startPos = 0;
    uint32_t totalLen = static_cast<uint32_t>(cmdHex.length() / BYTE_TO_HEX_LEN);
    uint32_t totalSubCmds = ((totalLen == 0) ? 1 : ((totalLen + MAX_UINT8 - 1) / MAX_UINT8));
    uint32_t leastLen = totalLen;
    /* When handling packet fragmentation, if the last packet of data is less than 255 bytes,
    it requires special handling outside the loop.
    */
    std::lock_guard<std::mutex> lock(mutex_);
    for (uint32_t i = 1; i < totalSubCmds; ++i) {
        std::string data = cmdHex.substr(startPos, cmdLen);
        ApduData apduData;
        ConstructApduData(P1_STORE_DATA_INTERM, i - 1, MAX_UINT8, data, apduData);
        AddApdu(apduData);
        startPos += cmdLen;
        leastLen -= MAX_UINT8;
    }
    std::string lastData = cmdHex.substr(startPos);
    ApduData lastApduData;
    ConstructApduData(P1_STORE_DATA_END, totalSubCmds - 1, leastLen, lastData, lastApduData);
    AddApdu(lastApduData);
}
} // namespace Telephony
} // namespace OHOS