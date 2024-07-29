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

#ifndef RESET_RESPONSE_H
#define RESET_RESPONSE_H

#include <cstdint>
#include <string>

namespace OHOS {
namespace Telephony {
class ResetResponse {
public:
    bool AnalysisAtrData(const std::string &atr);
    bool IsEuiccAvailable();

private:
    bool CheckOperationRes(uint8_t chr, const int32_t tMask, const int32_t comparedVal);
    bool AnalysisInterfaceData(const std::vector<uint8_t> &atrData, uint32_t atrDataLen, uint32_t &index);
    bool CheckIsEuiccAvailable(uint8_t charB, uint8_t charD);
    bool CheckAtrDataParam(const std::string &atr);
    bool isEuiccAvailable_ = false;
    uint8_t formatByte_ = 0;
};
} // namespace Telephony
} // namespace OHOS
#endif // RESET_RESPONSE_H