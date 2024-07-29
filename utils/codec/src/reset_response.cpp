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

#include "reset_response.h"
#include "asn1_constants.h"
#include "asn1_node.h"
#include "asn1_utils.h"
#include "telephony_log_wrapper.h"

namespace OHOS {
namespace Telephony {
namespace {
const int32_t BIT2_MASK = 0x02;
const int32_t BIT5_MASK = 0x10;
const int32_t BIT7_MASK = 0x40;
const int32_t HIGH_BITS_MASK = 0xF0;
const int32_t LOW_BITS_MASK = 0x0F;
const uint32_t MIN_ATR_DATA_LENGTH = 4;
const int32_t MAX_INTERFACE_VALUE = 0x0F;
const uint8_t REVERSED_AGREEMENT = 0x3B;
const uint8_t POSITIVE_AGREEMENT = 0x3F;
}

bool ResetResponse::IsEuiccAvailable()
{
    return isEuiccAvailable_;
}

bool ResetResponse::CheckIsEuiccAvailable(uint8_t charB, uint8_t charD)
{
    if (charB != '\0' && charD != '\0' && CheckOperationRes(charD, LOW_BITS_MASK, MAX_INTERFACE_VALUE)) {
        if ((!CheckOperationRes(charB, BIT8_MASK, 0)) && (!CheckOperationRes(charB, BIT2_MASK, 0))) {
            isEuiccAvailable_ = true;
            return true;
        }
    }
    return false;
}

bool ResetResponse::CheckOperationRes(uint8_t chr, const int32_t tMask, const int32_t comparedVal)
{
    if ((chr & tMask) != comparedVal) {
        return false;
    }
    return true;
}

bool ResetResponse::AnalysisInterfaceData(const std::vector<uint8_t> &atrData, uint32_t atrDataLen, uint32_t &index)
{
    uint8_t lastByteD = formatByte_;
    bool isContinue = CheckOperationRes(lastByteD, HIGH_BITS_MASK, 0);
    uint8_t charB = '\0';
    uint8_t charD = '\0';
    while (!isContinue) {
        if (!CheckOperationRes(lastByteD, BIT5_MASK, 0)) {
            if (index >= atrDataLen) {
                return false;
            }
            index++;
        }
        if (!CheckOperationRes(lastByteD, BIT6_MASK, 0)) {
            if (index >= atrDataLen) {
                return false;
            }
            charB = atrData[index];
            index++;
            if (charD != '\0' && (CheckIsEuiccAvailable(charB, charD))) {
                return true;
            }
        }
        if (!CheckOperationRes(lastByteD, BIT7_MASK, 0)) {
            if (index >= atrDataLen) {
                return false;
            }
            index++;
        }
        if (!CheckOperationRes(lastByteD, BIT8_MASK, 0)) {
            if (index >= atrDataLen) {
                return false;
            }
            charD = atrData[index];
            index++;
        }
        if (charD == '\0') {
            break;
        }
        lastByteD = charD;
        isContinue = CheckOperationRes(lastByteD, HIGH_BITS_MASK, 0);
    }
    return true;
}

bool ResetResponse::CheckAtrDataParam(const std::string &atr)
{
    if (atr.empty() || atr.length() % BYTE_TO_HEX_LEN != 0) {
        TELEPHONY_LOGE("ATR length %zu is not even.", atr.length());
        return false;
    }

    if (atr.length() < MIN_ATR_DATA_LENGTH) {
        TELEPHONY_LOGE("ATR is Valid, it must at least contains TS and T0.");
        return false;
    }
    return true;
}

bool ResetResponse::AnalysisAtrData(const std::string &atr)
{
    TELEPHONY_LOGD("AnalysisAtrData ATR string enter.");
    if (!CheckAtrDataParam(atr)) {
        TELEPHONY_LOGE("failed to check AtrData param!");
        return false;
    }
    std::vector<uint8_t> atrData = Asn1Utils::HexStrToBytes(atr);
    uint32_t atrDataLen = atrData.size();
    if (atrDataLen == 0) {
        TELEPHONY_LOGE("failed to transform HexStr To Bytes.");
        return false;
    }
    // convention byte
    uint32_t index = 0;
    if (atrData[index] != POSITIVE_AGREEMENT && atrData[index] != REVERSED_AGREEMENT) {
        TELEPHONY_LOGE("convention byte is valid!");
        return false;
    }
    index++;
    if (index >= atrDataLen) {
        return false;
    }
    // format byte
    formatByte_ = atrData[index];
    index++;
    if (index >= atrDataLen) {
        return false;
    }
    return AnalysisInterfaceData(atrData, atrDataLen, index);
}
} // namespace Telephony
} // namespace OHOS