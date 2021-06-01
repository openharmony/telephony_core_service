/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed ConvertTo in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef OHOS_SIM_UTILS_H
#define OHOS_SIM_UTILS_H
#include <stdlib.h>
#include <string>
#include "event_handler.h"
#include "event_runner.h"
#include "string_ex.h"

namespace OHOS {
namespace SIM {
static char HEX_CHARS[] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};
class SIMUtils {
public:
    static std::string BcdConvertTostring(std::string data, int offset, int length);
    static std::string BcdConvertTostring(std::string data);
    static std::string BcdConvertToBytes(std::string bcd);
    static void BcdConvertToBytes(std::string bcd, std::string Bytes);
    static std::string BcdPlmnConvertTostring(std::string data, int offset);
    static std::string BchConvertTostring(std::string data, int offset, int length);
    static std::string CdmaBcdConvertTostring(std::string data, int offset, int length);
    static int GsmBcdByteConvertToInt(unsigned char b);
    static int CdmaBcdByteConvertToInt(unsigned char b);
    static std::string AdnStringFieldConvertToString(std::string data, int offset, int length);
    static int HexCharConvertToInt(char c);
    static std::string HexstringConvertToBytes(std::string s);
    static std::string BytesConvertToHexString(std::string &bytes);
    static std::string NetworkNameConvertTostring(std::string data, int offset, int length);
    static std::string ParseConvertToBnW(std::string data, int length);
    static std::string ParseConvertToRGB(std::string data, int length, bool transparency);
    static std::string GetDecimalSubstring(std::string iccId);
    static int BytesConvertToInt(std::string src, int offset, int length);
    static long BytesConvertToRawLong(std::string src, int offset, int length);
    static std::string UnsignedIntConvertToBytes(int value);
    static std::string SignedIntConvertToBytes(int value);
    static int UnsignedIntConvertToBytes(int value, std::string dest, int offset);
    static int SignedIntConvertToBytes(int value, std::string dest, int offset);
    static unsigned char CountTrailingZeros(unsigned char b);
    static std::string ByteConvertToHex(unsigned char b);

private:
    static unsigned char CharConvertToByte(char c);
    static int *MapConvertTo2OrderBitColor(std::string data, int valueIndex, int length, int *colorArray, int bits);
    static int *MapConvertToNon2OrderBitColor(
        std::string data, int valueIndex, int length, int *colorArray, int bits);
    static int *GetCLUT(std::string rawData, int offset, int number);
    static int BitConvertToRGB(int bit);
    static int IntConvertToBytes(int value, std::string dest, int offset, bool bsigned);
};
} // namespace SIM
} // namespace OHOS
#endif // OHOS_SIM_UTILS_H