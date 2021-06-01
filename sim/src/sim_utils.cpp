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
#include "sim_utils.h"

using namespace std;

namespace OHOS {
namespace SIM {
std::string SIMUtils::BcdConvertTostring(std::string data, int offset, int length)
{
    (void)data;
    (void)offset;
    (void)length;
    return "";
}

std::string SIMUtils::BcdConvertTostring(std::string data)
{
    (void)data;
    return "";
}

std::string SIMUtils::BcdConvertToBytes(std::string bcd)
{
    (void)bcd;
    return "";
}

void SIMUtils::BcdConvertToBytes(std::string bcd, std::string Bytes)
{
    (void)bcd;
}

std::string SIMUtils::BcdPlmnConvertTostring(std::string data, int offset)
{
    (void)data;
    (void)offset;
    return "";
}

std::string SIMUtils::BchConvertTostring(std::string data, int offset, int length)
{
    (void)data;
    (void)offset;
    (void)length;
    return "";
}

std::string SIMUtils::CdmaBcdConvertTostring(std::string data, int offset, int length)
{
    (void)data;
    (void)offset;
    (void)length;
    return "";
}

int SIMUtils::GsmBcdByteConvertToInt(unsigned char b)
{
    (void)b;
    return 0;
}

int SIMUtils::CdmaBcdByteConvertToInt(unsigned char b)
{
    (void)b;
    return 0;
}

std::string SIMUtils::AdnStringFieldConvertToString(std::string data, int offset, int length)
{
    (void)data;
    (void)offset;
    (void)length;
    return "";
}

int SIMUtils::HexCharConvertToInt(char c)
{
    (void)c;
    return 0;
}

std::string SIMUtils::HexstringConvertToBytes(std::string s)
{
    (void)s;
    return "";
}

std::string SIMUtils::BytesConvertToHexString(std::string &bytes)
{
    return bytes;
}

std::string SIMUtils::NetworkNameConvertTostring(std::string data, int offset, int length)
{
    (void)data;
    (void)offset;
    (void)length;
    return "";
}

std::string SIMUtils::ParseConvertToBnW(std::string data, int length)
{
    (void)data;
    return "";
}

std::string SIMUtils::ParseConvertToRGB(std::string data, int length, bool transparency)
{
    (void)data;
    (void)length;
    (void)transparency;
    return "";
}

std::string SIMUtils::GetDecimalSubstring(std::string iccId)
{
    (void)iccId;
    return "";
}

int SIMUtils::BytesConvertToInt(std::string src, int offset, int length)
{
    (void)src;
    (void)offset;
    (void)length;
    return 0;
}

long SIMUtils::BytesConvertToRawLong(std::string src, int offset, int length)
{
    (void)src;
    (void)offset;
    (void)length;
    return 0;
}

std::string SIMUtils::UnsignedIntConvertToBytes(int value)
{
    (void)value;
    return "";
}

std::string SIMUtils::SignedIntConvertToBytes(int value)
{
    (void)value;
    return "";
}

int SIMUtils::UnsignedIntConvertToBytes(int value, std::string dest, int offset)
{
    (void)value;
    (void)dest;
    (void)offset;
    return 0;
}

int SIMUtils::SignedIntConvertToBytes(int value, std::string dest, int offset)
{
    (void)value;
    (void)dest;
    (void)offset;
    return 0;
}

unsigned char SIMUtils::CountTrailingZeros(unsigned char b)
{
    (void)b;
    return 0;
}

std::string SIMUtils::ByteConvertToHex(unsigned char b)
{
    (void)b;
    return "";
}

unsigned char SIMUtils::CharConvertToByte(char c)
{
    (void)c;
    return 0;
}

int *SIMUtils::MapConvertTo2OrderBitColor(std::string data, int valueIndex, int length, int *colorArray, int bits)
{
    (void)data;
    (void)valueIndex;
    (void)length;
    (void)colorArray;
    (void)bits;
    return nullptr;
}

int *SIMUtils::MapConvertToNon2OrderBitColor(
    std::string data, int valueIndex, int length, int *colorArray, int bits)
{
    (void)data;
    (void)valueIndex;
    (void)length;
    (void)colorArray;
    (void)bits;
    return nullptr;
}

int *SIMUtils::GetCLUT(std::string rawData, int offset, int number)
{
    (void)rawData;
    (void)offset;
    (void)number;
    return nullptr;
}

int SIMUtils::BitConvertToRGB(int bit)
{
    (void)bit;
    return 0;
}

int SIMUtils::IntConvertToBytes(int value, std::string dest, int offset, bool bsigned)
{
    (void)value;
    (void)dest;
    (void)offset;
    (void)bsigned;
    return 0;
}
} // namespace SIM
} // namespace OHOS