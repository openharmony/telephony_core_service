/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "parcel.h"

namespace OHOS {
namespace {
bool g_mockWriteUint32 = true;
bool g_mockWriteInt32 = true;
bool g_mockWriteString16 = true;
bool g_mockWriteBool = true;
bool g_mockReadUint32 = true;
bool g_mockReadInt32 = true;
bool g_mockReadString16 = true;
bool g_mockReadBool = true;

std::list<bool> g_mockWriteUint32List;
std::list<bool> g_mockWriteInt32List;
std::list<bool> g_mockWriteString16List;
std::list<bool> g_mockWriteBoolList;

std::list<bool> g_mockReadUint32List;
std::list<bool> g_mockReadInt32List;
std::list<bool> g_mockReadString16List;
std::list<bool> g_mockReadBoolList;

uint32_t g_mockReadUint32Date;
}

void MockWriteUint32(bool state, std::list<bool> *mockList)
{
    if (mockList != nullptr) {
        g_mockWriteUint32List = *mockList;
    }
    g_mockWriteUint32 = state;
}

void MockWriteInt32(bool state, std::list<bool> *mockList)
{
    if (mockList != nullptr) {
        g_mockWriteInt32List = *mockList;
    }
    g_mockWriteInt32 = state;
}

void MockWriteString16(bool state, std::list<bool> *mockList)
{
    if (mockList != nullptr) {
        g_mockWriteString16List = *mockList;
    }
    g_mockWriteString16 = state;
}

void MockWriteBool(bool state, std::list<bool> *mockList)
{
    if (mockList != nullptr) {
        g_mockWriteBoolList = *mockList;
    }
    g_mockWriteBool = state;
}

void MockReadUint32(bool state, uint32_t value, std::list<bool> *mockList)
{
    if (mockList != nullptr) {
        g_mockReadUint32List = *mockList;
    }
    g_mockReadUint32Date = value;
    g_mockReadUint32 = state;
}

void MockReadInt32(bool state, std::list<bool> *mockList)
{
    if (mockList != nullptr) {
        g_mockReadInt32List = *mockList;
    }
    g_mockReadInt32 = state;
}

void MockReadString16(bool state, std::list<bool> *mockList)
{
    if (mockList != nullptr) {
        g_mockReadString16List = *mockList;
    }
    g_mockReadString16 = state;
}

void MockReadBool(bool state, std::list<bool> *mockList)
{
    if (mockList != nullptr) {
        g_mockReadBoolList = *mockList;
    }
    g_mockReadBool = state;
}

void ResetParcelState()
{
    g_mockWriteUint32 = true;
    g_mockWriteInt32 = true;
    g_mockWriteString16 = true;
    g_mockWriteBool = true;
    g_mockReadUint32 = true;
    g_mockReadInt32 = true;
    g_mockReadString16 = true;
    g_mockReadBool = true;

    g_mockWriteUint32List.clear();
    g_mockWriteInt32List.clear();
    g_mockWriteString16List.clear();
    g_mockWriteBoolList.clear();

    g_mockReadUint32List.clear();
    g_mockReadInt32List.clear();
    g_mockReadString16List.clear();
    g_mockReadBoolList.clear();
}

bool Parcel::WriteUint32(uint32_t) const
{
    if (g_mockWriteUint32List.empty()) {
        return g_mockWriteUint32;
    }
    bool value = g_mockWriteUint32List.front();
    g_mockWriteUint32List.pop_front();
    return value;
}

bool Parcel::WriteInt32(int32_t) const
{
    if (g_mockWriteInt32List.empty()) {
        return g_mockWriteInt32;
    }
    bool value = g_mockWriteInt32List.front();
    g_mockWriteInt32List.pop_front();
    return value;
}

bool Parcel::WriteString16(const std::u16string&) const
{
    if (g_mockWriteString16List.empty()) {
        return g_mockWriteString16;
    }
    bool value = g_mockWriteString16List.front();
    g_mockWriteString16List.pop_front();
    return value;
}

bool Parcel::WriteBool(bool) const
{
    if (g_mockWriteBoolList.empty()) {
        return g_mockWriteBool;
    }
    bool value = g_mockWriteBoolList.front();
    g_mockWriteBoolList.pop_front();
    return value;
}

bool Parcel::ReadUint32(uint32_t &value) const
{
    value = g_mockReadUint32Date;
    if (g_mockReadUint32List.empty()) {
        return g_mockReadUint32;
    }
    bool ret = g_mockReadUint32List.front();
    g_mockReadUint32List.pop_front();
    return ret;
}

bool Parcel::ReadInt32(int32_t&) const
{
    if (g_mockReadInt32List.empty()) {
        return g_mockReadInt32;
    }
    bool ret = g_mockReadInt32List.front();
    g_mockReadInt32List.pop_front();
    return ret;
}

bool Parcel::ReadString16(const std::u16string&) const
{
    if (g_mockReadString16List.empty()) {
        return g_mockReadString16;
    }
    bool ret = g_mockReadString16List.front();
    g_mockReadString16List.pop_front();
    return ret;
}

bool Parcel::ReadBool(bool&) const
{
    if (g_mockReadBoolList.empty()) {
        return g_mockReadBool;
    }
    bool ret = g_mockReadBoolList.front();
    g_mockReadBoolList.pop_front();
    return ret;
}
} // namespace OHOS
