/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#ifndef MOCK_DATA_SHARE_RESULT_SET_H
#define MOCK_DATA_SHARE_RESULT_SET_H
#include <gmock/gmock.h>
#include "datashare_result_set.h"

namespace OHOS {
namespace Telephony {
using namespace DataShare;
class DataShareResultSetMock : public DataShareResultSet {
public:
    MOCK_METHOD(int, GetRowCount, (int &count), (override));
    MOCK_METHOD(int, GetAllColumnNames, (std::vector<std::string> &columnNames), (override));
    MOCK_METHOD(int, GetBlob, (int columnIndex, std::vector<uint8_t> &blob), (override));
    MOCK_METHOD(int, GetString, (int columnIndex, std::string &value), (override));
    MOCK_METHOD(int, GetInt, (int columnIndex, int &value), (override));
    MOCK_METHOD(int, GetLong, (int columnIndex, int64_t &value), (override));
    MOCK_METHOD(int, GetDouble, (int columnIndex, double &value), (override));
    MOCK_METHOD(int, IsColumnNull, (int columnIndex, bool &isNull), (override));
    MOCK_METHOD(int, GoToRow, (int position), (override));
    MOCK_METHOD(int, GetDataType, (int columnIndex, DataType &dataType), (override));
    MOCK_METHOD(int, GetRowIndex, (int &position), (const override));
    MOCK_METHOD(int, GoTo, (int offset), (override));
    MOCK_METHOD(int, GoToFirstRow, (), (override));
    MOCK_METHOD(int, GoToLastRow, (), (override));
    MOCK_METHOD(int, GoToNextRow, (), (override));
    MOCK_METHOD(int, GoToPreviousRow, (), (override));
    MOCK_METHOD(int, IsAtFirstRow, (bool &result), (const override));
    MOCK_METHOD(int, IsAtLastRow, (bool &result), (override));
    MOCK_METHOD(int, IsStarted, (bool &result), (const override));
    MOCK_METHOD(int, IsEnded, (bool &result), (override));
    MOCK_METHOD(int, GetColumnCount, (int &count), (override));
    MOCK_METHOD(int, GetColumnIndex, (const std::string &columnName, int &columnIndex), (override));
    MOCK_METHOD(int, GetColumnName, (int columnIndex, std::string &columnName), (override));
    MOCK_METHOD(bool, IsClosed, (), (const override));
    MOCK_METHOD(int, Close, (), (override));
    MOCK_METHOD(std::shared_ptr<AppDataFwk::SharedBlock>, GetBlock, (), (override));
    MOCK_METHOD(bool, OnGo, (int startRowIndex, int targetRowIndex, int *cachedIndex), (override));
    MOCK_METHOD(void, FillBlock, (int startRowIndex, AppDataFwk::SharedBlock *block), (override));
    MOCK_METHOD(void, SetBlock, (AppDataFwk::SharedBlock *block), (override));
    MOCK_METHOD(void, Finalize, (), (override));
};
} // Telephony
} // OHOS
#endif