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

#ifndef NETWORK_SEARCH_TEST_H
#define NETWORK_SEARCH_TEST_H

#include <gtest/gtest.h>
#include <list>

#include "core_service_client.h"
namespace OHOS {
namespace Telephony {
struct ImsRegStateCallback {
    int32_t slotId;
    ImsServiceType imsSrvType;
    sptr<ImsRegInfoCallback> imsCallback = nullptr;
};
class NetworkSearchTest : public testing::Test {
public:
    // execute before first testcase
    static void SetUpTestCase();
    void SetUp();
    void TearDown();
    static void TearDownTestCase();
    static sptr<ICoreService> GetProxy();
    void PrintCellInformation(std::vector<sptr<CellInformation>> cellList);
    void PrintSignalInformation(std::vector<sptr<SignalInformation>> signalList);
    void PrintNetworkStateInformation(sptr<NetworkState> result);

private:
    void PrintGsmCellInformation(sptr<CellInformation> cell);
    void PrintCdmaCellInformation(sptr<CellInformation> cell);
    void PrintWcdmaCellInformation(sptr<CellInformation> cell);
    void PrintTdscdmaCellInformation(sptr<CellInformation> cell);
    void PrintLteCellInformation(sptr<CellInformation> cell);
    void PrintNrCellInformation(sptr<CellInformation> cell);
    void PrintGsmSignalInformation(sptr<SignalInformation> signal);
    void PrintCdmaSignalInformation(sptr<SignalInformation> signal);
    void PrintWcdmaSignalInformation(sptr<SignalInformation> signal);
    void PrintTdScdmaSignalInformation(sptr<SignalInformation> signal);
    void PrintLteSignalInformation(sptr<SignalInformation> signal);
    void PrintNrSignalInformation(sptr<SignalInformation> signal);

public:
    static sptr<ICoreService> telephonyService_;
    static std::list<ImsRegStateCallback> imsRegStateCallbackList_;
};
} // namespace Telephony
} // namespace OHOS
#endif // NETWORK_SEARCH_TEST_H
