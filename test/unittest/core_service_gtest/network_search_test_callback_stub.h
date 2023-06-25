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

#ifndef NETWORK_SEARCH_TEST_CALLBACK_STUB_H
#define NETWORK_SEARCH_TEST_CALLBACK_STUB_H

#include <condition_variable>
#include <mutex>

#include "i_network_search_callback_stub.h"

namespace OHOS {
namespace Telephony {
class NetworkSearchTestCallbackStub : public INetworkSearchCallbackStub {
public:
    int32_t GetNetworkModeCallbackResult() const;
    bool SetNetworkModeCallbackResult() const;
    bool SetRadioStateCallbackResult() const;
    bool GetRadioStateCallbackResult() const;
    bool GetNetworkSearchInformationCallbackResult() const;
    bool SetPreferredNetworkCallbackResult() const;
    bool GetPreferredNetworkCallbackResult() const;
    bool SetNrOptionModeCallbackResult() const;
    bool GetNrOptionModeCallbackResult() const;
    void WaitForGetNetworkModeCallback(int32_t timeoutSecond);
    void WaitForSetNetworkModeCallback(int32_t timeoutSecond);
    void WaitForSetRadioStateCallback(int32_t timeoutSecond);
    void WaitForGetRadioStateCallback(int32_t timeoutSecond);
    void WaitForGetNetworkSearchInformationCallback(int32_t timeoutSecond);
    void WaitForSetPreferredNetworkCallback(int32_t timeoutSecond);
    void WaitForGetPreferredNetworkCallback(int32_t timeoutSecond);
    void WaitForSetNrOptionModeCallback(int32_t timeoutSecond);
    void WaitForGetNrOptionModeCallback(int32_t timeoutSecond);
    void OnGetNetworkModeCallback(const int32_t searchModel, const int32_t errorCode) override;
    void OnSetNetworkModeCallback(const bool setResult, const int32_t errorCode) override;
    void OnSetRadioStateCallback(const bool setResult, const int32_t errorCode) override;
    void OnGetRadioStateCallback(const bool isRadioOn, const int32_t errorCode) override;
    void OnGetNetworkSearchInformation(
        const sptr<NetworkSearchResult> &networkSearchResult, const int32_t errorCode) override;
    void OnSetPreferredNetworkCallback(const bool result, const int32_t errorCode) override;
    void OnGetPreferredNetworkCallback(const int32_t networkMode, const int32_t errorCode) override;
    void OnSetNrOptionModeCallback(const bool setResult, const int32_t errorCode) override;
    void OnGetNrOptionModeCallback(const int32_t mode, const int32_t errorCode) override;

private:
    int32_t getNetworkModeResult_ = false;
    bool setNetworkModeResult_ = false;
    bool setRadioStateResult_ = false;
    bool getRadioStateResult_ = false;
    bool getNetworkSearchInformationResult_ = false;
    bool setPreferredNetworkResult_ = false;
    bool getPreferredNetworkResult_ = false;
    bool setNrOptionModeResult_ = false;
    bool getNrOptionModeResult_ = false;
    std::mutex getNetworkModeMutex_;
    std::condition_variable getNetworkModeCv_;
    std::mutex setNetworkModeMutex_;
    std::condition_variable setNetworkModeCv_;
    std::mutex setRadioStateMutex_;
    std::condition_variable setRadioStateCv_;
    std::mutex getRadioStateMutex_;
    std::condition_variable getRadioStateCv_;
    std::mutex getNetworkSearchInformationMutex_;
    std::condition_variable getNetworkSearchInformationCv_;
    std::mutex setPreferredNetworkMutex_;
    std::condition_variable setPreferredNetworkCv_;
    std::mutex getPreferredNetworkMutex_;
    std::condition_variable getPreferredNetworkCv_;
    std::mutex setNrOptionModeMutex_;
    std::condition_variable setNrOptionModeCv_;
    std::mutex getNrOptionModeMutex_;
    std::condition_variable getNrOptionModeCv_;
};
} // namespace Telephony
} // namespace OHOS
#endif // NETWORK_SEARCH_TEST_CALLBACK_STUB_H
