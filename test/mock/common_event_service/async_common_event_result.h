/*
 * Copyright (C) 2025-2025 Huawei Device Co., Ltd.
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
#ifndef ASYNC_COMMON_EVENT_RESULT_H
#define ASYNC_COMMON_EVENT_RESULT_H

#include <string>

#include "iremote_object.h"

namespace OHOS {
namespace EventFwk {

class AsyncCommonEventResult {
public:
    AsyncCommonEventResult(const int32_t &resultCode, const std::string &resultData, const bool &ordered,
        const bool &sticky, const wptr<IRemoteObject> &token)
        : resultCode_(resultCode), resultData_(resultData), ordered_(ordered), sticky_(sticky), token_(token),
          abortEvent_(false), finished_(false)
    {}

    ~AsyncCommonEventResult() = default;

    bool SetCode(const int32_t &code)
    {
        if (!CheckSynchronous()) {
            return false;
        }
        resultCode_ = code;
        return true;
    }

    int32_t GetCode() const
    {
        return resultCode_;
    }

    bool SetData(const std::string &data)
    {
        if (!CheckSynchronous()) {
            return false;
        }
        resultData_ = data;
        return true;
    }

    std::string GetData() const
    {
        return resultData_;
    }

    bool SetCodeAndData(const int32_t &code, const std::string &data)
    {
        if (!CheckSynchronous()) {
            return false;
        }
        resultCode_ = code;
        resultData_ = data;
        return true;
    }

    bool AbortCommonEvent()
    {
        if (!CheckSynchronous()) {
            return false;
        }
        abortEvent_ = true;
        return true;
    }

    bool ClearAbortCommonEvent()
    {
        if (!CheckSynchronous()) {
            return false;
        }
        abortEvent_ = false;
        return true;
    }

    bool GetAbortCommonEvent() const
    {
        return abortEvent_;
    }

    bool FinishCommonEvent()
    {
        if (!CheckSynchronous()) {
            return false;
        }

        if (finished_) {
            return false;
        }

        finished_ = true;
        return true;
    }

    bool IsOrderedCommonEvent() const
    {
        return ordered_;
    }

    bool IsStickyCommonEvent() const
    {
        return sticky_;
    }

    bool CheckSynchronous() const
    {
        if (ordered_) {
            return true;
        } else {
            return false;
        }
    }

private:
    int32_t resultCode_;
    std::string resultData_;
    bool ordered_;
    bool sticky_;
    wptr<IRemoteObject> token_;
    bool abortEvent_;
    bool finished_;
};

}  // namespace EventFwk
}  // namespace OHOS

#endif  // ASYNC_COMMON_EVENT_RESULT_H