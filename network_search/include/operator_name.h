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
#ifndef OHOS_NS_OPERATOR_NAME_H
#define OHOS_NS_OPERATOR_NAME_H
#include <memory>
#include "want.h"
#include "event_handler.h"
#include "i_sim_file_manager.h"
#include "network_search_state.h"

namespace OHOS {
class OperatorName {
public:
    explicit OperatorName(std::shared_ptr<NetworkSearchState> networkSearchState);
    virtual ~OperatorName() = default;
    void HandleOperatorInfo(const AppExecFwk::InnerEvent::Pointer &event);
    void RenewSpnAndBroadcast();

private:
    void GsmOperatorInfo(const AppExecFwk::InnerEvent::Pointer &event);
    void CdmaOperatorInfo(const AppExecFwk::InnerEvent::Pointer &event);
    void PublishBroadcastEvent(const AAFwk::Want &want, int eventCode, const std::string &eventData);

    std::shared_ptr<NetworkSearchState> networkSearchState_;
    std::shared_ptr<SIM::ISimFileManager> simFileManager_;
    PhoneAbstract phone_;
    std::string curPlmn_ = "";
    bool curPlmnShow_ = false;
};
} // namespace OHOS
#endif // OHOS_NS_OPERATOR_NAME_H
