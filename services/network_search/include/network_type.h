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

#ifndef NETWORK_SEARCH_INCLUDE_NETWORK_TYPE_H
#define NETWORK_SEARCH_INCLUDE_NETWORK_TYPE_H

#include <memory>
#include "event_handler.h"
#include "iremote_stub.h"
#include "hril_network_parcel.h"
#include "network_state.h"

namespace OHOS {
namespace Telephony {
class NetworkSearchManager;
class NetworkType {
public:
    explicit NetworkType(std::weak_ptr<NetworkSearchManager> networkSearchManager);
    virtual ~NetworkType() = default;
    void ProcessGetPreferredNetwork(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &event) const;
    void ProcessSetPreferredNetwork(int32_t slotId, const AppExecFwk::InnerEvent::Pointer &event) const;
    void UpdatePhone(RadioTech csRadioTech);
    void SetPhoneType(PhoneType phoneType);
    PhoneType GetPhoneType() const;

private:
    PhoneType phoneType_ = PhoneType::PHONE_TYPE_IS_GSM;
    std::weak_ptr<NetworkSearchManager> networkSearchManager_;
};
} // namespace Telephony
} // namespace OHOS
#endif // NETWORK_SEARCH_INCLUDE_NETWORK_TYPE_H
