/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

#ifndef SATELLITE_CORE_CALLBACK_H
#define SATELLITE_CORE_CALLBACK_H

#include <map>

#include "iremote_stub.h"
#include "satellite_core_callback_ipc_interface_code.h"
#include "satellite_core_callback_stub.h"
#include "tel_event_handler.h"

namespace OHOS {
namespace Telephony {
class SatelliteCoreCallback : public SatelliteCoreCallbackStub {
public:
    explicit SatelliteCoreCallback(const std::shared_ptr<TelEventHandler> &handler);
    virtual ~SatelliteCoreCallback();

    int32_t SetRadioStateResponse(InnerEvent::Pointer &event) override;
    int32_t RadioStateChanged(InnerEvent::Pointer &event) override;
    int32_t SimStateChanged(InnerEvent::Pointer &event) override;
    int32_t SatelliteStatusChanged(InnerEvent::Pointer &event) override;

private:
    std::shared_ptr<TelEventHandler> handler_;
};
} // namespace Telephony
} // namespace OHOS

#endif // SATELLITE_CORE_CALLBACK_H
