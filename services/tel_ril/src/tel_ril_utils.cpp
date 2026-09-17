/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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
#include "tel_ril_utils.h"
#include "telephony_types.h"
#include "telephony_ext_wrapper.h"

namespace OHOS {
namespace Telephony {

bool TelRilUtils::IsValidSlotId(int32_t slotId)
{
    bool vsimEnable = TELEPHONY_EXT_WRAPPER.isVSimEnabled_ && TELEPHONY_EXT_WRAPPER.isVSimEnabled_();

    int32_t slotUpper = SIM_SLOT_COUNT >= THREE_CARD_COUNT ? SIM_SLOT_COUNT + 1 : SIM_SLOT_COUNT;
    return vsimEnable ?
        (slotId >= 0 && slotId < slotUpper) || slotId == SIM_SLOT_2 :
        (slotId >= 0 && slotId < slotUpper) && slotId != SIM_SLOT_2;
}

} // namespace Telephony
} // namespace OHOS