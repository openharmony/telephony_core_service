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

#ifndef OHOS_PARCEL_BASE_H
#define OHOS_PARCEL_BASE_H

#include "parcel.h"

namespace OHOS {
namespace Telephony {
#define READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(type, parcel, data) \
    do {                                                         \
        if (!(parcel).Read##type(data)) {                        \
            return false;                                        \
        }                                                        \
    } while (0)

#define WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(type, parcel, data) \
    do {                                                          \
        if (!(parcel).Write##type(data)) {                        \
            return false;                                         \
        }                                                         \
    } while (0)
} // namespace Telephony
} // namespace OHOS
#endif // OHOS_PARCEL_BASE_H
