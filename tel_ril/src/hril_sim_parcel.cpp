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

#include "hril_sim_parcel.h"
#include "hdf_log.h"
#include "hril_modem_parcel.h"
namespace OHOS {
std::shared_ptr<IccIoResultInfo> IccIoResultInfo::UnMarshalling(Parcel &parcel)
{
    std::shared_ptr<IccIoResultInfo> param = std::make_shared<IccIoResultInfo>();
    if (param == nullptr || !param->ReadFromParcel(parcel)) {
        param = nullptr;
    }
    return param;
}

bool IccIoResultInfo::ReadFromParcel(Parcel &parcel)
{
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, sw1);
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, sw2);
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(String, parcel, response);
    return true;
}

bool IccIoResultInfo::Marshalling(Parcel &parcel) const
{
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, sw1);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, sw2);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String, parcel, response);
    return true;
}

std::shared_ptr<IndicationInfo> IndicationInfo::UnMarshalling(Parcel &parcel)
{
    std::shared_ptr<IndicationInfo> param = std::make_shared<IndicationInfo>();
    if (param == nullptr || !param->ReadFromParcel(parcel)) {
        param = nullptr;
    }
    return param;
}

bool IndicationInfo::ReadFromParcel(Parcel &parcel)
{
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, sw1);
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, sw2);
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(String, parcel, response);
    return true;
}

bool IndicationInfo::Marshalling(Parcel &parcel) const
{
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, sw1);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, sw2);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String, parcel, response);
    return true;
}

bool IccIoRequestInfo::ReadFromParcel(Parcel &parcel)
{
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, fileId);
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(String, parcel, path);
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, cmd);
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, p2);
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, p3);
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, serial);
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, p1);
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(String, parcel, data);
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(String, parcel, pin2);
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(String, parcel, aid);
    return true;
}

bool IccIoRequestInfo::Marshalling(Parcel &parcel) const
{
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, fileId);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String, parcel, path);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, cmd);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, p2);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, p3);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, serial);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, p1);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String, parcel, data);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String, parcel, pin2);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String, parcel, aid);
    return true;
}

std::shared_ptr<IccIoRequestInfo> IccIoRequestInfo::UnMarshalling(Parcel &parcel)
{
    std::shared_ptr<IccIoRequestInfo> param = std::make_shared<IccIoRequestInfo>();
    if (param == nullptr || !param->ReadFromParcel(parcel)) {
        param = nullptr;
    }
    return param;
}

std::shared_ptr<SimRefreshResultInd> SimRefreshResultInd::UnMarshalling(Parcel &parcel)
{
    std::shared_ptr<SimRefreshResultInd> param = std::make_shared<SimRefreshResultInd>();
    if (param == nullptr || !param->ReadFromParcel(parcel)) {
        param = nullptr;
    }
    return param;
}

bool SimRefreshResultInd::ReadFromParcel(Parcel &parcel)
{
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, type);
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, efId);
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(String, parcel, aid);
    return true;
}

bool SimRefreshResultInd::Marshalling(Parcel &parcel) const
{
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, type);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, efId);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String, parcel, aid);
    return true;
}

bool IccContentInfo::ReadFromParcel(Parcel &parcel)
{
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, SimLockSubState);
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(String, parcel, aid);
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(String, parcel, iccTag);
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, substitueOfPin1);
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, stateOfPin1);
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, stateOfPin2);
    return true;
}

bool IccContentInfo::Marshalling(Parcel &parcel) const
{
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, SimLockSubState);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String, parcel, aid);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String, parcel, iccTag);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, substitueOfPin1);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, stateOfPin1);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, stateOfPin2);
    return true;
}

std::shared_ptr<IccContentInfo> IccContentInfo::UnMarshalling(Parcel &parcel)
{
    std::shared_ptr<IccContentInfo> param = std::make_shared<IccContentInfo>();
    if (param == nullptr || !param->ReadFromParcel(parcel)) {
        param = nullptr;
    }
    return param;
}

bool CardStatusInfo::ReadFromParcel(Parcel &parcel)
{
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, cardState);
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, iccType);
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, iccStatus);
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, pinState);
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, contentIndexOfGU);
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, contentIndexOfCdma);
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, contentIndexOfIms);
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, iccContentNum);
    iccContentInfo.resize(iccContentNum);
    for (int32_t i = 0; i < iccContentNum; i++) {
        iccContentInfo[i].ReadFromParcel(parcel);
    }
    return true;
}

bool CardStatusInfo::Marshalling(Parcel &parcel) const
{
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, cardState);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, iccType);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, iccStatus);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, pinState);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, contentIndexOfGU);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, contentIndexOfCdma);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, contentIndexOfIms);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, iccContentNum);
    for (int32_t i = 0; i < iccContentNum; i++) {
        iccContentInfo[i].Marshalling(parcel);
    }
    return true;
}

std::shared_ptr<CardStatusInfo> CardStatusInfo::UnMarshalling(Parcel &parcel)
{
    std::shared_ptr<CardStatusInfo> param = std::make_shared<CardStatusInfo>();
    if (param == nullptr || !param->ReadFromParcel(parcel)) {
        param = nullptr;
    }
    return param;
}
} // namespace OHOS