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
#ifndef OHOS_RIL_SMS_PARCEL_H
#define OHOS_RIL_SMS_PARCEL_H

#include <memory>
#include <string>
#include "parcel.h"
#include "string_ex.h"
#include "hril_types.h"
namespace OHOS {
struct GsmSmsMessageInfo : public Parcelable {
    int32_t serial;
    std::string smscPdu; /* Short Message Service Center Protocol Data Unit see GSM 03.40 */
    std::string pdu; /* Protocol Data Unit */
    bool ReadFromParcel(Parcel &parcel);
    virtual bool Marshalling(Parcel &parcel) const override;
    std::shared_ptr<GsmSmsMessageInfo> UnMarshalling(Parcel &parcel);
    void Dump(std::string, int32_t);
};

struct ImsSmsMessageInfo : public Parcelable {
    int32_t serial;
    int32_t technology;
    bool retry; /* if errorCode != 0, suggested retry time */
    int32_t msgRef; /* TP-Message-Reference for GSM,and BearerData MessageId for CDMA
                     * from 3GPP2 C.S0015-B, v2.0, 4.5-1 */
    int32_t gsmMessageSize;
    std::vector<GsmSmsMessageInfo> gsmMessage;
    bool ReadFromParcel(Parcel &parcel);
    virtual bool Marshalling(Parcel &parcel) const override;
    std::shared_ptr<ImsSmsMessageInfo> UnMarshalling(Parcel &parcel);
    void Dump(std::string, int32_t);
};

struct SmsMessageInfo : public Parcelable {
    int32_t indicationType;
    int32_t size;
    std::vector<uint8_t> pdu; /* Protocol Data Unit */
    bool ReadFromParcel(Parcel &parcel);
    virtual bool Marshalling(Parcel &parcel) const override;
    std::shared_ptr<SmsMessageInfo> UnMarshalling(Parcel &parcel);
    void Dump(std::string, int32_t);
};

struct ModeData : public Parcelable {
    int32_t serial;
    bool result;
    int32_t mode;
    std::string pdu; /* Protocol Data Unit */
    bool ReadFromParcel(Parcel &parcel);
    virtual bool Marshalling(Parcel &parcel) const override;
    std::shared_ptr<ModeData> UnMarshalling(Parcel &parcel);
    void Dump(std::string, int32_t);
};

struct SendSmsResultInfo : public Parcelable {
    int32_t msgRef; /* TP-Message-Reference for GSM,and BearerData MessageId for CDMA
                     * from 3GPP2 C.S0015-B, v2.0, 4.5-1 */
    std::string pdu; /* Protocol Data Unit */
    int32_t errCode;
    int64_t flag;
    bool ReadFromParcel(Parcel &parcel);
    virtual bool Marshalling(Parcel &parcel) const override;
    std::shared_ptr<SendSmsResultInfo> UnMarshalling(Parcel &parcel);
    void Dump(std::string, int32_t);
};
} // namespace OHOS
#endif // OHOS_RIL_SMS_PARCEL_H
