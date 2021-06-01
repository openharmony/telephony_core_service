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
#ifndef OHOS_RIL_SIM_PARCEL_H
#define OHOS_RIL_SIM_PARCEL_H

#include <memory>
#include <string>
#include "parcel.h"
#include "string_ex.h"
#include "hril_types.h"
namespace OHOS {
enum class SimRefreshTypeInd : int32_t { SIM_FILE_UPDATE = 0, SIM_INIT = 1, SIM_RESET = 2 };

/* Form 3GPP TS 27.007 V4.3.0 (2001-12) 8.18, + CRSM */
struct IccIoResultInfo : public Parcelable {
    int32_t sw1; /* information from the SIM about the execution of the actual command.
                  * These parameters are delivered to the TE in both cases,
                  * on successful or failed execution of the command */
    int32_t sw2;
    std::string response;

    bool ReadFromParcel(Parcel &parcel);
    virtual bool Marshalling(Parcel &parcel) const override;
    std::shared_ptr<IccIoResultInfo> UnMarshalling(Parcel &parcel);
    void Dump(std::string, int32_t);
};

/* Form 3GPP TS 27.007 V4.3.0 (2001-12) 8.18, + CRSM */
struct IndicationInfo : public Parcelable {
    int32_t sw1; /* information from the SIM about the execution of the actual command.
                  * These parameters are delivered to the TE in both cases,
                  * on successful or failed execution of the command */
    int32_t sw2;
    std::string response;

    bool ReadFromParcel(Parcel &parcel);
    virtual bool Marshalling(Parcel &parcel) const override;
    std::shared_ptr<IndicationInfo> UnMarshalling(Parcel &parcel);
    void Dump(std::string, int32_t);
};

/* Form 3GPP TS 27.007 V4.3.0 (2001-12) 8.18, + CRSM */
struct IccIoRequestInfo : public Parcelable {
    int32_t fileId; /* this is the identifier of a elementary datafile on SIM.
                     * Mandatory for every command except STATUS */
    std::string path; /* contains the path of an elementary file on the SIM/UICC
                       * in hexadecimal format as defined in ETSI TS 102 221 [60]
                       * (e.g. "7F205F70" in SIM and UICC case).
                       * The <pathid> shall only be used in the mode
                       * "select by path from MF" as defined in  ETSI TS 102 221 [60] */
    int32_t cmd; /* command passed on by the ME to the SIM; refer GSM 51.011 [28] */
    int32_t p1; /* parameters passed on by the MT to the SIM.
                 * These parameters are mandatory for every command,
                 * except GET RESPONSE and STATUS.
                 * The values are described in 3GPP TS 51.011 [28] */
    int32_t p2;
    int32_t p3;
    int32_t serial;
    std::string data; /* information which shall be written to the SIM
                       * (hexadecimal character format; refer +CSCS). */
    std::string pin2;
    std::string aid; /* AID value, from ETSI 102.221 8.1 and 101.220 4, if no value that is NULL */

    bool ReadFromParcel(Parcel &parcel);
    virtual bool Marshalling(Parcel &parcel) const override;
    std::shared_ptr<IccIoRequestInfo> UnMarshalling(Parcel &parcel);
    void Dump(std::string, int32_t);
};

/* From ETSI 102.221 8.1 and 101.220 4 */
struct SimRefreshResultInd : public Parcelable {
    int32_t type;
    int32_t efId; /* EFID is the updated file if the result is */
    std::string aid; /* application ID is the card application */

    bool ReadFromParcel(Parcel &parcel);
    virtual bool Marshalling(Parcel &parcel) const override;
    std::shared_ptr<SimRefreshResultInd> UnMarshalling(Parcel &parcel);
    void Dump(std::string, int32_t);
};

struct IccContentInfo : public Parcelable {
    int32_t SimLockSubState;
    std::string aid;
    std::string iccTag;
    int32_t substitueOfPin1;
    int32_t stateOfPin1;
    int32_t stateOfPin2;

    bool ReadFromParcel(Parcel &parcel);
    virtual bool Marshalling(Parcel &parcel) const override;
    std::shared_ptr<IccContentInfo> UnMarshalling(Parcel &parcel);
    void Dump(std::string, int32_t);
};

struct CardStatusInfo : public Parcelable {
    int32_t cardState;
    int32_t iccType;
    int32_t iccStatus;
    int32_t pinState;
    int32_t contentIndexOfGU;
    int32_t contentIndexOfCdma;
    int32_t contentIndexOfIms;
    int32_t iccContentNum;

    std::vector<IccContentInfo> iccContentInfo;
    bool ReadFromParcel(Parcel &parcel);
    virtual bool Marshalling(Parcel &parcel) const override;
    std::shared_ptr<CardStatusInfo> UnMarshalling(Parcel &parcel);
    void Dump(std::string, int32_t);
};
} // namespace OHOS
#endif // OHOS_RIL_SIM_PARCEL_H