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
#ifndef OHOS_RIL_CALL_PARCEL_H
#define OHOS_RIL_CALL_PARCEL_H

#include <memory>
#include <string>
#include "parcel.h"
#include "string_ex.h"
#include "hril_types.h"

namespace OHOS {
/* From 3GPP TS 27.007 V4.3.0 (2001-12) 7.7, AT + ATD */
struct DialInfo : public Parcelable {
    int32_t serial;
    std::string address;
    int32_t clir; /* Calling Line Identification Restriction . From TS 27.007 V3.4.0 (2000-03) */
    bool ReadFromParcel(Parcel &parcel);
    virtual bool Marshalling(Parcel &parcel) const override;
    std::shared_ptr<DialInfo> UnMarshalling(Parcel &parcel);
    void Dump(std::string, int32_t);
};

struct UusData : public Parcelable {
    int32_t uusDcs; /* Cell Broadcast Data Coding Scheme(default 0). */
    bool ReadFromParcel(Parcel &parcel);
    virtual bool Marshalling(Parcel &parcel) const override;
    std::shared_ptr<UusData> UnMarshalling(Parcel &parcel);
    void Dump(std::string, int32_t);
};

struct CallInfo : public Parcelable {
    int32_t state;
    int32_t index;
    int32_t typeOfAddress; /* type of address,  see 3GPP TS 23.140 [58]. */
    bool isEmpty; /* value is true when number is empty */
    bool isMT; /* value is true when call is mobile terminated */
    int32_t als; /* Alternate Line Service */
    bool isVoice; /* value is true when it is a voice call */
    std::string remoteNumber; /* Parameters <n> and <m> are used to enable/disable the presentation of incoming
                               * User-to-User Information Elements.When <n> = 1 and a User-to-User Information is
                               * received after a mobile originated call setup or after hanging up a call,
                               * intermediate result code +CUUS1I: <messageI>,<UUIE> is sent to the TE. When <m> =
                               * 1 and a User-to-User Information is received during a mobile terminated call setup
                               * or during a remote party call hangup, unsolicited result code
                               * +CUUS1U: <messageU>,<UUIE> is sent to the TE. */
    int32_t numberRemind; /* The command refers to an integer that allows a called party to enable or disable
                           * (<n>=0) the reporting of the ID of calling parties, and specifies the method of
                           * presentation of the ID. This is basically the same as GSM/UMTS supplementary service
                           * CLIP (Calling Line Identification Presentation). The presentation may be either
                           * formatted (<n>=1) or unformatted (<n>=2): Formatted presentation : data items are
                           * reported in the form of <tag>=<value> pairs. <tag>		<value> DATE		MMDD
                           * (month, day) TIME		HHMM (hour, minute) NMBR		calling number or P or O (P =
                           * number is private, O = number is unavailable) NAME		subscription listing name MESG
                           * data from other (unknown) tags */
    std::string remoteName; /* Remote party name */
    int32_t nameRemind; /* This command refers to the GSM/UMTS supplementary service CLIP (Calling Line
                         * Identification Presentation) that enables a called subscriber to get the calling line
                         * identity (CLI) of the calling party when receiving a mobile terminated call. Set command
                         * enables or disables the presentation of the CLI at the TE. It has no effect on the
                         * execution of the supplementary service CLIP in the network. */

    bool ReadFromParcel(Parcel &parcel);
    virtual bool Marshalling(Parcel &parcel) const override;
    std::shared_ptr<CallInfo> UnMarshalling(Parcel &parcel);
    void Dump(std::string, int32_t);
};

struct CallInfoList : public Parcelable {
    int32_t callSize;
    std::vector<CallInfo> calls;
    int32_t flag;

    bool ReadFromParcel(Parcel &parcel);
    virtual bool Marshalling(Parcel &parcel) const override;
    std::shared_ptr<CallInfoList> UnMarshalling(Parcel &parcel);
    void Dump(std::string, int32_t);
};
} // namespace OHOS
#endif // OHOS_RIL_CALL_PARCEL_H