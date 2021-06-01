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

#ifndef OHOS_RIL_H
#define OHOS_RIL_H 1

#include <net/if.h>
#include <stdint.h>
#include "hril_request.h"
#include "hril_notification.h"

#define HRIL_VERSION 1
#define HRIL_VERSION_MIN 1
typedef void *HRilHandle;

typedef enum { HRIL_SIM_1, HRIL_SIM_NUM } HRilSimId;

typedef enum {
    HRIL_ERR_SUCCESS = 0,
    HRIL_ERR_INVALID_ARGUMENTS = 1,
    HRIL_ERR_MEMORY_FULL = 2,
} HRilErrno;

/* From 3GPP TS 27.007 V4.3.0 (2001-12) ATD%s%s */
typedef enum {
    HRIL_CALL_ACTIVATE = 0,
    HRIL_CALL_HOLDING = 1,
    HRIL_CALL_DIALING = 2,
    HRIL_CALL_REMIND = 3,
    HRIL_CALL_INCOMING = 4,
    HRIL_CALL_WAITING = 5
} HRilCallState;

typedef enum {
    HRIL_RADIO_POWER_STATE_OFF = 0,
    HRIL_RADIO_POWER_STATE_UNAVAILABLE = 1,
    HRIL_RADIO_POWER_STATE_ON = 2,
} HRilRadioState;

typedef enum {
    HRIL_RADIO_TECHNOLOGY_UNKNOWN,
    HRIL_RADIO_TECHNOLOGY_GSM,
    HRIL_RADIO_TECHNOLOGY_1xRTT,
    HRIL_RADIO_TECHNOLOGY_WCDMA
} HRilRadioAccessTechnology;

/* From 3GPP TS 27.007 V4.3.0 (2001-12)  AT+CGDCONT */
typedef struct {
    HRilCallState state;
    int index;
    int typeOfAddress; /* Type of address octet in integer format (refer TS 24.008 [8] subclause 10.5.4.7);
                        * default 145 when dialling string includes international access code character "+",
                        * otherwise 129. see 3GPP TS 27.007 V4.3.0 (2001-12) 6.1 */
    char isEmpty; /* 0	call is not one of multiparty (conference) call parties
                   * 1	call is one of multiparty (conference) call parties */
    char isMT; /* integer type; call identification number as described in 3GPP TS 22.030 [19] subclause 4.5.5.1;
                * this number can be used in +CHLD command operations
                * 0	mobile originated (MO) call
                * 1	mobile terminated (MT) call */
    char als; /* Alternate Line Service */
    char isVoice; /* <mode> (bearer/teleservice): voice call */
    char isPrivacyMode; /* value is true when CDMA voice privacy mode was activated */
    char *remoteNumber; /* Parameters <n> and <m> are used to enable/disable the presentation of incoming
                         * User-to-User Information Elements.When <n> = 1 and a User-to-User Information is
                         * received after a mobile originated call setup or after hanging up a call, intermediate
                         * result code +CUUS1I: <messageI>,<UUIE> is sent to the TE. When <m> = 1 and a
                         * User-to-User Information is received during a mobile terminated call setup or during a
                         * remote party call hangup, unsolicited result code +CUUS1U: <messageU>,<UUIE> is sent to
                         * the TE. */
    int numberRemind; /* The command refers to an integer that allows a called party to enable or disable (<n>=0)
                       * the reporting of the ID of calling parties, and specifies the method of presentation of
                       * the ID. This is basically the same as GSM/UMTS supplementary service CLIP (Calling Line
                       * Identification Presentation). The presentation may be either formatted (<n>=1) or
                       * unformatted (<n>=2): Formatted presentation : data items are reported in the form of
                       * <tag>=<value> pairs. <tag>		<value> DATE		MMDD (month, day) TIME		HHMM (hour,
                       * minute) NMBR		calling number or P or O (P = number is private, O = number is
                       * unavailable) NAME		subscription listing name MESG		data from other (unknown) tags
                       */
    char *remoteName; /* Remote party name */
    int nameRemind; /* This command refers to the GSM/UMTS supplementary service CLIP (Calling Line
                     * Identification Presentation) that enables a called subscriber to get the calling line
                     * identity (CLI) of the calling party when receiving a mobile terminated call. Set command
                     * enables or disables the presentation of the CLI at the TE. It has no effect on the execution
                     * of the supplementary service CLIP in the network. */
} HRilCallInfo;

typedef struct {
    int state; /* from 3GPP TS 27.007 10.1.10 V4.3.0 (2001-12)
                * indicates the state of PDP context activation
                * 0 - deactivated
                * 1 - activated */
    int retryTime; /* if errorCode != 0, suggested retry time */
    int cid; /* from 3GPP TS 27.007 10.1.1 V4.3.0 (2001-12)
              * specifies a particular PDP context definition. The parameter is local to the TE-MT interface and
              * is used in other PDP context-related commands. */
    int active; /* 0: inactive, 1: active(physical link down), 2 : 2=active (physical link up) */
    char *type; /* PDP_type values from 3GPP TS 27.007 section 10.1.1.
                 * specifies the type of packet data protocol. The default value is manufacturer specific. */
    char *netPortName; /* Network interface name */
    char *address; /*  from 3GPP TS 27.007 10.1.1 V4.3.0 (2001-12)
                    *  a string parameter that identifies the MT in the address space applicable to the PDP. */
    char *dns; /* If the MT indicates more than two IP addresses of P-CSCF servers
                * or more than two IP addresses of DNS servers,
                * multiple lines of information per <cid> will be returned.
                * If the MT has dual stack capabilities,
                * First one line with the IPv4 parameters followed by one line with the IPv6 parameters. */
    char *gateway; /* network gateway address */
    int mtu; /* Maximum Transfer Unit. The range of permitted values (minimum value = 1
              * or if the initial PDP context is supported minimum value = 0)
              * is returned by the test form of the command. */
} HRilDataCallResponse;

typedef enum {
    RADIO_TECH_3GPP = 1, /* 3GPP Technologies (GSM, WCDMA) */
    RADIO_TECH_3GPP2 = 2 /* 3GPP2 Technologies (CDMA) */
} HRilRadioTechnologyFamily;

typedef struct {
    int msgRef; /* TP-Message-Reference for GSM, and BearerData MessageId for CDMA
                 * from 3GPP2 C.S0015-B, v2.0, 4.5-1 */
    char *pdu; /* Protocol Data Unit */
    int errCode; /* if unknown or not applicable, that is -1
                  * from 3GPP 27.005, 3.2.5 for GSM/UMTS,
                  * 3GPP2 N.S0005 (IS-41C) Table 171 for CDMA */
} HRilSmsResponse;

/* From 3GPP TS 27.007 V4.3.0 (2001-12) ATD%s%s */
typedef struct {
    char *address; /* Type of address octet in integer format (refer TS 24.008 [8] subclause 10.5.4.7);
                    * default 145 when dialling string includes international access code character "+", otherwise
                    * 129.
                    * */
    int clir; /* This command refers to CLIR service according to 3GPP TS 22.081 [3] that allows a calling subscriber
               * to enable or disable the presentation of the CLI to the called party when originating a call. <n>
               * (parameter sets the adjustment for outgoing calls): 0	presentation indicator is used according to
               * the subscription of the CLIR service 1	CLIR invocation 2	CLIR suppression <m> (parameter shows
               * the subscriber CLIR service status in the network): 0	CLIR not provisioned 1	CLIR provisioned in
               * permanent mode 2	unknown (e.g. no network, etc.) 3	CLIR temporary mode presentation restricted
               * 4	CLIR temporary mode presentation allowed */
} HRilDial;

/* Form 3GPP TS 27.007 V4.3.0 (2001-12) 8.18, + CRSM */
typedef struct {
    int command; /* This command related to a network service that provides "multiple called numbers
                  * (called line identifications) service" to an MT. This command enables a called subscriber to
                  * get the called line identification of the called party when receiving a mobile terminated call.
                  * Set command enables or disables the presentation of the called line identifications at the TE.
                  <n> (parameter sets/shows the result code presentation status in the TA):
                  * 0	disable
                  * 1	enable
                  * <m> (parameter shows the subscriber "multiple called numbers" service status in the network):
                  * 0	"multiple called numbers service" is not provisioned
                  * 1	"multiple called numbers service" is provisioned
                  * 2	unknown (e.g. no network, etc.)
                  * <number>: string type phone number of format specified by <type>
                  * <type>: type of address octet in integer format (refer TS 24.008 [8] subclause 10.5.4.7)
                  * <subaddr>: string type subaddress of format specified by <satype>
                  * <satype>: type of subaddress octet in integer format (refer TS 24.008 [8] subclause 10.5.4.8) */
    int fileid; /* By using this command instead of Generic SIM Access +CSIM TE application has easier
                 * but more limited access to the SIM database. Set command transmits to the ME the SIM <command>
                 * and its required parameters. ME handles internally all SIM ME interface locking and file
                 * selection routines. As response to the command, ME sends the actual SIM information parameters
                 * and response data. ME error result code +CME ERROR may be returned when the command cannot be
                 * passed to the SIM, but failure in the execution of the command in the SIM is reported in <sw1>
                 * and <sw2> parameters. Refer to subclause 9.2 for <err> values. <command> (command passed on by
                 * the ME to the SIM; refer GSM 51.011 [28]): 176	READ BINARY 178	READ RECORD 192	GET RESPONSE 214
                 * UPDATE BINARY 220	UPDATE RECORD 242	STATUS all other values are reserved */
    char *path; /* Action command returns the MSISDNs related to the subscriber (this information can be stored
                 * in the SIM/UICC or in the ME).
                 * <typex>: type of address octet in integer format (refer TS 24.008 [8] subclause 10.5.4.7)
                 * <speed>: as defined in subclause 6.7
                 * <service> (service related to the phone number):
                 * 0	asynchronous modem eth0
                 * 1	synchronous modem
                 * 2	PAD Access (asynchronous)
                 * 3	Packet Access (synchronous)
                 * 4	voice
                 * 5	fax */
    int p1; /* By using this command instead of Generic SIM Access +CSIM TE application has easier but
             * more limited access to the SIM database. parameters passed on by the ME to the SIM.
             * <P1>, <P2>, <P3>: integer type; parameters passed on by the ME to the SIM.
             * These parameters are mandatory for every command, except GET RESPONSE and STATUS.
             * The values are described in GSM 51.011 [28]. */
    int p2; /* By using this command instead of Generic SIM Access +CSIM TE application has easier but
             * more limited access to the SIM database. parameters passed on by the ME to the SIM.
             * <P1>, <P2>, <P3>: integer type; parameters passed on by the ME to the SIM.
             * These parameters are mandatory for every command, except GET RESPONSE and STATUS.
             * The values are described in GSM 51.011 [28]. */
    int p3; /* By using this command instead of Generic SIM Access +CSIM TE application has easier but
             * more limited access to the SIM database. parameters passed on by the ME to the SIM.
             * <P1>, <P2>, <P3>: integer type; parameters passed on by the ME to the SIM.
             * These parameters are mandatory for every command, except GET RESPONSE and STATUS.
             * The values are described in GSM 51.011 [28]. */
    char *data; /* By using this command instead of Generic SIM Access +CSIM TE application has easier but
                 * more limited access to the SIM database.
                 * <data>: information which shall be written to the SIM (hexadecimal character format; refer
                 * +CSCS) */
    char *pin2;
    char *aid; /* AID value, from ETSI 102.221 8.1 and 101.220 4, if no value that is NULL */
} HRilSimIO;

/* Form TS 27.007.8.18 +CRSM */
typedef struct {
    int sw1; /* By using this command instead of Generic SIM Access +CSIM TE application has easier but
              * more limited access to the SIM database.
              * <sw1>, <sw2>: integer type; information from the SIM about the execution of the actual command.
              * These parameters are delivered to the TE in both cases, on successful or
              * failed execution of the command */
    int sw2; /* By using this command instead of Generic SIM Access +CSIM TE application has easier but
              * more limited access to the SIM database.
              * <sw1>, <sw2>: integer type; information from the SIM about the execution of the actual command.
              * These parameters are delivered to the TE in both cases, on successful or
              * failed execution of the command */
    char *response; /* By using this command instead of Generic SIM Access +CSIM TE application has easier but
                     * more limited access to the SIM database.
                     * <response>: response of a successful completion of the command previously issued
                     * (hexadecimal character format; refer +CSCS). STATUS and GET RESPONSE return data,
                     * which gives information about the current
                     * elementary datafield.  After READ BINARY or READ RECORD command
                     * the requested data will be returned. <response> is not returned
                     * after a successful UPDATE BINARY or UPDATE RECORD command */
} HRilSimIOResponse;

typedef enum {
    HRIL_CALL_FAIL_NO_VALID_NUMBER = 1,
    HRIL_CALL_FAIL_NO_LINE_TO_TARGET_ADDRESS = 3
} HRilLastCallErrorCode;

typedef struct {
    HRilLastCallErrorCode errorCode; /* Execution command causes the TA to return one or more lines of information
                                      * text <report>, determined by the ME manufacturer, which should offer
                                      * the user of the TA an extended report of the reason for
                                      * the failure in the last unsuccessful call setup (originating or answering) or
                                      * in call modification;
                                      * the last call release;
                                      * the last unsuccessful GPRS attach or unsuccessful PDP context activation;
                                      * the last GPRS detach or PDP context deactivation. */
    char *vendorError; /* Error codes of vendor. */
} HRilLastCallErrorCodeInfo;

typedef enum { HRIL_ABSENT = 0, HRIL_PRESENT = 1, HRIL_ERROR = 2, HRIL_RESTRICTED = 3 } HRilIccCardState;

typedef enum {
    HRIL_SIMLOCK_UNKNOWN = 0,
    HRIL_SIMLOCK_IN_PROGRESS = 1,
    HRIL_SIMLOCK_READY = 2,
} HRilIccSimLockSub;

typedef enum {
    HRIL_UNKNOWNSTATE = 0,
    HRIL_DETECTED = 1,
    HRIL_PIN = 2,
    HRIL_PUK = 3,
    HRIL_SIMLOCK = 4,
    HRIL_STATEREADY = 5
} HRilIccStatus;

typedef enum {
    HRIL_PIN_STATE_UNKNOWN,
    HRIL_PIN_NOT_VERIFIED,
    HRIL_PIN_VERIFIED,
    HRIL_PIN_DISABLED,
    HRIL_PIN_BLOCKED_ENABLED,
    HRIL_PIN_BLOCKED_PERM
} HRilIccPinState;

typedef enum {
    HRIL_UNKNOWNTYPE = 0,
    HRIL_SIM = 1,
    HRIL_USIM = 2,
    HRIL_RUIM = 3,
    HRIL_CSIM = 4,
    HRIL_ISIM = 5
} HRilIccType;

#define HRIL_SIM_MAX_APPS 8
typedef struct {
    HRilIccType iccType;
    HRilIccStatus iccStatus;
    HRilIccSimLockSub SimLockSubState;
    char *aid;
    char *iccTag;
    int substitueOfPin1;
    HRilIccPinState stateOfPin1;
    HRilIccPinState stateOfPin2;
} HRilIccContent;

typedef struct {
    HRilIccCardState cardState;
    HRilIccPinState pinState;
    int contentIndexOfGU;
    int contentIndexOfCdma;
    int contentIndexOfIms;
    int iccContentNum;
    HRilIccContent iccContent[HRIL_SIM_MAX_APPS];
} HRilIccState;

/* From 3GPP TS 27.007 8.5 */
typedef struct {
    int rssi; /* Execution command returns received signal strength indication.
               * Refer subclause 9.2 . From 3GPP TS 27.007 V4.3.0  */
    int ber; /* bit error rate, value range 0 ~ 7, max is 99, if unknown then set to max */
} HRilGwRssi;

/* From 3GPP TS 27.007 V4.3.0 (2001-12) AT+CSQ */
typedef struct {
    int rssi; /* Received Signal Strength Indication, value range 0 ~ 31, max is 99, if unknown then set to max */
    int ber; /* bit error rate, value range 0 ~ 7, max is 99, if unknown then set to max */
    int ta; /* Timing Advance in bit periods. if unknown then set to max, e.g: 1 bit period = 48/13 us */
} HRilGsmRssi;

/* From 3GPP TS 27.007 8.5 */
typedef struct {
    int rssi; /* Received Signal Strength Indication, value range 0 ~ 31, max is 99, if unknown then set to max */
    int ber; /* bit error rate, value range 0 ~ 7, max is 99, if unknown then set to max */
} HRilWcdmaRssi;

/* From 3GPP TS 27.007 8.69 */
typedef struct {
    int absoluteRssi; /* Absolute value of signal strength.  This value is the actual Rssi value
                       * multiplied by -1.
                       * e.g: Rssi is -75, then this response value will be 75 */
    int ecno; /* ratio of the received energy per PN chip to the total received power spectral density,
               * e.g: If the actual Ec/Io is -12.5 dB, then this response value will be 125.
               * from 3GPP TS 25.133[95] */
} HRilCdmaRssi;

typedef struct {
    HRilGwRssi gwRssi;
    HRilCdmaRssi cdmaRssi;
} HRilRssi;

typedef void (*HRilRequestFunc)(int request, void *data, size_t dataLen, HRilHandle t);

typedef HRilRadioState (*HRilRadioStateRequest)();

typedef int (*HRilSupports)(int requestCode);

typedef void (*HRilCancel)(HRilHandle t);

typedef void (*HRilTimedCallback)(void *param);

typedef const char *(*HRilGetVersion)(void);

typedef struct {
    int version; /* set to HRIL_VERSION */
    HRilRequestFunc onRequest;
    HRilRadioStateRequest onStateRequest;
    HRilSupports supports;
    HRilCancel onCancel;
    HRilGetVersion getVersion;
} VendorCallbacks;

struct HRilInitEnv {
    void (*OnRequestResponse)(HRilHandle t, HRilErrno e, void *response, size_t responseLen);

    void (*OnUnsolicitedResponse)(int unsolResponse, const void *data, size_t dataLen);

    void (*RequestTimedCallback)(HRilTimedCallback callback, void *param, const struct timeval *relativeTime);

    void (*OnRequestAck)(HRilHandle t);
};

const VendorCallbacks *RilInit(const struct HRilInitEnv *env, int argc, char **argv);

#endif // OHOS_RIL_H