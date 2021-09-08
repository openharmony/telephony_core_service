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

#ifndef DATA_STORAGE_SMS_DATA_H
#define DATA_STORAGE_SMS_DATA_H

namespace OHOS {
namespace Telephony {
const std::string MSG_ID = "msg_id";
const std::string RECEIVER_NUMBER = "receiver_number";
const std::string SENDER_NUMBER = "sender_number";
const std::string START_TIME = "start_time";
const std::string END_TIME = "end_time";
const std::string MSG_TYPE = "msg_type";
const std::string MSG_TITLE = "msg_title";
const std::string MSG_CONTENT = "msg_content";
const std::string MSG_STATE = "msg_state";
const std::string MSG_CODE = "msg_code";
const std::string IS_LOCK = "is_lock";
const std::string IS_READ = "is_read";
const std::string IS_COLLECT = "is_collect";
const std::string SESSION_TYPE = "session_type";
const std::string RETRY_NUMBER = "retry_number";
const std::string ATTACHMENT_TYPE = "attachment_type";
const std::string ATTACHMENT_PATH = "attachment_path";
const std::string ATTACHMENT_FAILURE_TIME = "attachment_failure_time";
const std::string OPERATOR_SERVICE_NUMBER = "operator_service_number";
const std::string SESSION_ID = "session_id";
const std::string GROUP_ID = "group_id";
const std::string PDU_ID = "pdu_id";

struct MessageInfo {
    int msgId;
    std::string receiverNumber;
    std::string senderNumber;
    std::string startTime;
    std::string endTime;
    int msgType;
    std::string msgTitle;
    std::string msgContent;
    int msgState;
    std::string operatorServiceNumber;
    int msgCode;
    int isLock;
    int isRead;
    int isCollect;
    int sessionType;
    int retryNumber;
    int attachmentType;
    std::string attachmentPath;
    std::string attachmentFailureTime;
    int pdu_id;
    int sessionId;
    int groupId;
};

enum MsgType { SMS = 0, MMS };

enum MsgState { UNSENT = 0, FAILED, PENDING, SUCCEED };

const std::string uri = "dataability://telephony.sms";

enum class MessageUriType : int32_t {
    ALL,
    MMS,
    SMS,
    UNREAD,
    READ,
    UNLOCK,
    LOCK,
    COLLECT,
    CANCEL_COLLECT,
    DELETE_BY_IDS,
    DELETE_THIRTY_DATA,
    SELECT_BY_NUMBER,
    SELECT_COLLECT_DATA,
    MARK_READ
};
} // namespace Telephony
} // namespace OHOS
#endif // DATA_STORAGE_SMS_DATA_H
