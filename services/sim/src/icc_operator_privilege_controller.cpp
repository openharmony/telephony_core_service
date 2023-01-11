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

#include "icc_operator_privilege_controller.h"

#include <algorithm>
#include <charconv>
#include <chrono>
#include <mutex>

#include "inner_event.h"
#include "sim_data_type.h"
#include "telephony_log_wrapper.h"
#include "radio_event.h"

namespace OHOS {
namespace Telephony {
constexpr std::string_view ARAM_AID = "A00000015141434C00";
constexpr int32_t CLA = 0x80;
constexpr int32_t COMMAND = 0xCA;
constexpr int32_t P1 = 0xFF;
constexpr int32_t P2 = 0x40;
constexpr int32_t P2_EXTENDED_DATA = 0x60;
constexpr int32_t P3 = 0x00;
constexpr int32_t INT32_INTVALUE = 0;
constexpr int32_t INT32_ZERO = 0;
constexpr int32_t INT32_FST_NEGATIVE = -1;
constexpr size_t FST_POS = 0;
constexpr size_t TAG_BYTES = 4;
constexpr size_t LEN_BYTES = 2;
constexpr size_t CHR_BYTES = 2;
constexpr int32_t HEX = 16;

static std::string_view Strip(const std::string_view &src)
{
    size_t length = src.size();
    while (length && std::isspace(src.at(length - 1))) {
        --length;
    }
    size_t pos = FST_POS;
    for (; pos < src.size(); ++pos) {
        if (!std::isspace(src.at(pos))) {
            break;
        }
    }
    if (length <= pos) {
        return "";
    }
    return src.substr(pos, length - pos);
}

static bool IsOneTlvCompleted(const std::string_view &s)
{
    if (s.size() < (TAG_BYTES + LEN_BYTES)) {
        return false;
    }
    auto lenStr = s.substr(FST_POS + TAG_BYTES, LEN_BYTES);
    size_t len = 0;
    std::from_chars(std::addressof(lenStr.front()), std::addressof(lenStr.back()), len, HEX);
    return (s.size() >= ((CHR_BYTES * len) + TAG_BYTES + LEN_BYTES));
}

static AppExecFwk::InnerEvent::Pointer GenCallBackEvent(
    const std::shared_ptr<AppExecFwk::EventHandler> &owner, const uint32_t eventId)
{
    AppExecFwk::InnerEvent::Pointer event = AppExecFwk::InnerEvent::Get(eventId);
    if (event == nullptr) {
        TELEPHONY_LOGE("event is nullptr!");
        return AppExecFwk::InnerEvent::Pointer(nullptr, nullptr);
    }
    event->SetOwner(owner);
    return event;
}

class IccOperatorPrivilegeController::LogicalStateMachine {
    static constexpr size_t CALL_TIMEOUT = 60;
    static constexpr size_t TRANSMIT_TIMEOUT = CALL_TIMEOUT * 3;
    static constexpr size_t TIME_SLICE = 100;
    bool isTransmitting_ = false;
    bool isAvailable_ = false;
    mutable std::mutex mtx_;
    mutable std::condition_variable cv_;

public:
    std::chrono::system_clock::time_point openChannelTp = std::chrono::system_clock::now();
    int32_t currentChannelId = INT32_FST_NEGATIVE;
    std::string currData;

public:
    LogicalStateMachine() = default;

    inline bool IsTimeOut() const
    {
        return IsTimeOut(openChannelTp, TRANSMIT_TIMEOUT);
    }

    inline bool IsTimeOut(const std::chrono::system_clock::time_point &tp, const size_t timeout = CALL_TIMEOUT) const
    {
        auto now = std::chrono::system_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::seconds>(now - tp).count();
        auto seconds = static_cast<size_t>(duration);
        return seconds > timeout;
    }

    bool IsAppropriateToOpenChannel() const
    {
        if (currentChannelId < INT32_INTVALUE) {
            return true;
        }
        if (IsTimeOut()) {
            return true;
        }
        return false;
    }

    inline bool IsSimAvailable() const
    {
        return isAvailable_;
    }

    void SetSimAvailable(const bool available)
    {
        isAvailable_ = available;
        if (!isAvailable_) {
            currentChannelId = INT32_FST_NEGATIVE;
        }
        cv_.notify_one();
    }

    void SetForOpenChannel()
    {
        isTransmitting_ = true;
        currData.clear();
        openChannelTp = std::chrono::system_clock::now();
        currentChannelId = INT32_ZERO;
        cv_.notify_one();
    }

    void SetForCloseChannel()
    {
        isTransmitting_ = false;
        cv_.notify_one();
    }

    bool SuccessLoaded(const size_t timeSlice = TIME_SLICE) const
    {
        auto now = std::chrono::system_clock::now();
        std::unique_lock<std::mutex> lck(mtx_);
        while (isAvailable_ && isTransmitting_) {
            cv_.wait_for(lck, std::chrono::milliseconds(timeSlice));
            if (IsTimeOut(now)) {
                return false;
            }
        }
        return isAvailable_ && !isTransmitting_;
    }
};

IccOperatorPrivilegeController::IccOperatorPrivilegeController(std::shared_ptr<AppExecFwk::EventRunner> runner,
    std::shared_ptr<Telephony::ITelRilManager> telRilManager,
    std::shared_ptr<SimStateManager> simStateManager)
    : AppExecFwk::EventHandler(runner), slotId_(0), telRilManager_(telRilManager),
      simStateManager_(simStateManager), state_(new IccOperatorPrivilegeController::LogicalStateMachine())
{}

IccOperatorPrivilegeController::~IccOperatorPrivilegeController()
{
    delete state_;
}

void IccOperatorPrivilegeController::Init(const int32_t slotId)
{
    this->slotId_ = slotId;
    TELEPHONY_LOGI("IccOperatorPrivilegeController::Init begin");
    if (telRilManager_ == nullptr) {
        TELEPHONY_LOGE("telRilManager_ can not be nullptr!!");
        return;
    }
    if (simStateManager_ == nullptr) {
        TELEPHONY_LOGE("simStateManager_ can not be nullptr!!");
        return;
    }
    if (this->GetEventRunner() == nullptr) {
        auto runner = AppExecFwk::EventRunner::Create("UsimOperatorPrivilegeManager");
        if (runner == nullptr) {
            TELEPHONY_LOGE("IccOperatorPrivilegeController::Init Create thread fail!");
            return;
        }
        this->SetEventRunner(runner);
        if (runner->Run() != ERR_OK) {
            TELEPHONY_LOGE("runner->Run() fail!!");
        }
    }
    auto self = this->shared_from_this();
    simStateManager_->RegisterCoreNotify(self, RadioEvent::RADIO_SIM_STATE_CHANGE);
    /* try to load data */
    ProcessSimStateChanged();
}
int32_t IccOperatorPrivilegeController::HasOperatorPrivileges(bool &hasOperatorPrivileges)
{
    constexpr std::string_view certHash = "ABCD92CBB156B280FA4E1429A6ECEEB6E5C1BFE4";
    constexpr std::string_view packageName = "com.ohos.openharmony";
    return HasOperatorPrivileges(certHash, packageName, hasOperatorPrivileges);
}

int32_t IccOperatorPrivilegeController::HasOperatorPrivileges(
    const std::string_view &certHash, const std::string_view &packageName, bool &hasOperatorPrivileges)
{
    TELEPHONY_LOGI("IccOperatorPrivilegeController::HasOperatorPrivileges begin");
    constexpr int32_t RETRY_TIMES = 3;
    for (int32_t i = INT32_ZERO; i < RETRY_TIMES; ++i) {
        const bool isLoaded = state_->SuccessLoaded();
        if (isLoaded) {
            break;
        }
        if (state_->IsTimeOut()) {
            TELEPHONY_LOGI("retry to load data times %{public}d", i + 1);
            ProcessSimStateChanged(); // retry to load
        }
    }
    if (!state_->IsSimAvailable()) {
        TELEPHONY_LOGE(
            "IccOperatorPrivilegeController::HasOperatorPrivileges false with rules.size:%{public}zu and "
            "simState:%{public}d",
            rules_.size(),
            ((simStateManager_ == nullptr) ? SimState::SIM_STATE_UNKNOWN : simStateManager_->GetSimState()));
        hasOperatorPrivileges = false;
        return TELEPHONY_ERR_NO_SIM_CARD;
    }
    if (!rules_.empty()) {
        auto hash = Strip(certHash);
        auto package = Strip(packageName);
        for (const auto &rule : rules_) {
            if (rule.Matche(hash, package)) {
                TELEPHONY_LOGI("already found rule to match then return true");
                hasOperatorPrivileges = true;
                return TELEPHONY_ERR_SUCCESS;
            }
        }
    }
    TELEPHONY_LOGE("no rule can match then return false");
    hasOperatorPrivileges = false;
    return TELEPHONY_ERR_SUCCESS;
}

void IccOperatorPrivilegeController::ProcessEvent(const AppExecFwk::InnerEvent::Pointer &event)
{
    if (event == nullptr) {
        TELEPHONY_LOGE("event is nullptr!");
        return;
    }
    const uint32_t id = event->GetInnerEventId();
    switch (id) {
        case RadioEvent::RADIO_SIM_STATE_CHANGE:
            ProcessSimStateChanged();
            break;
        case MSG_OPEN_LOGICAL_CHANNEL_DONE:
            ProcessOpenLogicalChannelDone(event);
            break;
        case MSG_TRANSMIT_LOGICAL_CHANNEL_DONE:
            ProcessTransmitLogicalChannelDone(event);
            break;
        case MSG_CLOSE_LOGICAL_CHANNEL_DONE:
            ProcessCloseLogicalChannelDone();
            break;
        default:
            break;
    }
}

void IccOperatorPrivilegeController::ProcessSimStateChanged()
{
    const SimState state = simStateManager_->GetSimState();
    TELEPHONY_LOGI("ProcessSimStateChanged simState:%{public}d", state);
    switch (state) {
        case SimState::SIM_STATE_UNKNOWN:
        case SimState::SIM_STATE_NOT_READY:
        case SimState::SIM_STATE_NOT_PRESENT:
            TELEPHONY_LOGI("GetSimState is %{public}d then Operator privilege can not cussess loaded", state);
            state_->SetSimAvailable(false);
            rules_.clear();
            break;
        case SimState::SIM_STATE_LOADED:
        case SimState::SIM_STATE_READY:
            TELEPHONY_LOGI("GetSimState is %{public}d then try to reload operator privilege!", state);
            state_->SetSimAvailable(true);
            /* try to reload */
            OpenChannel();
            break;
        default:
            break;
    }
}

void IccOperatorPrivilegeController::OpenChannel()
{
    TELEPHONY_LOGI("IccOperatorPrivilegeController::openChannel begin");
    if (!state_->IsAppropriateToOpenChannel()) {
        TELEPHONY_LOGI("now is not appropriate to open a new logical channel!!");
        return;
    }
    TELEPHONY_LOGI("will to SimOpenLogicalChannel!");
    rules_.clear();
    state_->SetForOpenChannel();
    auto response = GenCallBackEvent(shared_from_this(), MSG_OPEN_LOGICAL_CHANNEL_DONE);
    telRilManager_->SimOpenLogicalChannel(slotId_, ARAM_AID.data(), P2, response);
}

void IccOperatorPrivilegeController::ProcessOpenLogicalChannelDone(const AppExecFwk::InnerEvent::Pointer &event)
{
    TELEPHONY_LOGI("Open Logical Channel Done!!");
    const bool timeout = state_->IsTimeOut();
    if (timeout) {
        TELEPHONY_LOGE("OpenLogical fail at isTimeout[%{public}d]", timeout);
        state_->SetForCloseChannel();
        state_->currentChannelId = INT32_FST_NEGATIVE;
        return;
    }
    TELEPHONY_LOGI("Will to SimTransmitApduLogicalChannel");
    auto resultPtr = event->GetUniqueObject<OpenLogicalChannelResponse>();
    if (resultPtr == nullptr) {
        TELEPHONY_LOGE("the data of result is nullptr! then will Close Logical Channel");
        return;
    }
    state_->currentChannelId = resultPtr->channelId;
    if (state_->currentChannelId <= INT32_ZERO) {
        TELEPHONY_LOGE("the logical channel transmit Unexpected shutdown");
        return;
    }
    auto transmitEvent = GenCallBackEvent(shared_from_this(), MSG_TRANSMIT_LOGICAL_CHANNEL_DONE);
    ApduSimIORequestInfo reqInfo;
    reqInfo.channelId = state_->currentChannelId;
    reqInfo.type = CLA;
    reqInfo.instruction = COMMAND;
    reqInfo.p1 = P1;
    reqInfo.p2 = P2;
    reqInfo.p3 = P3;
    reqInfo.data = "";
    telRilManager_->SimTransmitApduLogicalChannel(slotId_, reqInfo, transmitEvent);
}

void IccOperatorPrivilegeController::ProcessTransmitLogicalChannelDone(const AppExecFwk::InnerEvent::Pointer &event)
{
    TELEPHONY_LOGI("Transmit Logical Channel Done!!");
    auto resultPtr = event->GetUniqueObject<IccIoResultInfo>();
    do {
        if (resultPtr == nullptr) {
            TELEPHONY_LOGE("the data of result is nullptr! then will Close Logical Channel");
            break;
        }
        if (state_->currentChannelId <= INT32_ZERO) {
            TELEPHONY_LOGE("the logical channel transmit Unexpected shutdown");
            break;
        }
        if (state_->IsTimeOut()) {
            TELEPHONY_LOGE("the logical channel transmit is timeout");
            break;
        }
        state_->currData += resultPtr->response;
        if (!IsOneTlvCompleted(state_->currData)) {
            TELEPHONY_LOGI("need continue load TLV data");
            auto transmitEvent = GenCallBackEvent(shared_from_this(), MSG_TRANSMIT_LOGICAL_CHANNEL_DONE);
            ApduSimIORequestInfo reqInfo;
            reqInfo.channelId = state_->currentChannelId;
            reqInfo.type = CLA;
            reqInfo.instruction = COMMAND;
            reqInfo.p1 = P1;
            reqInfo.p2 = P2_EXTENDED_DATA;
            reqInfo.p3 = P3;
            reqInfo.data = "";
            telRilManager_->SimTransmitApduLogicalChannel(slotId_, reqInfo, transmitEvent);
            return;
        }
        if (!IccOperatorRule::CreateFromTLV(state_->currData, rules_)) {
            TELEPHONY_LOGE("Parse TLV data to Rules fail");
            break;
        }
    } while (false);
    auto closeEvent = GenCallBackEvent(shared_from_this(), MSG_CLOSE_LOGICAL_CHANNEL_DONE);
    if (state_->currentChannelId > INT32_ZERO) {
        telRilManager_->SimCloseLogicalChannel(slotId_, state_->currentChannelId, closeEvent);
    }
    state_->SetForCloseChannel();
    return;
}

void IccOperatorPrivilegeController::ProcessCloseLogicalChannelDone()
{
    TELEPHONY_LOGI("Logical Transmit Cussessfully End!");
    state_->currentChannelId = INT32_FST_NEGATIVE;
}
} // namespace Telephony
} // namespace OHOS
