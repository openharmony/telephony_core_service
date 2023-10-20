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
#include "time_zone_location_suggester.h"

#include "i18n_timezone.h"
#include "telephony_log_wrapper.h"
#include "time_service_client.h"
#include "time_zone_manager.h"

namespace OHOS {
namespace Telephony {
using namespace AppExecFwk;

constexpr int32_t INVALID_LAC = 0;
constexpr int64_t TIME_MS_TO_NS = 1000000;
constexpr double LOCATION_UPDATE_DISTANCE = 100 * 10000; // 100km
constexpr int64_t LOCATION_EXPIRATION_TIME_MS = 60 * 60 * 1000;
constexpr int64_t LOCATION_EXPIRATION_TIME_MS_ROAMING = 30 * 60 * 1000;

State::State(std::weak_ptr<TimeZoneLocationSuggester> &&locationSuggester, std::string &&name)
    : locationSuggester_(std::move(locationSuggester)), name_(std::move(name))
{}

void State::SetParentState(sptr<State> &parent)
{
    parent_ = parent;
}

std::string State::GetStateMachineName() const
{
    return name_;
}

StateMachineEventHandler::StateMachineEventHandler(const std::shared_ptr<EventRunner> &runner) : EventHandler(runner) {}

void StateMachineEventHandler::SetOriginalState(sptr<State> &originalState)
{
    originalState_ = originalState;
}

void StateMachineEventHandler::TransitionTo(sptr<State> &destState)
{
    TELEPHONY_LOGI("State machine transition to %{public}s", destState->name_.c_str());
    destState_ = destState;
}

void StateMachineEventHandler::Quit()
{
    sptr<State> tmpState = curState_;
    while (tmpState != nullptr && tmpState->isActive_) {
        tmpState->StateEnd();
        tmpState = tmpState->parent_;
        isQuit_ = true;
    }
}

void StateMachineEventHandler::ProcessTransitions(const InnerEvent::Pointer &event)
{
    if (curState_ == destState_) {
        return;
    }
    if (curState_ != nullptr) {
        sptr<State> tmpState = curState_->parent_;
        while (tmpState != nullptr) {
            tmpState->StateEnd();
            tmpState = tmpState->parent_;
        }
        curState_->StateEnd();
    }
    if (destState_ != nullptr) {
        sptr<State> tmpState = destState_->parent_;
        while (tmpState != nullptr) {
            tmpState->StateBegin();
            tmpState = tmpState->parent_;
        }
        destState_->StateBegin();
    }
    curState_ = destState_;
    SendDeferredEvent();
}

void StateMachineEventHandler::DeferEvent(InnerEvent::Pointer &&event)
{
    std::lock_guard<std::mutex> guard(mtx_);
    deferEvents_.push_back(std::move(event));
}

void StateMachineEventHandler::ProcessEvent(const InnerEvent::Pointer &event)
{
    if (event == nullptr || isQuit_) {
        TELEPHONY_LOGE("The event parameter is incorrect");
        return;
    }
    if (event->GetInnerEventId() == TimeZoneEventCode::STATE_MACHINE_QUIT) {
        TELEPHONY_LOGI("State machine exit");
        Quit();
        return;
    }
    if (event->GetInnerEventId() == TimeZoneEventCode::STATE_MACHINE_INIT) {
        destState_ = originalState_;
        InitCmdEnter(originalState_);
    }
    ProcessMsg(event);
    ProcessTransitions(event);
}

void StateMachineEventHandler::ProcessMsg(const InnerEvent::Pointer &event)
{
    sptr<State> tmpState = curState_;
    while (tmpState != nullptr && !tmpState->StateProcess(event)) {
        tmpState = tmpState->parent_;
    }
}

void StateMachineEventHandler::InitCmdEnter(const sptr<State> &state)
{
    if (state == nullptr) {
        TELEPHONY_LOGE("registerState_ is null");
        return;
    }
    if (state->parent_ != nullptr) {
        InitCmdEnter(state->parent_);
    }
    TELEPHONY_LOGI("Initialize entry %{public}s", state->name_.c_str());
    state->StateBegin();
    curState_ = state;
}

void StateMachineEventHandler::SendDeferredEvent()
{
    std::lock_guard<std::mutex> guard(mtx_);
    if (deferEvents_.empty()) {
        return;
    }
    for (size_t i = 0; i < deferEvents_.size(); ++i) {
        InnerEvent::Pointer event = std::move(deferEvents_[i]);
        SendImmediateEvent(event);
    }
    deferEvents_.clear();
}

StateMachine::StateMachine(const std::shared_ptr<EventRunner> &runner)
{
    stateMachineEventHandler_ = std::make_shared<StateMachineEventHandler>(runner);
    if (stateMachineEventHandler_ == nullptr) {
        TELEPHONY_LOGE("stateMachineEventHandler_ is null");
        return;
    }
}

void StateMachine::Quit()
{
    InnerEvent::Pointer event = InnerEvent::Get(TimeZoneEventCode::STATE_MACHINE_QUIT);
    if (stateMachineEventHandler_ == nullptr) {
        TELEPHONY_LOGE("stateMachineEventHandler_ is null");
        return;
    }
    stateMachineEventHandler_->SendImmediateEvent(event);
}

void StateMachine::Start()
{
    if (stateMachineEventHandler_ == nullptr) {
        TELEPHONY_LOGE("stateMachineEventHandler_ is null");
        return;
    }
    InnerEvent::Pointer event = InnerEvent::Get(TimeZoneEventCode::STATE_MACHINE_INIT);
    stateMachineEventHandler_->SendImmediateEvent(event);
}

void StateMachine::SetOriginalState(sptr<State> &originalState)
{
    if (originalState == nullptr) {
        TELEPHONY_LOGE("originalState is null");
        return;
    }
    if (stateMachineEventHandler_ == nullptr) {
        TELEPHONY_LOGE("stateMachineEventHandler_ is null");
        return;
    }
    stateMachineEventHandler_->SetOriginalState(originalState);
}

void StateMachine::TransitionTo(sptr<State> &destState)
{
    if (destState == nullptr) {
        TELEPHONY_LOGE("destState is null");
        return;
    }
    if (stateMachineEventHandler_ == nullptr) {
        TELEPHONY_LOGE("stateMachineEventHandler_ is null");
        return;
    }
    stateMachineEventHandler_->TransitionTo(destState);
}

void StateMachine::DeferEvent(const InnerEvent::Pointer &&event)
{
    if (stateMachineEventHandler_ == nullptr) {
        TELEPHONY_LOGE("stateMachineEventHandler_ is null");
        return;
    }
    stateMachineEventHandler_->DeferEvent(std::move(const_cast<InnerEvent::Pointer &>(event)));
}

void StateMachine::SendEvent(InnerEvent::Pointer &event)
{
    if (stateMachineEventHandler_ == nullptr) {
        TELEPHONY_LOGE("stateMachineEventHandler_ is null");
        return;
    }
    stateMachineEventHandler_->SendEvent(event);
}

TimeZoneLocationSuggester::TimeZoneLocationSuggester(const std::shared_ptr<EventRunner> &runner) : StateMachine(runner)
{}

void TimeZoneLocationSuggester::Init()
{
    idleState_ =
        new (std::nothrow) IdleState(std::weak_ptr<TimeZoneLocationSuggester>(shared_from_this()), "IdleState");
    nitzState_ =
        new (std::nothrow) NitzState(std::weak_ptr<TimeZoneLocationSuggester>(shared_from_this()), "NitzState");
    locationState_ =
        new (std::nothrow) LocationState(std::weak_ptr<TimeZoneLocationSuggester>(shared_from_this()), "LocationState");
    if (idleState_ == nullptr || nitzState_ == nullptr || locationState_ == nullptr) {
        TELEPHONY_LOGE("state is null");
        return;
    }
    nitzState_->SetParentState(idleState_);
    locationState_->SetParentState(idleState_);
    StateMachine::SetOriginalState(idleState_);
    StateMachine::Start();
}

void TimeZoneLocationSuggester::NitzUpdate()
{
    InnerEvent::Pointer event = InnerEvent::Get(TimeZoneEventCode::EVENT_NITZ_UPDATE);
    SendEvent(event);
}

void TimeZoneLocationSuggester::LocationUpdate(const std::unique_ptr<Location::Location> &location)
{
    if (location == nullptr) {
        TELEPHONY_LOGE("location is null");
        return;
    }
    locationUpdateTime_ = OHOS::MiscServices::TimeServiceClient::GetInstance()->GetBootTimeMs();
    currentLocation_ = std::make_unique<OHOS::Location::Location>(*location);
    InnerEvent::Pointer event = InnerEvent::Get(TimeZoneEventCode::EVENT_LOCATION_UPDATE);
    SendEvent(event);
}

bool TimeZoneLocationSuggester::HasLocation()
{
    return lastLocation_ != nullptr;
}

void TimeZoneLocationSuggester::ClearLocation()
{
    lastLocation_ = nullptr;
}

int64_t TimeZoneLocationSuggester::GetLocationExpirationTime()
{
    bool isRoaming = DelayedSingleton<TimeZoneManager>::GetInstance()->IsRoaming();
    return isRoaming ? LOCATION_EXPIRATION_TIME_MS_ROAMING : LOCATION_EXPIRATION_TIME_MS;
}

bool TimeZoneLocationSuggester::IsLocationExpired()
{
    int64_t lastTime = OHOS::MiscServices::TimeServiceClient::GetInstance()->GetBootTimeMs();
    int64_t expirationTime = GetLocationExpirationTime();
    if (lastTime - locationUpdateTime_ > expirationTime) {
        return true;
    }
    return false;
}

IdleState::IdleState(std::weak_ptr<TimeZoneLocationSuggester> &&locationSuggester, std::string &&name)
    : State(std::move(locationSuggester), std::move(name))
{}

void IdleState::StateBegin()
{
    isActive_ = true;
}

void IdleState::StateEnd()
{
    isActive_ = false;
}

bool IdleState::StateProcess(const InnerEvent::Pointer &event)
{
    TELEPHONY_LOGI("IdleState StateProcess");
    if (event == nullptr) {
        TELEPHONY_LOGE("IdleState event is null");
        return false;
    }
    std::shared_ptr<TimeZoneLocationSuggester> locationSuggester = locationSuggester_.lock();
    if (locationSuggester == nullptr) {
        TELEPHONY_LOGE("IdleState StateMachine is null");
        return false;
    }

    uint32_t eventCode = event->GetInnerEventId();
    switch (eventCode) {
        case TimeZoneEventCode::EVENT_NITZ_UPDATE:
            locationSuggester->nitzUpdateTime_ = OHOS::MiscServices::TimeServiceClient::GetInstance()->GetBootTimeMs();
            locationSuggester->nitzLac_ = DelayedSingleton<TimeZoneManager>::GetInstance()->GetCurrentLac();
            locationSuggester->TransitionTo(locationSuggester->nitzState_);
            return true;
        case TimeZoneEventCode::EVENT_LOCATION_UPDATE:
            if (ShouldUpdateTimeZone()) {
                locationSuggester->TransitionTo(locationSuggester->locationState_);
            }
            return true;
        default:
            break;
    }
    return false;
}

bool IdleState::ShouldUpdateTimeZone()
{
    std::shared_ptr<TimeZoneLocationSuggester> locationSuggester = locationSuggester_.lock();
    if (locationSuggester == nullptr) {
        TELEPHONY_LOGE("IdleState StateMachine is null");
        return false;
    }
    if (locationSuggester->currentLocation_ == nullptr) {
        TELEPHONY_LOGE("IdleState location is null");
        return false;
    }
    if (locationSuggester->lastLocation_ == nullptr || locationSuggester->timeZoneLocation_ == nullptr) {
        locationSuggester->lastLocation_ =
            std::make_unique<OHOS::Location::Location>(*(locationSuggester->currentLocation_));
        TELEPHONY_LOGI("last location is null, should update time zone");
        return true;
    }
    int64_t timeDiff =
        locationSuggester->currentLocation_->GetTimeSinceBoot() - locationSuggester->lastLocation_->GetTimeSinceBoot();
    double distance = Location::CommonUtils::CalDistance(locationSuggester->currentLocation_->GetLatitude(),
        locationSuggester->currentLocation_->GetLongitude(), locationSuggester->lastLocation_->GetLatitude(),
        locationSuggester->lastLocation_->GetLongitude());
    locationSuggester->lastLocation_ =
        std::make_unique<OHOS::Location::Location>(*(locationSuggester->currentLocation_));
    if (timeDiff > locationSuggester->GetLocationExpirationTime() * TIME_MS_TO_NS) {
        return true;
    }
    if (distance > LOCATION_UPDATE_DISTANCE) {
        return true;
    }
    return false;
}

NitzState::NitzState(std::weak_ptr<TimeZoneLocationSuggester> &&locationSuggester, std::string &&name)
    : State(std::move(locationSuggester), std::move(name))
{}

void NitzState::StateBegin()
{
    isActive_ = true;
}

void NitzState::StateEnd()
{
    isActive_ = false;
}

bool NitzState::StateProcess(const InnerEvent::Pointer &event)
{
    TELEPHONY_LOGI("NitzState StateProcess");
    if (event == nullptr) {
        TELEPHONY_LOGE("NitzState event is null");
        return false;
    }

    std::shared_ptr<TimeZoneLocationSuggester> locationSuggester = locationSuggester_.lock();
    if (locationSuggester == nullptr) {
        TELEPHONY_LOGE("NitzState StateMachine is null");
        return false;
    }
    uint32_t eventCode = event->GetInnerEventId();
    if (eventCode == TimeZoneEventCode::EVENT_LOCATION_UPDATE) {
        if (ShouldUpdateTimeZone()) {
            locationSuggester->TransitionTo(locationSuggester->locationState_);
        }
        return true;
    }
    return false;
}

bool NitzState::ShouldUpdateTimeZone()
{
    std::shared_ptr<TimeZoneLocationSuggester> locationSuggester = locationSuggester_.lock();
    if (locationSuggester == nullptr) {
        TELEPHONY_LOGE("NitzState StateMachine is null");
        return false;
    }
    if (locationSuggester->currentLocation_ == nullptr) {
        TELEPHONY_LOGE("NitzState location is null");
        return false;
    }
    bool isRoaming = DelayedSingleton<TimeZoneManager>::GetInstance()->IsRoaming();
    if (isRoaming && locationSuggester->lastLocation_ == nullptr) {
        locationSuggester->lastLocation_ =
            std::make_unique<OHOS::Location::Location>(*(locationSuggester->currentLocation_));
        TELEPHONY_LOGI("Roaming and location is null, should update time zone");
        return true;
    }
    locationSuggester->lastLocation_ =
        std::make_unique<OHOS::Location::Location>(*(locationSuggester->currentLocation_));
    int32_t lac = DelayedSingleton<TimeZoneManager>::GetInstance()->GetCurrentLac();
    bool hasSim = DelayedSingleton<TimeZoneManager>::GetInstance()->HasSimCard();
    bool isTimeDiff =
        OHOS::MiscServices::TimeServiceClient::GetInstance()->GetBootTimeMs() - locationSuggester->nitzUpdateTime_ >
        locationSuggester->GetLocationExpirationTime();
    bool isHasSim = !hasSim && lac == INVALID_LAC && locationSuggester->nitzLac_ == INVALID_LAC;
    bool isNewLac = lac != locationSuggester->nitzLac_;
    if (isTimeDiff && (isHasSim || isNewLac)) {
        return true;
    }
    return false;
}

LocationState::LocationState(std::weak_ptr<TimeZoneLocationSuggester> &&locationSuggester, std::string &&name)
    : State(std::move(locationSuggester), std::move(name))
{}

void LocationState::StateBegin()
{
    isActive_ = true;
    UpdateTimeZone();
    std::shared_ptr<TimeZoneLocationSuggester> locationSuggester = locationSuggester_.lock();
    if (locationSuggester == nullptr) {
        TELEPHONY_LOGE("LocationState StateMachine is null");
        return;
    }
    locationSuggester->TransitionTo(locationSuggester->idleState_);
}

void LocationState::StateEnd()
{
    isActive_ = false;
}

bool LocationState::StateProcess(const InnerEvent::Pointer &event)
{
    return false;
}

void LocationState::UpdateTimeZone()
{
    TELEPHONY_LOGI("LocationState::UpdateTimeZone");
    std::shared_ptr<TimeZoneLocationSuggester> locationSuggester = locationSuggester_.lock();
    if (locationSuggester->lastLocation_ == nullptr) {
        TELEPHONY_LOGE("location is null");
        return;
    }
    std::vector<std::string> zoneList = OHOS::Global::I18n::I18nTimeZone::GetTimezoneIdByLocation(
        locationSuggester->lastLocation_->GetLongitude(), locationSuggester->lastLocation_->GetLatitude());
    bool isValidZone = false;
    if (zoneList.size() >= 1) {
        if (!zoneList[0].empty()) {
            isValidZone = true;
        }
    }
    if (isValidZone) {
        TELEPHONY_LOGI("update location time zone[%{public}s]", zoneList[0].c_str());
        if (DelayedSingleton<TimeZoneManager>::GetInstance()->UpdateLocationTimeZone(zoneList[0])) {
            locationSuggester->timeZoneLocation_ =
                std::make_unique<OHOS::Location::Location>(*(locationSuggester->lastLocation_));
        }
    } else {
        TELEPHONY_LOGI("time zone is invalid, get country code from location");
        DelayedSingleton<TimeZoneManager>::GetInstance()->SendUpdateLocationCountryCodeRequest();
    }
}
} // namespace Telephony
} // namespace OHOS