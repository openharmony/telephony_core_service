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

#ifndef NETWORK_SEARCH_INCLUDE_TIME_ZONE_LOCATION_SUGGESTER_H
#define NETWORK_SEARCH_INCLUDE_TIME_ZONE_LOCATION_SUGGESTER_H

#include <memory>
#include <mutex>
#include <utility>
#include <vector>

#include "event_handler.h"
#include "inner_event.h"
#include "location.h"
#include "refbase.h"
#include "telephony_log_wrapper.h"

namespace OHOS {
namespace Telephony {
class TimeZoneEventCode {
public:
    static const uint32_t BASE = 0x00060000;
    static const uint32_t STATE_MACHINE_INIT = BASE + 0;
    static const uint32_t STATE_MACHINE_QUIT = BASE + 1;
    static const uint32_t EVENT_NITZ_UPDATE = BASE + 2;
    static const uint32_t EVENT_LOCATION_UPDATE = BASE + 3;
    static const uint32_t EVENT_LOCATION_TIMEOUT = BASE + 4;
    static const uint32_t EVENT_SCREEN_ON = BASE + 5;
    static const uint32_t EVENT_COUNTRY_CODE_CHANGE = BASE + 6;
    static const uint32_t EVENT_NETWORK_CONNECTED = BASE + 7;
    static const uint32_t EVENT_REQUEST_LOCATION_UPDATE = BASE + 8;
    static const uint32_t EVENT_REQUEST_LOCATION_COUNTRY_CODE = BASE + 9;
};

class TimeZoneLocationSuggester;

class State : public RefBase {
public:
    State(std::weak_ptr<TimeZoneLocationSuggester> &&locationSuggester, std::string &&name);
    virtual ~State() = default;
    virtual void StateBegin() = 0;
    virtual void StateEnd() = 0;
    virtual bool StateProcess(const AppExecFwk::InnerEvent::Pointer &event) = 0;

    void SetParentState(sptr<State> &parent);
    std::string GetStateMachineName() const;

protected:
    friend class StateMachineEventHandler;
    std::weak_ptr<TimeZoneLocationSuggester> locationSuggester_;
    std::string name_;
    sptr<State> parent_;
    bool isActive_ = false;
};

class StateMachineEventHandler : public AppExecFwk::EventHandler {
public:
    explicit StateMachineEventHandler(const std::shared_ptr<AppExecFwk::EventRunner> &runner);
    ~StateMachineEventHandler() = default;
    virtual void SetOriginalState(sptr<State> &originalState);
    virtual void TransitionTo(sptr<State> &destState);
    virtual void Quit();
    virtual void ProcessTransitions(const AppExecFwk::InnerEvent::Pointer &event);
    void DeferEvent(AppExecFwk::InnerEvent::Pointer &&event);
    virtual void ProcessEvent(const AppExecFwk::InnerEvent::Pointer &event);
    virtual void ProcessMsg(const AppExecFwk::InnerEvent::Pointer &event);

private:
    void InitCmdEnter(const sptr<State> &state);
    void SendDeferredEvent();

private:
    sptr<State> originalState_;
    sptr<State> destState_;
    sptr<State> curState_;
    std::vector<AppExecFwk::InnerEvent::Pointer> deferEvents_;
    std::mutex mtx_;
    bool isQuit_ = false;
};

class StateMachine {
public:
    explicit StateMachine(const std::shared_ptr<AppExecFwk::EventRunner> &runner);
    virtual ~StateMachine() {}
    void Quit();
    void Start();
    void SetOriginalState(sptr<State> &originalState);
    void TransitionTo(sptr<State> &destState);
    void DeferEvent(const AppExecFwk::InnerEvent::Pointer &&event);
    void SendEvent(AppExecFwk::InnerEvent::Pointer &event);

protected:
    std::shared_ptr<StateMachineEventHandler> stateMachineEventHandler_;
};

class TimeZoneLocationSuggester : public StateMachine, public std::enable_shared_from_this<TimeZoneLocationSuggester> {
public:
    explicit TimeZoneLocationSuggester(const std::shared_ptr<AppExecFwk::EventRunner> &runner);
    ~TimeZoneLocationSuggester() = default;
    void Init();
    void NitzUpdate();
    void LocationUpdate(const std::unique_ptr<Location::Location> &location);
    bool HasLocation();
    void ClearLocation();
    bool IsLocationExpired();

private:
    int64_t GetLocationExpirationTime();

private:
    friend class IdleState;
    friend class NitzState;
    friend class LocationState;
    sptr<State> idleState_;
    sptr<State> nitzState_;
    sptr<State> locationState_;
    std::unique_ptr<Location::Location> currentLocation_ = nullptr;
    std::unique_ptr<Location::Location> lastLocation_ = nullptr;
    std::unique_ptr<Location::Location> timeZoneLocation_ = nullptr;
    int64_t locationUpdateTime_ = 0;
    int64_t nitzUpdateTime_ = 0;
    int32_t nitzLac_ = 0;
};

class IdleState : public State {
public:
    IdleState(std::weak_ptr<TimeZoneLocationSuggester> &&locationSuggester, std::string &&name);
    virtual ~IdleState() = default;
    virtual void StateBegin();
    virtual void StateEnd();
    virtual bool StateProcess(const AppExecFwk::InnerEvent::Pointer &event);

private:
    bool ShouldUpdateTimeZone();
};

class NitzState : public State {
public:
    NitzState(std::weak_ptr<TimeZoneLocationSuggester> &&locationSuggester, std::string &&name);
    virtual ~NitzState() = default;
    virtual void StateBegin();
    virtual void StateEnd();
    virtual bool StateProcess(const AppExecFwk::InnerEvent::Pointer &event);

private:
    bool ShouldUpdateTimeZone();
};

class LocationState : public State {
public:
    LocationState(std::weak_ptr<TimeZoneLocationSuggester> &&locationSuggester, std::string &&name);
    virtual ~LocationState() = default;
    virtual void StateBegin();
    virtual void StateEnd();
    virtual bool StateProcess(const AppExecFwk::InnerEvent::Pointer &event);

private:
    void UpdateTimeZone();
};
} // namespace Telephony
} // namespace OHOS
#endif // NETWORK_SEARCH_INCLUDE_TIME_ZONE_LOCATION_SUGGESTER_H
