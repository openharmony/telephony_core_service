/*
 * Copyright (C) 2025-2025 Huawei Device Co., Ltd.
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
#ifndef MOCK_FFRT_API_CPP_MUTEX_H
#define MOCK_FFRT_API_CPP_MUTEX_H

#include <mutex>
#include "c/mutex.h"

namespace ffrt {

class mutex : public ffrt_mutex_t {
public:
    mutex() = default;
    ~mutex() = default;

    mutex(const mutex&) = delete;
    void operator=(const mutex&) = delete;

    inline bool try_lock()
    {
        return internal_mutex_.try_lock();
    }

    inline void lock()
    {
        internal_mutex_.lock();
    }

    inline void unlock()
    {
        internal_mutex_.unlock();
    }

private:
    std::mutex internal_mutex_;
};

class recursive_mutex : public ffrt_mutex_t {
public:
    recursive_mutex() = default;
    ~recursive_mutex() = default;

    recursive_mutex(const recursive_mutex&) = delete;
    void operator=(const recursive_mutex&) = delete;

    inline bool try_lock()
    {
        return internal_mutex_.try_lock();
    }

    inline void lock()
    {
        internal_mutex_.lock();
    }

    inline void unlock()
    {
        internal_mutex_.unlock();
    }

private:
    std::recursive_mutex internal_mutex_;
};
}  // namespace ffrt

#endif