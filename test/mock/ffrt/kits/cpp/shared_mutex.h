// Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
#ifndef MOCK_FFRT_API_CPP_SHARED_MUTEX_H
#define MOCK_FFRT_API_CPP_SHARED_MUTEX_H

#include "c/shared_mutex.h"

namespace ffrt {

class shared_mutex : public ffrt_rwlock_t {
public:
    shared_mutex()
    {}

    ~shared_mutex()
    {}

    shared_mutex(const shared_mutex &) = delete;

    void operator=(const shared_mutex &) = delete;

    inline void lock()
    {}

    inline bool try_lock()
    {
        return true;
    }

    inline void unlock()
    {}

    inline void lock_shared()
    {}

    inline bool try_lock_shared()
    {
        return true;
    }

    inline void unlock_shared()
    {}
};
}  // namespace ffrt

#endif