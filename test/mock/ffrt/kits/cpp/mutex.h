// Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
#ifndef MOCK_FFRT_API_CPP_MUTEX_H
#define MOCK_FFRT_API_CPP_MUTEX_H

#include "c/mutex.h"

namespace ffrt {

class mutex : public ffrt_mutex_t {
public:
    mutex()
    {}

    ~mutex()
    {
    }

    mutex(const mutex &) = delete;

    void operator=(const mutex &) = delete;

    inline bool try_lock()
    {
        return true;
    }

    inline void lock()
    {}

    inline void unlock()
    {}
};

class recursive_mutex : public ffrt_mutex_t {
public:
    recursive_mutex()
    {}

    ~recursive_mutex()
    {}

    recursive_mutex(const recursive_mutex &) = delete;

    void operator=(const recursive_mutex &) = delete;

    inline bool try_lock()
    {
        return true;
    }

    inline void lock()
    {}

    inline void unlock()
    {}
};
}  // namespace ffrt

#endif