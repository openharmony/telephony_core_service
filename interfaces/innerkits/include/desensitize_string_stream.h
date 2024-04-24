/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#ifndef DESENSITIZE_STRING_STREAM_H
#define DESENSITIZE_STRING_STREAM_H

#include <sstream>

namespace OHOS {
namespace Telephony {
namespace DSS {
    // encrypt
    inline void Dese() {}
}

/**
 * @brief Desensitized string stream: used to desensitize fields and output them into strings.
 *  When a field needs to be desensitized, please output DSS::Dese before the field output,
 *  for example: dss << DSS::Dese << field1 << field2.
 */
class DesensitizeStringStream {
    using dese = void(*)();

public:
    DesensitizeStringStream() = delete;
    DesensitizeStringStream(std::string &out, std::stringstream &ss, char separator = ',')
        : separator_(separator), ss_(ss), out_(out)
    {}

    inline DesensitizeStringStream &operator<<(dese d)
    {
        desensitize_ = true;
        return *this;
    }

    template<typename T>
    inline DesensitizeStringStream &operator<<(T t)
    {
        if (desensitize_) {
            operator()(t);
            desensitize_ = false;
        } else {
            ss_ << t << separator_;
        }
        return *this;
    }

    inline const char* operator*() const
    {
        out_ = ss_.str();
        return out_.c_str();
    }

private:
    /* Use bracket operators: desensitize specific fields. */
    template<typename T>
    inline void operator()(T &&t)
    {
        std::streampos s = ss_.tellp();
        ss_ << t;
        std::streampos e = ss_.tellp();
        std::streampos dur = (e - s) / 2;
        ss_.seekp(-dur, std::ios::end);
        ss_ << std::string(dur, '*') << separator_ << "\0";
    }

    char separator_;
    bool desensitize_ = false;
    std::stringstream &ss_;
    std::string &out_;
};
} // namespace Telephony
} // namespace OHOS
#endif // DESENSITIZE_STRING_STREAM_H