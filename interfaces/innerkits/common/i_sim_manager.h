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

#ifndef TELEPHONY_I_SIM_MANAGER_H
#define TELEPHONY_I_SIM_MANAGER_H

#include <unordered_map>
#include "parcel.h"

namespace OHOS {
namespace Telephony {
const int32_t CARRIER_CONFIG_STEP = 2;
const std::u16string DEFAULT_DISPLAY_NAME = u"simDefaultDisplayName";
const std::u16string DEFAULT_DISPLAY_NUMBER = u"simDefaultDisplayNumber";

struct CarrierConfig : public Parcelable {
    std::u16string configName;
    std::u16string iccId;
    std::unordered_map<std::u16string, std::u16string> configMap;

    bool Marshalling(Parcel &parcel) const
    {
        if (!parcel.WriteString16(configName)) {
            return false;
        }
        if (!parcel.WriteString16(iccId)) {
            return false;
        }
        if (!configMap.empty() && configMap.size() > 0) {
            std::vector<std::u16string> configVector;
            auto it = configMap.begin();
            while (it != configMap.end()) {
                configVector.emplace_back(it->first);
                configVector.emplace_back(it->second);
                it++;
            }
            if (!parcel.WriteString16Vector(configVector)) {
                return false;
            }
        }
        return true;
    };

    std::shared_ptr<CarrierConfig> UnMarshalling(Parcel &parcel)
    {
        std::shared_ptr<CarrierConfig> param = std::make_shared<CarrierConfig>();
        if (param == nullptr || !param->ReadFromParcel(parcel)) {
            param = nullptr;
        }
        return param;
    };

    bool ReadFromParcel(Parcel &parcel)
    {
        parcel.ReadString16(configName);
        parcel.ReadString16(iccId);
        configMap.clear();
        std::vector<std::u16string> *configVector = nullptr;
        parcel.ReadString16Vector(configVector);
        int i = 0;
        while ((int)configVector->size() > i) {
            configMap.emplace(
                std::pair<std::u16string, std::u16string>(configVector->at(i), configVector->at(i + 1)));
            i += CARRIER_CONFIG_STEP;
        }
        return true;
    };

    bool operator==(const CarrierConfig &p)
    {
        return (configName == p.configName && iccId == p.iccId);
    }
};

struct IccAccountInfo : public Parcelable {
    int32_t slotIndex;
    std::u16string displayName;
    std::u16string displayNumber;

    void Init(int32_t slotIndex, std::u16string displayName = DEFAULT_DISPLAY_NAME,
        std::u16string displayNumber = DEFAULT_DISPLAY_NUMBER)
    {
        this->slotIndex = slotIndex;
        this->displayName = displayName;
        this->displayNumber = displayNumber;
    };

    bool Marshalling(Parcel &parcel) const
    {
        if (!parcel.WriteInt32(slotIndex)) {
            return false;
        }
        if (!parcel.WriteString16(displayName)) {
            return false;
        }
        if (!parcel.WriteString16(displayNumber)) {
            return false;
        }
        return true;
    };

    std::shared_ptr<IccAccountInfo> UnMarshalling(Parcel &parcel)
    {
        std::shared_ptr<IccAccountInfo> param = std::make_shared<IccAccountInfo>();
        if (param == nullptr || !param->ReadFromParcel(parcel)) {
            param = nullptr;
        }
        return param;
    };

    bool ReadFromParcel(Parcel &parcel)
    {
        parcel.ReadInt32(slotIndex);
        parcel.ReadString16(displayName);
        parcel.ReadString16(displayNumber);
        return true;
    };

    bool operator==(const IccAccountInfo &p)
    {
        return (slotIndex == p.slotIndex);
    }
};

class ISimManager {
public:
    ISimManager() {};
    virtual ~ISimManager() {};
    virtual void Init();
    virtual bool GetSimAccountInfo(int32_t subId, IccAccountInfo &info);
    virtual bool SetDefaultVoiceSlotId(int32_t subId);
    virtual bool SetDefaultSmsSlotId(int32_t subId);
    virtual int32_t GetDefaultVoiceSlotId();
    virtual int32_t GetDefaultSmsSlotId();
};
} // namespace Telephony
} // namespace OHOS

#endif // TELEPHONY_I_SIM_MANAGER_H
