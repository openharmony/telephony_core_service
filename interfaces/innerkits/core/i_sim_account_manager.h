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

#ifndef OHOS_I_SIM_ACCOUNT_MANAGER_H
#define OHOS_I_SIM_ACCOUNT_MANAGER_H

#include <map>
#include "parcel.h"

namespace OHOS {
namespace Telephony {
struct OperatorConfig : public Parcelable {
    std::map<std::u16string, std::u16string> configValue;

    bool Marshalling(Parcel &parcel) const
    {
        if (!parcel.WriteInt32(configValue.size())) {
            return false;
        }
        auto valueIt = configValue.begin();
        while (valueIt != configValue.end()) {
            if (!parcel.WriteString16(valueIt->first)) {
                return false;
            }
            if (!parcel.WriteString16(valueIt->second)) {
                return false;
            }
            valueIt++;
        }
        return true;
    };

    std::shared_ptr<OperatorConfig> UnMarshalling(Parcel &parcel)
    {
        std::shared_ptr<OperatorConfig> param = std::make_shared<OperatorConfig>();
        if (param == nullptr || !param->ReadFromParcel(parcel)) {
            param = nullptr;
        }
        return param;
    };

    bool ReadFromParcel(Parcel &parcel)
    {
        configValue.clear();
        int32_t valueSize = parcel.ReadInt32();
        int32_t k = 0;
        while (valueSize > k) {
            std::u16string first = parcel.ReadString16();
            std::u16string second = parcel.ReadString16();
            configValue.emplace(std::pair<std::u16string, std::u16string>(first, second));
            k++;
        }
        return true;
    };
};

struct IccAccountInfo : public Parcelable {
    int32_t simId; // sim Id for card
    int32_t slotIndex; // slot index for card
    bool isEsim; // mark card is eSim or not
    bool isActive; // active status for card
    std::u16string iccId; // iccId for card
    std::u16string showName; // show name for card
    std::u16string showNumber; // show number for card
    inline static const std::u16string DEFAULT_SHOW_NAME = u"Card";
    inline static const std::u16string DEFAULT_SHOW_NUMBER = u"";
    inline static const std::u16string DEFAULT_ICC_ID = u"";
    void Init(int32_t simCardId, int32_t slotId)
    {
        this->simId = simCardId;
        this->slotIndex = slotId;
        this->isEsim = false;
        this->isActive = true;
        this->iccId = DEFAULT_ICC_ID;
        this->showName = DEFAULT_SHOW_NAME;
        this->showNumber = DEFAULT_SHOW_NUMBER;
    };

    void SetIsEsim(bool isEsimType)
    {
        this->isEsim = isEsimType;
    }

    void SetIsActive(bool activeEnabled)
    {
        this->isActive = activeEnabled;
    }

    void SetIccId(std::u16string id)
    {
        this->iccId = id;
    }

    void SetShowName(std::u16string name)
    {
        this->showName = name;
    }

    void SetShowNumber(std::u16string number)
    {
        this->showNumber = number;
    }

    bool Marshalling(Parcel &parcel) const
    {
        if (!parcel.WriteInt32(simId)) {
            return false;
        }
        if (!parcel.WriteInt32(slotIndex)) {
            return false;
        }
        if (!parcel.WriteBool(isEsim)) {
            return false;
        }
        if (!parcel.WriteBool(isActive)) {
            return false;
        }
        if (!parcel.WriteString16(iccId)) {
            return false;
        }
        if (!parcel.WriteString16(showName)) {
            return false;
        }
        if (!parcel.WriteString16(showNumber)) {
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
        parcel.ReadInt32(simId);
        parcel.ReadInt32(slotIndex);
        parcel.ReadBool(isEsim);
        parcel.ReadBool(isActive);
        parcel.ReadString16(iccId);
        parcel.ReadString16(showName);
        parcel.ReadString16(showNumber);
        return true;
    };

    bool operator==(const IccAccountInfo &p)
    {
        return (slotIndex == p.slotIndex && simId == p.simId);
    }
};

class ISimAccountManager {
public:
    ISimAccountManager() {};
    virtual ~ISimAccountManager() {};
    virtual void Init(int32_t slotId);
    virtual bool IsSimActive(int32_t slotId);
    virtual bool SetActiveSim(int32_t slotId, int32_t enable);
    virtual bool GetSimAccountInfo(int32_t slotId, IccAccountInfo &info);
    virtual bool SetDefaultVoiceSlotId(int32_t slotId);
    virtual bool SetDefaultSmsSlotId(int32_t slotId);
    virtual bool SetDefaultCellularDataSlotId(int32_t slotId);
    virtual bool SetShowNumber(int32_t slotId, const std::u16string number);
    virtual bool SetShowName(int32_t slotId, const std::u16string name);
    virtual int32_t GetDefaultVoiceSlotId();
    virtual int32_t GetDefaultSmsSlotId();
    virtual int32_t GetDefaultCellularDataSlotId();
    virtual std::u16string GetShowNumber(int32_t slotId);
    virtual std::u16string GetShowName(int32_t slotId);
    virtual bool GetActiveSimAccountInfoList(std::vector<IccAccountInfo> &iccAccountInfoList);
    virtual bool GetOperatorConfigs(int slotId, OperatorConfig &poc);
};
} // namespace Telephony
} // namespace OHOS

#endif // OHOS_I_SIM_MANAGER_H
