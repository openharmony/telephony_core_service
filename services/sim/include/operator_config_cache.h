/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#ifndef OHOS_OPERATOR_CONFIG_CACHE_H
#define OHOS_OPERATOR_CONFIG_CACHE_H
#include "core_service_errors.h"
#include "operator_file_parser.h"
#include "sim_file_manager.h"
#include "telephony_log_wrapper.h"

namespace OHOS {
namespace Telephony {
class OperatorConfigCache : public TelEventHandler {
public:
    explicit OperatorConfigCache(std::weak_ptr<SimFileManager> simFileManager, int32_t slotId);
    virtual ~OperatorConfigCache() = default;
    void ClearAllCache(int32_t slotId);
    void ClearMemoryCache(int32_t slotId);
    void ClearOperatorValue(int32_t slotId);
    int32_t LoadOperatorConfig(int32_t slotId, OperatorConfig &poc);
    int32_t GetOperatorConfigs(int32_t slotId, OperatorConfig &poc);
    std::string EncryptIccId(const std::string iccid);
    void ProcessEvent(const AppExecFwk::InnerEvent::Pointer &event);
    bool RegisterForIccChange();
    bool UnRegisterForIccChange();
    bool IsNeedOperatorLoad(int32_t slotId);

private:
    OperatorFileParser parser_;
    std::weak_ptr<SimFileManager> simFileManager_;
    std::string GetOpKey(int32_t slotId);
    void CopyOperatorConfig(const OperatorConfig &from, OperatorConfig &to);
    void SendSimMatchedOperatorInfo(int32_t slotId);
    bool AnnounceOperatorConfigChanged(int32_t slotId);
    inline static const std::string KEY_SLOTID = "slotId";
    inline static const std::string OPERATOR_CONFIG_CHANGED = "operatorConfigChanged";
    OperatorConfig opc_;
    int32_t slotId_;
    bool isLoadingConfig = false;
    std::mutex mutex_;
};
} // namespace Telephony
} // namespace OHOS
#endif // OHOS_OPERATOR_FILE_PARSER_H
