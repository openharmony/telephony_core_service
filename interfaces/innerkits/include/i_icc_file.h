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
#ifndef TELEPHONY_EXT_ICCFILE_EXT_H
#define TELEPHONY_EXT_ICCFILE_EXT_H

#include "inner_event.h"
#include "message_parcel.h"
#include "telephony_log_wrapper.h"
#include "telephony_errors.h"

namespace OHOS::Telephony {
class IIccFileExt {
public:
    enum FileChangeType {
        INVALID_FILE_OPE,
        ICCID_FILE_LOAD,
        GID1_FILE_LOAD,
        GID2_FILE_LOAD,
        SPN_FILE_LOAD,
        C_IMSI_FILE_LOAD,
        G_IMSI_FILE_LOAD,
        G_MCCMNC_FILE_LOAD,
        ALL_FILE_LOAD,
    };

    using FileChangeType = IIccFileExt::FileChangeType;
    virtual ~IIccFileExt()
    {
    }

    std::weak_ptr<OHOS::Telephony::IIccFileExt>& GetIccFile()
    {
        return iccFile_;
    }

    virtual void SetIccFile(std::shared_ptr<OHOS::Telephony::IIccFileExt> &iccFile) = 0;

    virtual void ClearData()
    {
    }

    virtual void LoadSimMatchedFileFromRilCache()
    {
    }

    virtual void LoadSimMatchedFileFromRilCacheByEfid(int fileId)
    {
    }

    virtual void AddRecordsToLoadNum()
    {
    }

    virtual bool ExecutOriginalSimIoRequest(int32_t filedId, int fileIdDone)
    {
        return false;
    }

    virtual bool FileChange(const std::string fileStr, FileChangeType changeType)
    {
        return false;
    }

    virtual int32_t GetCachedFileResult(MessageParcel &data)
    {
        return Telephony::TELEPHONY_ERR_UNINIT;
    }

    virtual int32_t GetCachedIccidResult(std::string &iccidResult)
    {
        return Telephony::TELEPHONY_ERR_UNINIT;
    }

    virtual void OnOpkeyLoad(const std::string opKey, const std::string opName)
    {
    }

    virtual void ProcessExtGetFileDone(const AppExecFwk::InnerEvent::Pointer &event)
    {
    }

    virtual void ProcessExtGetFileResponse()
    {
    }

protected:
    std::weak_ptr<OHOS::Telephony::IIccFileExt> iccFile_;
};
} // namespace OHOS::Telephony
#endif //TELEPHONY_EXT_ICCFILE_EXT_H