/*
 * Copyright (C) 2021-2022 Huawei Device Co., Ltd.
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
#ifndef MOCK_DATASHARE_HELPER_H
#define MOCK_DATASHARE_HELPER_H
#include "gmock/gmock.h"
#include "datashare_helper.h"
#include "datashare_result_set.h"

namespace OHOS {
using namespace DataShare;
namespace Telephony {
class MockDataShareHelper : public DataShare::DataShareHelper {
public:
    MOCK_METHOD(bool, Release, (), (override));
    MOCK_METHOD(std::vector<std::string>, GetFileTypes, (Uri &uri, const std::string &mimeTypeFilter), (override));
    MOCK_METHOD(int, OpenFile, (Uri &uri, const std::string &mode), (override));
    MOCK_METHOD(int, OpenRawFile, (Uri &uri, const std::string &mode), (override));
    MOCK_METHOD(int, Insert, (Uri &uri, const DataShare::DataShareValuesBucket &value), (override));
    MOCK_METHOD(int, InsertExt, (Uri &uri, const DataShare::DataShareValuesBucket &value,
        std::string &result), (override));
    MOCK_METHOD(int, Update, (Uri &uri, const DataShare::DataSharePredicates &predicates,
        const DataShare::DataShareValuesBucket &value), (override));
    MOCK_METHOD(int, BatchUpdate, (const DataShare::UpdateOperations &operations,
        std::vector<BatchUpdateResult> &results), (override));
    MOCK_METHOD(int, Delete, (Uri &uri, const DataShare::DataSharePredicates &predicates), (override));
    MOCK_METHOD(std::shared_ptr<DataShare::DataShareResultSet>, Query, (Uri &uri,
        const DataShare::DataSharePredicates &predicates,
        std::vector<std::string> &columns, DatashareBusinessError *businessError), (override));
    MOCK_METHOD(std::string, GetType, (Uri &uri), (override));
    MOCK_METHOD(int, BatchInsert, (Uri &uri, const std::vector<DataShare::DataShareValuesBucket> &values), (override));
    MOCK_METHOD(int, ExecuteBatch, (const std::vector<DataShare::OperationStatement> &statements,
        ExecResultSet &result), (override));
    MOCK_METHOD(int, RegisterObserver, (const Uri &uri,
        const sptr<AAFwk::IDataAbilityObserver> &dataObserver), (override));
    MOCK_METHOD(int, UnregisterObserver, (const Uri &uri,
        const sptr<AAFwk::IDataAbilityObserver> &dataObserver), (override));
    MOCK_METHOD(void, NotifyChange, (const Uri &uri), (override));
    MOCK_METHOD(Uri, NormalizeUri, (Uri &uri), (override));
    MOCK_METHOD(Uri, DenormalizeUri, (Uri &uri), (override));
    MOCK_METHOD(int, AddQueryTemplate, (const std::string &uri, int64_t subscriberId, Template &tpl), (override));
    MOCK_METHOD(int, DelQueryTemplate, (const std::string &uri, int64_t subscriberId), (override));
    MOCK_METHOD(std::vector<OperationResult>, Publish, (const Data &data, const std::string &bundleName), (override));
    MOCK_METHOD(Data, GetPublishedData, (const std::string &bundleName, int &resultCode), (override));
    MOCK_METHOD(std::vector<OperationResult>, SubscribeRdbData, (const std::vector<std::string> &uris,
        const TemplateId &templateId,
        const std::function<void(const RdbChangeNode &changeNode)> &callback), (override));
    MOCK_METHOD(std::vector<OperationResult>, UnsubscribeRdbData, (const std::vector<std::string> &uris,
        const TemplateId &templateId), (override));
    MOCK_METHOD(std::vector<OperationResult>, EnableRdbSubs, (const std::vector<std::string> &uris,
        const TemplateId &templateId), (override));
    MOCK_METHOD(std::vector<OperationResult>, DisableRdbSubs, (const std::vector<std::string> &uris,
        const TemplateId &templateId), (override));
    MOCK_METHOD(std::vector<OperationResult>, SubscribePublishedData, (const std::vector<std::string> &uris,
        int64_t subscriberId,
        const std::function<void(const PublishedDataChangeNode &changeNode)> &callback), (override));
    MOCK_METHOD(std::vector<OperationResult>, UnsubscribePublishedData, (const std::vector<std::string> &uris,
        int64_t subscriberId), (override));
    MOCK_METHOD(std::vector<OperationResult>, EnablePubSubs, (const std::vector<std::string> &uris,
        int64_t subscriberId), (override));
    MOCK_METHOD(std::vector<OperationResult>, DisablePubSubs, (const std::vector<std::string> &uris,
        int64_t subscriberId), (override));
    MOCK_METHOD((std::pair<int32_t, int32_t>), InsertEx, (Uri &uri,
        const DataShare::DataShareValuesBucket &value), (override));
    MOCK_METHOD((std::pair<int32_t, int32_t>), UpdateEx, (Uri &uri, const DataShare::DataSharePredicates &predicates,
        const DataShare::DataShareValuesBucket &value), (override));
    MOCK_METHOD((std::pair<int32_t, int32_t>), DeleteEx, (Uri &uri,
        const DataShare::DataSharePredicates &predicates), (override));
    MOCK_METHOD(int32_t, UserDefineFunc, (MessageParcel &data, MessageParcel &reply,
        MessageOption &option), (override));
    MOCK_METHOD(std::shared_ptr<DataShareHelper>, Creator, (const sptr<IRemoteObject> &token,
        const std::string &strUri, const std::string &extUri, const int waitTime));
};
} // Telephony
} // OHOS
#endif