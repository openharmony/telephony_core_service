# 路由：权限与敏感信息

新增/修改对外查询接口时，先判断是否涉及敏感信息（位置、设备标识、卡信息），并按既有权限路径对齐。

## 权限检查工具

- `utils/common/src/telephony_permission.cpp` — 权限校验封装（CheckPermission 等）
- NAPI 侧：`NapiUtil::ConverErrorMessageWithPermissionForJs`（frameworks/js/network_search/src/napi_radio.cpp:2410 等），把权限拒绝转成带语义的 JS 错误码

## 既有权限路径（查询类接口对齐参照）

| 接口 | 权限 | 备注 |
|---|---|---|
| getCellInformation（小区信息） | LOCATION（ohos.permission.LOCATION + 位置开关） | napi_radio.cpp:2410 权限错误转换 |
| getSignalInformation | 系统接口（部分版本无权限） | 版本差异，以 .d.ts 声明为准 |
| getImei / getMeid | GET_TELEPHONY_STATE | IMEI 类历史上有适配改动（AR20260708227798 imei 适配） |
| SIM 账户/卡信息 | GET_TELEPHONY_STATE | |

## 决策规则

1. 新接口返回**位置相关**（小区、物理信道、频点、邻区）→ 走 LOCATION 权限路径（对照 getCellInformation）
2. 新接口返回**设备标识/卡标识**（IMEI/ICCID/MSISDN）→ GET_TELEPHONY_STATE
3. 不确定时查 `interfaces/kits/js/*.d.ts` 中同类接口的权限声明 + frameworks/js 下权限宏
4. 权限拒绝时统一走 ConverErrorMessageWithPermissionForJs 转换，不裸抛错误码

## 多卡能力管控

- 多卡 slot3 能力仅允许系统应用/原生调用：common/capability_mgr/multi_sims_capability_manager.cpp
- 新增"能力查询"类接口需过 capability 检查（IsMultiSimsCapabilitySupported 模式见历史提交 e29829e03）
- 修改 capability 异步逻辑需谨慎（DTS2026082001864 有 async bug 史）
