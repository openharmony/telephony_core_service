# 代码地图：条件编译分支

本仓存在三组条件编译，默认关闭的分支不参与常规 CI，改动回归风险高：

## 分支总览

| 宏 | 启用内容 | 涉及路径 |
|---|---|---|
| `CORE_SERVICE_SUPPORT_ESIM` | eSIM 管理器/控制器/文件、ASN.1 codec | services/sim/src/esim_*、utils/codec/src/asn1_* |
| `CORE_SERVICE_SATELLITE` | 卫星服务交互 | services/satellite_service_interaction/、core_service_satellite* |
| `OHOS_BUILD_ENABLE_TELEPHONY_EXT` | 扩展封装（getCellInfoList_ 等函数指针钩子） | services/telephony_ext_wrapper/、telephony_core_service.gni:32-36 |

宏定义：telephony_core_service.gni:14-28（core_service_support_esim / core_service_satellite / telephony_extra_defines）。

## 使用规则

- **禁止** 在条件编译分支之外引用分支内的类型/符号（会破坏默认构建）
- **禁止** 在条件编译分支内引用分支外的类型而不提供默认路径
- 改动分支内代码时，须同时验证关闭宏的默认构建不受影响（分支代码需 `#ifdef` 完整包裹）
- 查询 ext 钩子模式见 services/telephony_ext_wrapper/include/telephony_ext_wrapper.h（函数指针 + 默认 nullptr 判空调用），mock 版本在 test/mock/telephony_ext_wrapper/

## eSIM 特有约束

- eSIM 相关：simlabel 映射、逻辑通道"重复关闭"是历史问题高发区（见 docs/knowledge/expert/historical-issues.md）
- eSIM 服务是独立 SA（66250），经 EsimServiceClient 异步加载（frameworks/native/src/esim_service_client.cpp:29）
- getimei 在 esim 开卡时读 slot2（历史提交 bfccb76ee），改动 IMEI 逻辑注意 eSIM 场景
