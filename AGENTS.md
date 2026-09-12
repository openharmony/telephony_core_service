# telephony_core_service 领域知识

## 项目定位

本仓库是 OpenHarmony `telephony_core_service` 的华为 fork（hmos_trunk），只含**电话核心服务主 SA（SAID 4010）**。优先按这些目录定位问题：

- `services/core/`：CoreService 主 SA 入口（OnStart 组装四模块）、IPC 分发（core_service_stub.cpp 2122 行、约 172 个接口码）
- `services/sim/`：SIM 卡服务（状态机、文件读写、账户、eSIM、STK、SIM 短信存储）——本仓最大模块（约 3.4 万行）
- `services/network_search/`：搜网服务（注册/选网/状态机、信号小区、运营商名、NITZ、EMC 救援）
- `services/tel_ril/`：RIL 通信层（六业务 Call/Data/Modem/Network/Sim/Sms，HDI V1_5 IRil，TaskSchedule 统一调度）
- `services/ims_service_interaction/`、`services/satellite_service_interaction/`、`services/telephony_ext_wrapper/`：跨 SA 交互与扩展（后两者条件编译）
- `frameworks/native/`、`frameworks/js/`（NAPI）、`frameworks/cj/`（Cangjie FFI）、`frameworks/ets/ani/`（Rust ANI，cxx 绑定）
- `interfaces/innerkits/`：部件内接口头文件；`interfaces/kits/`：对外 API（C API + .d.ts）
- `utils/`：vcard、codec（ASN.1）、common（事件/权限）、log、preferences
- `test/`：unittest（15 gtest 工程）、fuzztest（41 fuzzer）、mock、guard

⚠️ **本仓边界**：通话状态机（telephony_call_manager）、短信（telephony_sms_mms）、数据连接（telephony_cellular_data）、数据存储/联系人（telephony_data_storage）在独立仓。本仓只含其 RIL 信令层与 HISYSEVENT 上报。

## 任务到路径映射

执行任何任务前，先根据任务类型定位关键路径：

| 任务类型 | 先看这里 | 原因 |
|----------|----------|------|
| SIM 卡管理（状态/文件/账户/eSIM/PIN） | `services/sim/src/`，入口 sim_manager.cpp | 本仓 SIM 核心 |
| 搜网/radio 查询（状态/信号/小区/运营商名） | `services/network_search/src/` + core_service.cpp 转发 | 搜网服务在本仓 |
| RIL 命令/上报（调用/短信/数据信令） | `services/tel_ril/src/tel_ril_{call,sms,data,...}.cpp` | RIL 通信层 |
| 新增 IPC 接口 | `interfaces/innerkits/include/core_service_ipc_interface_code.h` 起始 | 见 docs/knowledge/routing/new-interface.md 的 18 文件清单 |
| 客户端/JS/Cangjie/Rust 暴露 | `frameworks/js/`（NAPI）、`frameworks/cj/`、`frameworks/ets/ani/` | 各语言绑定层 |
| 通话/短信/数据业务逻辑 | ⚠️ 不在本仓，去独立仓 | 本仓仅信令层 |
| 事件/权限/编解码工具 | `utils/common/`、`utils/codec/`、`utils/vcard/` | 共享工具 |
| 测试 | `test/unittest/`、`test/fuzztest/` | gtest + fuzzer |

## 知识索引

稳定背景知识放在 `docs/knowledge/`。改动前按场景读取对应文件：

| 场景 | 先读 |
|------|------|
| 判断任务归属本仓还是独立仓 | `docs/knowledge/routing/repo-boundary.md` |
| 新增/修改 IPC 接口（含 18 文件标准集） | `docs/knowledge/routing/new-interface.md` |
| RIL 层既有能力盘点（"新增"还是"贯通"） | `docs/knowledge/code_map/ril-capabilities.md` |
| 涉及权限/敏感信息的新接口 | `docs/knowledge/routing/permissions.md` |
| 改动 SIM/eSIM/多卡/并发/接口码 | `docs/knowledge/expert/constraints.md` |
| 历史问题与失败模式（含冲突文件） | `docs/knowledge/expert/historical-issues.md` |
| 条件编译分支（eSIM/卫星/ext） | `docs/knowledge/code_map/conditional-build.md` |
| 构建/测试/验证方法 | `docs/knowledge/verify/build-test.md` |

## 词汇触发路由

| 术语/缩写 | 含义 | 指向 |
|-----------|------|------|
| CoreService / 4010 | 本仓主 SA（电话核心服务） | `services/core/` |
| SIM / SimManager | SIM 卡管理聚合入口 | `services/sim/src/sim_manager.cpp` |
| RIL / TelRil / HDI IRil | 无线接口层（与 RIL Adapter 通信，V1_5） | `services/tel_ril/` |
| NetworkSearch / 搜网 | 网络注册、选网、信号小区 | `services/network_search/` |
| NAPI | JS 绑定层 | `frameworks/js/{sim,radio,esim,vcard}/` |
| ANI | Rust 绑定层（ArkUI Native Interop） | `frameworks/ets/ani/` |
| Cangjie / FFI | 仓颉绑定层 | `frameworks/cj/telephony_{radio,sim}/` |
| IPC 接口码 | CoreServiceInterfaceCode 枚举 | `interfaces/innerkits/include/core_service_ipc_interface_code.h` |
| SA / SAID | SystemAbility 及其 ID | `sa_profile/4010.json`、`services/etc/init/telephony_trust.json` |
| eSIM | 嵌入式 SIM（CORE_SERVICE_SUPPORT_ESIM 条件编译） | `services/sim/src/esim_*` |
| STK | SIM 应用工具包 | `services/sim/src/stk_*` |
| vCard | 联系人名片格式（2.1/3.0/4.0） | `utils/vcard/` |
| hb | OpenHarmony 构建工具 | docs/knowledge/verify/build-test.md |
| telephony_ext | 扩展封装（OHOS_BUILD_ENABLE_TELEPHONY_EXT） | `services/telephony_ext_wrapper/` |

## 约束和边界

详见 `docs/knowledge/expert/constraints.md`，核心禁止事项：

- **禁止** 修改/重排已有 IPC 接口码（core_service_ipc_interface_code.h），只允许追加
- **禁止** 对已有公共 API（interfaces/kits/）做不兼容变更
- **禁止** 新增并发代码使用 `std::mutex`——本仓已迁移到 `ffrt::mutex`（sim_state_manager、network_search_state 已改）
- **禁止** 在 eSIM/卫星/telephony_ext 条件编译分支外使用其类型，反之这些分支默认关闭、改动需额外谨慎
- **禁止** 删除失败的测试用例来"通过"；解码类函数改动必须跑对应 fuzzer
- **禁止** 未明确用户请求时提交代码
- 多卡 slot3 能力仅允许系统应用/原生调用（capability_mgr 管控），新能力查询需过 capability 检查

## 构建和验证

```sh
# 构建部件（需完整 OHOS 源码树，本仓挂载于 base/telephony/core_service）
hb build -T //base/telephony/core_service:tel_core_service

# 单测（gtest，聚合 target）
hb build -T //base/telephony/core_service/test:unittest
# 或设备上直接执行生成的 gtest 二进制；fuzztest：//base/telephony/core_service/test/fuzztest:fuzztest
```

详细命令、Rust ANI 构建限制与验证流程见 `docs/knowledge/verify/build-test.md`。

## 编辑前声明

动手修改前，先声明：
1. **任务类别**：API 变更 / 服务端逻辑 / SIM / 搜网 / RIL / NAPI / 测试 / 其他
2. **本次已读文档**：docs/knowledge/ 下已读哪些文件
3. **已知约束**：约束和边界中哪些相关

## Done 定义

1. [ ] 所有修改的文件 LSP 诊断无新增 error
2. [ ] 编译成功（hb build 对应 target）
3. [ ] 代码格式化已执行（仓库无格式化配置，遵循既有风格）
4. [ ] 相关测试用例通过（test/unittest/ 对应 gtest）
5. [ ] 未引入公共 API 不兼容变更（接口码只追加、kits 签名不变）
6. [ ] 未违反约束和边界中列出的禁止事项
7. [ ] 涉及解码类/字符串解析改动已跑对应 fuzzer
