# 路由：新增/修改 IPC 接口（18 文件标准集）

来源：历史提交 AR20260708227592（"core_service新增接口，以提供查询同运卡"）实证的 18 文件清单。

## 标准同步点（核心 18 文件）

### 1. 接口码 + 虚接口
| 文件 | 动作 |
|---|---|
| interfaces/innerkits/include/core_service_ipc_interface_code.h | **追加**新枚举码（+1，禁改已有） |
| interfaces/innerkits/include/i_core_service.h | 加虚接口 |
| interfaces/innerkits/include/core_service_proxy.h | 加 override 声明 |
| interfaces/innerkits/include/core_service_client.h | 加客户端声明 |
| interfaces/innerkits/include/core_manager_inner.h | 加内部单例声明（可选，部分接口直达 RIL） |

### 2. 服务端实现
| 文件 | 动作 |
|---|---|
| services/core/include/core_service.h | 加实现声明 |
| services/core/src/core_service.cpp | 实现（转发到 NetworkSearchManager/SimManager 等） |
| services/core/src/core_service_stub.h / .cpp | OnRemoteRequest 加 case + 处理方法（core_service_stub.cpp 巨型分发） |
| （按领域）services/core/src/core_service_sim.h/.cpp 或 network_search 侧 manager/handler | 实际查询实现 |

### 3. 客户端实现
| 文件 | 动作 |
|---|---|
| frameworks/native/src/core_service_proxy.cpp | SendRequest + parcel 序列化 |
| frameworks/native/src/core_service_client.cpp | 封装调用 |

### 4. 测试同步（必改，否则 mock 编译失败）
| 文件 | 动作 |
|---|---|
| test/mock/mock_i_core_service.h | 加 MOCK_METHOD |
| test/unittest/esim_gtest/mock/include/esim_core_service_stub_test.h | 加 override 桩 |
| test/unittest/core_service_gtest/*.cpp | 加用例（native_branch / slot_id / zero_branch 等） |

### 5. 可选暴露层（按 SR 范围）
| 层 | 文件 |
|---|---|
| NAPI | frameworks/js/{sim,radio}/src/napi_*.cpp + include 头（context 结构 + 回调 manager） |
| C API | interfaces/kits/c/telephony_radio/include/telephony_radio.h + 实现 |
| Cangjie FFI | frameworks/cj/telephony_{radio,sim}/src/telephony_*_ffi.cpp + .map |
| Rust ANI | frameworks/ets/ani/{radio,sim}/：wrapper.rs ↔ src/cxx/*.cpp ↔ include/*.h ↔ ets/*.ets ↔ BUILD.gn 五处同步 |
| .d.ts | interfaces/kits/js/*.d.ts |

## 流程

1. 先读 AGENTS.md 知识索引 → docs/knowledge/routing/new-interface.md + permissions.md
2. 判断"新增能力"还是"贯通既有能力"（见 docs/knowledge/code_map/ril-capabilities.md）
3. 用 `rg <接口名>` 全仓核实不存在，再动手
4. 接口码编号：追加到枚举末尾（查看当前最大码，如枚举后段有空位先对齐风格，禁重排）
5. 改完必跑 test/unittest/core_service_gtest（编译层面即能捕获漏改的 mock/stub）

## 反例（历史教训）

| 反例 | 正解 |
|---|---|
| 只改 API 入口签名，不改内部消息结构 | 沿链路所有层同步加字段/方法 |
| 只在客户端缓存字段，不写入跨进程 parcel | 字段写入 IPC payload（proxy 序列化） |
| 跳过中间层直接改服务端 | 从入口到派发逐层核对透传 |
| 漏改测试 mock → 编译失败 | 18 文件清单内同步测试文件 |
