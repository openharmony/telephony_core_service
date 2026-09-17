# 专家知识：历史问题与失败模式

来源：本仓 git 历史（hmos_trunk 分支 2026-07~09 提交，含 TicketNo DTS/AR 编号）。

## 冲突高发文件（改动时预期合流冲突）

| 文件 | 冲突原因 | 建议 |
|---|---|---|
| frameworks/js/network_search/src/napi_radio.cpp | 大量 PR 同时改（IMEI 适配、接口新增） | 改动前先 git pull，集中改 |
| BUILD.gn | 依赖/宏调整高频 | 同上 |
| services/sim/src/radio_protocol_controller.cpp | 逻辑通道修复多轮 | 同上 |
| services/sim/src/multi_sim_controller.cpp / multi_sim_helper.cpp | 多卡改动高频 | 同上 |

## 问题条目

### 1. 并发锁迁移（DTS2026090406270）
- 现象：std::mutex 与 ffrt 任务混用导致死锁/调度问题
- 根因：本仓进程运行在 FFRT 调度域，std::mutex 阻塞 worker 线程
- 修复：sim_state_manager、network_search_state 改用 ffrt::mutex
- 约束：**新增并发代码用 ffrt::mutex**；同模块沿用既有锁原语

### 2. MultiSimsCapabilityMgr 异步 bug（DTS2026082001864）
- 现象：多卡能力异步查询结果错误
- 修复：core_service_common_event_hub.cpp 移除多余订阅（5 行）
- 约束：capability 查询异步路径改动谨慎；IsMultiSimsCapabilitySupported 为新函数模式（e29829e03）

### 3. eSIM 逻辑通道重复关闭（AR20260708227798 系列）
- 现象：同一逻辑通道重复关闭崩溃
- 修复：radio_protocol_controller.cpp 加防重入
- 关联：SEP 不支持获取 port 口、esim 开卡 getimei 改 slot2、simlabel 映射修复（DTS2026090266123）
- 约束：esim 改动需同时考虑这些场景

### 4. 多卡 slot 上限（DTS2026091010111）
- 现象：tablet 上 slot count max 错误
- 修复：调整 slot 上限判断
- 约束：slotCount（services/etc/param/telephony.para）与 multi_sim 控制器联动，平台差异敏感

### 5. BytesToInt 边界（DTS2026082564627）
- 现象：字节转 int 的 if 判断错误导致解析异常
- 约束：utils 字节解析函数改动须带边界测试（0、超长、负数场景）

### 6. imei 适配（AR20260708227798）
- 现象：不同平台 IMEI 查询适配（冲突文件 napi_radio.cpp）
- 约束：IMEI 类接口改动注意多平台差异与 eSIM 场景（esim 开卡读 slot2）

### 7. so 体积（7bd88cb53 fix libradio.z.so size）
- 约束：ANI/Rust 层改动注意依赖不膨胀 so 体积

## 知识映射（问题 → 四类形态）

- 架构边界 → expert（constraints.md）+ routing（repo-boundary.md）
- 高风险入口 → code_map（modules.md 关键文件索引）
- 隐式约束/失效模式 → expert（constraints.md 失败模式表）
- 验证回归 → verify（build-test.md）
