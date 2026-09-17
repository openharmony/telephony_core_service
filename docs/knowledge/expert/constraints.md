# 专家约束：禁止事项与架构不变量

## 核心禁止事项

1. **禁止** 修改/重排已有 IPC 接口码（interfaces/innerkits/include/core_service_ipc_interface_code.h）——只允许追加，改码需同步 stub/proxy/client/测试 mock 5+ 处
2. **禁止** 对已有公共 API（interfaces/kits/）做不兼容变更（签名/权限/返回值语义）
3. **禁止** 新增并发代码使用 `std::mutex`——本仓已迁移 `ffrt::mutex`（sim_state_manager.cpp、network_search_state.cpp 已改，历史 DTS2026090406270）；沿用同模块既有锁原语
4. **禁止** 在条件编译分支（eSIM/卫星/telephony_ext）外使用其类型；分支内改动需验证默认构建不受影响
5. **禁止** 删除失败的测试用例来"通过"
6. **禁止** 未明确用户请求时提交代码
7. **禁止** 解码/字符串解析函数改动不跑对应 fuzzer（test/fuzztest/，如 simfileparse_fuzzer、vcard_fuzzer）

## 架构不变量

- **查询接口语义**：上层查询默认读 unsol 更新的内存缓存（对齐 GetCellInfoList/GetSignalInfoList），不主动打 RIL 查询命令（除非 SR 明确要求实时查询）
- **RIL 数据转换集中**：HDI 结构 → 内部 parcel 结构的转换在 tel_ril_* 的 Build* 函数（如 tel_ril_network.cpp:1194 BuildChannelConfigInfoList），上层不直接接触 HDI 类型
- **接口码 ↔ stub ↔ proxy ↔ mock 五处一致**：新增接口必须同时改 core_service_ipc_interface_code.h、core_service_stub.cpp、core_service_proxy.cpp、core_service_client.cpp、test/mock/*，否则编译失败
- **数据流单向**：IPC 请求 → CoreService → 各 Manager → Handler/RIL；unsol 上报反向。跨层不旁路（除 core_manager_inner 的 RIL 直达口，仅内部使用）
- **多卡 slot 上限**：slot 数量由 services/etc/param/telephony.para（slotCount）+ multi_sim 控制器管理，修改上限需注意平台差异（DTS2026091010111 tablet 修复）

## 失败模式（防踩坑）

| 模式 | 表现 | 规避 |
|---|---|---|
| 异步回调竞态 | 回调在对象销毁后到达、重复回调 | 回调注册/注销配对（handler Init/DeInit），判空共享指针 |
| 逻辑通道重入 | eSIM 逻辑通道重复关闭崩溃 | radio_protocol_controller.cpp 防重入（AR20260708227798） |
| 条件编译泄漏 | 默认构建引用 esim 符号 | #ifdef 完整包裹，改后验证默认构建 |
| 超大 parcel/数组 | channelConfig 等列表无上限检查崩溃 | 参照 network_register.cpp:203 MAX_SIZE 检查 |
| NAPI 回调未注销 | JS 回调悬挂 | 参照既有 napi 回调 manager（napi_ims_reg_info_callback_manager） |
| so 体积膨胀 | libradio.z.so 超限 | ANI 层改动注意依赖（7bd88cb53） |
