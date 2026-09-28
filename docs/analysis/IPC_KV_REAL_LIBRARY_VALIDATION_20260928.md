# IPC/KV 真库验证记录 — 2026-09-28

依据任务书 `docs/status/TASK_IPC_KV_VALIDATION_20260928.md`（PR #61）在原构建机执行。
授权状态如实：A-4 登记（PR #63）提交时点待所有者审批，运行依据维护者当日书面指示开始，
留痕见 PR #63 评论 5868775511。全部记录适用口径红线：**补丁运行库 / 无产品服务 /
自定义 x86_64_virt 构建配置**。

## 结果总表

| 案例 | 结果 | 层级 |
|---|---|---|
| IPC `ipc_null_bytearray` | **真库级证实**：`run.exit=139`，崩溃点 `case=1 null_len1_candidate` | 候选升级 |
| KV `kv_null_entry` | **隔离限制**（`run.exit=10`）：候选矩阵未执行，非候选结论 | 维持源码等价级 |

## IPC：真库级证实

- 对照隔离干净：`case=0`（`data=0 len=0`）正常返回 `write_error=0`；`case=1`
  （`data=0 len=1`）调用后立即 SIGSEGV——缺陷精确限定于"空 head + 非零 size"组合。
- 崩溃帧归属：两次 gdb 复现（ASLR 地址不同），rip 经 `/proc/maps` 映射落在
  `libcj_ipc_ffi.z.so` 内（file_offset `0x1ed9b`），非补丁 musl 运行库、非 hilog
  适配层；调用与崩溃间无日志尝试。函数级符号化未成（OH 预编译 llvm 工具对该帧
  返回 `??`），file_offset 供后续符号化。
- 证据：`out/ffi-direct-min/evidence/ipc-malformed-20260928/`（client/runner/
  build.log/run.log/run.exit/target-elf/inputs-*.sha256/gdb-full.txt）。

## KV：构建成功，验证被环境层阻塞（如实）

**产物**：`out/ffi-direct-kv2/.../libcj_distributed_kv_store_ffi.z.so`，x86_64 ELF
带 debug_info，85 个导出符号含全套 `FfiOHOSDistributedKVStore*`。两个构建变体：
CFI 版 sha256 `e05f3c46…`；no-CFI 版（最终用于验证）sha256 `5fd89da2…`。
构建攻关与全部树修改清单见 PR #63 评论 5869305856 与 5869762609。

**三轮验证与根因**（全部保留证据）：

1. CFI 版：SIGILL 于 musl `cfi_slowpath`（垃圾间接调用目标被 cross-DSO CFI 拦截）；
2. no-CFI 版：SIGSEGV 仍于 `stage=env_probe`；
3. **根因：客户端 ABI 失配**——树内钉定头文件签名为
   `CreateKVManager(const char*, OHOS::AbilityRuntime::Context*)`，而客户端按
   gitee master 形态的 `(const char*, int32_t*)` 调用：`&err` 被当作 Context
   指针解引用，必然崩溃（两轮崩溃现象均由此解释）。
4. 修复客户端（本 PR）：env_probe 不再以失配 ABI 调用，按任务书 B.4 记录隔离
   限制并 `exit 10`；复跑干净收口。

**候选层源码级判定（任务书 B.4 后半句）**：`SingleKVStorePutBatch`
（`distributed_kv_store_ffi.cpp:135-142`）先经 `FFIData::GetData` 校验 store id，
转换在 `CJSingleKVStore::PutBatch` 实现内、先于服务调用执行——即候选层本身
不依赖 KV 服务，但**抵达它需要合法 store id，而 manager 创建在纯 C 隔离客户端
不可达**（Context 无法构造）。候选维持"源码等价复现"层级，真库判定留待具备
AbilityRuntime 环境的后续批次。

## 证据打包（任务书 C 节）

`kv-ipc-evidence-20260928.zip`（sha256 `b7af2df0…`，本机 `.cache` 与构建机
`/tmp` 各一份）：四轮 evidence 目录全量 + `args.gn` + MANIFEST（库三摘要、
结果与红线、树修改指引）。

## 交接（任务书 D 节，lenovo 侧）

- IPC：按"真库级证实"升级 case.json；若提交工单，backtrace 证据在包内
  （file_offset `0x1ed9b` 可补符号名）。
- KV：case.json 按隔离限制如实记录；建议后续批次用带 AbilityRuntime 的
  环境重开真库判定。
