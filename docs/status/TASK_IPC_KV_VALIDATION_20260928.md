# IPC/KV 真库验证任务书（2026-09-28，交原构建机执行）

目标：把两个新发现候选从"源码等价复现"升级到"真实库复现"层级——这是
全库 18 案里唯二的新发现，也是最高价值提交候选。本机（lenovo）已完成
调用器与运行脚本（PR 见 `tools/validation_cases/`），对侧只需编译运行
留证。构建配方依据 `docs/analysis/REAL_BUILD_PROBE_20260925.md`。

## A. IPC 畸形输入验证（现成环境，预计 30 分钟）

对侧已有：`/home/airgap/oh-real-20260925` 隔离树、
`out/ffi-direct-min/communication/ipc/libcj_ipc_ffi.z.so`
（SHA 2bccd55c…）、修复后的 libc、可用的 OHOS Clang/sysroot——normal
检查已通过，全部条件现成。

```sh
git pull   # 取回本 PR 的 tools/validation_cases/
bash tools/validation_cases/run_malformed.sh \
  /home/airgap/oh-real-20260925 \
  /home/airgap/oh-real-20260925/out/ffi-direct-min \
  /home/airgap/oh-real-20260925/out/ffi-direct-min/evidence/ipc-malformed-20260928 \
  ipc_null_bytearray \
  communication/ipc/libcj_ipc_ffi.z.so
```

结果判读（两种都是有效结果，如实记录）：
- `run.exit`=139（SIGSEGV）且 `run.log` 最后一个 `case=` 标记停在
  `null_len1_candidate`/`null_len64_variant` → **真库级证实**（候选升级）
- 全部 case 打出 `done write_error=<码>` 且退出 0 → FFI 层有参数检查，
  **真库级证伪**（同样有价值：关掉该候选的产品影响主张）
- 崩溃时尽量补一份 backtrace（gdb --batch -ex run -ex bt 跑 client），
  证明崩溃帧在 IPC 库内而非补丁运行库

## B. KV 真库构建 + 畸形验证（需要构建，预计 0.5-2 天）

1. 同一隔离树，同一 x86_64 自定义配置（`product_name="x86_64_virt"` 是
   非 SDK 分支，KV 会编真实 CJ 源），root-target 换 KV 的 CJ FFI 目标
   （目标名读 `foundation/distributeddatamgr/kv_store/frameworks/cj/BUILD.gn`）
2. 构建可能拉入比 IPC 更多的依赖（distributeddb 等）——失败点如实记录
3. 产物路径假设 `out/ffi-direct-min/foundation/distributeddatamgr/kv_store/…so`
   （以实际为准，替换 LIBRARY_REL）
4. 先跑 normal 探针（kv_null_entry 的 stage=env_probe 段会先测
   CreateKVManager/GetKVStore）：**隔离环境若无 KV 服务导致 env_probe
   失败（退出 10/11），如实记录为隔离限制，不是候选结论**——此时看
   PutBatch 转换在服务调用前是否已执行（结合源码行号判断）
5. env_probe 通过则跑完整矩阵：`run_malformed.sh … kv_null_entry <LIBRARY_REL>`

## C. 证据打包回传（两边机器各留一份）

zip 清单（附 SHA-256 文件）：
- evidence 目录全套（client.c/runner/build.log/build.exit/run.log/run.exit/
  target-elf.txt/inputs-*.sha256/backtrace 如有）
- 所用 .so 与 libc 的本体或摘要
- build_gnargs.prop 与关键源码 HEAD 清单（按 probe 文档格式）
- （KV）构建日志 build-run*.log 与 .exit

通道：zip + sha256 清单经U盘/微信/私有分支任一传回 lenovo 机即可，本机
负责校验后归档与案例升级。

## D. 完成后（lenovo 机执行，无需对侧参与）

- case.json：runtime 证据升级为真库复现（或如实记录证伪/隔离限制），
  platform_binary_linked 仍按"自定义配置、非官方产品构建"口径标注
- 台账与 CHANGELOG 更新
- **若 IPC/KV 任一真库证实崩溃：按新发现提交奖励计划工单**（带真库
  backtrace 证据，层级高于现有 15 张缺口工单）

## 口径红线（与 probe 文档一致）

基础运行库打过补丁、无完整产品服务、自定义构建配置——三条必须出现在
所有证据与工单描述中；不得称为官方产品验证。
