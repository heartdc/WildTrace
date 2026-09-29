# Tier E/F/G 真库构建状态与工具链 — 2026-09-29

任务书 E/F/G 节（av_session / account+udmf / hiappevent+bluetooth）在原构建机的
执行状态。构建配方沿用 IPC/KV（PR #63/#65）；授权：A-4 已合并生效。

## 结论：三目标同撞"选择性检出缺件墙"，本机网络无法补齐；攻关工具链已入库可复用

三个目标（av_session `cj_multimedia_avsession_ffi`、account `cj_appAccount_ffi`、
hiappevent `cj_hiappevent_ffi`）的 gen 均推进到同一堵墙，此前共解决约 60 层
登记/源码缺失。**与 IPC/KV 不同**：这批新式 CJ FFI 目标的闭包经 ability_runtime
→ ipc/native/taihe → ets_runtime → static_core 拖入大半个产品树。

## 已攻克的层（工具链自动处理，全部可复现）

1. **部件登记注入**（`tools/validation_cases/component_inject.py`，随本 PR 入库）：
   组件级 + innerapi 级两类错误，三级源码解析（WSL 树自检 → Windows 全树 →
   rust crate 名映射 `rust_X` → `third_party/rust/crates/X`），自动补源码
   （tar 排除 .git）+ 注入 components.json + third_party_allow_list。
   已注入：sqlite(+sqliteicu)、skia 全家（libjpegm133/piexm133/dng_sdk/
   skia_paragraph_ohos_new）、sonic、xmp_toolkit_sdk、vulkan-headers/loader、
   vma（gitcode 克隆成功）、typescript、vixl、rust_rust-openssl 等。
2. **`taihe_template_bypass = true`**（out 目录 args.gn）：绕过新 IDL 代码生成
   对 `taihe_ffi_gen` 部件的依赖（模板走 touch 桩分支）。
3. **`runtime_core_enable_codegen = false`**（declare_args 直覆盖）：绕过
   static_core 对 asmjit/zydis 的 x86_64 配置需求。
4. **rust crate 批量同步**：全树有而 WSL 树缺的 42 个 crate 一次补齐（含 clap）。
5. skia `skia_use_vma` gni 补丁（vma 若由 skia 侧引入时可关；vma 部件本体已另行
   克隆入库，此补丁保留为备用）。

## 墙的三块砖（本机网络下均不可得）

| 缺件 | 消费者 | 尝试 |
|---|---|---|
| `taihe_ffi_gen` 子仓 | ipc/native/taihe → ability_runtime 链 | gitcode 403；gitee 数据传输挂起；github 不通 |
| `asmjit` / `zydis` 子仓 | static_core codegen（已由 3 绕过解析层；链接层是否需要待验证） | 同上 |
| rust-openssl workspace 的生成式 BUILD.gn | code_signature key_enable → 闭包 | 两树的该 crate 均无 BUILD.gn（生成器产物），workspace 含 4 子 crate，手补成本失控 |

## 对侧解锁清单（有网络一侧执行，约 30 分钟）

1. 克隆三个子仓进隔离树：`taihe_ffi_gen`（树根）、`third_party/asmjit`、
   `third_party/zydis`（gitcode/gitee/CI 任一通路）。
2. 跑一次 rust crates 的 BUILD.gn 生成（或从任一已完整构建的检出拷贝
   `rust-openssl{,-sys,-errors,-macros}/BUILD.gn`）。
3. 之后本机按既有配方收尾：`component_inject.py <out> <//root:target>` →
   `build_component.sh` 同款 gen+ninja → `run_malformed.sh`（客户端已随 #68/#70/#72 入库）。

## 边界

- 本轮无目标代码执行（gen/ninja 解析阶段即止），不涉及授权红线新增面。
- 全部树修改（补源、注入、args 覆盖、gni 补丁）在 out 目录与
  `docs/analysis` 记录留痕，与 #63 登记说明同口径。
- E/F/G 候选的真库判定仍未发生：现状=构建被缺件阻塞，非候选结论。
