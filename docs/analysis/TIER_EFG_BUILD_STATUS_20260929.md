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

## 追加（同日晚，代理恢复后）：解锁清单第 1、2 项已由本机完成

网络恢复（github/gitcode/gitee 三通）后的实际进展：

- **`taihe_ffi_gen` 已入库**：真名为 GitHub `openharmony/arkcompiler_taihe_ffi_gen`
  （gitee/gitcode 的 `taihe_ffi_gen` 不存在；codeload tarball 取回，含 BUILD.gn，
  置于树根 `taihe_ffi_gen/`）。asmjit/zydis 确认不在任何 OH 托管仓（ohos.xml
  496 项无此三者）——但 `runtime_core_enable_codegen=false` 已在解析层绕开，
  链接层是否需要待构建验证。
- **rust-openssl BUILD.gn 已生成**：树内本有生成器 `build/scripts/cargo2gn.py`；
  `--run --skipcargo` 为 workspace 成员生成（顶层用 group 转发到 `openssl:lib`，
  转发文件已带注释入库树）。
- **`drawable_inner_ani` 版本漂移**：全树不存在的 innerapi（新 resource_management
  对旧 ace_engine），以空 group 桩补入 ace_engine/BUILD.gn。
- **hiappevent 的 gn gen 已通过**（GEN_OK）——部件/源码层全部解决。

### 新的最终卡点（ninja 图级，两类）

1. **skia 双源重复输出**：根 `skia/BUILD.gn` 与 `m133/` 各自生成 skcms 规则且
   输出路径相同（`obj/.../m133/modules/skcms/...`）——已对根侧子图做安全去重
   （两条完全相同的 cxx 规则）；正解应是部件登记只指 m133 目标，待回归验证。
2. **跨工具链副本冲突**：`ohos_ets/build-tools/driver/build-system` 被默认与
   clang_x64（宿主）两条不同规则写同一路径——非安全可去重，需 GN 参数关闭
   宿主侧 ets 构建或单工具链化，超出注入工具能力范围。

结论更新：E/F/G 的**源码与登记层已全部打通**（此前的"缺件墙"清除），剩余为
ninja 图生成的两类冲突修复；候选判定仍未发生。

## 边界

- 本轮无目标代码执行（gen/ninja 解析阶段即止），不涉及授权红线新增面。
- 全部树修改（补源、注入、args 覆盖、gni 补丁）在 out 目录与
  `docs/analysis` 记录留痕，与 #63 登记说明同口径。
- E/F/G 候选的真库判定仍未发生：现状=构建被缺件阻塞，非候选结论。
