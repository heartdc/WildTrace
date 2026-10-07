# E 组 Tier C hiappevent 真库级证实 — 2026-10-03/04

任务书 G 节（Tier C）hiappevent 候选在**官方完整树**构建的真实库上验证成立。
授权状态：A-4（PR #63）已于 09-29 合并生效；本轮运行在完整树上进行。

## 环境（与此前选择性检出树的根本区别）

- 完整树 `~/oh-full-20261003`：官方 manifest repo sync（471+ 项目，gitcode 远端），
  LFS 大仓（ace_engine 27,930 文件 / graphic_2d 8,092 / graphic_3d 3,854）逐文件
  `git show` 完整抽取（`git archive` 遇 LFS 指针中断，此法绕开）。
- 官方 `gn gen --root-target` 一次通过；16,000+ 目标官方构建链全量编译。
- prebuilts 自旧树硬链接（clang 9.9GB / rustc / cmake / ark_tools / nodejs）。
- **树修改全部为登记性/环境兼容类**（部件 bundle.json 补注册、设备目录移植、
  POSIX 脚本修复、宿主 GCC12 头文件兼容），**不触碰任何 FFI 源码**——
  与选择性树上的 20+ 个 mock 补丁路线完全不同。

### 构建溯源（工单表单字段）

| 字段 | 值 | 来源 |
|---|---|---|
| hiappevent 仓构建提交 | `de94cb4d53f94afdbc75a5a7c46401f99bdcf17f`（2026-09-30 10:25:55 +0800，!628 merge master into master） | `.repo/projects/base/hiviewdfx/hiappevent.git` 裸仓 HEAD；工作树由该 HEAD 逐文件 `git show` 抽取（`.checkout_done` 标记），**即实际构建提交** |
| manifest 解析分支 | `master`（gitcode 远端 default revision，tracking `refs/heads/master`） | `.repo/manifests/default.xml` `<default remote="gitcode" revision="master"/>` |

注意：本地选择性检出树（`~/oh-real-20260925`，sweep HEAD 09-28）**不是**本案例的
构建来源；官方完整树的裸仓 HEAD 才是。两个值以上表为准。

## 结果

| case | 输入 | 结果 |
|---|---|---|
| 0（对照） | 合法 head 指针, size=1 | 返回错误码 `11101001`（FFI 层参数校验生效，**不崩溃**） |
| 1（候选） | `head=NULL, size=1` | **SIGSEGV** |

- 崩溃帧归属：gdb 两轮复现（ASLR 地址不同），rip 经 /proc/maps 映射在
  `libcj_hiappevent_ffi.z.so` 内（file_offset `0x11c9a`），不在 musl 运行库、
  不在 hilog。
- **源码级定位**：`base/hiviewdfx/hiappevent/frameworks/cj/ffi/src/hiappevent_ffi.cpp:372-385`——
  `for (int i = 0; i < watcher.appEventFilters.size; i++)` 循环直接
  `watcher.appEventFilters.head[i]` 解引用，**无 head 判空**。与 Tier C 链路追踪
  （PR #72）的预判完全一致。
- 库指纹：sha256 `bf8aa65e30c13782f54fa56b6d5e273a36425555865125a9bea6222943f6636a`，
  BuildID `252096ef`，15 个 `FfiOHOSHiAppEvent*` 导出符号。

## 判读口径

- **真库级证实**：case=1 在真实构建的库内崩溃，case=0 对照干净——缺陷精确限定于
  "null head + 非零 size" 组合。
- 红线：隔离环境（bwrap）、无产品服务、自定义 x86_64_virt 构建配置。
- 候选升级交由 lenovo 侧（任务书 D 节）：case.json 升级 + 工单提交
  （含 backtrace 证据）。

## 证据包

`hiappevent-evidence-20261003.zip`（sha256
`a8ae123ded484280d3dc15903683875518f90250d4f8104098ce9a157713c7a6`）：
完整 evidence 目录（client/runner/build.log/run.log/run.exit/target-elf/
inputs-*.sha256/gdb-full.txt）+ MANIFEST。

## 边界

- 这是畸形输入在真库内的崩溃证实，不是产品可达性结论：产品调用者、外部输入
  是否能触达该 FFI 入口仍是独立问题。
- F 组（account/udmf）与 av_session 的真库验证因 ace_engine idlize 生成器
  的 LFS 工具链 tarball 不可得而未完成——诚实入档，不在本 PR 范围。
