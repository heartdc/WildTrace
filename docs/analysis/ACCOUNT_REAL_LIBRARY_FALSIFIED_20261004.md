# F 组 Tier B account 真库级证伪 — 2026-10-04

任务书 F 节 account 候选在官方完整树构建的真实库上验证为**有参数校验（证伪）**。
与 E 组证实（PR #97）同树同构建链，授权 A-4 覆盖。

## 环境与转折

与 PR #97 相同的官方完整树（`~/oh-full-20261003`）。此前 F 组被 ace_engine
idlize 生成器的 LFS 工具链 tarball 卡住两天——根因是 **git-lfs 客户端从未安装**
（日志中反复出现 `git-lfs: not found` 被误判为"资源断供"）。安装
`git-lfs 3.7.1` 后 `git lfs fetch -I "arkui_idlize/*.tgz"` 从 gitcode 官方
LFS 端点一次取回全部 6 个 tarball，SHA-256 全部校验通过（官方原始包替换了
此前手工编译的替代品）。生成器 `npm install` 恢复原始逻辑（撤销全部手工
node_modules 补丁），构建即通过。

教训入档：**"工具未安装"不等于"资源不可得"。** 两天的 TS 工具链手工重编
是不必要的；正确动作是安装 LFS 客户端。

## 结果

| case | 输入 | 结果 |
|---|---|---|
| 0（对照） | 合法 head, size=1 | rc=`12300001` |
| 1（候选） | `head=NULL, size=5` | rc=`12300001`，**无崩溃** |
| 2（变体） | head 合法, `size=-1` | rc=`12300001`，无崩溃 |
| 3（对照） | `head=NULL, size=0` | rc=`12300001`，无崩溃 |

全部 4 case 返回统一错误码 `12300001`，`malformed_matrix=completed_no_crash`。

## 判读

- **真库级证伪**：FFI 入口对 null head / 非法 size 有完整参数校验。Tier B
  链路追踪（PR #69）预判的"顶层 head 不查空"在当前构建的真实库上不成立。
- 候选如实关闭：该候选不再主张产品影响；如后续上游移除该校验或新版本
  行为变化，需重新登记。
- 库指纹：sha256
  `9b11ef49caf68c3e48074c4c21b02fe6c125c253050b719b24d6d12b1218ef5f`，
  BuildID `3adb90be`，29 个 `FfiAppAccountManager*` 导出符号。
- 红线：隔离环境、无产品服务、自定义 x86_64_virt 构建配置。

## 证据包

`account-evidence-20261004.zip`（sha256
`2770c4e4be3ee42a469ec0cb53c79613bf6f21b0e9c88383dfec9ab7fa677b35`）：
完整 evidence 目录（client/runner/build.log/run.log/run.exit/target-elf/
inputs-*.sha256）+ lib.sha256。

## 汇总（真库验证批次，官方完整树）

| 组 | 候选 | 结果 | PR |
|---|---|---|---|
| E 组 hiappevent | null head + size>0 | **证实**（SIGSEGV 库内） | #97 |
| F 组 account | null head + size=5 | **证伪**（参数校验拦截） | 本 PR |
