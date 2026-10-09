# G 组 av_session 真库级证伪 — 2026-10-08（issue #112 交付）

任务书 G 节 av_session 候选（issue #112）在官方完整树构建的真实库上验证为
**入口层有防护（证伪）**。与 E 组证实（PR #97）、F 组 account 证伪（PR #98）
同树同构建链，授权 A-4（PR #63）覆盖。

## 环境

- 官方完整树 `~/oh-full-20261003`（同 PR #97，无回归）。
- root-target：`//foundation/multimedia/av_session/interfaces/cj:cj_multimedia_avsession_ffi`。
- ninja 图重复规则以 sweep 脚本清理（自盖章边、跨工具链同名产物），仅删图边、
  不触碰源码与产物内容。

### 构建溯源（工单表单字段）

| 字段 | 值 | 来源 |
|---|---|---|
| av_session 仓构建提交 | `000ed1e3b8dc9e2cdb44aabd9a91807fecd6ff9e` | `.repo/projects/foundation/multimedia/av_session.git` 裸仓 HEAD |
| manifest 解析分支 | `master`（gitcode 远端 default revision） | `.repo/manifests/default.xml` |

## 结果

| case | 输入（CArray→CParameters 分发） | 结果 |
|---|---|---|
| 0（对照） | 合法 head, size=1, vt=1 | rc=`-1011`，无崩溃 |
| 1（候选） | `value=NULL`, vt=7（字符串指针） | rc=`-1011`，**无崩溃** |
| 2（变体） | `value=NULL`, vt=8（i32 指针） | rc=`-1011`，无崩溃 |
| 3（变体） | `value=NULL`, vt=10（double 指针） | rc=`-1011`，无崩溃 |

全部 4 case 返回统一错误码 `-1011`，`malformed_matrix=completed_no_crash`，
run.exit=0。**含合法对照在内全部被拒**——`SendCommonCommand` 的
CArray→CParameters 分发在触碰 `value` 指针之前就被入口层拦截
（会话/连接状态校验），候选的 null `value` 解引用路径当前不可达。

## 判读

- **真库级证伪**：候选主张的"分发循环不查 value 空指针"在当前构建的真实库上
  不成立。参数/状态校验先行，任何 value 指针（含合法值）都未被解引用。
- 候选如实关闭：不再主张产品影响；若上游放宽会话前置校验或新版本行为变化，
  需重新登记。
- 库指纹：sha256
  `09ad4eda4f8beb996d65fad8aba218d575d7c304e13bbf932b0535d4bbe09879`，
  BuildID `6da810a67c02fafaddbb0c047aee454f`，55 个 `T` 导出符号
  （`FfiAVSession*`）。
- 红线：隔离环境（bwrap）、无产品服务、自定义 x86_64_virt 构建配置。

## 证据包

`avsession-evidence-20261008.zip`（sha256
`fe85af7f2b0be1b60f1c8feff327afa61b9c032c59bedfb24633cc8558b4eab2`）：
完整 evidence 目录（client.c/runner.sh/build.log/run.log/run.exit/
target-elf.txt/library-path.txt/inputs-*.sha256）。

## 边界

- 单库单入口（SendCommonCommand 分发路径）；av_session 其余 FFI 导出未展开，
  后续批次按台账候选另行排。
- x86_64_virt 跨平台构建 + musl 加载器运行；真机行为以工单侧复核为准。
