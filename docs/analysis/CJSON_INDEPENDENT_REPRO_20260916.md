# cJSON MergePatch 案例第二人独立复现记录 — 2026-09-16

## 结论

由第二复现人（GLM-5.3，操作账号 @heartdc 环境）在独立环境完成对
`cjson-merge-nonobject-alias` 案例的授权运行：**矩阵 26/26 行全部通过**，
与原运行记录的观测结构完全一致。本记录补上原记录自述的缺口
（"same driver, not independent human review"）。

## 独立性要素

| 要素 | 原运行（AerGap） | 本复现（GLM-5.3） |
|---|---|---|
| 操作者 | AerGap | GLM-5.3（第二复现人） |
| 源码获取 | 本地 OpenHarmony 树 | gitcode 镜像 `openharmony/third_party_cjson` 独立拉取，checkout `388cfc9`，两文件 sha256 与 case.json 逐字节一致（cJSON.c=caf16328…、cJSON_Utils.c=09c85ee0…） |
| 工具链 | llvm/clang 22.1.8 | Ubuntu clang 18.1.3（不同版本；二进制 sha256 8ef402d4…，运行记录内含版本日志） |
| 环境 | 原 WSL + bubblewrap | 独立 WSL Ubuntu 24.04 + bubblewrap（`--unshare-all --cap-drop ALL`，探针验证独立 netns/pidns、无宿主挂载、无 /home） |
| 驱动 | tools/cjson_case.py（已审入库） | 同一已审驱动（复现要求流程一致；自造驱动反而违反授权书 §2"执行代码须先审入库"） |

## 结果对比

| 观测 | 原记录 | 本复现 |
|---|---|---|
| library_uaf_observed | 文档表述"各 4 次" | 原版 subtree×3 + 独立副本 subtree×1，**共 4 次**；行级期望 26/26 通过 |
| functional_control_passed | 22 次 | 22 次（原版控制组 8 + 补丁组 14） |
| 矩阵状态 | passed, target_executed=true | passed, target_executed=true |

**口径修正**：原文档"原版和独立副本各 4 次"应为"合计 4 次"（矩阵选择为
原版 subtree×3 + 独立副本×1）。此差异即项目审计所记"运行次数与矩阵不符"项，
本复现将其钉死，建议随 #23 修正 CJSON_RUNTIME_CASE_20260915.md 措辞。

## 边界与限制

- 公开已知案例（CVE-2026-87933 / 上游 issue 1060）的库级回归验证，
  不是 WildTrace 新发现；产品可达性仍为 not_established。
- 同一驱动属有意选择（流程一致性）；独立性的差异来自操作者、源码获取路径、
  工具链版本与运行环境。
- 运行产物（acceptance.json、26 份日志、隔离探针、编译器指纹）保留于
  本地 `.cache` 与工作区，按既有约定不入库；摘要可按需提供复核。
- 跨系统 prepare/run 会使快照校验失败（.git index 被另一侧 git 刷新），
  本复现全程在单一 WSL 会话内完成 prepare+run；建议在 README 提示同侧执行。

## 授权合规

依据已签署的 EXECUTION_AUTHORIZATION.md 执行：仓库内已审案例材料与驱动、
只读源码、无网络（仅回环）、prlimit 资源限制、全程记录。
附录 A/B 的正式登记（含本复现工具链）待主线补录。
