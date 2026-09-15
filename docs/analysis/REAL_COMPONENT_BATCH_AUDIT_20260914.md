# 真实组件接入与批处理验收 — 2026-09-14

## 验收边界

本批完成了真实源码 profile 接入、串行多组件批处理、失败隔离及报告绑定。
这是工程工作包的完成，不是比赛项目完成，也不代表发现了可提交的漏洞。
没有执行 OpenHarmony 目标程序、修改源代码工作区、安装依赖、提交或回滚项目 Git。
项目基线为 `132b05670b539203cf5eafe3872b2f6979e75f75`。

四个用户声明的目录均能通过 TaskQuay 打开。本轮实际分析使用
`C:\Projects\OpenHarmony-complete`。该目录的只读盘点发现 14 个仓库根、
6,290 个非 Git 文件、144,872,745 字节；目录名称不意味着产品源码已完整。
旧 `OpenHarmony` 目录可读到另一份快照记录，但一条自动盘点命令被工具拦截。
没有从别的路径绕过该拦截，也没有混用两个目录的提交号。

## 系统改动

新增 `ohvul/component_batch.py`、`tests/test_component_batch.py` 和
`docs/engineering/COMPONENT_BATCH.md`。输入清单 `component-batch-0.1` 明确声明
每个作业的 ID、源码根和 profile。先校验整份清单的结构、路径与输出冲突，
再按作业执行来源预检；预检不调用分析器。实际分析串行运行，单个作业失败
保留失败原因而不阻断其他独立作业。部分分析结果只能是诊断，不能生成成功报告。

结果、candidate-only 报告、逐作业 receipt、增量 summary 均保留哈希。
最终 summary 再核对所有已完成作业的配置、源码和产物字节。
`summary-NNNN.json` 中只有最终 `completed` 才表示全批验收；预检是 `ready`，
不是已分析。无自动恢复、后台队列或多文件事务承诺。

独立复核修正了 Codex 补丁中的三个边界：CLI 超时必须为 1–900 的整数；
产物采用独占创建，避免 POSIX 检查后 rename 覆盖竞争；profile 使用已有的
有界读取器，不在校验前无界读取文件。另保留固定 totals 与详细失败状态。

依据 hilog 的实际 BUILD.gn，有限编译参数白名单增加 `-fno-common`、
`-fno-strict-aliasing`、`-O2`。其余响应文件、插件、输出覆盖和任意转发约束不变。

## 真实输入与结果

| 作业 | 声明源文件 | Clang | clang-tidy | 原始候选 |
| --- | ---: | --- | --- | ---: |
| camera_app | 3 | completed | completed | 0 |
| securec | 39 | completed | completed | 31 |
| hilog_featured | 2 | completed | completed | 4 |

使用已安装的 Clang/clang-tidy 22.1.8。camera 保留原有 4 个仓库约束，
从实际依赖补齐 9 个提交，共 13 个 clean/matched 仓库；没有刷新错误旧 pin。
securec 使用 `libsec_src.gni` 声明的全部 39 个 C 源文件及 BUILD.gn 的标准分支定义。
hilog 使用 featured 非 LiteOS-M 分支的两个源文件、包含路径与编译选项。
后两者仍是宿主静态分析配置，不是完整 OpenHarmony 产品构建。

正式清单和 profile 位于 `docs/profiles/`：

```text
real_components_20260914.batch.json
camera_app_captured_20260914.json
securec_captured_20260914.json
hilog_featured_captured_20260914.json
```

真实预检 3/3 ready，分析器尝试数为 0；实际批次 3/3 completed，无失败作业。
44 是显式声明的源文件数量，不是全平台覆盖率，也不是两个引擎结果的相加。
单次实测预检命令约 43.40 秒、实际分析命令约 183.48 秒；包含来源和快照复核。
没有测量峰值内存或完成大规模平台性能评测，不将本次耗时外推为平台吞吐率。

## 原始诊断的复核索引

35 条诊断按作业、源码位置和规范化检查器归为 29 个复核组，原始结果未修改。
31 条是 securec 内部 API 使用提示（CWE-676），归为 27 个位置/规则组；
4 条是 hilog 两处 dead store 在两个引擎中的重复观察，归为 2 组。
不同翻译单元和宏配置的证据引用继续保留，不能据此推断为 29 个独立漏洞。

已抽查 `memcpy_s.c` 的候选上下文及 `hiview_log.c:1550–1552`。
前者是在安全封装实现中调用底层内存函数的提示，需要继续检查参数验证与
可达性；后者当前只有未被读取的赋值描述。都没有独立安全影响或触发证据。
复核索引所有结论保持 `undetermined`，真实漏洞确认数为 0。

## 测试和证据

Codex 终端实际写入批处理实现，但在收尾遇到
`Selected model is at capacity. Please try a different model.`，退出码 1。
宿主随后独立读取代码、修复契约并执行验收，不依据模型自述接受结果。
Codex CLI 没有返回用量事件，实际 token 数未知；受管执行账本的 0 不代表 CLI 零消耗。
原生 Agent 接口的失败边界是 `DAEMON_STARTUP_FAILURE`，未修改 TaskQuay 配置来绕过。

独立新回归先运行 31 个方法，出现 5 个失败断言（含子测试），修正后 31/31 通过。
最终专项 90 项全部通过。全量运行 336 项，332 项通过，4 项因
`symlink unavailable` 跳过；不能把跳过项当作当前环境已验证。
源码哈希、HEAD 与原有 Obsidian 字节在最终验收期间保持一致，差异检查退出码 0。

```powershell
python -m unittest tests.test_component_batch tests.test_profile_input_contract tests.test_engine_execution_contract tests.test_workflow_p0 -v
python -m unittest discover -s tests -v
python -m ohvul.component_batch --manifest docs/profiles/real_components_20260914.batch.json --output .cache/real-components-preflight-new --preflight-only --timeout 60
python -m ohvul.component_batch --manifest docs/profiles/real_components_20260914.batch.json --output .cache/real-components-run-new --timeout 60
```

输出目录必须是新目录。正式执行日志及机器验收记录：

```text
.cache/real_components_c0d3/acceptance.json
.cache/real_components_c0d3/accept-focused.log
.cache/real_components_c0d3/accept-full.log
.cache/real_components_c0d3/preflight/summary-0005.json
.cache/real_components_c0d3/batch/summary-0005.json
.cache/real_components_c0d3/review-queue.json
.cache/real_components_c0d3/real-profile-origins.json
```

## 后续自动工作与人工依赖

不预先削减组件或漏洞族范围。下一阶段的自动工程队列是依赖/编译配置导入、
上下文与边界研判、复核队列产品化、快照开销测量与复用、资源统计和受控恢复。
现有批处理每作业调用引擎 profile，并非完整 LLM 业务 Agent，也不是漏洞验证器。
其他仓库仍在接入范围内；本轮三个作业不代表项目永久范围。

需要人工确认的是目标产品与分支矩阵、可恢复的隔离运行/设备环境，以及
最终漏洞评审与私下提交责任人。详见 `docs/status/HUMAN_ACTIONS_20260914.md`。
当前 SECURITY.md 对真实目标执行的边界没有改变。
