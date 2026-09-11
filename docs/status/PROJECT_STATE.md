# 当前工程检查点

- 阶段：Phase 3 静态候选与证据模型，仍在进行。
- 检查点：STATIC_BENCHMARK_TAXONOMY_IMPLEMENTED。
- 最近增量：独立封存标记生成命令及归档验证复用。
- 验证：python -m unittest discover -s tests -q，共 81 项，79 通过、2 跳过（当前 Windows 环境不能创建符号链接）。
- 没有在运行的后台任务，没有安全策略阻断。
- 上轮属于有效进展；总体目标未完成，不能用工具数量或测试通过推断参赛能力已完成。

## 本次已完成

新增 ohvul/archive_seal_record.py，复用归档校验再创建标记。输出独立于归档，使用独占创建，拒绝覆盖已有文件，没有 --force 开关。增加 tests/test_seal_record.py 覆盖正常生成/校验、重复写入、源归档保护和无效输入。

从 ohvul/journal_archive_verify.py 提取 validate_archive，使归档校验入口和标记生成使用相同规则。文档更新见 docs/engineering/ARCHIVE_LIFECYCLE.md。

## 当前能力边界

- 本地文本规则扫描、启发式组件识别、精确版本候选匹配、JSON 证据、检查点、日志、报告、人工审核记录及归档均已存在。
- 大多数是原型；没有证据证明高准确率、全面覆盖、真实 OpenHarmony 漏洞确认或提交能力。
- 封存仅是普通 JSON 内容关联标记，不是数字签名、身份验证或文件系统只读控制。
- 标记生成只校验归档结构和事件摘要，不代替源扫描、报告和审核链的联合验证。
- 独占创建不提供多文件事务。写入过程突然中断可能留下不完整新标记；应检查后换新输出路径，不能视为成功。

## 尚未完成的关键项

- FSM 在直接 transition 与恢复入口之间的统一门控、恢复重试预算的端到端保持。
- 源码读取范围的一致性、扫描期间输入变化检测和严格错误报告。
- 报告投影字段与扫描结果的完整一致性、审核身份与批次摘要的可信绑定。
- 元数据库读取与摘要同源、时间筛选的真正日期比较、旧格式迁移契约。
- 构建/语义分析、评测基准、用户手册、最终比赛交付物。
- 持久化的多文件事务、跨进程互斥和目录替换竞争防护。

## 恢复操作

1. 读取本文件、CHANGELOG.md 和相关工程契约。
2. 使用上述命令确认代码基线，不重写过去的测试数量。
3. 本次修改文件：ohvul/archive_seal_record.py、ohvul/journal_archive_verify.py、tests/test_seal_record.py，以及状态/归档生命周期/变更文档。
4. 下一步继续 Phase 3 核心验收：报告投影字段已补强，转向扫描规则与误报基准。

## 阻断与输入

仅使用临时合成 JSON 验证，没有生成真实操作者审核或封存记录。测试临时文件已自动清理。若未来真实路径受阻，应保留错误与最后成功检查点，再选择允许的恢复路径；不得尝试规避限制。

## 报告端到端绑定增量

新增 CLI 回归：同时保存扫描 JSON 和 candidate-only 报告，再用 report_verify 校验绑定。76 项测试，72 通过、2 跳过。

## 扫描期间输入门禁增量

CLI 在扫描前后比较 source_snapshot_sha256；源码扫描期间变化会拒绝生成结果链。76 项测试，72 通过、2 跳过。

## 报告字段投影增量

validate_report_against_result 现在要求候选告警集合、告警 ID、CWE、规则、位置和 evidence_refs 与扫描结果完全一致；76 项测试，72 通过、2 跳过。

## 规则质量小增量

扫描器支持行级 `// ohvul:ignore` 明确抑制某条候选，其他行仍扫描；新增两个回归测试。该注释是人工抑制记录，不是安全证明。

## 静态规则基准增量

新增 docs/design/rule_benchmark.json，覆盖内存复制候选、人工忽略、上下文相关候选和安全控制样例；新增回归测试。76 项测试通过，2 项跳过。

## 基准统计增量

新增 python -m ohvul.benchmark docs/design/rule_benchmark.json，输出候选 TP/FP/FN、precision/recall 和逐例结果，明确免责声明。76 项测试通过，2 项跳过。

## 基准规则扩展增量

增加整数长度和指针解引用候选样例；为避免规则重叠，内存复制行不重复报告 CWE-476。81 项测试，75 通过、2 跳过。

## 安全反例增量

增加已显式判空但仍被启发式指针规则命中的安全反例，作为可解释的 FP 候选；81 项测试通过，2 项跳过。

## 基准原因标注增量

每条合成样例新增 reason，解释候选、人工抑制、安全反例或需要上下文的标注依据；81 项测试通过，2 项跳过。

## 规则重叠统计增量

benchmark 输出 rule_overlap_cases，并为每例输出 rule_overlap 和 reason；用于识别同一行多规则重复命中。81 项测试通过，2 项跳过。

## 基准统计快照增量

生成 docs/design/rule_benchmark_report.json：8 个合成样例，候选 TP=5、FP=2、FN=0、precision≈0.714、recall=1.0、重叠样例 1。该快照仅用于规则回归，不能外推真实准确率。

## 基准分类标签增量

规则基准样例新增 language/component 分类字段，支持后续按 CWE、语言和 OpenHarmony 组件类型分层统计；81 项测试通过，2 项跳过。

## 基准分层统计增量

benchmark 报告新增 groups，按 component::language 汇总 cases、TP、FP、FN；报告快照已重新生成。81 项测试通过，2 项跳过。


## 状态计数校准

以当前工作区实际命令为准：python -m unittest discover -s tests -q 运行 81 项，79 通过，2 跳过。历史增量文字不作为当前计数证据。


## 基准输入契约增量（2026-09-10）

benchmark 在任何临时文件创建前校验数组、字段集合、唯一 ID、标签/CWE 一致性、语言和 CWE 格式；CLI 对无效标注输出 INVALID。样例 ID 仅作为展示元数据，临时文件使用固定安全文件名。新增 5 个回归测试。全套 86 项测试，84 通过、2 跳过。

未完成：基准仍为小规模合成样例，不代表真实准确率；下一步继续扫描规则与误报基准扩展。

## OpenHarmony 受限源码样本扫描（2026-09-10）

用户授权本地源码目录 C:\Projects\OpenHarmony。只读盘点发现约 292,493 个 C/C++ 文件；为避免全仓库扫描造成不可控资源消耗，本次仅扫描 commonlibrary/utils_lite/timer_task 子树。输出 docs/design/openharmony_timer_task_scan.json，verify 校验通过（29 条不同证据记录）。结果仅为候选发现，不代表 OpenHarmony 平台漏洞结论。

未完成：全仓库分片策略、忽略目录契约和误报人工基准仍待设计。下一步为受控分片扫描器设计。

## 受控分片清单增量（2026-09-10）

新增 ohvul.shards.build_manifest：按路径排序、过滤 C/C++ 扩展名、生成固定大小分片及路径列表 SHA-256；不读取源码内容、不执行代码。新增 2 项测试。下一步接入分片扫描调度与资源上限。


## 分片资源门控增量（2026-09-10）

分片清单新增 max_files 上限，非法预算会在扫描前拒绝；新增资源门控回归测试。仍未接入实际分片扫描调度。


## 分片扫描调度增量（2026-09-10）

scan_path 支持显式相对文件集合，新增 scan_shard 仅扫描清单分片；新增 2 项测试。尚未实现跨分片结果合并与超时控制。


## 跨分片合并增量（2026-09-10）

新增 merge_shard_results：绑定源码根目录、按位置和 CWE 确定性排序、去重证据并重新编号告警；新增合并回归测试。尚未进入 Phase 4，仍缺少超时/取消门控和本地独立复现契约。


## 回归校验（2026-09-10）

全套 python -m unittest discover -s tests -q：92 项，90 通过、2 跳过。分片清单、受限扫描和跨分片合并均有回归覆盖；Phase 3 尚未完成，待补合并结果的统一证据验证与本地安全验证契约。


## 分片证据验证增量（2026-09-10）

跨分片合并输出已接入现有 validate_result 回归校验，确认合并结果仍受证据引用和摘要门控约束。分片专项测试 7 项通过。尚未进入 Phase 4。


## 本地独立证据复核增量（2026-09-10）

新增 ohvul.local_recheck.recheck_finding，按授权源码位置重算行哈希并报告可复现性；不执行目标代码、不联网。新增 2 项测试。该步骤仍不构成漏洞确认，Phase 4 入口还需 FSM 门控与隔离 harness 契约。


## Phase 4 入口门控增量（2026-09-10）

新增 verification_gate.can_request_local_verification：仅允许 static_scan 状态且所有候选通过本地证据复核后请求隔离 harness 审查。新增 1 项门控测试。尚未执行 harness，故仍未进入 Phase 4。


## 隔离 harness 契约增量（2026-09-10）

新增 local_harness.evaluate_synthetic，仅接受合成 case，复用验证门控并始终输出 review_required=true、verdict=undetermined；不编译或执行目标代码。新增 2 项测试通过。Phase 4 尚未正式开始，需先完成 FSM 迁移接入和人工审核记录契约。


## 本地验证迁移意图增量（2026-09-10）

验证门控新增 request_local_verification_transition，只有 static_scan 且证据全部可复现时返回 local_verification 迁移意图；实际 FSM 状态枚举尚未扩展，避免破坏既有检查点兼容性。新增回归断言通过。


## FSM 本地验证状态增量（2026-09-10）

FSM 新增 local_verification 状态，static_scan 可显式进入本地验证，再回到 triage 或 blocked；保留原 static_scan->triage 路径。新增状态迁移测试通过。Phase 4 尚未开始，仍需把门控结果写入检查点并定义隔离 harness 记录 schema。


## Harness 记录 schema 增量（2026-09-10）

新增独立 harness_record.validate_record，固定 schema 0.1，要求 undetermined、review_required=true 和布尔 reproducible；拒绝 confirmed 等确定性漏洞结论。新增 2 项测试。Phase 4 入口条件接近，仍需将记录与 FSM local_verification 状态关联。


## Harness 记录关联增量（2026-09-10）

local_harness 新增 to_record，将合成评估结果投影为可校验的人工审核记录；保持 undetermined 和人工审核要求。


## 验证记录持久化关联增量（2026-09-10）

新增 verification_link，将 task_id、checkpoint_sha256 与 harness 记录摘要绑定并可离线校验；不修改旧检查点 schema。新增 1 项测试通过。Phase 4 入口所需关联链已具备，仍需端到端执行并更新阶段状态。


## Phase 4 已开始（2026-09-10）

端到端本地安全验证完成：对 timer_task 受限扫描的 29 条候选逐条重算源码行哈希，全部可复现；通过 static_scan 门控生成 review-only harness 记录和检查点关联，记录 verdict=undetermined、review_required=true。产物 docs/design/openharmony_timer_task_harness_record.json。此结果不是漏洞确认，也不代表 OpenHarmony 平台结论。


## Phase 4 首个闭环验收（2026-09-10）

独立校验 harness 记录 schema 与摘要关联通过；全套回归 101 项，99 通过、2 跳过。当前 Phase 4 仅完成静态证据复核和合成 harness 闭环，未执行目标代码，不能宣称漏洞复现。下一步继续做隔离环境输入/输出契约。


## 隔离 I/O 契约增量（2026-09-10）

新增 isolation_contract，限制 harness 输入为标量合成值，输出必须保持 undetermined、review_required=true、no_target_execution=true；新增 2 项测试通过。


## Phase 4 隔离契约回归（2026-09-10）

全套测试 103 项，101 通过、2 跳过；隔离输入输出契约与证据链兼容。Phase 4 当前闭环仍限于静态复核和合成 harness，未执行目标代码。


## 隔离资源预算增量（2026-09-10）

隔离输入契约新增 max_bytes（1..1MiB）和 timeout_ms（1..60s）预算校验；新增边界测试通过。


## 隔离预算执行校验增量（2026-09-10）

max_bytes 预算现在实际约束字符串/字节合成输入长度，新增超限回归测试；避免仅声明预算而不执行。


## Phase 4 回归核对（2026-09-10）

全套回归 103 项，101 通过、2 跳过；隔离预算与 harness/FSM 链路保持稳定。未执行目标代码，未生成真实攻击输入。


## Harness 输出即时门控增量（2026-09-10）

local_harness.evaluate_synthetic 现在生成结果后立即调用 isolation_contract.validate_output，确保 review-only 和 no_target_execution 约束不会被绕过。专项测试 4 项通过。


## Phase 4 回归稳定性（2026-09-10）

全套测试 103 项，101 通过、2 跳过；harness 输出即时门控修复后整体稳定。


## 隔离输入实际门控（2026-09-10）

evaluate_synthetic 现在强制调用 validate_input，预算与标量输入约束在运行入口实际生效；专项测试通过。


## Phase 4 回归确认（2026-09-10）

全套测试 103 项，101 通过、2 跳过；隔离输入门控修复后无回归。


## Phase 4 契约文档（2026-09-10）

新增 docs/engineering/PHASE4_LOCAL_VALIDATION.md，统一记录输入、输出、资源、证据绑定和验收边界。


## Harness 记录安全落盘增量（2026-09-10）

save_record 使用独占创建、拒绝符号链接和覆盖，记录先经 schema 校验；新增覆盖保护测试通过。


## Phase 4 全量回归（2026-09-10）

全套测试 104 项，102 通过、2 跳过；安全落盘与现有工作流兼容。


## 深入审计修复：符号链接一致性（2026-09-10）

审计发现 scanner 会跟随符号链接，与 source_snapshot 跳过策略不一致；现已显式跳过 symlink，并新增回归测试。专项测试 4 项，3 通过、1 跳过。


## LLM 运行时适配器增量（2026-09-10）

新增 ohvul.llm_adapter，仅在调用时从 OSLOVELACE_API_KEY 读取 key，默认不联网；请求内容明确限制为候选证据分析草稿，返回 final_verdict=undetermined。仓库与日志不保存 key。


## LLM 适配器离线安全回归（2026-09-10）

新增 mock 网络测试，验证运行时 key 仅进入授权请求头，不进入返回结果，且 final_verdict 始终为 undetermined。


## LLM 上下文边界增量（2026-09-10）

LLM 适配器现在只接受结构化 dict 且限制序列化上下文不超过 64 KiB，拒绝大规模源码误传；新增 2 项边界测试。


## LLM 超时资源门控（2026-09-10）

LLM 适配器 timeout 现在限制为 1..60 秒，与隔离资源契约一致；新增边界测试通过。


## LLM 运行时配置文档（2026-09-10）

README 新增可选 LLM 适配器配置说明，明确环境变量读取、显式调用和 review-only 输出边界。


## LLM 模型白名单增量（2026-09-10）

适配器新增模型白名单，当前仅允许已验证的 grok-4.6；新增未授权模型拒绝测试。


## LLM HTTPS 边界增量（2026-09-10）

LLM 适配器拒绝非 HTTPS Base URL，新增离线测试；避免 key 通过明文 HTTP 传输。


## LLM 响应 schema 校验增量（2026-09-10）

适配器对 choices/message/content 做结构化校验，异常响应拒绝进入分析链，草稿必须为文本；专项测试通过。


## LLM 输出大小门控增量（2026-09-10）

适配器限制模型草稿不超过 16 KiB，避免异常响应污染后续证据链；编译检查通过。


## CI 离线回归增量（2026-09-10）

新增 .github/workflows/offline-tests.yml，在 push/PR 上运行本地 unittest；不使用 secrets、不联网扫描目标。


## CI 密钥形态门禁增量（2026-09-10）

离线 CI 新增 sk- 形态凭据扫描，防止未来提交意外包含 API key；仅扫描仓库内容，不访问网络。


## 本地凭据忽略规则增量（2026-09-10）

.gitignore 新增 .env、密钥和 secrets 文件模式，与 CI 凭据扫描共同降低误提交风险。


## CI 最小权限增量（2026-09-10）

离线测试工作流新增 contents: read 最小权限声明，减少 CI 任务写入仓库的能力。


## 跨平台 CI 验证（2026-09-11）

GitHub Actions offline-tests 在 Ubuntu 上对提交 beadf8d 执行成功；本地 Windows 全套测试仍为 108 项，105 通过、3 跳过。


## 可交付打包元数据增量（2026-09-10）

新增 pyproject.toml，声明 WildTrace 包元数据和 CLI 入口；无运行时联网依赖。


## 本地打包验证（2026-09-10）

editable 安装（--no-deps）成功，wildtrace --help 可用；生成目录已加入忽略规则。原清理命令受环境策略阻断，未重复尝试。


## 本地安装文档增量（2026-09-10）

README 补充无 key 的本地安装和离线测试命令，并说明仅显式调用 LLM 适配器时配置环境变量。


## 公开仓库安全策略文档（2026-09-10）

新增 SECURITY.md，明确授权范围、候选结论边界和禁止提交真实攻击材料的规则。


## 协作者审核规则增量（2026-09-10）

新增 .github/CODEOWNERS，所有路径默认请求项目维护者 AerGap 审核。


## 验证关联安全持久化增量（2026-09-10）

save_link 将 checkpoint/harness 关联记录安全写入独立文件，先校验摘要和 review-only 约束，拒绝覆盖及符号链接；新增测试通过。


## 分片合并资源门控增量（2026-09-10）

merge_shard_results 新增 max_shards 上限，防止超大源码树结果无界合并；专项测试通过。


## 扫描网络隔离回归（2026-09-10）

新增测试确认普通 scan_path 流程不会调用 urllib 或 LLM；网络仅存在于显式适配器入口。


## 验证摘要格式门控增量（2026-09-10）

verification_link.validate_link 现在严格要求 checkpoint_sha256 为 64 位小写十六进制摘要；新增伪造摘要拒绝测试。


## 分片证据冲突门控增量（2026-09-10）

跨分片合并遇到相同 evidence_id 但内容不同的记录现在明确拒绝，防止证据替换；新增冲突测试通过。


## Phase 4 验收清单（2026-09-10）

新增 PHASE4_ACCEPTANCE.md，按证据列出本地复核、隔离契约、FSM、检查点关联、合成 harness 和回归状态，并明确未执行目标代码、未确认漏洞。


## 验证关联恢复增量（2026-09-10）

新增 load_link，重启后从磁盘读取并重新校验 harness 摘要绑定；新增恢复读取断言通过。

## 当前有效检查点说明（2026-09-10）

文档前部的历史条目保留作记录；当前有效状态以文档末尾最新检查点为准：Phase 4 已开始，验证链和 CI 已通过，后续聚焦隔离 harness 与检查点进一步集成。

## Phase 4 闭环检查点（2026-09-11）

Phase 4 的允许范围已完成：静态证据独立复核、合成 harness、输入输出预算、FSM local_verification、检查点摘要关联、冲突拒绝、恢复读取、跨平台回归和 CI 门禁均已验证。真实 OpenHarmony 目标代码执行仍被禁止，因此不产生漏洞确认结论。下一阶段为 Phase 5：分支影响、补丁验证和报告。


## Phase 5 分支影响比较增量（2026-09-11）

新增 branch_impact.compare_findings，仅比较本地保存结果的 evidence_id，输出新增/消失候选并要求人工审核；不访问远程 Git。新增测试通过。


## Phase 5 补丁范围门控增量（2026-09-11）

新增 validate_patch_scope，限制补丁路径在授权源码根目录内，拒绝路径穿越；新增测试通过。


## Phase 5 结果 schema 门控增量（2026-09-11）

分支影响比较器严格要求扫描结果 schema 0.3，拒绝旧格式；测试通过。


## Phase 5 本地路径门控增量（2026-09-11）

补丁范围校验明确拒绝 URL 形式路径，确保仅处理本地路径；新增测试通过。


## Phase 5 源码根目录绑定增量（2026-09-11）

分支影响比较器现在拒绝不同源码根目录的扫描结果，避免跨项目误比较；测试通过。


## Phase 5 本地来源门控回归（2026-09-11）

新增测试确保分支影响比较拒绝非 local_only 扫描结果；专项测试 3 项通过。


## Phase 5 findings 结构门控增量（2026-09-11）

分支影响比较器校验 findings 结构和 evidence_id 类型，损坏输入明确拒绝；新增测试通过。


## Phase 5 分支影响 CLI 增量（2026-09-11）

branch_impact 支持 python -m ohvul.branch_impact 对两份本地 JSON 结果做离线比较，错误输入输出 INVALID；不访问远程 Git。


## Phase 5 CLI 回归覆盖增量（2026-09-11）

新增分支影响 CLI 成功路径测试，验证本地 JSON 比较输出可解析；专项测试 5 项通过。
