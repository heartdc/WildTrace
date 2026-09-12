# Changelog

## Joint verification single-read consistency

- 扫描结果摘要和解析共用单次读取字节，修复原先两次读取可能不一致的问题。
- 增加联合校验/CLI 成功路径、结果字节变化、错任务、缺失证据、损坏 envelope 和无效 workflow 测试。
- 相关 11 项测试：10 通过、1 跳过；只验证合成 JSON 关联，不宣称 harness 或漏洞复现成功。

## Actual checkpoint linkage validation

- 新增 make_checkpoint_link / validate_checkpoint_link，以实际检查点字节生成并验证摘要，同时核对 schema、任务、local_verification 状态与 harness 记录。
- 复用 validate_checkpoint_data，解析和摘要使用相同字节来源。
- 新增字节变化、任务变化、伪造摘要、错误状态及无效记录测试；相关 38 项测试通过。
- 校正 Phase 4 验收声明：旧 link 校验不证明检查点关联；生产链集成仍待完成。本轮不推送。

## 2026-09-10

- 建立防御性代码审计 MVP。
- 增加工程主提示词、阶段状态和恢复协议。
- 当前扫描器仅处理本地 C/C++ 源码，输出候选发现。

## 2026-09-10 (Phase 2)

- 增加只读本地组件识别和版本元数据读取。
- CLI JSON 结果加入 components 字段。
- 通过 2 项单元测试。

## 2026-09-10 (Phase 2 metadata)

- 增加可选本地 JSON 漏洞元数据加载和组件/版本匹配。
- CLI 增加 --vuln-db 参数，默认不联网。
- 通过 3 项单元测试。

## 2026-09-10 (Phase 3 evidence)

- 增加统一 EvidenceBundle 数据模型。
- 静态候选结果加入 evidence_id 和证据摘要。
- 通过 4 项单元测试。

## 2026-09-10 (Phase 3 evidence links)

- 本地漏洞元数据匹配结果关联 EvidenceBundle。
- 通过 4 项单元测试。

## Evidence validation increment

- 证据标识改用完整记录的 SHA-256，扫描格式升级到 0.3。
- 新增 python -m ohvul.verify，检查摘要、静态片段、位置和引用。
- 新增 3 个测试方法，全套 7 项通过。
- 修复 PROJECT_STATE.md 换行错误，明确开发标签不是运行时 FSM，普通 JSON 不是不可变存储。
- 恢复入口及限制详见 docs/engineering/EVIDENCE_VALIDATION.md。

## Conservative metadata matching

- 版本缺失、unknown 或星号标记进入 unresolved，不能作为版本匹配成功。
- 精确版本相等输出 exact_version_candidate，仍不代表目标代码受影响。
- 元数据输入采用 UTF-8 BOM 兼容读取并拒绝无效记录。
- 校验器检查 unresolved 证据引用；全套 11 项测试通过。
- 后续继续补完整数据库来源绑定和 FSM，未完成总体目标。

## Metadata source binding

- 匹配 EvidenceBundle 绑定本地数据库数组摘要和来源标识。
- 校验器检查元数据来源标识，11 项测试通过。

## Complete metadata presentation binding

- 匹配项保留来源记录副本并绑定数据库数组摘要、来源标识和 evidence_id。
- 校验器核对 id、cwe、summary 等展示字段与来源记录一致；修改后拒绝。
- CLI 回归验证通过；全套 11 项测试通过。
- 这仍是候选元数据证据，不是漏洞确认或来源签名。

## Output and source protection

- CLI 默认拒绝覆盖已有结果，显式 `--force` 才允许替换。
- 本地漏洞数据库文件写入字节 SHA-256；数组摘要继续保留用于记录语义。
- 新增覆盖保护回归测试；全套 12 项测试通过。
- 哈希仍用于完整性检测，不等同于数字签名或可信来源证明。

## Deterministic FSM checkpoint core

- 新增有限状态机核心和检查点保存/恢复。
- 非法迁移、阻断原因、恢复清除和检查点覆盖保护均有测试。
- 全套 15 项单元测试通过。
- 尚未接入 CLI、Agent 或目标代码执行。

## CLI workflow checkpoint integration

- CLI 增加 --checkpoint 和 --task-id，扫描结果包含 workflow。
- 仅在本地扫描成功后进入 static_scan；错误记录 blocked。
- 全套 16 项测试通过；未自动推进到 triage/report。

## Checkpoint result binding

- 检查点增加 result_sha256，绑定实际保存的结果字节。
- verify 增加 --checkpoint，检查摘要、任务、状态和证据。
- 新增修改拒绝和失败检查点测试，全套 18 项通过。
- 重写恢复状态，清除过期能力声明：尚无自动恢复或事务保存；数据库数组摘要未单独保留，前文所述“双摘要”并未实现。

## Path isolation and atomic result publishing

- 拒绝结果/检查点位于扫描源码目录内。
- 拒绝结果/检查点与漏洞数据库相同，即使传入 `--force`。
- 结果使用同目录临时文件、fsync 和 replace 发布。
- 新增路径安全测试，全套 20 项测试通过。
- 尚未覆盖符号链接/硬链接竞争和多文件事务。

## Bounded recovery

- `resume_blocked` 只接受 blocked 检查点。
- 恢复目标限制为 intake 或 static_scan，禁止跳到 triage/report/completed。
- 重试次数上限为 3；恢复清除旧结果摘要。
- 新增恢复边界和预算测试，全套 22 项通过。

## Explicit recovery CLI

- 新增 `python -m ohvul.recover checkpoint.json --target intake|static_scan`。
- 只读取 blocked 检查点并写入下一状态，不自动运行扫描。
- 受最大 3 次重试限制；非 blocked 和越权目标均拒绝。
- 新增 CLI 恢复测试，全套 24 项通过。

## Checkpoint schema validation

- 检查点固定版本 1 和字段集合。
- 校验 task_id、状态、重试次数、错误字段和结果摘要格式。
- 拒绝未知字段、缺失字段、错误类型和超出预算的检查点。
- 新增 schema 回归测试，全套 26 项通过。

## Recovery task association

- 恢复命令不自动运行扫描。
- 使用同一个 `--task-id` 重新运行 CLI 后，结果和检查点保持同一任务标识。
- 重新扫描会生成新的结果摘要，旧摘要不会复用。
- 新增恢复关联回归测试，全套 27 项通过。

## Source snapshot binding

- 扫描开始前为普通源码文件生成路径、大小和内容 SHA-256 清单摘要。
- 摘要写入结果 workflow 和检查点；跳过符号链接，不执行文件。
- 摘要用于恢复时比较输入是否变化，不等同于提交签名或漏洞证据。
- 27 项测试通过；源码快照变更拒绝和竞争保护仍待实现。

## Snapshot recovery gate

- 使用已有检查点重跑时校验源码快照摘要。
- task_id 不一致、源码发生变化或检查点仍为 blocked 时拒绝。
- blocked 检查点必须先用 `ohvul.recover` 恢复。
- 新增快照门禁测试，全套 29 项通过。

## Checkpoint link safety

- 保存检查点时拒绝符号链接路径。
- 防止普通文本写入跟随链接修改非预期目标。
- 链接能力不可用的平台测试会显式 skipped，不伪装为通过。
- 全套 30 项测试通过。

## Atomic checkpoint publishing

- 检查点保存改用临时文件、flush、fsync 和 replace。
- 结果和检查点的跨文件一致性仍由 result_sha256 校验，不宣称多文件事务。
- 全套 30 项测试通过。

## Source snapshot regression

- 验证相同目录摘要稳定。
- 验证普通文件内容变化会改变摘要。
- 验证符号链接不参与摘要；当前环境不支持时显式 skipped。
- 全套 32 项测试通过。

## Journal core

- 新增追加式 AuditJournal，事件写入后 fsync。
- 可区分 committed、incomplete 和 aborted 任务。
- 非法事件或记录拒绝读取。
- 暂不接入默认 CLI，避免在事务策略未定前改变主流程；全套 34 项测试通过。

## CLI journal integration

- CLI 可选 `--journal`。
- 成功顺序：begin、result、checkpoint、commit；异常记录 abort。
- 日志位于扫描目录外并通过 AuditJournal fsync。
- 默认未启用日志时主流程不变；全套 35 项测试通过。

## Journal consistency validation

- `validate_commit` 只认 committed 终态。
- 同时校验 task_id、结果字节摘要、检查点和证据结构。
- 结果被修改或日志未提交时拒绝。
- 全套 36 项测试通过。

## Read-only journal status

- 新增 `python -m ohvul.journal_status JOURNAL`。
- 只读报告任务状态。
- incomplete 状态提示人工检查结果和检查点，不自动重放。
- 全套 37 项测试通过。

## Journal sequence integrity

- 修复异常路径可能追加 commit 的缺陷。
- 合法提交序列严格为 begin/result/checkpoint/commit。
- 失败路径追加 abort，不再追加 commit。
- validate_commit 核对日志摘要、checkpoint 状态和源码快照。
- 新增失败回归测试，全套 38 项通过。

## Joint journal/checkpoint/result report

- `journal_status --task-id TASK --result RESULT --checkpoint CHECKPOINT` 联合校验三类文件。
- 输出 `CONSISTENT` 或 `INCONSISTENT`，并使用非零返回码表示不一致。
- 不提供联合文件时仍只显示日志状态。
- 全套 39 项测试通过。

## Stable JSON status report

- `journal_status --json` 输出稳定 JSON。
- 联合校验成功包含 task_id、journal_status、consistent=true。
- 失败包含 consistent=false 和 error。
- 不执行恢复或目标代码；全套 40 项测试通过。

## Defensive audit report schema

- 新增 `ohvul.report`，定义 report schema 0.1。
- 报告将候选发现、证据引用和 workflow 状态分离。
- 默认安全状态为 `candidate_only`，确认漏洞数固定为 0。
- 校验器拒绝把候选改写为已确认漏洞。
- 全套 42 项测试通过。

## Candidate report CLI

- CLI 增加 `--report-output`。
- 报告与扫描结果分开保存并原子发布。
- 写出前执行报告 schema 校验，固定为 candidate_only。
- 全套 43 项测试通过。

## Report source binding

- report schema 升级到 0.2。
- 报告记录生成它的扫描结果 SHA-256。
- `validate_report_against_result` 检查报告和扫描结果一致。
- 报告仍固定 candidate_only；全套 44 项测试通过。

## Report verification CLI

- 新增 `python -m ohvul.report_verify report.json scan.json`。
- 只读校验报告与扫描结果绑定。
- 扫描结果变化、报告越权状态或证据缺失时返回非零。
- 全套 45 项测试通过。

## Human review record

- 新增 review schema 0.1 和 `python -m ohvul.review_record`。
- 审核记录独立于报告，不修改候选或证据。
- 只允许流程决定，`final_vulnerability_verdict` 固定为 false。
- 记录绑定报告 SHA-256；全套 47 项测试通过。

## Review record overwrite protection

- 审核记录输出默认拒绝覆盖。
- `--force` 是显式替换开关。
- 替换前后仍要求报告摘要绑定；不改变最终 verdict=false。
- 全套 48 项测试通过。

## Review verification CLI

- 新增 `python -m ohvul.review_verify review.json report.json`。
- 校验审核记录 schema、报告摘要和非确认结论。
- 报告变化后拒绝旧审核记录。
- 全套 49 项测试通过。

## Review task binding

- 审核记录包含 task_id。
- task_id 从报告 workflow 继承。
- 校验拒绝跨任务复用审核记录。
- 全套 49 项测试通过。

## Review batch binding

- 新增批次审核 schema 0.1。
- 批次绑定 batch_id、task_id、报告摘要和审核条目。
- 跨任务或跨报告批次拒绝；最终 verdict 固定 false。
- 全套 50 项测试通过。

## Review batch verification CLI

- 新增 `python -m ohvul.review_batch_verify batch.json report.json`。
- 校验批次、任务、报告摘要和审核条目一致性。
- 报告变化后拒绝旧批次记录。
- 全套 51 项测试通过。

## Review batch journal event

- AuditJournal 新增 `review_batch` 事件。
- 事件记录 batch_id、task_id、report_sha256。
- 强制 `final_vulnerability_verdict=false`。
- 全套 53 项测试通过。

## Review chain verification

- 新增 `python -m ohvul.review_chain_verify BATCH REPORT JOURNAL`。
- 联合校验报告、批次审核和 journal review_batch 事件。
- 校验 task_id、batch_id、报告摘要和 final_vulnerability_verdict=false。
- 全套 54 项测试通过。

## Review chain JSON output

- `review_chain_verify --json` 输出稳定机器可读结果。
- 成功包含 consistent、task_id、batch_id 和 verdict=false。
- 文本输出保持兼容；全套 55 项测试通过。

## Journal history query

- `journal_status --task-id TASK --history` 输出任务事件序列。
- `--json` 将序列放入 history 字段。
- 查询只读，不执行重放或修改日志。
- 全套 56 项测试通过。

## Journal history archive

- 新增 `python -m ohvul.journal_archive JOURNAL TASK_ID OUTPUT`。
- 导出事件序列和摘要，默认拒绝覆盖。
- 原始日志只读且保持不变。
- 全套 57 项测试通过。

## Journal archive verification

- 新增 `python -m ohvul.journal_archive_verify ARCHIVE`。
- 校验归档 schema、任务 ID、事件结构和事件摘要。
- 不读取或修改源日志；全套 58 项测试通过。

## Archive event filtering

- `journal_archive --event EVENT` 支持按事件类型筛选。
- 归档记录 `event_filter`，摘要基于筛选后的事件重新计算。
- 部分归档不会被误认为完整日志。
- 全套 59 项测试通过。

## Archive filter verification

- 归档校验器检查 `event_filter` 与实际事件一致。
- 筛选声明或事件内容被改动时拒绝。
- 全套 60 项测试通过。

## Journal timestamps and since filtering

- 事务事件记录 UTC `created_at`。
- 归档支持 `--since` ISO-8601 下界。
- 缺少时间戳时拒绝时间筛选，不猜测事件时间。
- 全套 61 项测试通过。

## Legacy journal compatibility

- 状态查询报告 `legacy_timestamp_events`。
- 旧日志缺少时间戳时仍可查看和归档（不使用时间筛选）。
- 使用 `--since` 时拒绝缺少时间戳的事件，不进行猜测或自动迁移。
- 全套 62 项测试通过。

## Legacy journal compatibility documentation

- 新增 docs/engineering/LEGACY_JOURNAL_COMPAT.md。
- 明确旧日志可验证字段、不可推断字段、时间筛选限制和人工迁移边界。
- 不自动改写历史日志或补造时间戳。

## Archive lifecycle policy

- 新增 docs/engineering/ARCHIVE_LIFECYCLE.md。
- 明确 active/sealed/superseded 逻辑状态、永久保留默认值和人工删除边界。
- 明确封存前校验、恢复和旧日志补充规则。
- 当前工具不自动清理、封存、删除或覆盖历史归档。

## Read-only archive seal marker

- 新增 seal schema 0.1。
- 封存标记绑定归档 SHA-256、操作者、时间和原因。
- 生成或校验封存标记不修改归档内容。
- 全套 64 项测试通过。

## Archive seal verification

- 新增 `python -m ohvul.archive_seal_verify SEAL ARCHIVE`。
- 只读校验封存标记和归档摘要一致。
- 归档变化后旧封存标记失效。
- 全套 65 项测试通过。

## Seal marker creation CLI

- 新增 archive_seal_record；复用 validate_archive，校验后独占创建独立标记，不提供覆盖开关。
- 源归档不修改，损坏归档不生成标记；创建不等于身份认证或整条审计链验证。
- 新增 3 项回归测试；全套 68 项中 66 通过、2 跳过。
- 重写 PROJECT_STATE.md，纠正历史测试统计重复替换造成的歧义；保留历史变更日志。
- 后续工作回到 Phase 3 核心验收，优先报告与扫描结果字段一致性。

## Report end-to-end binding regression

- CLI 同时生成扫描结果和候选报告。
- report_verify 成功校验保存文件之间的 scan_result_sha256 绑定。
- 全套 69 项测试，67 通过、2 项符号链接能力不可用而跳过。

## Scan-time input consistency gate

- CLI 扫描前后比较源码快照。
- 扫描期间源码变化会拒绝结果、报告和正常提交链。
- 新增输入门禁测试；全套 70 项，68 通过、2 项符号链接能力不可用而跳过。

## Strict report projection consistency

- 报告候选集合必须与扫描结果告警一一对应。
- 校验 alert_id、evidence_id、CWE、rule、location 和 evidence_refs。
- 缺少、篡改或新增报告字段时拒绝联合校验。
- 全套 72 项测试，70 通过、2 项符号链接能力不可用而跳过。

## Rule-quality suppression

- 支持源码行级 `// ohvul:ignore`，用于人工记录已审查的局部候选。
- 抑制只影响同一行，不影响其他位置。
- 不改变候选以外的结论，也不证明代码安全。
- 规则基准测试更新；总测试 74 项，72 通过、2 跳过。

## Static rule benchmark

- 新增离线 C/C++ 规则基准和标注类别。
- 覆盖候选、人工抑制、需要上下文和安全控制样例。
- 基准只评估候选命中，不宣称漏洞确认。
- 全套 75 项测试通过，2 项符号链接能力不可用而跳过。

## Offline rule benchmark statistics

- 新增 `python -m ohvul.benchmark docs/design/rule_benchmark.json`。
- 输出候选规则 TP/FP/FN、precision/recall 和逐例统计。
- 结果明确是候选规则统计，不是漏洞确认。
- 全套 76 项测试通过，2 项符号链接能力不可用而跳过。

## Rule benchmark evaluation contract

- 新增 docs/design/RULE_BENCHMARK.md。
- 明确 TP/FP/FN、precision/recall 和合成样例限制。
- 明确候选统计不等于漏洞真值或平台影响。

## Extended static rule benchmark

- 增加 CWE-190 整数长度和 CWE-476 指针解引用候选样例。
- 避免在内存复制 API 行上重复报告指针规则，减少明显重复候选。
- 全套 77 项测试通过，2 项符号链接能力不可用而跳过。

## Safe counterexample benchmark

- 增加已检查空指针的安全反例。
- 基准保留该候选作为 FP 观察，不隐藏误报。
- 全套 78 项测试通过，2 项符号链接能力不可用而跳过。

## Explainable benchmark labels

- 每条规则基准样例新增 `reason`。
- 原因说明候选、人工抑制、安全反例或上下文依赖。
- 基准统计仍不等同于漏洞确认。
- 全套 79 项测试通过，2 项符号链接能力不可用而跳过。

## Rule-overlap benchmark statistics

- benchmark 输出 `rule_overlap_cases`。
- 每例输出 `rule_overlap` 和标注 `reason`。
- 用于区分重复规则命中和新增候选覆盖，不改变漏洞结论。
- 全套 80 项测试通过，2 项符号链接能力不可用而跳过。

## Benchmark report snapshot

- 生成 docs/design/rule_benchmark_report.json。
- 当前合成基准：8 cases，候选 TP=5、FP=2、FN=0，precision 约 0.714，recall 1.0，重叠样例 1。
- 统计仅用于规则回归，不代表真实 OpenHarmony 准确率或漏洞确认。

## Benchmark taxonomy labels

- 基准样例增加 `language` 和 `component` 分类。
- 支持后续按语言、CWE 和组件类型分层统计。
- 不改变候选判定或安全结论。
- 全套 81 项测试通过，2 项符号链接能力不可用而跳过。

## Benchmark grouped statistics

- benchmark 报告新增按 `component::language` 的 groups 汇总。
- 每组包含 cases、TP、FP、FN，保留总体指标和免责声明。
- 统计不等同于真实漏洞准确率；全套 82 项测试通过，2 项跳过。

## Test count calibration

当前实际测试命令报告 81 项，79 通过、2 跳过；PROJECT_STATE 已按工作区输出校准。

## Current status calibration

当前工作区实测 81 项测试，79 通过、2 跳过；状态文档已校准。

## Benchmark input contract

- 在扫描前严格校验合成基准结构、标签/CWE 一致性、唯一 ID 和语言。
- 临时样例文件使用固定文件名，ID 保留为展示字段。
- 新增 5 个输入校验回归测试；全套 86 项测试通过，2 项跳过。

## Authorized OpenHarmony source sample

- 经用户授权对 C:\Projects\OpenHarmony 进行只读源码盘点。
- 发现约 292,493 个 C/C++ 文件；仅扫描 commonlibrary/utils_lite/timer_task 受限子树。
- 生成 docs/design/openharmony_timer_task_scan.json，29 条证据记录通过离线 verify。结果仍是候选发现，不是漏洞确认。

## Deterministic source shard manifest

- 新增本地 C/C++ 路径分片清单生成器及确定性摘要。
- 清单不读取源码内容、不执行目标代码；新增 2 项测试。

## Shard resource gate

- 分片清单新增 max_files 资源上限，非法预算明确拒绝。

## Manifest-bound shard scanning

- 扫描器支持显式相对文件集合。
- 新增 scan_shard 受清单约束运行，新增 2 项回归测试。

## Deterministic shard result merge

- 新增跨分片结果合并、根目录绑定、证据去重和确定性告警排序。

## Regression checkpoint

- 全套回归 92 项，90 通过、2 跳过。

## Shard evidence validation

- 增加合并结果通过现有 evidence verifier 的回归覆盖。

## Offline local evidence recheck

- 新增基于源码位置和行哈希的独立复核函数及 2 项测试。

## Local verification request gate

- 新增确定性本地安全验证请求门控，要求 static_scan 状态和全部证据可复现。

## Synthetic local harness contract

- 新增合成输入本地 harness 评估器，保持结果为 undetermined 并要求人工审核。

## Local verification transition intent

- 验证门控新增 local_verification 迁移意图，保留既有 FSM 检查点兼容性。

## FSM local verification state

- FSM 新增 local_verification 状态及 static_scan/local_verification/triage 迁移。

## Harness record schema

- 新增版本化合成 harness 记录校验，强制 undetermined 与人工审核。

## Verification linkage

- 新增工作流检查点与 review-only harness 记录的摘要绑定和校验。

## Phase 4 local verification entry

- 完成 timer_task 受限样本 29 条候选的端到端行哈希复核。
- 生成 review-only harness 记录及检查点摘要关联，保持 undetermined。
- 正式进入 Phase 4：本地安全验证与独立复现。

## Phase 4 closure checkpoint

- harness 记录 schema 与摘要关联离线校验通过。
- 全套测试 101 项，99 通过、2 跳过。

## Isolation harness I/O contract

- 新增合成 harness 输入/输出边界校验，拒绝路径对象和确定性漏洞结论。

## Phase 4 isolation regression

- 全套回归 103 项，101 通过、2 跳过。隔离 I/O 契约与既有证据链兼容。

## Isolation resource budgets

- 合成 harness 输入新增字节与超时预算门控。

## Enforced isolation input budget

- 实际执行合成输入 max_bytes 上限并增加超限测试。

## Phase 4 regression audit

- 全套回归 103 项，101 通过、2 跳过。

## Harness output gate

- 合成 harness 输出生成后立即执行隔离契约校验。

## Phase 4 validation contract documentation

- 新增本地安全验证契约文档，明确合成输入、资源预算、证据绑定和人工审核边界。

## Safe harness record persistence

- harness 记录采用独占创建，拒绝覆盖和符号链接路径。

## Audit fix: symlink consistency

- 扫描器显式跳过符号链接，和源码快照边界保持一致。

## Runtime LLM adapter

- 新增可选 LLM 适配器，key 仅从环境变量读取，输出保持 undetermined。

## LLM adapter safety regression

- 增加离线 mock 测试，验证 key 不出现在结果且输出保持 review-only。

## LLM context boundary

- LLM 适配器新增结构化上下文和 64 KiB 大小限制。

## LLM timeout gate

- LLM 适配器新增 1..60 秒超时校验。

## LLM runtime configuration docs

- README 增加 key 脱敏和显式调用说明。

## LLM model allowlist

- LLM 适配器限制为已验证的 grok-4.6 模型。

## LLM HTTPS boundary

- LLM 适配器强制 HTTPS Base URL。

## LLM response schema validation

- 新增 LLM 响应结构和文本类型校验。

## LLM draft size gate

- LLM 草稿输出新增 16 KiB 大小上限。

## Offline CI regression

- 新增 GitHub Actions 离线单元测试工作流。

## CI credential pattern gate

- GitHub Actions 新增离线 API key 形态扫描。

## Local credential ignore rules

- 新增 .env、密钥和 secrets 文件忽略规则。

## CI least privilege

- 离线测试 workflow 设置 contents: read 最小权限。

## Cross-platform CI verification

- Ubuntu GitHub Actions offline-tests 对 beadf8d 执行成功。

## Packaging metadata

- 新增最小 pyproject.toml，声明项目元数据与 wildtrace CLI 入口。

## Local package validation

- editable 安装（--no-deps）和 wildtrace CLI 帮助验证通过。

## Local installation documentation

- README 增加本地安装、测试和 LLM 环境变量说明。

## Repository security policy

- 新增 SECURITY.md，明确本地审计范围和安全报告边界。

## Code ownership

- 新增 CODEOWNERS，要求项目维护者审核变更。

## Safe verification link persistence

- 新增验证关联记录的 schema 校验、独占持久化和覆盖保护。

## Shard merge resource gate

- 跨分片合并新增 max_shards 上限。

## Scanner network isolation regression

- 增加扫描流程不触发网络或 LLM 的回归测试。

## Verification digest format gate

- 验证关联严格校验 checkpoint SHA-256 格式。

## Shard evidence conflict gate

- 跨分片合并拒绝同 ID 不同内容的证据记录。

## Phase 4 acceptance checklist

- 新增证据驱动的 Phase 4 验收清单。

## Verification link recovery

- 验证关联记录支持离线读取和重新校验。

## Current checkpoint clarification

- 明确 PROJECT_STATE 前部历史条目与末尾最新检查点的优先级。

## Phase 4 bounded closure

- Phase 4 允许范围闭环完成，明确不执行真实目标代码。
- 下一阶段进入 Phase 5 准备：分支影响、补丁验证和报告。

## Phase 5 branch impact comparison

- 新增本地扫描结果分支影响比较器，输出候选变化并保持 review_required。

## Phase 5 patch scope gate

- 新增本地补丁路径范围校验，拒绝越界路径。

## Phase 5 scan schema gate

- 分支影响比较要求扫描结果 schema 0.3。

## Phase 5 local path only gate

- 补丁路径校验拒绝 URL 形式输入。

## Phase 5 scan root binding

- 分支影响比较绑定扫描源码根目录。

## Phase 5 local result gate regression

- 增加非 local_only 结果拒绝测试。

## Phase 5 findings structure gate

- 分支影响比较新增 findings 结构校验。

## Phase 5 branch impact CLI

- 新增本地 JSON 分支影响比较 CLI。

## Phase 5 branch impact CLI regression

- 增加 CLI 成功路径回归测试。

## Phase 5 installed CLI entry

- 新增 wildtrace-impact 安装后命令行入口。

## Phase 5 JSON root type gate

- 分支影响比较器新增 JSON 根类型校验。

## Phase 5 patch hash verification

- 新增本地补丁文件 SHA-256 校验。

## Phase 4 joint file validation

- 新增检查点、扫描结果和 harness 记录的联合文件校验入口。

## Verification link generation consistency

- link 生成端与校验端统一 SHA-256 格式约束。

## Phase 5 patch digest format gate

- 补丁文件摘要校验新增标准 SHA-256 格式门控。

## Phase 5 impact draft projection

- 新增分支影响到 review-only 草稿的确定性投影。

## Phase 4 joint verification CLI

- 新增 verify-joint 联合文件校验命令行入口。

## Phase 5 impact draft validation

- 增加分支影响草稿 review-only schema 校验。

## Phase 5 impact report projection

- 新增绑定双扫描结果摘要的 review-only 影响报告。

## Phase 5 review report projection

- 分支影响报告可投影进入现有人工审核 API。

## Phase 5 task association validation

- 增加影响报告无效任务关联拒绝测试。

## Phase 5 review API integration test

- 验证影响报告可进入现有人工审核 API，保持不可确认结论。

## Phase 4 joint input symlink gate

- 联合验证入口拒绝符号链接输入。

## Phase 5 impact review batch

- 分支影响报告接入人工审核批次创建流程，禁止最终确认。

## Phase 5 bounded closure and Phase 6 start

- Phase 5 允许范围闭环完成：分支影响、补丁校验、报告草稿和审核批次均已验证。
- 123 项测试，119 通过、4 跳过。
- 正式进入 Phase 6：性能评测、演示和交付准备。

## Phase 6 synthetic performance benchmark

- 新增有资源上限的合成扫描性能基准。

## Phase 6 performance CLI

- 新增 wildtrace-perf 命令和 JSON 输出回归测试。

## Phase 6 performance regression

- 性能专项 3 项、全量 126 项测试通过（4 项跳过）。

## Phase 6 performance contract documentation

- 新增性能评测契约文档，明确合成输入和统计边界。

## Phase 6 performance matrix

- 新增受边界限制的多规模合成性能矩阵。

## Phase 6 CI performance smoke

- CI 增加受限性能基准 smoke test。

## Phase 6 throughput regression comparison

- 新增本地性能吞吐退化比较器和门控测试。

## Phase 6 local demo guide

- 新增安全本地演示流程文档。

## Phase 4 FSM joint verification gate

- local_verification 到 triage 必须通过 checkpoint/result/harness 联合校验。
- 验证失败保持状态不变，相关专项 47 项测试通过。

## Phase 6 performance result schema

- 新增性能结果 schema 和安全字段校验。

## Phase 6 throughput field gate

- 性能结果新增 files_per_second 字段门控。

## Phase 6 performance CLI schema gate

- 性能 CLI 输出前新增即时 schema 校验。

## Phase 6 bounded shard scheduler

- 新增按 manifest 顺序的受控分片扫描调度。

## Phase 4 source snapshot joint gate

- 联合验证新增 checkpoint/result 源码快照摘要一致性校验。

## Phase 4 source snapshot regression

- 全套测试 135 项，131 通过、4 跳过。
- 源码快照联合校验与完整工作流无回归。

## Phase 6 peak memory metric

- 性能基准新增峰值内存采样和 schema 校验。

## Phase 6 performance result persistence

- 新增性能结果安全落盘和覆盖保护。

## Phase 6 performance result recovery

- 性能基线支持读取并重新校验。

## Phase 6 performance report formatting

- 新增性能矩阵 Markdown 报告生成函数。

## Phase 6 performance baseline snapshot

- 新增合成性能基线 Markdown 快照。

## Versioned local vulnerability knowledge base

- 新增本地 CVE/CWE 知识库记录校验和整体摘要。

## Knowledge base resource handling

- 修复知识库读取未关闭文件句柄问题。

## Deterministic knowledge base matching

- 新增组件和版本精确匹配函数。

## Knowledge base unresolved matching

- 知识库版本未精确匹配时保留 unresolved 候选。

## Knowledge base source binding

- CVE/CWE 匹配结果携带知识库和源记录摘要。
