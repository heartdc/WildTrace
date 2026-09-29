# 引擎候选基准标注规范

该基准只评估 Clang/clang-tidy 候选召回和规则映射，不宣布漏洞成立。样本必须来自用户授权的本地源码、固定版本和可追溯文件快照。

## 标注字段

```json
{
  "id": "稳定样本标识",
  "source_file": "相对源码根路径",
  "source_snapshot_sha256": "源码快照摘要",
  "component": "组件名",
  "version": "固定版本",
  "expected_cwe": ["CWE-476"],
  "label": "candidate_requires_context",
  "reason": "人工依据和复核范围",
  "reviewer": "人工审核者标识",
  "reviewed_at": "UTC 时间"
}
```

允许的 `label` 为 `candidate`、`candidate_requires_context`、`reviewed_suppressed` 和 `safe_control`。`safe_control` 与 `reviewed_suppressed` 必须有空的 `expected_cwe`；其他标签只有在人工确认候选类别后才能填写 CWE。未完成人工复核的样本应留在待标注状态，不得计入 precision/recall。

## 评测规则

1. 使用同一源码快照和同一引擎版本生成 schema 0.3 结果。
2. 旧入口以文件样本 ID 和 `cwe_candidate` 集合对齐，计算文件/CWE 存在性统计；重复告警被折叠，不能当逐告警准确率。位置级评测使用下面的严格入口。
3. 记录引擎规则、规则版本、编译参数摘要和 EvidenceBundle ID。
4. 任何构建失败、缺头文件或路径不一致都标记为输入不可用，不计作真阴性。
5. 报告必须同时给出总体指标和按组件/语言/漏洞族分组指标。

使用入口：

```text
wildtrace-engine-benchmark cases.json engine-result.json
```

输出中的 precision/recall 只描述候选统计；它们不构成漏洞确认、OpenHarmony 平台结论或 CVE 证明。

## 严格位置级评测

```text
wildtrace-engine-benchmark reviewed-locations.json engine-result.json --location-metrics
```

每个文件样本除唯一 `id`、规范根相对 `source_file`、`label` 外，还需要：

- `review_status: "reviewed"`，非空 `reviewer` 和 `reviewed_at`；字段是复核声明，不认证审核者身份。
- `source_snapshot_sha256`，必须与结果 `scan.source_snapshot_sha256` 一致。
- `expected_findings`：每条包含唯一 `id`、`cwe` 和包含端点的正整数 `line_start`、`line_end`。候选样本必须有位置标注；安全/抑制样本须为空。

同文件、同 CWE 且行号在标注范围内才可匹配。最大一对一匹配使每条告警和每个人工标注最多贡献一次 TP；额外告警为 FP，未匹配标注为 FN。未知 CWE 单列且计 FP；未标注文件单列为范围外。比如一个标注对应 50 条重复告警，结果为 TP=1、FP=49，而不是 precision=1。

输入错误按规范根相对路径精确关联；尚不自动转换绝对路径错误记录，遇到无法归属的记录会返回不可评估，不静默排除同名文件。缺失标签、快照不一致或超出匹配资源预算，返回 `status=not_evaluable`、`candidate_metrics=null` 和原因，绝不退回旧聚合指标。

严格入口仅接受 `completed` 或失败文件可精确归属的 `partial` 结果。CLI 不可评估时输出 JSON 并以退出码 2 结束，便于流水线保留原因且拒绝使用不存在的指标。

现有 `bench/engine_counterexamples/cases.json` 是合成文件级标签，未补齐真实人工位置复核，不用于声称严格准确率。严格入口的合成测试只验证匹配算法。根因去重后的指标、重复率以及冻结真实评测集仍需单独完成。

## 从结果生成待复核草稿

代码接口 `ohvul.engine_benchmark.bootstrap_cases()` 可以从 schema 0.3 结果生成标注草稿。它只写入源码位置、快照、组件、版本和 `candidate_requires_context`，`expected_cwe` 保持为空。人工完成上下文复核后，才可以将草稿作为 `cases.json` 输入评测器。
