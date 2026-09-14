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
2. 以文件样本 ID 和 `cwe_candidate` 对齐，计算候选级 TP、FP、FN。
3. 记录引擎规则、规则版本、编译参数摘要和 EvidenceBundle ID。
4. 任何构建失败、缺头文件或路径不一致都标记为输入不可用，不计作真阴性。
5. 报告必须同时给出总体指标和按组件/语言/漏洞族分组指标。

使用入口：

```text
wildtrace-engine-benchmark cases.json engine-result.json
```

输出中的 precision/recall 只描述候选统计；它们不构成漏洞确认、OpenHarmony 平台结论或 CVE 证明。

## 从结果生成待复核草稿

代码接口 `ohvul.engine_benchmark.bootstrap_cases()` 可以从 schema 0.3 结果生成标注草稿。它只写入源码位置、快照、组件、版本和 `candidate_requires_context`，`expected_cwe` 保持为空。人工完成上下文复核后，才可以将草稿作为 `cases.json` 输入评测器。
