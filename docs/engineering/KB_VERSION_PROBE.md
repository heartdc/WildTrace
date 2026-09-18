# CVE 知识库版本探测作战包 — 使用说明

三层知识库的匹配入口。**所有输出都是候选评审线索，不是漏洞结论。**

## 组成

| 文件 | 内容 |
|---|---|
| `kb/third_party_targets/records.json` | 19 个 OH 高价值 third_party 组件的 CVE 子库（446 条，从 cvelistV5 全量提取，digest `c309fe578debad77…`） |
| `kb/partner/batch-2026-09/records_runtime.json` | 师弟采集第一批的运行时层（72 条 OH 原生 CVE，双人复核通过） |
| `kb/partner/batch-2026-09/records_evidence.json` | 同批的富证据边车（逐分支修复 commit + 逐文件 diff） |
| `tools/kb_partner_import.py` | 采集批次的转换入库工具（富格式 → 运行时 + 边车） |
| `tools/kb_version_probe.py` | 版本探测：读 OH 树的 `third_party/*/README.OpenSource`，对 KB 做 exact/unresolved 匹配 |

## 一次性探测（朋友机器，OpenHarmony-complete 检出）

```powershell
python -X utf8 tools/kb_version_probe.py C:/Projects/OpenHarmony-complete `
  --kb kb/third_party_targets/records.json `
  --kb kb/partner/batch-2026-09/records_runtime.json `
  --output .cache/kb_probe_report.json
```

输出摘要打印到 stdout，完整报告含每个命中组件的 CVE 清单。两类结果：

- **exact_candidates**：探测到的版本落在某 CVE 的受影响版本列表 → 中间形态靶点，
  逐条人工核（源码指纹确认 + 修复是否存在）；
- **unresolved_components**：组件在库中但版本未命中 → 版本串格式差异或确已修复，
  需人工看一眼。

## 已知边界

1. `README.OpenSource` 的 `Version:` 字段是人工维护的，可能滞后于实际代码——
   exact 命中后必须用源码指纹（如头文件宏、`git log`）复核；
2. 组件名匹配经 `_component_alias` 归一（目前仅 cjson 一组别名），新别名在
   探测报告的 unresolved 里发现后补入工具；
3. OSS-Fuzz OSV 导出实测不含任何 CVE 关联（aliases 与 references 均为零），
   该层对 CVE 键控知识库无贡献，已如实记录；`kb_sync` 的 references 解析保留
   （对未来带 CVE 引用的 OSV 数据集有效）；
4. 全量层（375,265 条）不入库（体积），需要时用 `ohvul.kb_sync build` 重建，
   命令见 `LOCAL_KB_SYNC.md`。
