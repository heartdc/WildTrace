# 本地 CVE 知识库同步契约

`ohvul.kb_sync` 将本地准备的公开漏洞数据归一化为 `ohvul.knowledge_base` 可加载的
schema-0.1 分片知识库。构建阶段完全离线：源数据由操作者事先准备（git clone 或下载
解压），工具本身不联网、不执行目标代码。

## 输入源

| 源 | 形态 | 说明 |
|---|---|---|
| cvelistV5 | 本地 checkout | 布局无关，rglob `CVE-*.json`；取 cveMetadata/cna 的描述、CWE、affected 产品与版本 |
| OSV 导出 | 解压目录 | 仅保留带 CVE 别名的记录；生态白名单默认 `OSS-Fuzz`（`--osv-ecosystem` 可重复指定） |

同 CVE 多源冲突时 cvelistV5 优先。GHSA YAML 不直接解析（GHSA 数据经 OSV 别名到达）。

## 输出

```
<out>/manifest.json      # kb-manifest-0.1：snapshot_version、分片清单（文件+计数+sha256）、
                         # records_total、records_sha256（与 load_records 摘要公式一致）、source_stats
<out>/kb_part_0000.json  # schema-0.1 记录分片，单片 ≤ max-records-per-shard 且 < 8 MiB
```

分片在写出时即经过 `knowledge_base.load_records` 回验，坏输出在构建期失败。

## 验证

`load_sharded_kb(dir)` 逐分片走规范加载器，校验分片 sha256、跨分片重复 id、
记录总数与总摘要，任何不一致都拒绝。CLI：

```
python -m ohvul.kb_sync build --cvelist <dir> --osv <dir> --out <dir> --snapshot 2026-09-14
python -m ohvul.kb_sync verify --kb <dir>
```

## 已知限制（v1）

- schema 0.1 以 CVE id 为主键，一条记录一个组件；同一 CVE 多产品时保留首个，
  其余记入 manifest `source_stats.*.dropped_product_samples`（上限 1000 条、
  超出置 truncated 标记）作为召回候选，不进入记录本体。
- 版本语义只有精确字符串；`fixed_versions` 中的值是**区间边界**而非经核实的
  精确修复版本——每条记录带 `fixed_version_semantics` 声明投影来源
  （`cvelist_lessThan_boundaries` / `osv_fixed_events` / `none`）。
- 分片上限（2000 条/片，可调）与 16 MiB 单文件加载上限配合使用。

## 构建安全性与残留处理

- 构建先写入同级临时 staging 目录，整体经 `load_sharded_kb` 自校验后原子换入；
  换入失败自动回滚，失败构建不留 staging 残留、不触碰旧输出。
- 目录换入意味着上一次构建的陈旧分片随旧目录整体消失，无需单独清理。
- `load_sharded_kb` 拒绝 manifest 中绝对路径、含 `..`、或 resolve 后越出
  kb 目录的分片条目。
