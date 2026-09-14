# WildTrace 本地 CVE/CWE 知识库采集设计

## 目标

建立一个可离线复核、可版本化、只提供候选匹配的 OpenHarmony CVE/CWE 知识库。知识库不得替代源码证据，也不得单独宣布漏洞成立。

## 当前兼容格式

`ohvul.knowledge_base.load_records` 当前接受：

```json
{
  "schema": "0.1",
  "records": [
    {
      "id": "CVE-2024-0001",
      "cwe": ["CWE-120"],
      "summary": "简短事实描述",
      "component": "组件规范名",
      "affected_versions": ["版本或提交标识"],
      "fixed_versions": ["修复版本或提交标识"],
      "source": "https://权威来源或本地归档索引"
    }
  ]
}
```

采集阶段必须保留原始来源、访问日期、版本证据和修复提交；当前运行格式可以先生成，扩展字段待 schema 0.2 迁移时加入。

## 推荐采集记录

合作伙伴每条记录应同时填写以下字段：

| 字段 | 要求 |
|---|---|
| `id` | 标准 CVE 编号；没有 CVE 时进入待确认表，不伪造编号 |
| `cwe` | 官方或公告明确的 CWE；允许多个，保留依据 |
| `summary` | 事实性摘要，说明受影响组件、触发条件和影响类型，不写利用步骤 |
| `component` | 与 WildTrace 组件命名表一致，不使用自由变体 |
| `affected_versions` | 明确版本、tag 或 commit；未知时留空并标记 unresolved |
| `fixed_versions` | 修复版本或 commit；未知时留空 |
| `source` | 权威公告、OpenHarmony/GitCode/GitHub 提交或 NVD 页面 |
| `source_date` | 来源发布日期或最后更新日期 |
| `source_record` | 原始公告标题、URL、commit、关键段落摘要 |
| `evidence_refs` | 版本范围、受影响文件、修复提交等证据引用 |
| `confidence` | `high`、`medium` 或 `low`，由证据完整度决定 |
| `review_status` | `unreviewed`、`reviewed`、`needs_user_review` |

## 采集优先级

1. OpenHarmony 官方安全公告和修复提交。
2. OpenHarmony 组件仓库的固定版本、tag 和 commit。
3. NVD/CVE 官方记录及其引用的上游修复。
4. CWE 官方条目，用于解释弱点类别。
5. 第三方文章仅作线索，不能作为唯一来源。

优先覆盖与比赛目标相关的组件和漏洞族：IPC/权限、内存生命周期、边界长度、信息泄露、解析器和媒体组件。

## 版本与组件规范

- 组件名必须来自项目组件注册表；同一组件不得同时使用目录名、仓库名和产品名三种写法。
- 版本优先使用 tag，其次使用完整 commit SHA；不得只写 `latest`、`master` 或模糊日期。
- `affected_versions` 与 `fixed_versions` 必须能映射到本地源码 profile；不能映射的记录只能返回 `unresolved`。
- 不把 CWE 号相同当作 CVE 匹配；CWE 只能作为候选过滤和报告分类。

## 审核流程

1. 采集原始来源和本地归档摘要。
2. 两人分别核对 CVE、CWE、组件和版本范围。
3. 用固定提交验证受影响文件或修复提交是否存在。
4. 生成 schema 0.1 兼容 JSON，并计算记录和数据库摘要。
5. 运行离线 schema 校验、重复 ID 校验和版本格式校验。
6. 将不完整记录标记为 `unresolved`，不得删除来源或补猜版本。
7. 只有源码扫描候选与知识库记录、源码快照和人工审核同时成立，才可进入报告草稿。

## 合作伙伴交付物

- `records.json`：兼容 schema 0.1 的记录。
- `collection_notes.md`：每条记录的来源、版本判断和不确定项。
- `source_index.json`：来源 URL/commit、访问日期、原始摘要和本地文件摘要。
- `validation.log`：使用的离线命令及输出。
- `unresolved.json`：无法确定版本或组件的条目，不能混入已审核记录。

## 明确禁止

- 不生成不存在的 CVE 编号。
- 不把新闻、博客或模型猜测当作确认来源。
- 不写真实目标利用链、攻击载荷或远程验证步骤。
- 不把知识库匹配结果描述为源码漏洞确认。
- 不自动向外部平台提交报告或奖励计划。

## WildTrace 集成验收

- `load_records` 成功读取且数据库摘要稳定。
- 同一 CVE 不重复，组件名可映射到固定 profile。
- 精确版本返回 `exact`；无法确定版本只能返回 `unresolved`。
- 匹配结果绑定知识库摘要、源记录摘要、组件、版本和 CWE。
- 删除或修改源记录会导致摘要变化并触发复核。
