# P0 执行记录（2026-09-22）

对应规划：`docs/status/AUDIT_REMAINING_PLAN_20260922.md` 第五节 P0 项。执行人：GLM 会话；网络备注：执行期间本机到 github.com:443 中断，PR #49 经 GitHub Git Data API 构造提交推送。

## P0.1 落库止损 — 完成

- 6 个未跟踪案例目录 + `tools/kb_gap_audit.py` + curl_psl 提交记录（OHSA26-092226014）经 **PR #48** 合并（c6637d2）。
- probe 修复（清单名内嵌版本规范化 + 回归测试）经 **PR #45** 合并（e189860）。
- master 现含全部 10 个案例（8 旧 + 2 新，见 P0.2）；CI 全绿。

## P0.2 CVE-2026-66038 / CVE-2026-70628 人工 L4 — 完成

- **CVE-2026-66038**（lcldec 未解压尾部未清零，CWE-908 堆信息泄露）：OH `libavcodec/lcldec.c` 与上游 n7.1.1 逐字节一致；`mszh_decomp` 返回点与 `zlib_decomp` 短解出路径均无 memset 尾部清零（121/155 行）；上游修复 `e7cbfd1c`（2026-06-28）对 OH 检出 `git apply --check` 直接通过。
- **CVE-2026-70628**（dvbsub_parser 容量守卫有符号溢出，CWE-190→CWE-787）：OH `libavcodec/dvbsub_parser.c` 106 行仍为三数相加形态；真实修复为 `93f2a525`（=分支回移 `02fc47e1`，diff 逐字节一致，2026-07-22），verbatim 适用。**勘误**：CVE 引用列表中的 `c6ec28b1` 是 2005 年解码器引入提交；`gap_l4_batch.json` 以其为参考的批量行不采信（已在对照.txt 记录）。
- 产物：`D:/cve_data/submission_66038/`、`D:/cve_data/submission_70628/`（上游修复对照.txt、patch.diff、upstream_fix 原文、表单草稿、附件包 zip）；案例 case.json 经 **PR #49** 合并（721385f）。
- ffmpeg gap batch 至此 5/5 收口（66036/66041 运行时验证、64832/66038/70628/65704/52296 源级 L4）。剩余 2 项 already_fixed 复核为低优先级尾项。

## P0.3 提交材料核验与交接 — 完成（提交动作待所有者）

7 个待提交案例材料全部齐备（表单 + 补丁 + 对照/运行记录 + 附件包）：

| CVE | 案例目录材料 | 表单附件数 |
|---|---|---|
| CVE-2026-52296 | 对照 + patch + upstream diff + 表单 + zip | 4 |
| CVE-2026-64832 | 对照 + patch + upstream diff + 表单 + zip | 4 |
| CVE-2026-65704 | 对照 + patch + upstream diff + 表单 + zip | 4 |
| CVE-2026-66036 | patch + poc + 运行验证记录 + 表单 + zip | 4 |
| CVE-2026-66041 | upstream diff（即补丁）+ poc + 运行验证记录 + 表单 + zip | 4 |
| CVE-2026-66038 | 对照 + patch + upstream diff + 表单 + zip（本次新增） | 4 |
| CVE-2026-70628 | 对照（含勘误）+ patch + upstream diff + 表单 + zip（本次新增） | 4 |

**待所有者（账号"北辰522"）执行**：按表单逐例提交至 https://bugbounty.openharmony.cn ；同时跟进已有两工单（OHSA26-092209031、OHSA26-092226014）审核状态。提交回执请回填各案例 case.json 的 submission 字段（参照 curl_psl 格式）。

## P0.4 文档同步 — 完成（PR #49）

- CHANGELOG：补录 2026-09-16 → 09-22 全部断档；移除误嵌入的 PROJECT_STATE 重写脚本片段（保留原 CRLF 行尾，diff 收敛 +35/−16）。
- README：LLM 暂停表述解除（z.ai 验收 2026-09-16、gpt-6-astra 白名单）；当前优先级更新。
- PROJECT_STATE：新增 2026-09-22 顶部状态节。
- `pr41_review/` 暂存副本已删除（PR41 已合并为 0fc1c6a；p.tar 为 GitHub 可重取快照；已确认无独有内容）。

## P0.5 LLM 29 组全量评审 + 双模型交叉验证 — 未执行（硬前提缺失，交接）

本机缺失两个前提，无法代跑：
1. **API 密钥**：设计上不落盘（`--key-stdin` 或 `OSLOVELACE_API_KEY` 运行时注入），需所有者提供。
2. **流水线输入与源码树**：`.cache/real_components_c0d3/batch/summary-0005.json`、queue/context JSON 与 `C:/Projects/OpenHarmony-complete` 树不在本机（在原跑批机器上）。

在有上述输入的机器上执行（每组一条，换 `--group`；表单见 docs/engineering/LLM_REVIEW.md）：

```powershell
python -m ohvul.llm_review `
  --summary .cache/real_components_c0d3/batch/summary-0005.json `
  --queue .cache/review_33f843/queue.json `
  --context .cache/review_33f843/context.json `
  --source-root camera_app=C:/Projects/OpenHarmony-complete `
  --source-root hilog_featured=C:/Projects/OpenHarmony-complete `
  --source-root securec=C:/Projects/OpenHarmony-complete/third_party/bounds_checking_function `
  --group <RG-ID> --output .cache/llm-plan-g<RG> --plan
# 密钥经 stdin 注入后运行：
#   ... --output .cache/llm-run-g<RG> --run --allow-network --key-stdin
# 双模型：--model glm-5.3 与 --model gpt-6-astra 各跑一遍后比对分歧
```

## 遗留尾项（非阻塞）

- 本地仓库需在 github.com 网络恢复后 `git fetch` 同步（远端 master = 721385f；本地分支与 API 构造提交内容一致但 SHA 不同）。
- `gap_l4_batch.json` 中 70628 行的参考提交勘误仅记录于对照.txt，JSON 本身未重生成。
- 技术说明书 §5 实测证据汇总仍待纳入 09-22 新案例（并入 P1.5 v1.0 工作）。
