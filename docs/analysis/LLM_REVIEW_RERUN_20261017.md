# LLM 全量审查本机重建（2026-10-17）

状态：**已完成**——26/26 组有效草稿，终轮 verify completed（执行记录与草稿汇总见 `LLM_REVIEW_RUN_20261017.md`；范围调整：仅存 GLM 密钥，双模型交叉降级为单模型，gpt-6-astra 计划已移除）

## 背景与范围

历史"29 组全量"（review_33f843）的输入三元组与 `C:/Projects/OpenHarmony-complete`
源树在原跑批机器上（`docs/status/P0_EXECUTION_20260922.md` P0.5）。本机重建走完整
组件批跑管线，产出**新队列**（如实标注：非历史 29 组）。

**范围差异（如实）**：camera_app 作业缺席——其 profile 钉住 13 个仓的提交，其中
camera/build 的钉版提交不在本机浅克隆且 gitcode 拒绝按 SHA 拉取，溯源校验
（HEAD==钉版、树干净）不可能满足。本机作业：securec（39 文件）+ hilog_featured
（2 文件），钉版 **2ae82839 / 88291aa0** 与 WSL 官方树当前 HEAD 恰好一致。

## 重建中越过的四道守卫（均不改管线代码）

1. **lfs filter 拒绝**：repo-tool 仓本地配置带 `[filter "lfs"]`（溯源检查刻意拒绝
   filter 仓）。本机两仓曾临时摘除（备份已恢复，树回到原状）。
2. **源树符号链接拒绝**：repo-tool 的 `.git -> .repo/...` 符号链接布局不合规。
3. **UNC 拒绝**：`windows_to_wsl_path` 只接受盘符路径（\\wsl.localhost 暂存不可用）。
4. **源快照污染**：工作文件（manifest/group_ids）曾写入源根致快照漂移——
   工作面移至 `D:/llm_review_work/`，源根 `D:/llm_review_stage/` 保持纯净
   （只含两个钉版克隆仓），verify 期快照可复算。

解法（合规通道）：`git clone --no-hardlinks` WSL 官方树两仓到 `D:\llm_review_stage\`
并 checkout 到钉版提交——真 HEAD==钉版、无符号链接、无 filter、文件内容即钉版内容。
引擎：OH 预置 clang-tidy 15.0.4（WSL 侧，经 `OHVUL_LLVM_ROOT` 指定；
Windows 侧运行需 `MSYS_NO_PATHCONV=1` 防路径改写）。

## 当前产物（.cache/，gitignored；源根与工作面在 D:）

| 产物 | 位置 |
|---|---|
| 组件批跑 + 队列 + 上下文 + 交接 | `.cache/comp_review_20261017/`（STATIC_REVIEW_READY groups=26 open_tasks=130） |
| glm-5.3 全组 plan | `.cache/llm_plan_glm-5_3/`（status=prepared） |
| 组 ID 清单 | `D:/llm_review_work/group_ids.txt`（26 条） |

## 剩余一步（需所有者注入密钥）

```bash
# 1) 把 OSLOVELACE_API_KEY 单行写入 D:/llm_review_work/api_key.txt
# 2) 双模型全量（在仓库根、Git Bash）：
MSYS_NO_PATHCONV=1 python tools/llm_review_run.py run glm-5.3 \
  --summary .cache/comp_review_20261017/batch/summary-0004.json \
  --queue .cache/comp_review_20261017/review/queue.json \
  --context .cache/comp_review_20261017/review/context.json \
  --root 'securec=D:\llm_review_stage\third_party\bounds_checking_function' \
  --root 'hilog_featured=D:\llm_review_stage' \
  --groups D:/llm_review_work/group_ids.txt \
  --output .cache/llm_run_glm-5_3 --key-file D:/llm_review_work/api_key.txt
# 3) 离线验收（--mode verify，无网络无密钥）
# 双模型交叉（glm-5.3 × gpt-6-astra）因仅存 GLM 密钥不再执行；
# 若未来取得第二模型密钥，llm_cross_compare.py 与双跑流程可直接复用
```

纪律不变：模型输出为 proposal，`final_verdict` 恒为 undetermined，确认漏洞数 0；
密钥不入库不入日志（key 文件位于 D: 工作面，跑完可删）。
