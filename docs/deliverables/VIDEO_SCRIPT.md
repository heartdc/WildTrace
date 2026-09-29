# 比赛演示视频脚本（配 DEMO_RUNBOOK，2026-09-28）

目标时长 8-12 分钟；每段落标注画面必须出现的要素与旁白要点。
纪律与 RUNBOOK 一致：验证层级分开陈述，不把等价复现说成产品复现，
失败记录不删不改。

## 0. 片头（30s）

- 画面：仓库根目录 `git log --oneline -5` + `python -m unittest discover -s tests -q` 结尾摘要行
- 旁白：版本与全量回归通过作为基线声明（念出测试数与 OK 行）

## 1. 环境预检（1min）

```powershell
python -m ohvul.toolchain --output .\demo-out\preflight.json
```

- 画面：preflight JSON 全文（含 resolved 路径与逐项 status）
- 旁白：演示前先证明工具链可用与路径来源（env 覆盖 → 内置默认）；
  任一 required 项非 ok 时演示终止——这就是"预检失败不继续"的现场证明

## 2. 扫描与候选队列（2-3min）

按 RUNBOOK"推荐录屏顺序"四条命令逐条执行，每条：

- 画面：完整命令行 + 退出码 + 输出 JSON 关键字段（source_file/line/file_sha256/rule/final_verdict=undetermined）
- 旁白：候选≠结论；指出 input_errors 的保留（故意演示一个不存在文件路径）

## 3. 分诊队列（1-2min）

- 画面：triage JSON 的五条泳道与各告警的 lane + 理由字段
- 旁白：泳道是工作流提示不是判定；"test_support 不代表安全"的例子

## 4. 案例证据层级（3-4min，核心段）

- 画面：`python -m ohvul.competition_report --cases cases --output ... --markdown ...` 生成的报告
- 旁白逐层讲：完整度矩阵中各案"✓/—"的含义；
  重点两案——cjson（库级复现+第二人，公开 CVE 回验）与 IPC（等价复现，
  平台二进制未链接，next_gate 明确）。**明确说出"确认产品漏洞数为 0"及原因**
- 若演示机有真实库证据：按 REAL_BUILD_PROBE_20260925 的口径展示
  `libcj_ipc_ffi.z.so` 构建产物与正常路径 harness，同时口头声明
  "基础运行库带补丁、非完整产品服务环境"

## 5. 漏洞报告组装（1-2min）

- 画面：competition_report.md 的矩阵与分案记录
- 旁白：报告只投影 case.json、未知项显式保留、不发明 confirmed 数字

## 6. 片尾交付清单（30s）

- 画面：RUNBOOK"录屏交付清单"逐项
- 旁白：视频旁附同版本命令脚本与 SHA-256 的位置

## 预检清单（录制前 24h 核对）

- [ ] 干净 Python 3.10+ 环境 `pip install -e . --no-deps` 成功
- [ ] `toolchain_preflight` required 全 ok（或按环境变量指向演示工具链后全 ok）
- [ ] demo-source 固定源码目录 + 快照摘要就绪
- [ ] 全量回归当前 HEAD 通过
- [ ] 磁盘上有预演产物（避免录制时首次冷启动等待）
- [ ] 无 API key/真实用户数据/未授权源码入镜
