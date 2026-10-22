# 比赛演示视频脚本（v2，2026-10-17，配 DEMO_RUNBOOK）

> v2 修订要点：删除 v1（2026-09-28）中"确认产品漏洞数为 0"的过时声明——现有
> 四项真库级 SIGSEGV 证实；新增"真库验证"与"工作台"两个演示段；全部数字对齐
> 当前 master（1,162 项回归、漏斗 2,662→13、影响矩阵 20 案全分支判定）。
> 目标时长 10-14 分钟；每段落标注画面必须出现的要素与旁白要点。
> 纪律与 RUNBOOK 一致：验证层级分开陈述，不把等价复现说成产品复现，
> 失败记录不删不改，模型输出永远是 proposal。

## 0. 片头（30s）

- 画面：仓库根目录 `git log --oneline -3` + `python -m unittest discover -s tests -q` 结尾摘要行
- 旁白：版本与全量回归通过作为基线声明（念出 1,162 项与 OK 行）

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
- 补一句现状：dsoftbus 全量 2,662 条 lead 经指针状态模型语义收敛至 13 条
  （每个不发射的访问都有抑制日志原因——可审计）

## 3. 分诊队列与工作台（2min，新增 UI 段）

```powershell
.\Start-Workbench.ps1   # 或 python -m ohvul.workbench.launch
```

- 画面：浏览器打开工作台——总览页指标（案例完整度矩阵）、案例对话框
  （源码/审查/版本影响三标签）、候选审查页、报告中心
- 旁白：概览指标为"计数无关"断言口径；打开 ipc 案例对话框展示证据链字段；
  指出双引擎（P6 规则层 + Joern CPG 选配）在工作台同一界面下工作

## 4. 案例证据层级（3-4min，核心段，口径已更新）

- 画面：`python -m ohvul.competition_report --cases cases --output ... --markdown ...` 生成的报告
- 旁白逐层讲：完整度矩阵（实质率 68%、20 案×6 分支影响矩阵全分支判定）
  的 ✓/—含义；
- 重点三案：
  - **IPC / HiAppEvent**：真库 dlopen 复现 SIGSEGV（帧归因库内）→ 已按负责任
    披露提交漏洞奖励计划（17 单评审中）；
  - **UDMF**：round-trip 自毁论据（getter 合法输出回喂 setter 必崩）+
    run_malformed exit 139；
  - **cjson**：公开 CVE 回验（ASan 矩阵 + 第二人独立复现）。
- **明确声明边界**：真库级证实 = 隔离配置下的官方完整树真库崩溃（gdb 帧归因
  库内），产品整机环境复现未建立，全部案例如实标注；证伪（account/avsession
  两案）与"源级三侧对照"案的层级差异也讲一句——证据分级是本工具的属性

## 5. 真库验证一键化（2min，新增段，接第 4 段）

- 画面：`bash tools/validation_cases/run_malformed.sh ...` 与
  `bash tools/validation_cases/run_bt_dereg.sh ...` 两条命令的完整输出
  （run.exit=139、attribution.txt 的符号化行
  `bluetooth_socket_server.cpp:54`）
- 旁白：2026-10-17 新增的 bluetooth 服务端空指针（无权限要求）从构建到
  帧归因一键完成；等价性论证（逐字节一致 + 修复 diff apply --check）解释
  为什么上游构建的结论代表 OH 组件

## 6. 漏洞报告组装（1-2min）

- 画面：competition_report.md 的矩阵与分案记录；IMPACT_MATRIX.md 的
  🔴/—/？三态与"上游预测独立呈现"分区
- 旁白：报告只投影 case.json、未知项显式保留、不发明 confirmed 数字；
  ？格已通过分支钉版实证清零（第三方 16 案 + 原生四案符号级探测）

## 7. 片尾交付清单（30s）

- 画面：RUNBOOK"录屏交付清单"逐项
- 旁白：视频旁附同版本命令脚本与 SHA-256 的位置；DEMO 中出现的全部命令
  都在仓库 tools/ 与 docs/deliverables/ 内可复跑

## 预检清单（录制前 24h 核对）

- [ ] 干净 Python 3.10+ 环境 `pip install -e . --no-deps` 成功
- [ ] `toolchain_preflight` required 全 ok（或按环境变量指向演示工具链后全 ok）
- [ ] demo-source 固定源码目录 + 快照摘要就绪
- [ ] 全量回归当前 HEAD 通过（当前基线 1,162 项）
- [ ] 磁盘上有预演产物（避免录制时首次冷启动等待）
- [ ] 工作台可启动且预置案例数据就绪（第 3 段依赖）
- [ ] run_malformed / run_bt_dereg 预演过一次（第 5 段依赖，WSL 环境就绪）
- [ ] 无 API key/真实用户数据/未授权源码入镜
