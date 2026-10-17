# WildTrace 使用说明书（赛题交付件 3 · 文档部分）

> 版本：1.0（2026-09-30，对应 master `a023018`）。配套演示视频按 `docs/deliverables/VIDEO_SCRIPT.md` 录制，
> 逐命令操作顺序见 `docs/deliverables/DEMO_RUNBOOK.md`。

## 1. 依赖环境

| 项 | 要求 | 说明 |
|---|---|---|
| 操作系统 | Windows 10+ / Linux | 两条路径均已验证；路径含空格可用（已做引用处理） |
| Python | 3.10+ | 零第三方运行时依赖（`pip install -e . --no-deps` 即装即用） |
| Git | 可执行 | 知识库同步与 profile 来源校验需要；纯扫描不需要 |
| WSL（可选） | Ubuntu 24.04 + LLVM/Clang | Clang AST 引擎、Joern（`/opt/joern`）、运行时验证矩阵需要 |
| LLM 密钥（可选） | `OSLOVELACE_API_KEY` 环境变量 | 仅 `ohvul.llm_review` / `ohvul.llm_poc` 选配功能；默认扫描全程离线 |

安装与自检：

```powershell
python -m pip install -e . --no-deps
python -m unittest discover -s tests -q        # 当前基线 1058 项通过
python -m ohvul.toolchain --output preflight.json   # 工具链预检（演示第一步）
```

`preflight.json` 中 `ok=true` 表示 WSL/Clang/clang-tidy 通道可用；任一 required 项失败时按
"预检失败不继续" 纪律处理（这是演示的一个环节，不是缺陷）。

## 2. 主命令速查

### 2.1 自动化分析管线（autopilot v3）—— 主入口

```powershell
python -m ohvul.autopilot .\authorized-source --output .\out [--min-confidence 60] [--joern]
```

- 默认 **10 层**：P1–P3（CJ FFI 面三族，仅当树含 `/cj/` 路径时运行）+ P4–P9（通用 C/C++ 六族）+
  跨函数 UAF/双重释放（位置别名 + 局部变量追踪）
- `--joern` 增加**第 11 层**（Joern CPG，需 WSL `/opt/joern`；不可用时警告降级，不中断）
- 产出：`findings.json`（含逐条 0-100 置信度与因子分解、PoC 模板）+ `findings.md`（人读报告）
- 口径：**lead ≠ 漏洞**——置信度是排序优先级，不是准确率保证

### 2.2 影响矩阵与交付件组装

```powershell
python -m ohvul.impact_matrix --cases cases --output docs/deliverables/IMPACT_MATRIX
python -m ohvul.vuln_report --cases cases --output docs/deliverables/VULN_REPORT.md --force
python -m ohvul.competition_report --cases cases --output out\report.json --markdown out\report.md
```

影响矩阵按 CVE 联接知识库（`kb/third_party_targets`，cvelistV5）做证据分级判定；
两个报告生成器均不发明数字（？= 待定，confirmed 只投影显式字段）。

### 2.3 离线证据链管线（Phase 1 纪律层）

```powershell
python -m ohvul.cli .\authorized-source --output findings.json --checkpoint ck.json
python -m ohvul.candidate_triage --result findings.json --output triage.json
python -m ohvul.verify findings.json
```

候选一律待人工复核；`input_error` 不计为干净扫描。

### 2.4 选配：LLM PoC 生成（已加固）

```powershell
# 需 OSLOVELACE_API_KEY；finding 路径限制在 source_root 内，输出过危险 API 屏蔽
python -m ohvul.llm_poc .\out\findings.json .\authorized-source --output llm_pocs --min-confidence 70
```

### 2.5 知识库与基准

```powershell
python -m ohvul.kb_sync build --kb-dir <dir>     # CVE 知识库构建/校验
python -m ohvul.benchmark cases.json             # 配对真假基准（builtin vs function_rules 可对比）
python tools/kb_gap_audit.py <component-repo> --kb <kb.json>   # 回移缺口四信号审计
```

## 3. 扫描覆盖率与粒度（对应评价备注 7）

| 层 | 覆盖面 | 粒度 |
|---|---|---|
| autopilot 规则层（P1–P9 + 跨函数） | 树内**全部** `.c`/`.cpp` 文件（无白名单） | 函数级（注释/字符串掩码后的结构切分） |
| Joern 层（`--joern`） | 同上（整树 CPG） | 路径敏感 CPG 查询 |
| Clang AST 层 | 按组件 profile 声明的文件清单 | 编译器事实级（含精确值/区间标量流） |
| 覆盖率口径 | `findings.json` 的 `surface` 字段如实记录扫描面（文件数/行数估计/CJ 命中）；声明外文件不计为已分析 | |

实测示例见 `docs/deliverables/PERFORMANCE.md`（dsoftbus 47,896 行 / 173–2,967 文件级目标 +
CJ FFI 63+ 仓，耗时与内存数据随附）。

## 4. 常见问题

- **扫描输出目录**：必须在被扫描树之外；已存在的报告默认拒绝覆盖（`--force` 显式覆盖）。
- **WSL 不可用**：Clang/Joern 相关功能降级或提示，不影响规则层扫描。
- **行尾**：仓库已配 `.gitattributes`（`* text=auto`，`*.sh`/`*.sc` 强制 LF），Windows 检出可直接用。
- **密钥安全**：密钥仅运行时读取，不落盘不入日志；CI 含密钥形态扫描。

## 5. 交付件索引

`docs/deliverables/`：TECHNICAL_SPEC（技术说明书）、VULN_REPORT（漏洞分析报告）、
IMPACT_MATRIX（影响矩阵）、PERFORMANCE（性能说明）、VIDEO_SCRIPT + DEMO_RUNBOOK（演示）、
USAGE（本文件）。状态台账在 `docs/status/`，审计与实验记录在 `docs/analysis/`。

## 6. 本地工作台（2026-10 增补）

```powershell
.\Start-Workbench.ps1                 # 或：python -m ohvul.workbench.launch
# 浏览器打开 http://127.0.0.1:8765
```

- 总览页：案例证据完整度指标（计数无关断言）、扫描/任务状态
- 案例对话框：源码位置 / PoC 与附件 / 版本影响三标签，证据链字段直读 case.json
- 候选审查页与报告中心：发现队列、报告预览与导出；双引擎（P6 规则层 +
  Joern CPG 选配）同一界面驱动
- 数据目录默认 `.cache/workbench`，可用 `--data-dir` 指定

## 7. 验证 harness 一键化（2026-10 增补）

`tools/validation_cases/`（17 个 .c/.sh，含 20+ 验证客户端）：

| runner | 用途 |
|---|---|
| `run_malformed.sh` | 任意真库 malformed 客户端的编译-加载-执行-封存（udmf/ipc/kv/hiappevent 等，exit 139 判读） |
| `run_ipc_normal.sh` | IPC 正常路径 round-trip（对照组） |
| `run_bt_dereg.sh` | bluetooth 服务端 DeregisterServerObserver PoC：构建到帧归因一键完成（符号化 `bluetooth_socket_server.cpp:54`） |

其余单案客户端（`*_null_*.c`、`bluetooth_neg_advert.c` 等）均以
`run_malformed.sh <root> <out> <evid> <client> <lib>` 统一驱动，证据哈希
前后封存。LLM 侧：`tools/llm_review_run.py`（plan/run/verify）与
`tools/llm_cross_compare.py`。
