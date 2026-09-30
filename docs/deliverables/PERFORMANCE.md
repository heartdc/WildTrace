# 工具性能说明（赛题交付件 #5）

测量日期：2026-09-30 | 工具版本：WildTrace master | Python 3.12.1 | 平台 x86_64（Windows 原生，无 WSL 依赖）

## 1. 自动化分析管线（autopilot v3，10 层，旗舰数据）

| 目标 | 源码规模 | 管线耗时 | 吞吐 | lead 产出 | 管线峰值内存 |
|---|---|---|---|---|---|
| dsoftbus 组件 | 1737 文件 / 681,529 行 | **651.67s** | ~1,046 行/s | **3033 条**（高危 580） | 176.4MB |
| CJ FFI 63+ 仓 | 714 文件（含 489 CJ 命中）/ 173,901 行 | **272.08s** | ~639 行/s | **380 条**（高危 84） | 58.4MB |

dsoftbus 模式分布：P6_null_deref 2453 条；P8_use_after_free 511 条；P9_format_string 3 条；P8_double_free 6 条；P8_cross_uaf 60 条。
CJ FFI 模式分布：P6_null_deref 193 条；P8_use_after_free 40 条；P1_null_len 31 条；P8_double_free 2 条；P8_cross_uaf 26 条；P2_truncation 17 条；P3_nested_deref 10 条；P7_alloc_overflow 61 条。

> 口径说明：本轮为检测质量修复（跨函数 UAF 按 (callee,变量) 去重、判定收紧）后的**现役口径**——
> 跨函数发现 60 条（dsoftbus），与历史未去重记录（889 条）不可直接比较；PoC 模板随 lead 生成。
> 内存为管线子进程自报峰值（Windows GetProcessMemoryInfo / POSIX getrusage）。

## 2. 分阶段明细（同一轮实测）

| 阶段 | 耗时(s) | Python峰值(MB) | 进程RSS(MB) | 产出 |
|---|---|---|---|---|
| oh_dsoftbus_surface | — | — | — | 文件 2967 |
| oh_dsoftbus_autopilot | 652.08 | 12.2 | 28.7 | leads=3033 high=580 行数=681,529 管线内存=176.4MB |
| oh_dsoftbus_lexical | 1.26 | 2.3 | 28.7 | files=655, pattern_hits=1960 |
| oh_dsoftbus_cjffi | 13.72 | 0.0 | 28.7 | note=files=1737 leads=25 -> cjffi_leads.json missing-both-checks: 16, files=1737, leads=25 |
| oh_dsoftbus_snapshot | 7.91 | 8.1 | 39.7 |  |
| cjffi_63repos_surface | — | — | — | 文件 1178 |
| cjffi_63repos_autopilot | 272.27 | 1.5 | 39.7 | leads=380 high=84 行数=173,901 管线内存=58.4MB |
| cjffi_63repos_lexical | 0.42 | 0.1 | 39.7 | files=2, pattern_hits=0 |
| cjffi_63repos_cjffi | 5.48 | 0.0 | 39.7 | note=files=714 leads=37 -> cjffi_leads.json missing-both-checks: 32, files=714, leads=37 |
| cjffi_63repos_snapshot | 10.48 | 10.1 | 44.2 |  |

## 3. 总计与口径

- 本轮全阶段总耗时 **963.6s**（含 surface 统计、autopilot、词法、CJ 扫描、快照摘要）
- 管线峰值内存 **176.4MB**（autopilot 子进程自报；轻量阶段进程 RSS ≤ 44.2MB）
- 扫描覆盖率：autopilot 规则层覆盖树内**全部** .c/.cpp（无白名单），面数据如实记录于 findings.json 的 surface 字段
- 测量工具：`tools/perf_measure.py`（本轮起含 autopilot 阶段与 Windows 原生内存读取；修复了历史 rss 计算错误）

## 4. 环境与依赖说明

- 扫描目标为真实 OpenHarmony 源码：dsoftbus 组件（681,529 行）+ CJ FFI 136 仓克隆（173,901 行）
- 全部测量在 Windows 原生完成（零第三方依赖）；Clang AST / Joern 层需 WSL 环境单独测量
- 历史口径提示：早期记录的"742K 行 217s / 2466 lead"为检测质量修复前的测量，已被本节现役数据取代

## 5. Clang AST / Joern 层（WSL，选配）

| 引擎 | 目标 | 实测记录 |
|---|---|---|
| Joern CPG（--joern 第 11 层） | dsoftbus | CPG 构建 158s + 查询 58s（独立运行记录） |
| Clang AST 引擎 | 按组件 profile | 单文件 ~200-500ms，依赖编译数据库（profile 加载） |
