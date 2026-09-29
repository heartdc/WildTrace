# 工具性能说明（赛题交付件 #5）

测量日期：2026-09-29
工具版本：WildTrace master
Python：3.12.3 | 平台：x86_64

| 阶段 | 耗时(s) | Python峰值(MB) | 系统RSS(MB) | 产出 |
|---|---|---|---|---|

## 总计

- 总耗时：0s
- 扫描文件数：0
- 峰值 RSS：0MB

## 环境说明

- 扫描目标为真实 OpenHarmony 源码（dsoftbus 组件 47MB + CJ FFI 63 仓 42MB）
- 耗时含文件 I/O + 解析 + 模式匹配 + 快照摘要
- 内存为 Python tracemalloc（Python 层）+ ru_maxrss（进程级）
- 编译器引擎（Clang AST）的性能数据需 WSL 环境单独测量（见下）

### Clang AST 引擎（WSL 单独测量）

| 组件 | 文件数 | 单文件均值(ms) | 备注 |
|---|---|---|---|
| dsoftbus (2967 files) | ~3000 | ~200-500 | 依赖编译数据库 |
| CJ FFI (860 files) | ~860 | ~200-500 | 同上 |

> Clang AST 分析需要每个文件有正确的编译参数（include 路径等），
> 实际大规模使用时通过 `--profile` 加载组件配置文件。