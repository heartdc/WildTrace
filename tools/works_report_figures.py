#!/usr/bin/env python3
"""Generate figures 1-2 for the works report (architecture + ladder).

Output: docs/deliverables/assets/fig1_architecture.png, fig2_ladder.png
CJK-capable fonts are probed at runtime; falls back gracefully.
"""
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch

OUT = Path(__file__).resolve().parent.parent / "docs" / "deliverables" / "assets"
OUT.mkdir(parents=True, exist_ok=True)

for fam in ["Microsoft YaHei", "SimHei", "Noto Sans CJK SC", "WenQuanYi Micro Hei"]:
    try:
        matplotlib.rcParams["font.family"] = fam
        break
    except Exception:
        continue
matplotlib.rcParams["axes.unicode_minus"] = False


def box(ax, x, y, w, h, text, fc, ec="#37474f", fs=10, tc="#212121"):
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.02,rounding_size=0.02",
                                fc=fc, ec=ec, lw=1.2))
    ax.text(x + w / 2, y + h / 2, text, ha="center", va="center",
            fontsize=fs, color=tc, linespacing=1.5)


def arrow(ax, x1, y1, x2, y2, style="-|>", color="#455a64"):
    ax.add_patch(FancyArrowPatch((x1, y1), (x2, y2), arrowstyle=style,
                                 mutation_scale=16, color=color, lw=1.4))


# ---------------- Figure 1: architecture ----------------
fig, ax = plt.subplots(figsize=(11, 5.6), dpi=150)
ax.set_xlim(0, 12)
ax.set_ylim(0, 6)
ax.axis("off")

box(ax, 0.3, 4.9, 3.2, 0.9, "OpenHarmony 全树\n（136 仓 · 173,901 行 FFI 面 / dsoftbus 68 万行）",
    "#e3f2fd", fs=9)
box(ax, 4.4, 4.9, 3.2, 0.9, "T1 边界收割\nFFI 导出符号 + ABI 契约提取", "#bbdefb", fs=9)
box(ax, 8.5, 4.9, 3.2, 0.9, "T2 模式族分诊\nF1 头长失配 / F2 嵌套指针 / F3 负长度", "#bbdefb", fs=9)

box(ax, 0.3, 3.3, 3.2, 0.9, "1-day 回移缺口判定\ncvelistV5 联接 + patch 文件形态", "#f3e5f5", fs=9)
box(ax, 4.4, 3.3, 3.2, 0.9, "已知答案回放评估\n正向盲点 / 反向误报闭环", "#f3e5f5", fs=9)
box(ax, 8.5, 3.3, 3.2, 0.9, "验证客户端合成\n对照/候选/变体三组矩阵", "#ffe0b2", fs=9)

box(ax, 0.3, 1.7, 5.0, 1.1, "T3 真库验证阶梯\n官方完整树零改动构建 → 对照矩阵\n→ 双 ASLR gdb 帧归因 → 证实/证伪归档",
    "#ffcc80", fs=8.5)
box(ax, 6.0, 1.7, 5.7, 1.1, "证据一致性契约（三出口）\n工作台 / 影响矩阵 / 漏洞报告 同输入同判定\n分支实证(18 格) 与 上游预测 分层呈现",
    "#c8e6c9", fs=8.5)

box(ax, 0.3, 0.2, 5.0, 1.0, "证据包归档\n库指纹/构建溯源/红线声明/MANIFEST", "#dcedc8", fs=8.5)
box(ax, 6.0, 0.2, 5.7, 1.0, "20 案证据链 + 漏洞奖励计划提交\n（2 真库级新发现 + 16 张 CVE 缺口工单）", "#dcedc8", fs=8.5)

arrow(ax, 3.5, 5.35, 4.4, 5.35)
arrow(ax, 7.6, 5.35, 8.5, 5.35)
arrow(ax, 10.1, 4.9, 10.1, 4.2)
arrow(ax, 10.1, 3.3, 10.1, 2.8)
arrow(ax, 2.8, 4.9, 2.8, 4.2)
arrow(ax, 2.8, 3.3, 2.8, 2.8)
arrow(ax, 5.3, 1.7, 5.3, 1.2)
arrow(ax, 8.8, 1.7, 8.8, 1.2)
arrow(ax, 5.3, 2.25, 6.0, 2.25)
# replay evaluation feeds detector-rule fixes back into T2 (dashed)
arrow(ax, 6.0, 4.2, 6.6, 4.9, style="-|>", color="#8e24aa")
ax.text(6.05, 4.42, "误报抑制/盲点反馈", fontsize=7.5, color="#8e24aa", ha="left")
arrow(ax, 4.4, 3.75, 3.5, 3.75)

ax.text(6, 5.95, "图 1  WildTrace 系统总体架构", ha="center", fontsize=13, weight="bold")
fig.tight_layout()
fig.savefig(OUT / "fig1_architecture.png", bbox_inches="tight")
plt.close(fig)

# ---------------- Figure 2: verification ladder ----------------
fig, ax = plt.subplots(figsize=(9, 5.2), dpi=150)
ax.set_xlim(0, 10)
ax.set_ylim(0, 6.4)
ax.axis("off")

steps = [
    ("L1 官方完整树构建", "repo manifest 同步 · 471+ 项目 · 零 FFI 源码改动", "#e3f2fd"),
    ("L2 对照矩阵运行", "对照(合法)/候选(畸形)/变体 三组 —— 缺陷精确限定于畸形组合", "#bbdefb"),
    ("L3 双 ASLR gdb 帧归因", "两次地址布局复现 · 崩溃帧映射目标库内 file_offset 级", "#90caf9"),
    ("L4 结论与归档", "证实 → 工单提交奖励计划；证伪/隔离限制 → 如实归档", "#64b5f6"),
]
y = 0.5
for i, (title, sub, fc) in enumerate(steps):
    box(ax, 0.6 + i * 0.55, y, 7.4, 0.95, f"{title}\n{sub}", fc, fs=9)
    if i < 3:
        arrow(ax, 4.3 + i * 0.55, y + 0.95, 4.85 + i * 0.55, y + 1.35)
    y += 1.4

box(ax, 8.6, 2.6, 1.2, 0.8, "证据包\nsha256/BuildID\n/MANIFEST", "#c8e6c9", fs=8)
arrow(ax, 8.0, 3.0, 8.6, 3.0)

ax.text(5, 6.15, "图 2  真库验证阶梯（T3）", ha="center", fontsize=13, weight="bold")
fig.tight_layout()
fig.savefig(OUT / "fig2_ladder.png", bbox_inches="tight")
plt.close(fig)

print("written:", OUT / "fig1_architecture.png", OUT / "fig2_ladder.png")

# ---------------- Figure 4: funnel convergence ----------------
fig, ax = plt.subplots(figsize=(9, 5.0), dpi=150)
stages = [
    ("初始 lead（autopilot 全层）", 3033, "#ef9a9a"),
    ("误报治理后（宏守卫/去重）", 2662, "#f48fb1"),
    ("指针状态模型语义收敛", 13, "#ce93d8"),
    ("高价值目标真库验证", 6, "#90caf9"),
    ("真库级证实新发现", 4, "#a5d6a7"),
]
labels = [s[0] for s in stages]
values = [s[1] for s in stages]
colors = [s[2] for s in stages]
bars = ax.barh(range(len(stages))[::-1], [max(v, 8) for v in values], color=colors, edgecolor="#37474f", height=0.62)
for i, (bar, v) in enumerate(zip(bars, values)):
    ax.text(bar.get_width() + 40, bar.get_y() + bar.get_height() / 2,
            f"{v:,}" if v >= 100 else str(v), va="center", fontsize=11, weight="bold")
ax.set_yticks(range(len(stages))[::-1])
ax.set_yticklabels(labels, fontsize=10)
ax.set_xlabel("数量（条/个）", fontsize=10)
ax.set_xlim(0, 3450)
for spine in ("top", "right"):
    ax.spines[spine].set_visible(False)
ax.set_title("图 4  检测漏斗：从 3,033 条 lead 到 4 项真库级新发现（dsoftbus 68 万行）", fontsize=12, weight="bold", pad=12)
ax.text(0.985, 0.03, "误报治理精确消除 229 条宏守卫误报；语义收敛 2,662→13；另 2 项诚实证伪未计入",
        transform=ax.transAxes, ha="right", fontsize=8, color="#616161")
fig.tight_layout()
fig.savefig(OUT / "fig4_funnel.png", bbox_inches="tight")
plt.close(fig)

# ---------------- Figure 5: impact matrix heatmap ----------------
import json
matrix = json.loads((OUT.parent / "IMPACT_MATRIX.json").read_text(encoding="utf-8"))
branches = ["v4.1", "v5.0", "v5.1", "v6.0", "v7.0", "master"]
cmap = {"affected": 0, "not_affected": 1, "fixed": 2, "unknown": 3}
color_list = ["#e53935", "#9e9e9e", "#43a047", "#ffffff"]
rows = []
items = matrix.items() if isinstance(matrix, dict) else ((c.get("id", c.get("case", "?")), c) for c in matrix)
case_names = []
for name, case in items:
    case_names.append(name)
    cells = []
    for b in branches:
        v = case.get("branches", {}).get(f"OpenHarmony-{b}-Release",
                        case.get("branches", {}).get(b, "unknown"))
        cells.append(cmap.get(v, 3))
    rows.append(cells)
import numpy as np
grid = np.array(rows)
fig, ax = plt.subplots(figsize=(8.6, 7.4), dpi=150)
ax.imshow(grid, cmap=matplotlib.colors.ListedColormap(color_list), vmin=0, vmax=3, aspect="auto")
ax.set_xticks(range(len(branches)))
ax.set_xticklabels(branches, fontsize=10)
names = [n[:34] for n in case_names]
ax.set_yticks(range(len(case_names)))
ax.set_yticklabels(names, fontsize=7.6)
for i in range(grid.shape[0]):
    for j in range(grid.shape[1]):
        v = grid[i, j]
        mark = {0: "🔴", 1: "—", 2: "✅", 3: "？"}[v]
        ax.text(j, i, mark, ha="center", va="center", fontsize=8)
ax.set_xticks(np.arange(-0.5, len(branches), 1), minor=True)
ax.set_yticks(np.arange(-0.5, len(matrix), 1), minor=True)
ax.grid(which="minor", color="#fafafa", linewidth=0.8)
ax.tick_params(which="minor", length=0)
ax.set_title("图 5  影响矩阵：20 案 × 6 分支全部判定（钉版联接/符号探测，零待定格）", fontsize=11.5, weight="bold", pad=12)
fig.tight_layout()
fig.savefig(OUT / "fig5_matrix.png", bbox_inches="tight")
plt.close(fig)

# ---------------- Figure 6: dual-engine union ----------------
fig, ax = plt.subplots(figsize=(8.4, 4.4), dpi=150)
cats = ["规则层独有\n（P4/P5/P6/P8）", "双引擎交集\n（函数粒度）", "Joern 独有\n（J6/J8）"]
vals = [589, 752, 105]
cols = ["#90caf9", "#a5d6a7", "#ffcc80"]
bars = ax.bar(cats, vals, color=cols, edgecolor="#37474f", width=0.55)
for bar, v in zip(bars, vals):
    ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 14, str(v),
            ha="center", fontsize=12, weight="bold")
ax.set_ylabel("函数数", fontsize=10)
for spine in ("top", "right"):
    ax.spines[spine].set_visible(False)
ax.set_title("图 6  双引擎函数粒度并集（nstackx 子组件）：Joern 覆盖函数的 88% 获双引擎互证", fontsize=11.5, weight="bold", pad=12)
ax.text(0.5, 0.94, "规则层 2,404 发现 / Joern 1,271 发现；锚点差异（函数起始行 vs 解引用行）已在文档注明",
        transform=ax.transAxes, ha="center", fontsize=8, color="#616161")
fig.tight_layout()
fig.savefig(OUT / "fig7_dualengine.png", bbox_inches="tight")
plt.close(fig)

print("written:", OUT / "fig4_funnel.png", OUT / "fig5_matrix.png", OUT / "fig7_dualengine.png")

# ---------------- Figure: P6 state model timeline (fig6_statemodel) ----------------
fig, ax = plt.subplots(figsize=(9.4, 5.0), dpi=150)
ax.set_xlim(0, 10)
ax.set_ylim(0, 6.2)
ax.axis("off")

code = [
    ("sptr<T> proxy = GetRemoteProxy();", "MaybeNull", "#fff9c4"),
    ("if (proxy == nullptr) { return; }", "→ NonNull（守卫确认）", "#c8e6c9"),
    ("proxy->Ping();", "NonNull：安全，不发射", "#a5d6a7"),
]
x = 0.5
for i, (line, state, fc) in enumerate(code):
    box(ax, x, 3.4, 3.0, 1.0, line, "#eceff1", fs=8.5)
    box(ax, x + 0.1, 1.9, 2.8, 0.85, state, fc, fs=9)
    if i < 2:
        arrow(ax, x + 3.0, 3.9, x + 3.5, 3.9)
    x += 3.5

box(ax, 0.5, 5.0, 2.8, 0.9, "Null\n（确定性崩溃）", "#ffcdd2", fs=10)
box(ax, 3.6, 5.0, 2.8, 0.9, "MaybeNull\n（待论证/分层）", "#fff9c4", fs=10)
box(ax, 6.7, 5.0, 2.8, 0.9, "NonNull\n（安全，不发射）", "#c8e6c9", fs=10)
ax.text(5.0, 0.6, "每个不发射的访问都记录抑制原因（抑制日志）——漏斗 2,662 → 13 的每一步可审计",
        ha="center", fontsize=9, color="#37474f")
ax.set_title("图 6  指针状态模型：Null / NonNull / MaybeNull 三态时间线与可证明性分层", ha="center", fontsize=12, weight="bold", y=6.05)
fig.tight_layout()
fig.savefig(OUT / "fig6_statemodel.png", bbox_inches="tight")
plt.close(fig)

# ---------------- Figure: LLM PoC four-step loop (fig8_llm_loop) ----------------
fig, ax = plt.subplots(figsize=(9.4, 5.2), dpi=150)
ax.set_xlim(0, 10)
ax.set_ylim(0, 6.4)
ax.axis("off")

steps = [
    ("③ 语义注入", "P6 状态模型输出\n→ LLM 提示词\n（10 种触发策略）", "#e1bee7"),
    ("① 编译反馈环", "生成 → 编译 →\n失败 stderr 回喂重试\n（上限 2 次）", "#b3e5fc"),
    ("② ASan 执行", "SIGSEGV / ASan\n报告检测", "#c8e6c9"),
    ("④ 真库验证", "dlopen 真实 .so\n+ musl 加载器\n→ exit 139", "#ffcc80"),
]
x = 0.4
positions = [(0.4, 3.2), (2.9, 3.2), (5.4, 3.2), (7.9, 3.2)]
for (title, sub, fc), (px, py) in zip(steps, positions):
    box(ax, px, py, 2.1, 1.7, f"{title}\n{sub}", fc, fs=8.5)
for i in range(3):
    arrow(ax, positions[i][0] + 2.1, positions[i][1] + 0.85, positions[i+1][0], positions[i+1][1] + 0.85)
arrow(ax, positions[1][0] + 1.05, 3.2, positions[1][0] + 1.05, 2.2)
ax.text(positions[1][0] + 1.05, 1.9, "编译失败 → 回喂重试", ha="center", fontsize=8, color="#b71c1c")
box(ax, 0.4, 0.4, 9.6, 1.0,
    "端到端 ~30 秒/案（人工约 2 小时）· 密钥仅运行时环境变量 · LLM 永不产生漏洞结论（供信号不裁决）",
    "#fafafa", fs=9.5)
ax.set_title("图 8  LLM PoC 四步闭环：语义注入 → 编译反馈环 → ASan 执行 → 真库验证", ha="center", fontsize=12, weight="bold", y=6.25)
fig.tight_layout()
fig.savefig(OUT / "fig8_llm_loop.png", bbox_inches="tight")
plt.close(fig)

print("written:", OUT / "fig6_statemodel.png", OUT / "fig8_llm_loop.png")
