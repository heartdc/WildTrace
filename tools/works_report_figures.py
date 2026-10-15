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
