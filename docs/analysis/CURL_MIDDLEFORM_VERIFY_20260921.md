# curl 中间形态核验报告 — 2026-09-21

对版本探测的 43 条 curl 精确命中做源码级核验（OH third_party_curl @ gitcode
master，_tip f044ac3，2026-09-11_）。**结论：41/43 已在 OH master 修复；
2 条为真实候选**。

## 核验方法（四层递进）

1. **显式回移**：`git log --grep=<CVE>` 查 OH 历史中按 CVE 号命名的修复提交 → 22 条命中
2. **对象存在**：修复 commit SHA `git cat-file -e` → 0 新增（OH 历史经改写，SHA 不可比）
3. **修复日期 vs 快照日期**：OH 于 2026-08-20 提交 `84b0153b1 upgrade to version
   20260819`（lib/http.c 等实证）→ 上游修复日期早于 2026-08-19 者已随快照进入 → 13 条
4. **年代代理**：2024/2025 初的 CVE，修复远早于快照 → 6 条

## 真实候选（2 条）

| CVE | 描述 | 修复日期 | OH 状态证据 |
|---|---|---|---|
| **CVE-2026-80231**（CWE-488） | HTTPS 连接复用错误：给定主机可能错误复用已有连接 | 2026-08-25（晚于快照） | 无 `--grep` 命中、无回移提交（对照：18924/80230 于 9/14-17 显式回移至 6.0/6.1/7.0 各分支） |
| **CVE-2026-82209**（CWE-201） | libpsl 启用时未正确执行公共后缀列表校验，恶意服务器可注入 PSL 域 supercookie | 2026-08-28（晚于快照） | 内容级证据：OH `lib/cookie.c` 为快照形态的旧 PSL 结构（`#ifndef USE_LIBPSL` + `cookie_tailmatch`），修复引入的新逻辑（tailmatch×PSL 联合判定）不在 |

两条的下游动作：走 cJSON 路线（案例准备 → 授权运行验证 → 报告 + 奖励计划提交）。
产品可达性前置问题：OH 产品的 libcurl 使用面（网络栈哪些路径走 libcurl、
cookie/连接复用是否可达外部输入）。

## 重要方法论发现

1. **版本字符串失真**：README.OpenSource 与 `curlver.h` 均写 8.8.0，实际代码为
   上游 20260819 快照 + 显式 CVE 回移——**活跃同步组件上，版本号匹配是弱信号**；
   可靠信号是修复提交/回移历史。建议版本探测工具新增"同步新旧度"预检
   （近期 upgrade commit 扫描），对活跃组件自动降级版本命中置信度。
2. **OH 的回移节奏**：9/14-17 一次性回移 CVE-2026-18924/80230 至三个 release
   分支——他们按公告节奏补丁；晚于快照且未被公告覆盖的修复（本报告两条，
   8/25、8/28 修复）正是缝隙。
3. **release 分支需单独核验**：master 的结论不能外推；6.0/6.1/7.0 分支的 curl
   状态是独立问题（回移选择性存在）。

## 数据工件

- `D:\cve_data\curl_hits.json`（43 条命中记录富化版）
- `D:\cve_data\curl_verify_final.json`（四层核验明细）
- `D:\cve_data\curl_unconf_dates.json`（21 条待确认的日期核验）
- OH curl 克隆：`D:\cve_data\oh_curl`（gitcode master）
