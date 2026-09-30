# 已知答案反向评估：communication_bluetooth 回放实验（2026-09-30）

## 目的

把社区**已合并的安全修复**当作 ground truth，回放 WildTrace 扫描器，回答两个问题：

1. **正向**：工具能否自动定位已知修复的位置？（召回）
2. **反向**：工具的发现中，有多少被社区后续修复证实？（精度信号）

这是仓颉 FFI 方向 ground truth 构建策略的第一个实例（师兄意见 2026-09-30）。

## 实验设置

- **对象仓**：`openharmony/communication_bluetooth`（CJ FFI 63 仓扫描成员，本地 blobless 克隆）
- **回放基线**：`59cac79b`（2024-06-11 hid_host nullptr 修复的父提交）——该树同时包含
  后续三个修复对应的未修缺陷（2024-09 socket、2024-12 gatt、2025-08 observer×7）
- **回放命令**：`python -m ohvul.autopilot <worktree> --output replay_bt`
- **扫描面**：173 个 .cpp / 47,896 行 / 调用图 548 函数 / 耗时 1472s
- **当前态对照**：HEAD `56803de7`（!1749，2026-09 时代）
- 产物：`D:/cve_data/cjffi_sweep/replay_bt/findings.json`、worktree `wt_btpre`（保留供复现）

## 正向结果：已知答案 4 处，命中 0/4——但盲点全部命名

| # | 已知修复 | 日期 | 位置 | 缺陷形态 | 工具能否见 |
|---|---|---|---|---|---|
| GT1 | `88b2edee` add nullptr | 2024-06 | bluetooth_hid_host.cpp impl::Set/GetConnectStrategy | **局部智能指针** `sptr<> proxy = GetRemoteProxy(...)` 解引用无检查 | ✗ 局部变量不在参数模型内 |
| GT2 | `100402f0` spp nullptr | 2024-09 | bluetooth_socket.cpp ClientSocket::Init/Connect 等 | **类成员指针** `pimpl` 解引用无检查 | ✗ 成员不在参数模型内 |
| GT3 | `b9fd4075` add nullptr check | 2024-12 | ohos_bt_gatt_server.cpp:899 BleGattsStartService | **空检查不完备**（查 GATTSERVER 漏 GATTSERVICE） | ✗ 宏展开取指针不可见 |
| GT4 | `432c8b3e` observer nullptr | 2025-08 | 7 个 inner 文件 RegisterObserver 等 | **智能指针参数** `shared_ptr<> observer` 解引用无检查 | ✗ 参数正则只匹配裸指针 |

**结论**：四个盲点全部是**非裸指针的指针形态**（成员 / 局部智能指针 / 智能指针参数 / 宏展开）——
与代码内既有"已知漏报"文档一致，但现在是 ground truth 背书的定量证据（0/4）。
GT4 最接近可达：`shared_ptr<T> name` 参数只需扩展参数正则即可覆盖。

## 反向结果：13 条 P6 发现的逐一裁定（严格函数体对比）

| 裁定 | 数量 | 明细 |
|---|---|---|
| **确认误报（根因已定位）** | 2 | `SocketUpdateCocConnectionParams(param)`：修复前已有 `CHECK_AND_RETURN_LOG_RET(param, ...)` **真值宏形态检查**，P6 抑制正则不识别；`BleStartAdvWithAddr(ownAddrParams)`：前后版本均靠 `IsRpa(ownAddrParams)` **过程间语义防护**（IsRpa 内部空检查 + 早退），模式级检查不可见 |
| **社区后续修复直接证实** | 0 | （宽松窗口初判 4 条，函数体级严格对比后全部纠正——过程记录见下） |
| **至今开放（无检查）** | 11 | 含 `SetOneScanFilter(nativeScanFilter ×19 derefs)`、`SetServiceUuidParameter(×7)` 等 c_adapter 系——与 30 条候选中 bluetooth 验证执行件（bluetooth_neg_advert.c / bluetooth_null_filter.c）对应 |

**方法学修正记录**：首轮用"函数名后 3000 字符窗口"宽松匹配得 4 条"已证实"；改用
前后版本完整函数体提取 + 严格对比后纠正为 0。教训：反向评估必须在函数体粒度做。

## 综合结论

1. **类别相关性成立**：该仓四年间的 4 个安全修复全部是空指针类（CWE-476），与我们
   P1-P3/P6 规则的目标类别一致——类别选对了。
2. **形态覆盖是真实差距**：0/4 召回不是规则逻辑错误，而是**指针建模只覆盖裸指针参数**。
3. **精度有两个可修根因**：真值宏检查识别（`CHECK_*(var,` 形态，一行正则）与
   过程间语义防护（IsRpa 类，需跨函数传播——正好是 cross_uaf/L4 链路分析的用武之地）。
4. **11 条开放 lead 是候选新发现**：c_adapter 的 nativeScanFilter 系列（×7/×19 解引用）
   与既有验证执行件合流，构成下一批工单候选。

## 下一步 roadmap（每项有 ground truth 支撑）

| 优先 | 改进 | 验证方式 |
|---|---|---|
| P0 | P6/P1 参数模型扩展 `shared_ptr<T>`/`unique_ptr<T>` 参数 | GT4 的 7 处应转为命中 |
| P0 | 抑制正则识别 `CHECK_AND_RETURN*(var,` 真值宏形态 | SocketUpdate 误报消除 |
| P1 | 局部变量指针建模（`T* p = f(); p->…` 无检查） | GT1 的 proxy 两处 |
| P1 | 成员指针建模（构造/Reset 后的 `pimpl->`） | GT2 的 ClientSocket 系列 |
| P2 | 宏展开取指针（GATTSERVICE(serverId, handle) 形态表） | GT3 |
| P2 | 过程间空防护传播（被调用函数内部含 null 检查则视作守卫） | BleStartAdv 误报消除 |

## 复现

```bash
cd D:/cve_data/cjffi_sweep/repos/communication_bluetooth
git fetch --unshallow --filter=blob:none
git worktree add --detach ../wt_btpre 59cac79b   # 并 sparse-checkout disable
cd <WildTrace> && python -m ohvul.autopilot D:/cve_data/cjffi_sweep/wt_btpre --output D:/cve_data/cjffi_sweep/replay_bt
# 严格对比脚本：见本文件"反向结果"节的方法描述（git show 前后版本 + 函数体提取）
```
