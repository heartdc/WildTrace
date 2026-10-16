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

## 闭环复评（P0 两项落地后，同日）

落地：`scan_p6` 增加 `_SMART_PTR_PARAM`（shared/unique_ptr 参数含 const&）与
`_TRUTHY_MACRO_GUARD`（`CHECK_*(var,` 真值形态抑制）；8 项专项测试
（tests/test_p6_smartptr_macros.py）。同一 worktree 复跑（1472→1481s）：

| 指标 | 修复前 | 修复后 | 变化 |
|---|---|---|---|
| 发现总数 | 13 | 12 | **−1 = 恰好移除确认误报 SocketUpdateCocConnectionParams** |
| 其余发现 | 12 | 12 | 全部保留，置信度无漂移（零误伤） |
| 智能指针新增发现 | — | 0 | GT4 站点解引用数 <3，未达 P6 发射阈值 |

**判读**：P0-2（真值宏抑制）在真实仓上精确验证——目标误报消除且无副作用。
P0-1（智能指针参数建模）机制层面生效（单测证明该形态可标记、有检查可抑制），
但该仓 observer 站点低于 3 次解引用阈值故未发射——**阈值调整（智能指针按
解引用计数加权）成为有 GT4 ground truth 的下一项**，不盲调。
评估→改进→再评估闭环成立，全程可复现。

## 复现

```bash
cd D:/cve_data/cjffi_sweep/repos/communication_bluetooth
git fetch --unshallow --filter=blob:none
git worktree add --detach ../wt_btpre 59cac79b   # 并 sparse-checkout disable
cd <WildTrace> && python -m ohvul.autopilot D:/cve_data/cjffi_sweep/wt_btpre --output D:/cve_data/cjffi_sweep/replay_bt
# 严格对比脚本：见本文件"反向结果"节的方法描述（git show 前后版本 + 函数体提取）
```

---

## 复评 2026-10-15：GT4 解锁，三层遮挡链归因（learn/p6-detection-contract）

上节留下的"阈值调整"按导师提升_doc 路线执行（次数降为排序因子而非发射门槛）。回放复跑发现
GT4 的遮挡其实有三层，此前文档只命名了第三层：

| 层 | 遮挡 | 修复 |
|---|---|---|
| 解析层 | `Class::Method(...)` 跨行定义（OH C++ 标准写法）在 `_FUNC_RE` 下解析为 0 个函数——proxy/impl 类 cpp 整文件不可见（GT4 站点全部在此类文件中） | 函数头正则分隔符 `\s+`→`\s*` |
| 形态层 | GT4 实际参数形态是 OH 自研 `const sptr<I...>&`，而智能指针正则只覆盖 `std::shared_ptr/unique_ptr`（本文件原文写 `shared_ptr<>`，与真实站点不符） | `_SMART_PTR_PARAM` 增补 `sptr/wptr` |
| 门槛层 | 解引用次数 <3 不发射（本文件"智能指针新增发现 0"行的原因） | 生成与排序分离；单次解引用 -10 分降权 |

**复跑结果**（wt_btpre @59cac79b，同树同法）：

- 回放总量 13 → **73**；
- **GT4 RegisterObserver 命中 0 → 12 站点**（本文件正向表仅登记 7 处——a2dp_src、map_mse 等
  站点在 2026-09-30 评估时因整文件不可解析而缺席，本次一并浮出）；
- 正向召回 0/4 → **1/4 GT 族**；GT1（局部智能指针）/GT2（成员指针）/GT3（宏展开取指针）
  仍为命名盲点，对应导师第六步（扩展局部智能指针、函数摘要和成员状态）。

**同批 dsoftbus 对照**（master 基线锚定 2,662 条，同树同机复跑）：

| 指标 | master | 本分支 |
|---|---|---|
| 总 lead | 2,662 | 5,599 |
| 高危 | 438 | 564 |
| conf≥70 | 1,340 | 1,788 |
| 基线键保留 | — | 2,651/2,653（99.9%） |
| 语义类 lead（检查过晚/仅日志/重赋值失效） | — | 14 |

**如实记录**：nstackx_dfile.c 的 2 条 P8 跨函数 join（DFileRecverInit / DFileSenderInitWithTargetDev）
随解析图变化消失——人工复裁定为**分支互斥误报**（CloseSocket 均在 `CheckFdSetSize != EOK` 错误分支内
且立即 return，后续使用全在未释放路径上），属正确移除而非回归；P8 的分支敏感化与 P6 同型，
列为本文件后续项。新增 lead 的反向逐条裁定（误报率）为后续工作，不在本次宣称。

---

## 回放验证 2026-10-16（第 5 步，状态模型版）——三个诚实结论

**方法**：全树 worktree（sparse-checkout 必须禁用——早轮"修复后归零"结论全部为 sparse 假象，
已作废）在 59cac79b、02471572±、432c8b3e± 五个点位重扫。

**结论 1（第 5 步的边界）**：GT1-GT4 四类 ground truth 全部落在当前模型的命名盲区类
（局部/成员/宏形态、参数透传），**当前模型覆盖范围内不存在干净的单提交修复对**可验证
"修复前命中、修复后消失"——第 6 步（形态扩展）是第 5 步严格验证的前置，如实记录而非
硬造验证。现有证据退而求其次：相邻提交点位结果完全确定（180=180、199=199），判定
不随机漂移；修复使用的守卫宏族（CHECK_AND_RETURN_LOG 条件式）在单测层验证识别正确。

**结论 2（12 个开放候选）**：解析解锁浮出的 12 个代理侧 RegisterObserver
（`ipc/src/bluetooth_*_proxy.cpp`，`data.WriteRemoteObject(observer->AsObject())`
无判空）在 59cac79b→432c8b3e（2024-06→2025-08）全窗口恒在——**432c8b3e 修复只给
inner/src 三文件加检查，未触及代理侧**。这 12 处是上游至今未修的真实开放候选，转
lead 台账跟踪（调用方可达性分析后决定是否走工单）。

**结论 3（工具教训）**：git worktree 继承 sparse-checkout 配置，20-46 秒的"扫描"即
红灯信号；本轮两次结论翻转（12→0、0→12）皆源于此。任何 worktree 回放先
`git sparse-checkout disable` 并核对扫描耗时与文件数。

---

## 严格验证达成 2026-10-16（GT1 建模后）：88b2edee 修复对完整走通

上节结论 1 的前置已补：GT1（局部指针/智能指针）建模落地后，四类 GT 中的 GT1
进入模型覆盖，**第 5 步首次获得并走通了真实单提交修复对**：

| 指标（导师验收表） | 结果 |
|---|---|
| 已标注缺陷命中 | **1/1**：基线（88b2edee^）命中 `SetConnectStrategy/proxy`（`sptr<> proxy = GetRemoteProxy(...)` 无判空直解引用——GT1 真身形态） |
| 修复后同根因残留 | **0**：88b2edee 后该候选消失 |
| 零误伤 | 全树 284→283（精确 -1），其余 11 条 hid_host 发现与全树其余发现逐键不动 |

同批两个新修复（回放暴露）：①**复合析取守卫**此前整体不可见——条件正则不允许
嵌套括号，`if (p == nullptr || other())` 连 if 都匹配不上；已修（允许一层平衡
括号 + 短路语义判定：析取守卫、合取不守卫，各带正反例测试）。②hid_host 的
`GetConnectionStrategy/profile` 等 11 条为修复未覆盖的其余站点，并入开放候选
台账（与代理侧 12 条同类）。

GT2（成员指针）/GT3（宏展开取指针）仍在模型外——它们是下一批严格验证对的前置。
