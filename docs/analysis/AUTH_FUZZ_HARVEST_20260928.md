# auth fuzz 双靶收割报告（2026-09-28）

对应：P0-2 第三靶（DeviceId/`UnpackDeviceIdJson`）、第四靶（DeviceInfo/
`UnpackDeviceInfoMessage`），施工图 `docs/design/auth_fuzz_extraction_plan.md`
与 `docs/design/deviceinfo_fuzz_extraction_plan.md`。工程：
`D:/cve_data/fuzz_authdev/`（WSL 镜像 ~/fa）。

## 1. 终局数据

| 项 | T3（fuzz_authdev） | T4（fuzz_authdeinfo） |
|---|---|---|
| 累计执行 | 约 1.77 亿 | 约 2.71 亿 |
| 终局 cov / ft | 3024 / 14474 | 2676 / 12359 |
| 收获语料 | 21,800 输入 | 16,366 输入 |
| crash / leak / timeout | **0 / 0 / 0** | **0 / 0 / 0** |

时间线：T3 于 09-23 建成（120s 快测 149 万次）→ 12h 长跑被宿主机隔夜休眠中断
（有效 3.3h/1.22 亿次）→ 09-24 白班重启跑满 8h → 后续多轮续跑至平台化；
T4 于 09-24 建成（120s 快测 207 万次）→ 8h 起连续多轮至平台化。覆盖多日增长
趋缓（T3 cov 3010→3024），现 stub 配置下可达面已探满。

**结论：双靶在当前 stub 配置下未发现任何内存安全问题（约 4.5 亿次执行）。**
确认产品漏洞数口径不变（0）。

## 2. 覆盖判读的重要方法学发现：-O1 内联假象

函数级回放（`-runs=0 -print_coverage=1` 全语料）中，`IsSameAccount`、
`GetLocalUdidShortHash`、T3 侧 `ConvertHexStringToBytes` 显示 UNCOVERED
（hits:0）。经 fprintf 插针证伪：外部认证尾段**实际可达且已执行**
（探针输出 `p1=1 p2=1`，即 UDID_SHORT_HASH 与 accountHash 均读通后进入
`IsSameAccount` 调用点）。根因：**-O1 下外部链接的单调用点函数被内联进调用者
执行，其独立符号副本保持 0 命中**——`-print_coverage` 的 per-symbol 计数
把"内联执行"误报为"未覆盖"。

**后续收割规范**：函数级覆盖清单中，凡"定义存在但 hits:0 的外部链接
单调用点函数"，必须先用行为探针（插桩或断言）证伪内联假象，再下
"不可达"结论。静态函数则相反——不出现在清单里即已被内联，属正常。

## 3. 不可达面清单（按设计被 stub 封死，非缺陷）

- `ParseFastAuthValue` / `ParseNormalizedKeyValue` 的 AES-GCM 解密路径
  （密钥源 stub 全部"查无"先行返回）
- `TryGetDmSessionKeyForUnpack` 成功分支（GetSessionKeyProfile stub false）
- 凭证协商接收端状态机三函数（stub false → COMPATIBLE）
- 证书链（IsSupportUDIDAbatementPacked stub false 早退）
- `UnpackWifiSinglePassInfo` 的 DevIpHash 匹配分支（需猜中 FNV-hex，
  对 fuzzer 事实上不可达——语义为"IP 校验通过"，非解析面）

这些均为施工图 §3.C 声明的取舍，属密钥/凭证门控而非消息解析面。

## 4. stage-2 取舍：暂缓，转入 P1.6 案例闭环

stage-2（密钥 stub 换确定性密钥 + 真 AES-GCM，打开解密路径）技术上可行，
但被打开的路径以解密后缓冲操作为主，解析面已由现配置覆盖；按比赛审计
（`docs/analysis/COMPETITION_CODE_AUDIT_20260923.md`）的投入建议
（案例影响闭环 50%），优先级让位于 P1.6 纵向闭环（IPC/KV 两案的
next_gate 即平台级隔离构建验证——离"产品级确认"最近的路径）。
双靶语料（21800+16366）与一键重建（build.sh）保留在 ~/fa，stage-2
随时可续。

## 5. 资产与复现

- 语料与产物：`~/fa/corpus`、`~/fa/corpus_devinfo`（零崩溃故无 artifact）
- 重建：`bash /mnt/d/cve_data/fuzz_authdev/build.sh`（双目标）
- 回放判读：`./fuzz_authdev -runs=0 -print_coverage=1 corpus`
  （注意 §2 内联假象）
- 本报告插针诊断所用临时改动已全部还原（extracted.c md5 与 D: 侧母本一致，
  种子回归 8+8 通过）
