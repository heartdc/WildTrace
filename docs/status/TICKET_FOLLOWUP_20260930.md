# 平台工单跟进包（2026-09-30）

> 用途：对照 bugbounty.openharmony.cn 逐单操作。数据源：`docs/status/CASE_LEDGER_20260924.md`
> （单号权威源）+ 各 `cases/*/case.json` + `D:/cve_data/submission_*/` 实测盘点（2026-09-30）。
> 口径：16 张工单全部"待受理"为交接记录口径，**第一步先上平台逐单核对实际状态**。

## 0. 第一步：状态核对（先做，10 分钟）

1. 登录 bugbounty.openharmony.cn 逐单查看 16 张工单的当前状态（受理/需补材料/驳回）；
2. 核对哪些单已有 PoC 评论（交接记录称 8 案已补，仓库内无平台侧留痕，以平台为准，避免重复贴）；
3. 09-21 提交的三张（092209031 / 092226014 / 092224773）已超一周无动静——若平台无进度，
   用赛题咨询邮箱 lixiang531@huawei.com 或答疑社区询问受理周期（要点见 §5）。

## 1. 工单总览（16 张）

| 工单号 | 案例 | CVE | 提交日 | 证据等级 | PoC 在手 | patch | 运行验证记录 | 建议动作 |
|---|---|---|---|---|---|---|---|---|
| OHSA26-092209031 | curl_native_ca_reuse | 2026-80231 | 09-21 | 源级 L4 | **无**（D 盘目录为空） | ✓ | — | **优先补材料**（§4） |
| OHSA26-092226014 | curl_psl_supercookie | 2026-82209 | 09-21 | 源级 L4 | ✓（库+D 盘齐） | ✓ | — | 贴 PoC+对照 |
| OHSA26-092224773 | ffmpeg_nvdec_doublefree | 2026-64832 | 09-21 | 源级 L4 | 无 | ✓ | — | 贴修复对照 |
| OHSA26-092224881 | ffmpeg_quirc_resize_oob | 2026-66041 | 09-21* | **运行时 2×3 矩阵** | ✓ | ✓ | **✓ 运行验证记录.md** | 贴运行记录+PoC |
| OHSA26-092848127 | ffmpeg_hqdn3d | 2026-66036 | 09-28 | **运行时 verified** | ✓ | ✓ | **✓ 运行验证记录.md** | 贴运行记录+PoC |
| OHSA26-092831132 | ffmpeg_lcldec | 2026-66038 | 09-28 | 源级 L4 | ✓（库内） | ✓ | — | 贴 PoC+对照 |
| OHSA26-092858135 | ffmpeg_dvbsub | 2026-70628 | 09-28 | 源级 L4 | ✓（库内） | ✓ | — | 贴 PoC+对照 |
| OHSA26-092855121 | ffmpeg_ty_ac3 | 2026-65704 | 09-28 | 源级 L4 | ✓（库内） | ✓ | — | 贴 PoC+对照 |
| OHSA26-092819230 | ffmpeg_wmaenc | 2026-52296 | 09-28 | 源级 L4 | ✓（库内） | ✓ | — | 贴 PoC+对照；名称补正评论已在 |
| OHSA26-092800126 | ffmpeg_floodfill | 2026-65705 | 09-28 | 源级 L4（触发尝试未成） | ✓ | ✓ | — | 贴 PoC；**如实注明 attempted_not_triggered** |
| OHSA26-092853125 | ffmpeg_swaprect | 2026-65706 | 09-28 | 源级 L4 | ✓（库内） | ✓ | — | 贴 PoC+对照 |
| OHSA26-092837123 | openssl_ocb | 2026-45445 | 09-28 | **运行时 verified** | ✓ | ✓ | **✓ 运行验证记录.md** | 贴运行记录+PoC；分类评论已在 |
| OHSA26-092835171 | ffmpeg_iamf | 2026-66037 | 09-28 | 源级 L4 | 无 | ✓ | — | 贴修复对照；**注意 DoS 口径**（§4.3） |
| OHSA26-092850129 | ffmpeg_rscc | 2026-70629 | 09-28 | 源级 L4 | 无 | ✓×2 | — | 贴修复对照 |
| OHSA26-092843135 | ffmpeg_cfhd | 2026-70632 | 09-28 | 源级 L4 | 无 | ✓×2 | — | 贴修复对照 |
| OHSA26-092953990 | ipc_cj_array_null | —（新发现） | 09-29 | **真库级证实** | 等价复现+执行件 | — | REAL_BUILD_PROBE 口径 | 等评审；可补口径说明（§4.4） |

\* quirc 单由另一工作集提交（提交前已核对无重复）；本方以评论补材料形式参与。

## 2. 最高价值动作：三张有运行验证记录的单（先贴这三张）

评审最认运行时证据。三张单的 `运行验证记录.md` 已在本地，直接贴工单评论：

- **OHSA26-092224881（quirc）**：`D:/cve_data/submission_66041/运行验证记录.md`——
  原版构建 heap-buffer-overflow WRITE（ASan，vf_quirc.c:102，exit 1）× 触发/对照 2×3 矩阵，
  打补丁后 CASE_DONE exit 0。附 `poc_quirc.c`。
- **OHSA26-092848127（hqdn3d）**：`D:/cve_data/submission_66036/运行验证记录.md` + `poc_hqdn3d.c`。
- **OHSA26-092837123（openssl OCB）**：`D:/cve_data/submission_45445/运行验证记录.md` + `poc_ocb_iv.c`。

## 3. 第二梯队：有 PoC 的单（7 张）

贴法统一为：PoC 源码全文 + 一行编译/运行说明 + `上游修复对照.txt` 摘要（修在哪、我们基线为何含缺陷）。
PoC 来源：`cases/<案名>/poc.c`（库内，11 案在库）；curl_psl 另有 D 盘完整包
（`submission_82209/`：poc.c + poc_ctl/poc_current/poc_orig_final 三组产物 + 验证 json）。

- floodfill（092800126）**必须如实注明**：PoC 为源码级对照，运行时触发尝试未成功
  （`attempted_not_triggered`）——按"失败记录不删不改"纪律写明，反而可信。
- wmaenc（092819230）名称字段表单异常的补正评论已附，无需重复。

## 4. 材料缺口与口径注意

**4.1 OHSA26-092209031（curl CA 复用）——最大缺口**：`D:/cve_data/submission_80231/` 目录为空，
库内也无 poc.c。补救：从 `cases/curl_native_ca_reuse/case.json` 的 `oh_source.gap_evidence`
（native_ca_store 在 setopt.c/urldata.h 的位置与合法读点清单）+ 上游修复 commit 组织评论材料；
是否补写 PoC 视该单评审反馈决定（curl 自定义 CA 复用的可执行 PoC 需 TLS 中间人环境，成本高）。

**4.2 四张无 PoC 的 ffmpeg 单**（iamf/rscc/cfhd/nvdec）：源级定位 + 上游修复对照是完整口径，
按"贴对照"处理；若要补 PoC，rscc/cfhd/nvdec 三个是内存类（可走 LLM PoC 生成器 + WSL 验证流程）。

**4.3 iamf（092835171）DoS 口径**：赛题明确"普通 DoS 不建议纳入"。该案是已公开 CVE 的缺口回验
（有 CVE 编号），风险低，但评论措辞聚焦"计数整数缺陷导致解析 DoS，上游按安全修复"而非渲染危害。

**4.4 IPC 新发现（092953990）**：等评审期间可补一条口径评论：真库级证实（SIGSEGV 崩溃帧归属
libcj_ipc_ffi.z.so）+ 隔离构建三红线声明（自定义配置非官方产品构建，如实）——
与 `docs/analysis/REAL_BUILD_PROBE_20260925.md` 一致，不升级口径。

## 5. 催办要点（如需要）

- 邮箱/社区询问模板要点：参赛队身份 + 赛题名 + 工单号列表 + 提交日期 + 询问受理周期/是否需补材料；
- 附上最有力的三张（§2）作为材料质量示例；
- 不催单张，按批次（09-21 批 / 09-28 批）询问。

## 6. 盘点口径说明

- PoC 在手 = `cases/*/poc.c`（库）或 `D:/cve_data/submission_*/poc*.c`（D 盘）任一存在；
- "运行验证记录" = D 盘目录内 `运行验证记录.md` 实测存在（2026-09-30 盘点）；
- `submission_49795/` 为残包（仅上游 patch），不在队列，忽略；
- 本表不改变任何 case.json 字段；平台侧操作后如有状态变化，回填 `submission.status` 并同步台账。
