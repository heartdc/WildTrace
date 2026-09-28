# 提交队列单（2026-09-28，交所有者账号"北辰522"逐例执行）

> **执行结果（2026-09-28 14:35-14:49，经平台 web 表单逐例提交）：12 例全部完成提交。**
> 工单号已回填各 case.json；平台现有 15 条工单全部"待受理"。
> 特例备注：52296 名称字段表单异常已评论补正；45445 分类说明评论已附；66041（quirc）
> 早前已由另一工作集提交（OHSA26-092224881），本队列提交前核对无重复。

平台：https://bugbounty.openharmony.cn （操作流程同已提交 3 案）
每例动作：打开对应 `奖励计划表单v1_*.md` → 按表单填写 → 附 `附件包_*.zip` → 提交 →
**把工单号回填该案 case.json 的 submission 字段**（参照 curl_psl 格式）。

## 待提交 12 例（材料全部齐装：表单 + 补丁 + 上游对照/运行记录 + 附件 zip）

| # | CVE | 案例（cases/） | CWE | 材料目录 | 备注 |
|---|---|---|---|---|---|
| 1 | CVE-2026-52296 | ffmpeg_wmaenc_extradata_padding | CWE-125 | `D:/cve_data/submission_52296/` | 源级 L4 |
| 2 | CVE-2026-66036 | ffmpeg_hqdn3d_dynamic_size_oob | CWE-122 | `D:/cve_data/submission_66036/` | 含 poc + 运行验证记录 |
| 3 | CVE-2026-66037 | ffmpeg_iamf_count_label_dos | CWE-400 | `D:/cve_data/submission_66037/` | gap-batch-2 |
| 4 | CVE-2026-66038 | ffmpeg_lcldec_zlib_tail_disclosure | CWE-908 | `D:/cve_data/submission_66038/` | 人工 L4 已核（09-22） |
| 5 | CVE-2026-65704 | ffmpeg_ty_ac3_trim_underflow | CWE-191→787 | `D:/cve_data/submission_65704/` | |
| 6 | CVE-2026-65705 | ffmpeg_floodfill_point_stack_oob | CWE-787 | `D:/cve_data/submission_65705/` | 含 poc；参考提交勘误已记 |
| 7 | CVE-2026-65706 | ffmpeg_swaprect_temp_row_oob | CWE-787 | `D:/cve_data/submission_65706/` | |
| 8 | CVE-2026-70628 | ffmpeg_dvbsub_parser_capacity_overflow | CWE-190→787 | `D:/cve_data/submission_70628/` | 人工 L4 已核（09-22，含勘误） |
| 9 | CVE-2026-70629 | ffmpeg_rscc_short_deflate_uninit_leak | CWE-908 | `D:/cve_data/submission_70629/` | gap-batch-2 |
| 10 | CVE-2026-70632 | ffmpeg_cfhd_transform2_width_oob | CWE-787 | `D:/cve_data/submission_70632/` | gap-batch-2 |
| 11 | CVE-2026-45445 | openssl_ocb_oneshot_iv_discard | CWE-325 | `D:/cve_data/submission_45445/` | 含 poc + 运行验证记录 |
| 12 | CVE-2026-66041 | ffmpeg_quirc_resize_oob | CWE-787 | `D:/cve_data/submission_66041/` | 含 poc + 运行验证记录；⚠ case.json 缺 submission_materials 字段（本 PR 顺手回填）；另审计机曾有嵌套提交记录，提交前先确认平台无重复工单 |

## 已提交 3 例（跟审核状态，回执更新 case.json）

| 工单 | CVE | 提交日 |
|---|---|---|
| OHSA26-092209031 | CVE-2026-80231（curl native CA） | 09-21 |
| OHSA26-092226014 | CVE-2026-82209（curl PSL） | 09-21 |
| OHSA26-092224773 | CVE-2026-64832（ffmpeg nvdec） | 09-21 |

## 不提交项（口径）

- cjson（CVE-2026-87933）：公开 CVE 回验/演示用途，不计新发现，无提交动作
- `D:/cve_data/submission_49795/`：残包（仅上游补丁一文件，无表单/对照），非成案，不提交
- IPC/KV 两案：等价复现层级，平台二进制未链接——按 next_gate 完成隔离构建验证前不提交

## 台账同步说明

案例台账（CASE_LEDGER_20260924.md）按本队列更新至 18 例：并入 #51 的
gap-batch-2 三案（66037/70629/70632，均源级 L4、not_run）；quirc 补记
submission_materials；49795 残包登记为未成案。
