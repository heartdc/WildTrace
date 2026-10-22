# 版本分支影响矩阵

生成日期：2026-10-22（工具 `ohvul.impact_matrix` 从 cases/ 自动生成）

| 案例 | CVE | 组件 | 引入版本 | 上游修复 | v4.1 | v5.0 | v5.1 | v6.0 | v7.0 | master | 证实分支数 | 检出 | 钉版 | 符号 | 待定格数 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| cjson_merge_alias | CVE-2026-87933 | cjson | 1.7.0 | pending | 🔴 | 🔴 | 🔴 | 🔴 | 🔴 | 🔴 | 6 | 1 | 5 | 0 | 0 |
| curl_native_ca_reuse | CVE-2026-80231 | curl | 7.71.0 | 8.22.0 | 🔴 | 🔴 | 🔴 | 🔴 | 🔴 | 🔴 | 6 | 1 | 5 | 0 | 0 |
| curl_psl_supercookie | CVE-2026-82209 | curl | 7.46.0 | 8.22.0 | 🔴 | 🔴 | 🔴 | 🔴 | 🔴 | 🔴 | 6 | 1 | 5 | 0 | 0 |
| ffmpeg_cfhd_transform2_width_oob | CVE-2026-70632 | ffmpeg | 4.4 | 9.0 | 🔴 | 🔴 | 🔴 | 🔴 | 🔴 | 🔴 | 6 | 1 | 5 | 0 | 0 |
| ffmpeg_dvbsub_parser_capacity_overflow | CVE-2026-70628 | ffmpeg | 0.5 | 9.0 | 🔴 | 🔴 | 🔴 | 🔴 | 🔴 | 🔴 | 6 | 1 | 5 | 0 | 0 |
| ffmpeg_floodfill_point_stack_oob | CVE-2026-65705 | ffmpeg | 3.4 | pending | 🔴 | 🔴 | 🔴 | 🔴 | 🔴 | 🔴 | 6 | 1 | 5 | 0 | 0 |
| ffmpeg_hqdn3d_dynamic_size_oob | CVE-2026-66036 | ffmpeg | 0 | pending | 🔴 | 🔴 | 🔴 | 🔴 | 🔴 | 🔴 | 6 | 1 | 5 | 0 | 0 |
| ffmpeg_iamf_count_label_dos | CVE-2026-66037 | ffmpeg | 0 | pending | — | — | — | — | 🔴 | 🔴 | 2 | 1 | 1 | 0 | 0 |
| ffmpeg_lcldec_zlib_tail_disclosure | CVE-2026-66038 | ffmpeg | 0 | pending | 🔴 | 🔴 | 🔴 | 🔴 | 🔴 | 🔴 | 6 | 1 | 5 | 0 | 0 |
| ffmpeg_nvdec_sep_ref_doublefree | CVE-2026-64832 | ffmpeg | 4.4 | pending | 🔴 | 🔴 | 🔴 | 🔴 | 🔴 | 🔴 | 6 | 1 | 5 | 0 | 0 |
| ffmpeg_quirc_resize_oob | CVE-2026-66041 | ffmpeg | 7.0 | pending | — | — | — | — | 🔴 | 🔴 | 2 | 1 | 1 | 0 | 0 |
| ffmpeg_rscc_short_deflate_uninit_leak | CVE-2026-70629 | ffmpeg | 3.0 | 9.0 | 🔴 | 🔴 | 🔴 | 🔴 | 🔴 | 🔴 | 6 | 1 | 5 | 0 | 0 |
| ffmpeg_swaprect_temp_row_oob | CVE-2026-65706 | ffmpeg | 3.0 | pending | 🔴 | 🔴 | 🔴 | 🔴 | 🔴 | 🔴 | 6 | 1 | 5 | 0 | 0 |
| ffmpeg_ty_ac3_trim_underflow | CVE-2026-65704 | ffmpeg | 0 | pending | 🔴 | 🔴 | 🔴 | 🔴 | 🔴 | 🔴 | 6 | 1 | 5 | 0 | 0 |
| ffmpeg_wmaenc_extradata_padding | CVE-2026-52296 | ffmpeg | 0 | 9.0 | 🔴 | 🔴 | 🔴 | 🔴 | 🔴 | 🔴 | 6 | 1 | 5 | 0 | 0 |
| hiappevent_ffi_watcher_null_filter | — | oh_native | unknown | pending | — | 🔴 | 🔴 | 🔴 | 🔴 | 🔴 | 5 | 1 | 0 | 4 | 0 |
| ipc_cj_array_null_validation | — | oh_native | unknown | pending | — | — | 🔴 | 🔴 | 🔴 | 🔴 | 4 | 1 | 0 | 3 | 0 |
| kv_ffi_array_validation | — | oh_native | unknown | pending | — | 🔴 | 🔴 | 🔴 | 🔴 | 🔴 | 5 | 1 | 0 | 4 | 0 |
| openssl_ocb_oneshot_iv_discard | CVE-2026-45445 | openssl | 3.0.0 | 4.0.1 | 🔴 | 🔴 | 🔴 | 🔴 | 🔴 | 🔴 | 6 | 1 | 5 | 0 | 0 |
| udmf_ffi_setproperties_null_tag | — | oh_native | unknown | pending | — | — | — | 🔴 | 🔴 | 🔴 | 3 | 1 | 0 | 2 | 0 |

**总计**：20 案 × 6 分支；🔴 证实 affected 105 格（检出级 20 / 钉版联接 72 / 符号探测 13）；— 证实不受影响 15 格；？待定 0 格。本表只声明有证据的格子，？不是安全结论。

> 🔴 affected = 本案例记录了具体分支提交及验证证据；上游版本推测不计为分支实证。  
> 上面三列是 🔴 的证据强度：**检出级**＝该案的验证基线检出（是否跑过见报告第 3 节）；**钉版联接**＝manifest 钉住→README 版本→kb 区间；**符号探测**＝漏洞函数在该分支基线在位。三者不可互换，故分列计数。  
> （证据分层，2026-10-18 外部复审 F08：🔴 中 2026-10-17 新增格分两类——**钉版联接**（manifest 钉版→README 版本→kb 区间）与**符号探测**（漏洞函数在位性），弱于检出/复现级实证；分支引用名→SHA 固化列为后续项，见 docs/analysis/EXTERNAL_REVIEW_RESPONSE_20261018.md）  
> ✅ fixed = 分支基线已含上游修复  
> — not_affected = 分支基线早于缺陷引入版本  
> ？ unknown = 现有材料不足以给出该分支的判定——既非安全结论，也非扫描失败

## 上游版本预测（风险线索，非分支实证）

| 案例 | v4.1 | v5.0 | v5.1 | v6.0 | v7.0 | master |
|---|---|---|---|---|---|---|
| cjson_merge_alias | 🔴 | 🔴 | 🔴 | 🔴 | 🔴 | 🔴 |
| curl_native_ca_reuse | 🔴 | 🔴 | 🔴 | 🔴 | 🔴 | 🔴 |
| curl_psl_supercookie | 🔴 | 🔴 | 🔴 | 🔴 | 🔴 | 🔴 |
| ffmpeg_cfhd_transform2_width_oob | 🔴 | 🔴 | 🔴 | 🔴 | 🔴 | 🔴 |
| ffmpeg_dvbsub_parser_capacity_overflow | 🔴 | 🔴 | 🔴 | 🔴 | 🔴 | 🔴 |
| ffmpeg_floodfill_point_stack_oob | 🔴 | 🔴 | 🔴 | 🔴 | 🔴 | 🔴 |
| ffmpeg_hqdn3d_dynamic_size_oob | 🔴 | 🔴 | 🔴 | 🔴 | 🔴 | 🔴 |
| ffmpeg_iamf_count_label_dos | 🔴 | 🔴 | 🔴 | 🔴 | 🔴 | 🔴 |
| ffmpeg_lcldec_zlib_tail_disclosure | 🔴 | 🔴 | 🔴 | 🔴 | 🔴 | 🔴 |
| ffmpeg_nvdec_sep_ref_doublefree | 🔴 | 🔴 | 🔴 | 🔴 | 🔴 | 🔴 |
| ffmpeg_quirc_resize_oob | — | — | — | — | 🔴 | 🔴 |
| ffmpeg_rscc_short_deflate_uninit_leak | 🔴 | 🔴 | 🔴 | 🔴 | 🔴 | 🔴 |
| ffmpeg_swaprect_temp_row_oob | 🔴 | 🔴 | 🔴 | 🔴 | 🔴 | 🔴 |
| ffmpeg_ty_ac3_trim_underflow | 🔴 | 🔴 | 🔴 | 🔴 | 🔴 | 🔴 |
| ffmpeg_wmaenc_extradata_padding | 🔴 | 🔴 | 🔴 | 🔴 | 🔴 | 🔴 |
| hiappevent_ffi_watcher_null_filter | ？ | ？ | ？ | ？ | ？ | ？ |
| ipc_cj_array_null_validation | ？ | ？ | ？ | ？ | ？ | ？ |
| kv_ffi_array_validation | ？ | ？ | ？ | ？ | ？ | ？ |
| openssl_ocb_oneshot_iv_discard | 🔴 | 🔴 | 🔴 | 🔴 | 🔴 | 🔴 |
| udmf_ffi_setproperties_null_tag | ？ | ？ | ？ | ？ | ？ | ？ |

> 本节按上游受影响范围与各分支基线比对得到**预测**，回答"上游版本视角该基线是否在风险范围内"；它不证明对应 OH 分支包含缺陷代码、也不证明已回移修复。分支级结论以上方主表（严格口径）为准，两区信息分别保留、互不覆盖。

## 判定依据

1. **kb 联接（首选）**：按 CVE 联接 `kb/third_party_targets/records.json`（源 cvelistV5）的上游受影响/修复版本，按 cvelist 边界语义（起点 ≤ 基线 < 修复点；无修复记录则上界开放）逐分支判定。
2. **结构化受影响范围**：case.json 的 `affected_raw`（CVE 5.0 语义）与分支基线做范围比较。
3. **上游推测**：版本范围与版本等价仅保存在 upstream_predictions，不能证明 OH 分支是否回移补丁或包含相关构建。
4. **分支实证**：原生代码与第三方组件统一要求 branch_evidence 中的 source_commit、reference、verdict；缺失时为 unknown。
5. **不跨组件借用基线**：某分支缺该组件基线时判 ？，绝不用其他组件的版本号代替（2026-09-29 审计 P0：旧实现以 ffmpeg 基线兜底，造成 curl/openssl/cjson 全红假象）。
6. ？格升级路径：补 case.json 的具体分支证据后重新生成；补上游版本信息不会自动提升为分支实证。

## 版本基线数据

| 分支 | ffmpeg | curl | openssl | cjson |
|---|---|---|---|---|
| v4.1 (2023-04) | 4.4.1 | 8.4.0 | 3.0.9 | 1.7.16 |
| v5.0 (2024-10) | 5.1.4 | 8.6.0 | 3.0.9 | 1.7.17 |
| v5.1 (2025-04) | 5.1.4 | 8.8.0 | 3.0.9 | 1.7.17 |
| v6.0 (2025-10) | 5.1.4 | 8.8.0 | 3.0.9 | 1.7.17 |
| v7.0 (2026-08) | 7.1.1 | 8.8.0 | 3.0.9 | 1.7.19 |
| master (2026-09) | 7.1.1 | 8.8.0 | 3.0.9 | 1.7.19 |

> cJSON 基线 2026-10-07 实测回填（各分支 README.OpenSource）：该仓 release 分支无 v 前缀，v7.0 仅存在于 gitcode 镜像（388cfc96=1.7.19）；gitee master 为停更镜像（1.7.17，2025-09），现行开发 master 在 gitcode（1.7.19，与本案 observed_version 一致）。
> 旧手写矩阵（13×6 全红/60 红）已归档至 `docs/analysis/IMPACT_MATRIX_HANDAUTHORED_20260929.md`，其全红口径未经分支级验证，以本工具输出为准。