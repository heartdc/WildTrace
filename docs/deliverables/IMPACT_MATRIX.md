# 版本分支影响矩阵

生成日期：2026-09-29

| 案例 | CVE | 组件 | v4.1 | v5.0 | v5.1 | v6.0 | v7.0 | master | 影响分支数 |
|---|---|---|---|---|---|---|---|---|---|
| cjson_merge_alias | CVE-2026-87933 | cjson | 🔴 | 🔴 | 🔴 | 🔴 | 🔴 | 🔴 | 6 |
| curl_native_ca_reuse | CVE-2026-80231 | curl | 🔴 | 🔴 | 🔴 | 🔴 | 🔴 | 🔴 | 6 |
| curl_psl_supercookie | CVE-2026-82209 | curl | 🔴 | 🔴 | 🔴 | 🔴 | 🔴 | 🔴 | 6 |
| ffmpeg_dvbsub_parser_capacity_overflow | CVE-2026-70628 | ffmpeg | 🔴 | 🔴 | 🔴 | 🔴 | 🔴 | 🔴 | 6 |
| ffmpeg_floodfill_point_stack_oob | CVE-2026-65705 | ffmpeg | 🔴 | 🔴 | 🔴 | 🔴 | 🔴 | 🔴 | 6 |
| ffmpeg_hqdn3d_dynamic_size_oob | CVE-2026-66036 | ffmpeg | 🔴 | 🔴 | 🔴 | 🔴 | 🔴 | 🔴 | 6 |
| ffmpeg_lcldec_zlib_tail_disclosure | CVE-2026-66038 | ffmpeg | 🔴 | 🔴 | 🔴 | 🔴 | 🔴 | 🔴 | 6 |
| ffmpeg_nvdec_sep_ref_doublefree | CVE-2026-64832 | ffmpeg | 🔴 | 🔴 | 🔴 | 🔴 | 🔴 | 🔴 | 6 |
| ffmpeg_quirc_resize_oob | CVE-2026-66041 | ffmpeg | 🔴 | 🔴 | 🔴 | 🔴 | 🔴 | 🔴 | 6 |
| ffmpeg_swaprect_temp_row_oob | CVE-2026-65706 | ffmpeg | 🔴 | 🔴 | 🔴 | 🔴 | 🔴 | 🔴 | 6 |
| ffmpeg_ty_ac3_trim_underflow | CVE-2026-65704 | ffmpeg | 🔴 | 🔴 | 🔴 | 🔴 | 🔴 | 🔴 | 6 |
| ffmpeg_wmaenc_extradata_padding | CVE-2026-52296 | ffmpeg | 🔴 | 🔴 | 🔴 | 🔴 | 🔴 | 🔴 | 6 |
| openssl_ocb_oneshot_iv_discard | CVE-2026-45445 | openssl | 🔴 | 🔴 | 🔴 | 🔴 | 🔴 | 🔴 | 6 |

**总计**：13 案 × 6 分支；🔴 affected 78 格。

> 🔴 = 该分支的组件基线含缺陷代码（上游修复晚于基线，未回移）
> ？ = 该分支基线信息待补充（OH 原生代码在旧分支的引入时间未确认）

## 版本基线数据

| 分支 | ffmpeg | curl | openssl |
|---|---|---|---|
| v4.1 | n4.1 | 8.1.1 | 3.0.9 |
| v5.0 | n5.1.6 | 8.6.0 | 3.0.9 |
| v5.1 | n5.1.6 | 8.6.0 | 3.0.9 |
| v6.0 | n6.1.1 | 8.11.0 | 3.0.12 |
| v7.0 | n7.1.1 | 8.13.0 | 3.0.9 |
| master | n7.1.1 | 8.13.0 | 3.0.9 |

## 影响范围判定依据

1. **ffmpeg 缺口案**：缺陷代码在 n5.x 即存在（上游 CVE 受影响范围含旧版本），
   OH 各分支的 ffmpeg 基线均在受影响范围内；上游修复均晚于 n7.1.1 tag（2025-02）。
2. **curl 两案**：缺陷在 curl 8.x 系列存在；OH 的 curl 基线 8.1.1→8.13.0 均受影响。
3. **openssl OCB**：缺陷在 OpenSSL 3.0.x 存在；OH 基线 3.0.9 受影响。
4. **cJSON**：缺陷在 cJSON 1.7.x 全版本存在。
5. **OH 原生（IPC/CJ FFI 系列）**：v7.0/master 确认存在；旧分支需确认 CJ FFI 引入时间。