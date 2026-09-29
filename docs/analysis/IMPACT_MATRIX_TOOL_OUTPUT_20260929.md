# 版本分支影响矩阵

生成日期：2026-09-29

| 案例 | CVE | 组件 | 引入版本 | 上游修复 | v5.0-Release | v5.1-Release | v6.0-Release | v7.0-Release | master |
|---|---|---|---|---|---|---|---|---|---|
| cjson_merge_alias | CVE-2026-87933 | cjson | 1.7.19 | pending | 🔴 | 🔴 | 🔴 | 🔴 | 🔴 |
| curl_native_ca_reuse | CVE-2026-80231 | curl | unknown | pending | ？ | ？ | ？ | ？ | ？ |
| curl_psl_supercookie | CVE-2026-82209 | curl | unknown | pending | ？ | ？ | ？ | ？ | ？ |
| ffmpeg_dvbsub_parser_capacity_overflow | CVE-2026-70628 | ffmpeg | unknown | pending | ？ | ？ | ？ | ？ | ？ |
| ffmpeg_floodfill_point_stack_oob | CVE-2026-65705 | ffmpeg | unknown | pending | ？ | ？ | ？ | ？ | ？ |
| ffmpeg_hqdn3d_dynamic_size_oob | CVE-2026-66036 | ffmpeg | unknown | pending | ？ | ？ | ？ | ？ | ？ |
| ffmpeg_lcldec_zlib_tail_disclosure | CVE-2026-66038 | ffmpeg | unknown | pending | ？ | ？ | ？ | ？ | ？ |
| ffmpeg_nvdec_sep_ref_doublefree | CVE-2026-64832 | ffmpeg | unknown | pending | ？ | ？ | ？ | ？ | ？ |
| ffmpeg_quirc_resize_oob | CVE-2026-66041 | ffmpeg | unknown | pending | ？ | ？ | ？ | ？ | ？ |
| ffmpeg_swaprect_temp_row_oob | CVE-2026-65706 | ffmpeg | unknown | pending | ？ | ？ | ？ | ？ | ？ |
| ffmpeg_ty_ac3_trim_underflow | CVE-2026-65704 | ffmpeg | unknown | pending | ？ | ？ | ？ | ？ | ？ |
| ffmpeg_wmaenc_extradata_padding | CVE-2026-52296 | ffmpeg | unknown | pending | ？ | ？ | ？ | ？ | ？ |
| openssl_ocb_oneshot_iv_discard | CVE-2026-45445 | openssl | unknown | pending | ？ | ？ | ？ | ？ | ？ |

> 🔴 affected = 该分支的组件基线含缺陷  
> ✅ fixed = 该分支的组件基线已含修复  
> — not_affected = 该分支的组件基线早于缺陷引入  
> ？ unknown = 无法判定（需补充该分支的基线信息）