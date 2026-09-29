# 版本分支影响矩阵

生成日期：2026-09-29

数据源：各案 case.json + README.OpenSource 基线版本 + 上游修复时间线。

| 案例 | CVE | 组件 | v4.1 | v5.0 | v5.1 | v6.0 | v7.0 | master | 影响分支数 |
|---|---|---|---|---|---|---|---|---|---|
| cjson_merge_alias | CVE-2026-87933 | cjson | 🔴 | 🔴 | 🔴 | 🔴 | 🔴 | 🔴 | 6 |
| curl_native_ca_reuse | CVE-2026-80231 | curl | ？ | ？ | ？ | ？ | ？ | ？ | 0 |
| curl_psl_supercookie | CVE-2026-82209 | curl | ？ | ？ | ？ | ？ | ？ | ？ | 0 |
| ffmpeg_dvbsub_parser_capacity_overflow | CVE-2026-70628 | ffmpeg | 🔴 | 🔴 | 🔴 | 🔴 | 🔴 | 🔴 | 6 |
| ffmpeg_floodfill_point_stack_oob | CVE-2026-65705 | ffmpeg | 🔴 | 🔴 | 🔴 | 🔴 | 🔴 | 🔴 | 6 |
| ffmpeg_hqdn3d_dynamic_size_oob | CVE-2026-66036 | ffmpeg | 🔴 | 🔴 | 🔴 | 🔴 | 🔴 | 🔴 | 6 |
| ffmpeg_lcldec_zlib_tail_disclosure | CVE-2026-66038 | ffmpeg | 🔴 | 🔴 | 🔴 | 🔴 | 🔴 | 🔴 | 6 |
| ffmpeg_nvdec_sep_ref_doublefree | CVE-2026-64832 | ffmpeg | 🔴 | 🔴 | 🔴 | 🔴 | 🔴 | 🔴 | 6 |
| ffmpeg_quirc_resize_oob | CVE-2026-66041 | ffmpeg | 🔴 | 🔴 | 🔴 | 🔴 | 🔴 | 🔴 | 6 |
| ffmpeg_swaprect_temp_row_oob | CVE-2026-65706 | ffmpeg | 🔴 | 🔴 | 🔴 | 🔴 | 🔴 | 🔴 | 6 |
| ffmpeg_ty_ac3_trim_underflow | CVE-2026-65704 | ffmpeg | 🔴 | 🔴 | 🔴 | 🔴 | 🔴 | 🔴 | 6 |
| ffmpeg_wmaenc_extradata_padding | CVE-2026-52296 | ffmpeg | 🔴 | 🔴 | 🔴 | 🔴 | 🔴 | 🔴 | 6 |
| openssl_ocb_oneshot_iv_discard | CVE-2026-45445 | openssl | ？ | ？ | ？ | ？ | ？ | ？ | 0 |

**总计**：13 案 × 6 分支 = 78 格；🔴 affected 60 格。

> 🔴 affected = 该分支的组件基线含缺陷代码
> ✅ fixed = 该分支的组件基线已含上游修复
> — not_affected = 该分支的组件基线早于缺陷引入
> ？ unknown = 该分支的基线信息缺失，需补充

## 补充说明

全部 ffmpeg 缺口案的缺陷代码在 n5.x 即存在（上游 CVE 受影响范围含旧版本），
OH 各分支的 ffmpeg 基线（n4.1→n7.1.1）均在受影响范围内；上游修复均晚于
n7.1.1 tag（2025-02），故 OH 无任何分支含修复。

curl 两案的缺陷在 curl 8.x 系列存在；OH 的 curl 基线 8.1.1→8.13.0 均在
受影响范围内，修复未回移。

OH 原生案（IPC/KV/CJ FFI 系列）在 v7.0 和 master 确认存在；旧分支需检查
对应代码的引入时间（部分 CJ FFI 绑定可能在 v6.0 后才加入）。