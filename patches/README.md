# 修复补丁索引

《漏洞分析报告》（docs/deliverables/VULN_REPORT.md）第 5 节的补丁附件。19 个案例各一份，
内容与该报告内联的 `diff` 一致；`curl_native_ca_reuse` 只给修复方向（该缺陷的改动涉及
连接缓存结构，未做成单文件补丁）。

| 案例 | 目标文件 | 执行目录 | 来源 | hunk 数 |
|---|---|---|---|---|
| `cjson_merge_alias` | `cJSON_Utils.c` | third_party/cJSON | 自报告第 5 节提取 | 1 |
| `curl_psl_supercookie` | `lib/cookie.c` | third_party/curl | 自报告第 5 节提取 | 1 |
| `ffmpeg_cfhd_transform2_width_oob` | `libavcodec/cfhd.c` | third_party/ffmpeg | 自报告第 5 节提取 | 4 |
| `ffmpeg_dvbsub_parser_capacity_overflow` | `libavcodec/dvbsub_parser.c` | third_party/ffmpeg | 自报告第 5 节提取 | 1 |
| `ffmpeg_floodfill_point_stack_oob` | `libavfilter/vf_floodfill.c` | third_party/ffmpeg | 自报告第 5 节提取 | 3 |
| `ffmpeg_hqdn3d_dynamic_size_oob` | `libavfilter/vf_hqdn3d.c` | third_party/ffmpeg | 自报告第 5 节提取 | 1 |
| `ffmpeg_iamf_count_label_dos` | `libavformat/iamf_parse.c` | third_party/ffmpeg | 自报告第 5 节提取 | 1 |
| `ffmpeg_lcldec_zlib_tail_disclosure` | `libavcodec/lcldec.c` | third_party/ffmpeg | 自报告第 5 节提取 | 2 |
| `ffmpeg_nvdec_sep_ref_doublefree` | `libavcodec/nvdec.c` | third_party/ffmpeg | 自报告第 5 节提取 | 2 |
| `ffmpeg_quirc_resize_oob` | `libavfilter/vf_quirc.c` | third_party/ffmpeg | 自报告第 5 节提取 | 3 |
| `ffmpeg_rscc_short_deflate_uninit_leak` | `libavcodec/rscc.c` | third_party/ffmpeg | 自报告第 5 节提取 | 2 |
| `ffmpeg_swaprect_temp_row_oob` | `libavfilter/vf_swaprect.c` | third_party/ffmpeg | 自报告第 5 节提取 | 2 |
| `ffmpeg_ty_ac3_trim_underflow` | `libavformat/ty.c` | third_party/ffmpeg | 自报告第 5 节提取 | 1 |
| `ffmpeg_wmaenc_extradata_padding` | `libavcodec/wmaenc.c` | third_party/ffmpeg | 自报告第 5 节提取 | 1 |
| `hiappevent_ffi_watcher_null_filter` | `base/hiviewdfx/hiappevent/frameworks/cj/ffi/src/hiappevent_ffi.cpp` | （OpenHarmony 源码根） | 对照检出源码生成 | 1 |
| `ipc_cj_array_null_validation` | `foundation/communication/ipc/interfaces/innerkits/cj/src/message_sequence_impl.cpp` | （OpenHarmony 源码根） | 对照检出源码生成 | 1 |
| `kv_ffi_array_validation` | `foundation/distributeddatamgr/kv_store/frameworks/cj/src/distributed_kv_store_impl.cpp` | （OpenHarmony 源码根） | 对照检出源码生成 | 1 |
| `openssl_ocb_oneshot_iv_discard` | `providers/implementations/ciphers/cipher_aes_ocb.c` | third_party/openssl | 自报告第 5 节提取 | 1 |
| `udmf_ffi_setproperties_null_tag` | `foundation/distributeddatamgr/udmf/interfaces/cj/src/unified_data_ffi.cpp` | （OpenHarmony 源码根） | 对照检出源码生成 | 1 |

## 应用方式

```bash
# 在补齐 a/ b/ 前缀对应的目录下执行（见上表「执行目录」）
patch -p1 --dry-run < patches/<case>.patch   # 先干跑
patch -p1 < patches/<case>.patch
```

## 验证状态

- `ipc_cj_array_null_validation`、`udmf_ffi_setproperties_null_tag`、
  `hiappevent_ffi_watcher_null_filter`、`kv_ffi_array_validation` 四份：已用检出源码
  `patch -p1 --dry-run` 验证可应用（2026-10-22），**未做编译验证**。
- 其余 15 份：从报告第 5 节原样提取，未在本机对照源码复验（本机没有 ffmpeg /
  openssl / curl 的检出树）。上游修复的语义与提交号见各案第 5 节。
