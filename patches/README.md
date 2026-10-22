# 修复补丁索引

补丁原件本来就在各案目录：`cases/<case>/patch.diff`（19 案各有 1 份）。
本目录是它的**镜像 + 索引**，只为评审方便：内容与原件逐字节一致（仅行尾统一为 LF），
`ffmpeg_quirc_resize_oob` 原件缺失，这里是唯一副本。

| 案例 | 原件 | 目标文件 | 执行目录 | hunk | 备注 |
|---|---|---|---|---|---|
| `cjson_merge_alias` | `cases/cjson_merge_alias/patch.diff` | `cJSON_Utils.c` | third_party/cJSON | 1 |  |
| `curl_native_ca_reuse` | `cases/curl_native_ca_reuse/patch.diff` | `third_party/curl/lib/vtls/vtls.c` | （OpenHarmony 源码根） | 1 | 批量比对成员不在 ssl_primary_config，编译不过（见报告第 5 节） |
| `curl_psl_supercookie` | `cases/curl_psl_supercookie/patch.diff` | `lib/cookie.c` | third_party/curl | 1 |  |
| `ffmpeg_cfhd_transform2_width_oob` | `cases/ffmpeg_cfhd_transform2_width_oob/patch.diff` | `libavcodec/cfhd.c` | third_party/ffmpeg | 4 |  |
| `ffmpeg_dvbsub_parser_capacity_overflow` | `cases/ffmpeg_dvbsub_parser_capacity_overflow/patch.diff` | `libavcodec/dvbsub_parser.c` | third_party/ffmpeg | 1 |  |
| `ffmpeg_floodfill_point_stack_oob` | `cases/ffmpeg_floodfill_point_stack_oob/patch.diff` | `libavfilter/vf_floodfill.c` | third_party/ffmpeg | 3 |  |
| `ffmpeg_hqdn3d_dynamic_size_oob` | `cases/ffmpeg_hqdn3d_dynamic_size_oob/patch.diff` | `libavfilter/vf_hqdn3d.c` | third_party/ffmpeg | 1 |  |
| `ffmpeg_iamf_count_label_dos` | `cases/ffmpeg_iamf_count_label_dos/patch.diff` | `libavformat/iamf_parse.c` | third_party/ffmpeg | 1 |  |
| `ffmpeg_lcldec_zlib_tail_disclosure` | `cases/ffmpeg_lcldec_zlib_tail_disclosure/patch.diff` | `libavcodec/lcldec.c` | third_party/ffmpeg | 2 |  |
| `ffmpeg_nvdec_sep_ref_doublefree` | `cases/ffmpeg_nvdec_sep_ref_doublefree/patch.diff` | `libavcodec/nvdec.c` | third_party/ffmpeg | 2 |  |
| `ffmpeg_quirc_resize_oob` | `—` | `libavfilter/vf_quirc.c` | third_party/ffmpeg | 3 | 原件缺失，本目录为唯一副本 |
| `ffmpeg_rscc_short_deflate_uninit_leak` | `cases/ffmpeg_rscc_short_deflate_uninit_leak/patch.diff` | `libavcodec/rscc.c` | third_party/ffmpeg | 2 |  |
| `ffmpeg_swaprect_temp_row_oob` | `cases/ffmpeg_swaprect_temp_row_oob/patch.diff` | `libavfilter/vf_swaprect.c` | third_party/ffmpeg | 2 |  |
| `ffmpeg_ty_ac3_trim_underflow` | `cases/ffmpeg_ty_ac3_trim_underflow/patch.diff` | `libavformat/ty.c` | third_party/ffmpeg | 1 |  |
| `ffmpeg_wmaenc_extradata_padding` | `cases/ffmpeg_wmaenc_extradata_padding/patch.diff` | `libavcodec/wmaenc.c` | third_party/ffmpeg | 1 |  |
| `hiappevent_ffi_watcher_null_filter` | `cases/hiappevent_ffi_watcher_null_filter/patch.diff` | `base/hiviewdfx/hiappevent/frameworks/cj/ffi/src/hiappevent_ffi.cpp` | （OpenHarmony 源码根） | 1 |  |
| `ipc_cj_array_null_validation` | `cases/ipc_cj_array_null_validation/patch.diff` | `foundation/communication/ipc/interfaces/innerkits/cj/src/message_sequence_impl.cpp` | （OpenHarmony 源码根） | 1 |  |
| `kv_ffi_array_validation` | `cases/kv_ffi_array_validation/patch.diff` | `foundation/distributeddatamgr/kv_store/frameworks/cj/src/distributed_kv_store_impl.cpp` | （OpenHarmony 源码根） | 1 |  |
| `openssl_ocb_oneshot_iv_discard` | `cases/openssl_ocb_oneshot_iv_discard/patch.diff` | `providers/implementations/ciphers/cipher_aes_ocb.c` | third_party/openssl | 1 |  |
| `udmf_ffi_setproperties_null_tag` | `cases/udmf_ffi_setproperties_null_tag/patch.diff` | `foundation/distributeddatamgr/udmf/interfaces/cj/src/unified_data_ffi.cpp` | （OpenHarmony 源码根） | 1 |  |

## 应用方式

```bash
# 到上表的「执行目录」下执行（a/ b/ 前缀与源码根对应）
patch -p1 --dry-run < patches/<case>.patch
patch -p1 < patches/<case>.patch
```

## 说明

- 镜像与原件的一致性：`diff <(tr -d "\r" < cases/<case>/patch.diff) patches/<case>.patch`
  应为空（原件在 Windows 检出下是 CRLF）。
- `curl_native_ca_reuse` 的补丁表达的是语义：比对成员 `native_ca_store` 实际位于
  `struct ssl_config_data`，而 `match_ssl_primary_config()` 只接收 `ssl_primary_config`，
  按现状编译不过；报告第 5 节给了可落地的方向。
- 其余 18 份未在本机编译验证（缺少对应组件的检出树）。
