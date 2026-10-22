# 证据质量矩阵（2026-10-18）

口径：按 VULN_REPORT 生成器 `read_case()` 的实际解析结果逐字段分级。
图例：● 实质（2 分）｜◐ 降级（1 分：指针/回退/派生/模板+补丁）｜○ 占位或缺失（0 分）｜— 不适用（如新发现无 CVE）。

注意：`版本判定` 列来自 `read_case()` 内的 `evaluate_case(strict_evidence=False)`——即非严格模式，其中"实"包含上游版本推断，与工作台出口（严格模式）判定口径不同（导师 2026-10 一致性批评所指）。统一口径后的矩阵以 learn/impact-contract 修复重生成版为准。

| 案例 | CVE | 漏洞描述 | 触发条件 | 攻击路径 | 源码片段 | PoC代码 | PoC用法 | 模块定位 | 修复建议 | 补丁 | 版本判定 | 真库复现 | 得分 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| cjson_merge_alias | ● | ● | ● | ● | ◐ | ● | ● | ◐ | ◐ | ● | ● | — | 19/22 |
| curl_native_ca_reuse | ● | ● | ● | ● | ◐ | ● | ◐ | ◐ | ● | ● | ● | — | 19/22 |
| curl_psl_supercookie | ● | ● | ● | ● | ◐ | ● | ◐ | ◐ | ● | ● | ● | — | 19/22 |
| ffmpeg_cfhd_transform2_width_oob | ● | ● | ● | ● | ◐ | ● | ◐ | ◐ | ◐ | ● | ● | — | 18/22 |
| ffmpeg_dvbsub_parser_capacity_overflow | ● | ● | ● | ● | ◐ | ● | ◐ | ◐ | ● | ● | ● | — | 19/22 |
| ffmpeg_floodfill_point_stack_oob | ● | ● | ● | ● | ◐ | ● | ◐ | ◐ | ● | ● | ● | — | 19/22 |
| ffmpeg_hqdn3d_dynamic_size_oob | ● | ● | ● | ● | ◐ | ● | ◐ | ◐ | ● | ● | ● | — | 19/22 |
| ffmpeg_iamf_count_label_dos | ● | ● | ● | ● | ◐ | ● | ◐ | ◐ | ◐ | ● | ● | — | 18/22 |
| ffmpeg_lcldec_zlib_tail_disclosure | ● | ● | ● | ● | ◐ | ● | ◐ | ◐ | ● | ● | ● | — | 19/22 |
| ffmpeg_nvdec_sep_ref_doublefree | ● | ● | ● | ● | ◐ | ● | ◐ | ◐ | ◐ | ● | ● | — | 18/22 |
| ffmpeg_quirc_resize_oob | ● | ● | ● | ● | ◐ | ● | ◐ | ◐ | ● | ● | ● | — | 19/22 |
| ffmpeg_rscc_short_deflate_uninit_leak | ● | ● | ● | ● | ◐ | ● | ◐ | ◐ | ◐ | ● | ● | — | 18/22 |
| ffmpeg_swaprect_temp_row_oob | ● | ● | ● | ● | ◐ | ● | ◐ | ◐ | ● | ● | ● | — | 19/22 |
| ffmpeg_ty_ac3_trim_underflow | ● | ● | ● | ● | ◐ | ● | ◐ | ◐ | ● | ● | ● | — | 19/22 |
| ffmpeg_wmaenc_extradata_padding | ● | ● | ● | ● | ◐ | ● | ◐ | ◐ | ● | ● | ● | — | 19/22 |
| hiappevent_ffi_watcher_null_filter | — | ● | ● | ◐ | ◐ | ● | ◐ | ◐ | ● | ● | ● | ● | 18/22 |
| ipc_cj_array_null_validation | — | ● | ◐ | ◐ | ◐ | ● | ◐ | ◐ | ● | ● | ● | ● | 17/22 |
| kv_ffi_array_validation | — | ● | ◐ | ◐ | ◐ | ● | ◐ | ◐ | ● | ● | ● | — | 15/20 |
| openssl_ocb_oneshot_iv_discard | ● | ● | ● | ● | ◐ | ● | ◐ | ◐ | ● | ● | ● | — | 19/22 |
| udmf_ffi_setproperties_null_tag | — | ● | ◐ | ◐ | ● | ● | ◐ | ◐ | ● | ● | ● | ● | 18/22 |

## 字段汇总（按占位数升序 = 最差字段在前）

| 字段 | ●实质 | ◐降级 | ○占位 | —不适用 |
|---|---|---|---|---|
| 模块定位 | 0 | 20 | 0 | 0 |
| 源码片段 | 1 | 19 | 0 | 0 |
| PoC用法 | 1 | 19 | 0 | 0 |
| 修复建议 | 15 | 5 | 0 | 0 |
| 攻击路径 | 16 | 4 | 0 | 0 |
| 触发条件 | 17 | 3 | 0 | 0 |
| CVE | 16 | 0 | 0 | 4 |
| 漏洞描述 | 20 | 0 | 0 | 0 |
| PoC代码 | 20 | 0 | 0 | 0 |
| 补丁 | 20 | 0 | 0 | 0 |
| 版本判定 | 20 | 0 | 0 | 0 |
| 真库复现 | 3 | 0 | 0 | 17 |

## 逐案降级/占位明细

### cjson_merge_alias
- 源码片段: 指针+证据引文,未嵌码
- 模块定位: 缺省回退component尾段
- 修复建议: 仅指向补丁附件
- 版本判定: 6实/0unknown

### curl_native_ca_reuse
- 源码片段: 指针+证据引文,未嵌码
- 模块定位: 缺省回退component尾段
- 版本判定: 6实/0unknown

### curl_psl_supercookie
- 源码片段: 指针+证据引文,未嵌码
- 模块定位: 缺省回退component尾段
- 版本判定: 6实/0unknown

### ffmpeg_cfhd_transform2_width_oob
- 源码片段: 指针+证据引文,未嵌码
- 模块定位: 缺省回退component尾段
- 修复建议: 仅指向补丁附件
- 版本判定: 6实/0unknown

### ffmpeg_dvbsub_parser_capacity_overflow
- 源码片段: 指针+证据引文,未嵌码
- 模块定位: 缺省回退component尾段
- 版本判定: 6实/0unknown

### ffmpeg_floodfill_point_stack_oob
- 源码片段: 指针+证据引文,未嵌码
- 模块定位: 缺省回退component尾段
- 版本判定: 6实/0unknown

### ffmpeg_hqdn3d_dynamic_size_oob
- 源码片段: 指针+证据引文,未嵌码
- 模块定位: 缺省回退component尾段
- 版本判定: 6实/0unknown

### ffmpeg_iamf_count_label_dos
- 源码片段: 指针+证据引文,未嵌码
- 模块定位: 缺省回退component尾段
- 修复建议: 仅指向补丁附件
- 版本判定: 6实/0unknown

### ffmpeg_lcldec_zlib_tail_disclosure
- 源码片段: 指针+证据引文,未嵌码
- 模块定位: 缺省回退component尾段
- 版本判定: 6实/0unknown

### ffmpeg_nvdec_sep_ref_doublefree
- 源码片段: 指针+证据引文,未嵌码
- 模块定位: 缺省回退component尾段
- 修复建议: 仅指向补丁附件
- 版本判定: 6实/0unknown

### ffmpeg_quirc_resize_oob
- 源码片段: 指针+证据引文,未嵌码
- 模块定位: 缺省回退component尾段
- 版本判定: 6实/0unknown

### ffmpeg_rscc_short_deflate_uninit_leak
- 源码片段: 指针+证据引文,未嵌码
- 模块定位: 缺省回退component尾段
- 修复建议: 仅指向补丁附件
- 版本判定: 6实/0unknown

### ffmpeg_swaprect_temp_row_oob
- 源码片段: 指针+证据引文,未嵌码
- 模块定位: 缺省回退component尾段
- 版本判定: 6实/0unknown

### ffmpeg_ty_ac3_trim_underflow
- 源码片段: 指针+证据引文,未嵌码
- 模块定位: 缺省回退component尾段
- 版本判定: 6实/0unknown

### ffmpeg_wmaenc_extradata_padding
- 源码片段: 指针+证据引文,未嵌码
- 模块定位: 缺省回退component尾段
- 版本判定: 6实/0unknown

### hiappevent_ffi_watcher_null_filter
- 攻击路径: 回退到 candidate.entry_point
- 源码片段: 指针+证据引文,未嵌码
- 模块定位: 缺省回退component尾段
- 版本判定: 6实/0unknown

### ipc_cj_array_null_validation
- 触发条件: 回退到 candidate.input_type
- 攻击路径: 回退到 candidate.entry_point
- 源码片段: 指针+证据引文,未嵌码
- 模块定位: 缺省回退component尾段
- 版本判定: 6实/0unknown

### kv_ffi_array_validation
- 触发条件: 回退到 candidate.input_type
- 攻击路径: 回退到 candidate.entry_point
- 源码片段: 指针+证据引文,未嵌码
- 模块定位: 缺省回退component尾段
- 版本判定: 6实/0unknown

### openssl_ocb_oneshot_iv_discard
- 源码片段: 指针+证据引文,未嵌码
- 模块定位: 缺省回退component尾段
- 版本判定: 6实/0unknown

### udmf_ffi_setproperties_null_tag
- 触发条件: 回退到 candidate.input_type
- 攻击路径: 回退到 candidate.entry_point
- 模块定位: 缺省回退component尾段
- 版本判定: 6实/0unknown

## 跨案例重复字符串（≥3 案复用，模板文案候选）

> 其中 schema 标签、状态枚举（`verified`、`case-specific-validation-0.2`）、组件名/仓 URL、基线日期属正常复用，非文案问题；真正的模板文案见 PoC 用法字段。

- [20案] affected
- [20案] OpenHarmony-4.1-Release
- [20案] OpenHarmony-5.0-Release
- [20案] OpenHarmony-5.1.0-Release
- [20案] OpenHarmony-6.0-Release
- [20案] OpenHarmony-7.0-Release
- [15案] case-specific-validation-0.2
- [12案] third_party/ffmpeg
- [12案] https://gitcode.com/openharmony/third_party_ffmpeg
- [12案] 0a0c4dd33c
- [9案] OpenHarmony 漏洞奖励计划 (https://bugbounty.openharmony.cn)
- [9案] OpenHarmony-v7.0-Release（2026-08-21）
- [7案] 0a0c4dd33c (2026-09-10)
- [6案] FFmpeg 7.1.1, snapshot 2026-06-01
- [6案] not_affected
- [5案] third_party_ffmpeg
- [5案] verified
- [4案] 2026-09-21
- [4案] 2026-09-28
- [4案] wildtrace-candidate-case-0.2
- [3案] FFmpeg 7.1.1
- [3案] 2026-07-13
- [3案] FFmpeg 7.1.1, README.OpenSource last change 2026-06-01
- [3案] real_library_reproduction_confirmed

## VULN_REPORT.md 渲染占位计数（逐案）

- curl-native-ca-reuse-mismatch: 无可执行触发器×1; 见 case.json×1
- ffmpeg-cfhd-transform2-width-oob: 无可执行触发器×1
- ffmpeg-iamf-count-label-dos: 无可执行触发器×1
- ffmpeg-nvdec-sep-ref-doublefree: 无可执行触发器×1
- ffmpeg-rscc-short-deflate-uninit-leak: 无可执行触发器×1
