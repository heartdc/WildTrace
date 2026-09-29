# ffmpeg 缝隙批量甄别报告（needs_manual 13 条 · 2026-09-21）

核验方法：cvelist refs 逐一甄别（剔除引入/无关 commit）→ 真修复
diff 的核心防御行语义比对 → OH 树（=n7.1.1 逐字节一致基线）核验。
判定口径：修复新增的核心防御条件行在 OH 缺失即缺口成立（PARTIAL
仅为 master 与 7.1.1 上下文漂移所致，缺失行均为关键语义行）。

## 结果：13/13 确认缺口

| CVE | 组件 | 真修复 | 缺失的核心防御 | 家族 |
|---|---|---|---|---|
| 2026-64834 | rtpdec_asf | 11d5f475 | `if (chunksize < sizeof(ff_asf_guid) + 8)` | 整数守卫 |
| 2026-65703 | tdsc | fd3ee52f | realloc 前 `av_frame_unref(ctx->refframe)` | 生命周期 |
| 2026-66039 | mace | aafb5c65 | `int64_t nb_samples = 3 * ((int64_t)buf_size << …) / channels` | 整数守卫 |
| 2026-66040 | pngenc | b506fafe | exif 尺寸一致性检查（AVBufferRef *exif_data 路径） | 一致性 |
| 2026-65705 | vf_floodfill | 24c322fd† | points_size 动态分配（点栈按当前帧尺寸） | 尺寸不匹配 |
| 2026-65706 | vf_swaprect | a7e38b61 | temp 行缓冲按最宽平面尺寸 | 尺寸不匹配 |
| 2026-70630 | screenpresso | 70589006+c22667d0 | `if (length < src_linesize * avctx->height)` | 短输出未清零 |
| 2026-70631 | tiff | 2f234ea3+3c287af3 | inflate 输出短于 strip 的拒绝/清零 | 短输出未清零 |
| 2026-75142 | mpegenc | 9d786e4b | 系统头流计数溢出拒绝 | 整数守卫 |
| 2026-75146 | dashdec | 65b0dab9 | `if (rep_dest->cur_seq_no < 0)` | 整数守卫 |
| 2026-52295 | iamf_writer/mov | 8439e020 | extradata 分配 padding 溢出检查 | padding |
| 2026-52297 | iamf_writer/mov | 8439e020 | 同上（同修复双 CVE） | padding |
| （已另案） | 66037 | 8670835 | 见独立档案 | 整数守卫 |

† 65705 的真修复为 24c322fd（"size the point stack for the current
frame"），cvelist 首引的 f186c50f（"remove unneeded variables"）为
同日随行清理提交，非修复本体——refs 甄别再次必要。

## 家族规律（本批次 21 条确认缺口的归类）

1. **短解压输出未清零**（CWE-908）：66038 lcldec、70629 rscc、
   70630 screenpresso、70631 tiff —— 4 例
2. **配置尺寸分配 vs 帧尺寸使用**（CWE-787）：66041 quirc、
   66036 hqdn3d、65705 floodfill、65706 swaprect —— 4 例
3. **守卫整数溢出/负值**（CWE-190）：70628 dvbsub、66039 mace、
   75142 mpegenc、75146 dashdec、64834 rtpdec_asf、66037 iamf —— 6 例
4. **extradata padding**（CWE-125/787）：52296 wmaenc、
   52295/52297 avformat —— 3 例
5. 其他：65703 tdsc（realloc 生命周期）、66040 pngenc（尺寸一致性）、
   65704 ty（下溢裁剪）、70632 cfhd（宽度约束）—— 4 例

家族规律本身即变体挖掘规则的输入（P1-4）：每个家族可编译为
一条可执行规则反投 OH 其他组件。

## 后续

- 4 案已提交平台；9 案材料就绪待提交；本报告 12 条为批量甄别
  证据，按需逐案立案（优先级建议：家族 2 的 65705/65706 可参照
  66036 模式做运行级验证；家族 1 的 70630/70631 可参照 66038 模式）
- 全部数据：gap_audit_ffmpeg.json / gap_l4_batch.json /
  manual_triage.py（甄别脚本）
