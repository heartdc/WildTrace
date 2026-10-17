# 运行验证记录（2026-10-17）

构建：上游 FFmpeg n7.1.1（与 OH third_party_ffmpeg 0a0c4dd33c 的 iamf_parse.c
逐字节一致），clang-asan 靶向构建（demuxer=iamf）。
PoC：cases/ffmpeg_iamf_count_label_dos/poc.c（运行时自生成畸形 .iamf）。

## 判读（ASan 分配上限定点拦截）

    ASAN_OPTIONS=max_allocation_size_mb=1024:detect_leaks=0 ./poc trigger t.iamf
      ==21924==ERROR: AddressSanitizer: requested allocation size 0x7ffffff8
        (0x80001040 after adjustments ...) exceeds maximum supported size of
        0x40000000 (thread T0)
          #4 mix_presentation_obu libavformat/iamf_parse.c:865:40
          #5 ff_iamfdec_read_descriptors libavformat/iamf_parse.c:1123:19
      SUMMARY: AddressSanitizer: allocation-size-too-big ... in posix_memalign
    ./poc control c.iamf
      case=iamf_control open_input_ret=-541478725（AVERROR_EOF：Mix Presentation
      解析通过，描述符-only 文件缺音频帧 OBU 以 EOF 收场，属预期）

结论：count_label=0x0FFFFFFF（leb128 4 字节声明 2.68 亿标签，剩余输入 0 字节）
触发 av_calloc 无界申请（~2GB），分配点即 iamf_parse.c:865，申请量与剩余输入
无关——上游修复 86708357（count_label 对照可用字节校验）所指缺陷，运行级证实。
