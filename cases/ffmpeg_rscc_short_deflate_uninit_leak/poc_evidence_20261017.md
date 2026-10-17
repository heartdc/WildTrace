# 运行验证记录（2026-10-17）

构建：上游 FFmpeg n7.1.1（与 OH third_party_ffmpeg 0a0c4dd33c 的 rscc.c 逐字节一致），
clang --toolchain=clang-asan 靶向构建（decoder=rscc；--disable-x86asm，不影响受测 C 路径）。
PoC：cases/ffmpeg_rscc_short_deflate_uninit_leak/poc.c（运行时自生成短解压 RSCC 流）。

## 判读（ASan malloc_fill 差分，确定性）

    ASAN_OPTIONS=malloc_fill_byte=170:max_malloc_fill_size=200000 ./poc trigger
      case=rscc_trigger frame=64x64 checksum=26da572f745dbfc3
    ASAN_OPTIONS=malloc_fill_byte=187:max_malloc_fill_size=200000 ./poc trigger
      case=rscc_trigger frame=64x64 checksum=31b9a38e0da95a13
    ASAN_OPTIONS=malloc_fill_byte=170:... ./poc control
      case=rscc_control frame=64x64 checksum=35058dda7af76383
    ASAN_OPTIONS=malloc_fill_byte=187:... ./poc control
      case=rscc_control frame=64x64 checksum=35058dda7af76383

结论：trigger 两跑帧校验和不同 ⇒ 解压输出（16 字节）之后的未初始化堆尾部
（12288-16 字节）流入输出帧（未初始化信息泄露，运行级证实）；control
（packed_size==pixel_size 原始路径）两跑一致（无回归）。
与上游修复 cd1f545c/a5fe21a1（memset 补零）所指缺陷一致。
