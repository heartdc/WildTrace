# 驱动验证记录（2026-10-17）

构建：上游 FFmpeg n7.1.1（cfhd.c 与 OH 0a0c4dd33c 逐字节一致），clang-asan。
PoC：cases/ffmpeg_cfhd_transform2_width_oob/poc.c（demo / sample 双模式）。

## demo 模式（tag-only 流，维度记账路径）

    ./poc_cfhd demo
      case=cfhd_demo send=-1163346256 recv=-11
      （send=AVERROR(EINVAL)；无系数数据，重构写循环不可达——clean 拒绝，符合预期）

## 运行级观测口径（如实申报）

tag-only 流不含 VLC 系数数据，无法驱动到 level-2 重构写循环；越界写的运行级
观测需上游修复 commit 所载样本（cfhd_transform2_output_width_oob.avi，含系数
流）经 sample 模式或 ffmpeg CLI 在 ASan 构建下解码（heap-buffer-overflow WRITE，
预期落点 cfhd.c:1032-1038 的 lowpass_width*2 行宽循环）。本案维持"源级三侧
对照"申报口径，PoC 以 sample 模式备好复现入口。
