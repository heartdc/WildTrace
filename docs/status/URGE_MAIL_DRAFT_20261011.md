# 催办邮件样本（2026-10-11 十七单版，交所有者自行发送）

> 收件人：lixiang531@huawei.com（2026 网安揭榜赛 OpenHarmony 赛题对接人）
> 口径依据：`TICKET_FOLLOWUP_20260930.md` §5（按批次、附最强三单、询问受理周期与补材料需求，不催单张）。
> 状态依据：**2026-10-11 15:54 平台实测**——名下 17 单全部"待受理"（两页逐单核验，与 10-07/10-08 相比零变化）。
> 占位符【姓名】【手机号】发送前自行替换。

---

**主题：【2026 网安揭榜赛 · OpenHarmony 赛题】漏洞工单受理进度咨询（北辰522，名下 17 单，两批超期）**

李老师您好！

我是 2026 年网安揭榜赛「OpenHarmony 开源代码漏洞挖掘」赛题的参赛选手（漏洞奖励计划平台账号：北辰522）。冒昧来信，想跟进我们在平台提交的漏洞工单的受理进度，并确认是否需要补充材料。

截至 2026-10-11 下午（平台"已提交漏洞"列表逐单核验），我们名下 17 个工单均处于"待受理"状态，分三批（第三批为今周新提交，仅列全，不在本次咨询范围）：

**第一批（2026-09-22 提交，已 19 天）**

1. OHSA26-092209031 — third_party/cURL：HTTPS 连接复用未校验原生 CA 存储设置差异（CVE-2026-80231）
2. OHSA26-092226014 — third_party/cURL：cookie 处理违反公共后缀列表（PSL）边界，可产生通配子域 supercookie（CVE-2026-82209）
3. OHSA26-092224773 — third_party/FFmpeg：NVDEC 独立参考帧路径在 decoder surface 耗尽时二次释放解码上下文（CVE-2026-64832）
4. OHSA26-092224881 — third_party/FFmpeg：quirc 滤镜输入尺寸变化时未重分配解码缓冲致堆越界写（CVE-2026-66041）

**第二批（2026-09-28/09-29 提交，已 13 天）**

5. OHSA26-092837123 — third_party/OpenSSL：AES-OCB 经 EVP_Cipher() 一次性接口加密时调用方 IV 被静默丢弃（CVE-2026-45445）
6. OHSA26-092848127 — third_party/FFmpeg：hqdn3d 滤镜变尺寸帧直入去噪管线致堆越界写（CVE-2026-66036）
7. OHSA26-092843135 — third_party/FFmpeg：CFHD 解码器 transform-2 输出宽度未受平面宽度约束致堆越界写（CVE-2026-70632）
8. OHSA26-092850129 — third_party/FFmpeg：RSCC 解码器 deflate 短输出未清零尾部致堆未初始化信息泄露（CVE-2026-70629）
9. OHSA26-092858135 — third_party/FFmpeg：DVB 字幕解析容量守卫有符号整数溢出致栈缓冲区溢出（CVE-2026-70628）
10. OHSA26-092831132 — third_party/FFmpeg：LCL/ZLIB 解码器未解压尾部未清零致堆未初始化信息泄露（CVE-2026-66038）
11. OHSA26-092835171 — third_party/FFmpeg：IAMF 混音呈现解析 count_label 未对照剩余输入字节即分配（CVE-2026-66037）
12. OHSA26-092853125 — third_party/FFmpeg：swaprect 滤镜复用固定尺寸临时行缓冲致越界读写（CVE-2026-65706）
13. OHSA26-092800126 — third_party/FFmpeg：floodfill 滤镜 fill_points 栈缓冲超限越界写（CVE-2026-65705）
14. OHSA26-092855121 — third_party/FFmpeg：mpegtyestream 复用器 Series2 AC-3 帧长处理下溢致越界写（CVE-2026-65704）
15. OHSA26-092819230 — third_party/FFmpeg：WMA 编码器（CVE-2026-52296；该单名称字段存在表单历史异常，已评论补正）
16. OHSA26-092953990 — foundation/communication/ipc：CJ WriteByteArray 空指针数组未校验即遍历，真库实配下 SIGSEGV（新发现，暂无 CVE）

**第三批（2026-10-08 提交，仅列全）**

17. OHSA26-100821855 — base/hiviewdfx/hiappevent：CJ AddWatcher 空指针数组未校验即遍历，官方完整树真库实配下 SIGSEGV（新发现，暂无 CVE）

想请教两个问题：

1. 目前的评审/受理周期大致是多久？前两批是否已进入评审队列？
2. 是否需要我们补充材料？大部分工单已附 PoC 与上游修复对照，其中三张附有完整运行验证记录（ASan 实测矩阵），可作为材料质量示例：
   - OHSA26-092848127（hqdn3d）：ASan 堆越界写运行验证矩阵 + 机理闭环 + 复现命令；
   - OHSA26-092837123（OpenSSL OCB）：密码学等价法 2×2 验证矩阵（缺陷版密文 DIFF / 补丁版密文 SAME）；
   - OHSA26-092224881（quirc）：2×3 运行验证矩阵（已内嵌于提交正文）。

   两张新发现单（ipc / hiappevent）为官方完整树真库实配下的崩溃证实（gdb 崩溃帧归属库内），完整证据包可随时提供。
   任一工单如需完整材料包（PoC 源码、patch、运行验证记录），我们可立即提供。

打扰之处敬请谅解，盼复，感谢！

【姓名】
2026 网安揭榜赛「OpenHarmony 开源代码漏洞挖掘」赛题参赛选手
漏洞奖励计划平台账号：北辰522
联系电话：【手机号】
