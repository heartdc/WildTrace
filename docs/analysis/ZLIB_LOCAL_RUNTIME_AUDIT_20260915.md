# 本地真实目标运行：zlib 固定版本对照

## 结论与证据等级

用户在本轮对话明确授权真实本地验证。已使用实际 zlib 目标代码完成两次
独立构建、十次新建沙箱运行，四类输入模式全部通过解压与扩展头截取检查。
这不再是语法检查、fixture-only 输入生成或模拟传输。

目标是当前已经包含边界保护的 zlib 1.3.1，**不是历史脆弱版本**。
结论为 `functional_controls_passed`，不是 CVE-2022-37434 触发成功，
不是新漏洞发现，也不满足团队 W3“一个带真实运行证据的漏洞”里程碑。
只证明所列固定配置和输入的库级功能／回归表现；未证明产品可达性。

## 固定输入和实际执行

- 原始仓库：`C:/Projects/OpenHarmony/third_party/zlib`。
- 提交：`7d1c4cdd5b5396ed14e60691713d5543a523fd12`；构建前后工作区干净。
- 复用 `tools/validation_cases/zlib_gzip_extra_37434.c`，未改写其字节。
- 直接编译 adler32、crc32、inflate、inffast、inftrees、zutil 六个实际源文件，
  加九个显式头文件。运行从核对哈希的副本构建，没有修改原始目标。
- Clang 使用 `-std=c11 -O1 -g -fno-omit-frame-pointer -fsanitize=address,undefined`。
  没有运行仓库 configure/Makefile，没有链接系统 zlib 来冒充目标源码。
- 编译器版本完整输出、构建命令、返回码、耗时、两个可执行文件及其 SHA-256、
  每次 stdout/stderr、输入文件摘要均保存。编译器版本观察不是完整工具链签名。

| 模式 | 运行次数 | 核对内容 | 结果 |
| --- | ---: | --- | --- |
| fragmented | 4 | 32字节扩展头、8字节接收容量、分段交付；验证完整解压和正确截取 | 全通过 |
| whole | 2 | 相同输入整体交付 | 全通过 |
| no-capture | 2 | 不启用扩展头接收API的对照 | 全通过 |
| full-capacity | 2 | 接收缓冲区足额的对照 | 全通过 |

原文和gzip输入长度、流结束、输入消费、扩展头完成状态／截取内容，以及
inflateEnd返回值都由现有测试代码检查，不以“进程没崩溃”作为唯一通过条件。
十次运行均有 CASE_START 和合格JSON结果，未观察到ASan/UBSan错误。
LeakSanitizer在本环境中明确关闭，因此不宣称完成泄漏检测。

## 隔离和资源约束

复用已安装WSL Ubuntu、bwrap和可信Clang。每次运行使用新的用户、PID、挂载和
网络命名空间，丢弃capabilities、清除继承环境；只读挂载显式输入和目标程序，
运行时不提供主机可写目录。实际预检观察到uid1000、仅lo网络接口、有效权限位0，
且不可见 `/mnt/c` 和 `/home/airgap`。本轮不访问公网、不下载历史源码。

构建限制为60秒墙钟、45秒CPU、4GiB虚拟地址空间；目标运行限制为10秒墙钟、
5秒CPU、有限文件/输出大小。ASan的512MiB RSS watchdog为辅助限制，不是cgroup
硬内存上限。ASan需要较大的虚拟shadow区域，运行期不设置RLIMIT_AS。

两次独立构建和新的沙箱会话属于同一操作者的重复验证，不宣称第二人独立审计。
凭据、生产文件和未经授权的远程目标均未进入环境。

## 可重复入口

```powershell
python -X utf8 tools/validation_cases/run_zlib_controls.py `
  --root C:/Projects/OpenHarmony/third_party/zlib `
  --output .cache/zlib-controls-another-run `
  --allow-target-execution --approval-reference project-owner-approved-local-controls

python -X utf8 tools/validation_cases/run_zlib_controls.py `
  --root C:/Projects/OpenHarmony/third_party/zlib `
  --output .cache/zlib_runtime_f340 --verify
```

首条命令会真实执行，输出必须使用新目录；第二条仅核对原始源码、保存副本、
构建和日志摘要，并从原始结果重新计算分类，不再次调用目标。审批引用是可追溯
记录，不是工具生成的授权书或真实性签名；普通扫描和LLM不能自动选择执行模式。

实际产物：`.cache/zlib_runtime_f340/acceptance.json`、`build-1/case`、`build-2/case`、
`run-*.stdout`、`run-*.stderr`、`inputs/`。项目回归与静态交付复核记录另存 `qa_final/`。

最终专项52项全部通过；全量763项运行、759项通过、4项符号链接环境跳过。
本轮新增执行入口的14项测试仅用模拟过程，不在单元测试中执行真实目标。
真实目标日志来自显式授权的独立命令。旧静态交付独立复核及运行日志离线复核
均退出0；最终验收期间源码字节和HEAD稳定，git diff --check通过。
普通非零退出、超时、布尔返回码和篡改后的构建/结果摘要不能伪装成成功。

## 后续真正的漏洞链缺口

已核实本地zlib仓库是浅克隆；准备文档中的两个明确历史提交
`6c2de9b55e77f0a6a76d73e933514b024e218832`、
`6c4646bfb303506b12ac15fede09b23309af17f1` 不在本地，未找到对应v3.0标签。
这只说明已检查对象不可用，不宣称全机器不存在历史源码归档。

下一步需要真实的脆弱／修复对照源码及可核对来源。不得通过删除当前保护来制造
“历史漏洞”。来源到位后继续使用同一输入和工具链取得真实错误栈、重复运行和
修复对照；产品调用路径与比赛适用版本仍须另外判断。
本轮没有重试之前被拦截的历史下载请求，也没有以其他通道绕过该拦截。
