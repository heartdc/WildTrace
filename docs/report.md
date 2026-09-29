# 当前项目审计与后续规划

## 审计基线与范围

- 原工作目录：C:/Projects/LSH；master 为 9b3fdad5f37a1252ab21c59cc2a9bf2ac63f59e1，工作区干净。
- 本地保存的 origin/master 为 dbd53ce，master 显示 behind 20。本轮没有 fetch，不能据此声明远端实时状态。
- 较新案例分支：codex/runtime-evidence-cjson-case，固定提交 0f9a0645f56b9716db98254bcbbd9dfdc833c30b。
- 使用 TaskQuay 隔离 detached worktree 审计该提交；没有切换、重置、提交、推送或修改原项目业务代码。
- 隔离目录：C:/Users/35466/.devspace/worktrees/LSH-33fbe9c2。
- 本轮执行离线回归和一个无可执行入口的 Clang 语法树对照；没有运行 OpenHarmony 目标、LLM 或 Codex。

## 实际验证

Windows / Python 3.13.13 上，全量运行 816 项：787 通过，1 失败，24 错误，4 项 symlink unavailable 跳过。
全量日志：隔离目录下 .cache/audit_0f9a064/full.log。
日志 SHA-256：db08e54431c50744e7c3fb029e705d87bd7c0a8bdeb48cbd27035628de9f2a5a。
首次汇总脚本在测试结束后发生正则表达式错误，已从保存的原始日志恢复汇总，没有重跑或更改测试。
恢复汇总：.cache/audit_0f9a064/recovered-summary.json。最终 HEAD 未变，Git 工作区仍干净。

## 发现与优先级（工程修复优先级，不是目标漏洞严重性）

### P0：源码、清单和测试协议不同步，完整交付路径当前失败

ohvul/component_batch.py:72,83-91 仍为五参数 _validate，仅接受 component-batch-0.1 与旧 job 字段。
tools/component_review.py 的新入口依赖 modern/analyses，verify_pipeline 传 existing_output=True。
较新的 manifest 与集成/交付测试使用 0.2。实际回归有 24 项错误为 invalid batch schema or job count，另有 1 项失败。
不得用历史已通过的工作区验收代表此提交；不能通过只改 schema 字符串或删除测试解决。

### P1：类型大小计算存在已实测的误报

ohvul/clang_facts.py:79-96 先把所有 [N] 当作数组维度，不能区分指向数组的指针声明。
选定编译器目标指针大小为 8 字节，size_of('char (*)[4]', layout) 却返回 32。
实际 Clang 对照含 char dst[16], src[16]; char (*p)[4]; memcpy(dst,src,sizeof p)。
编译器静态断言 sizeof p == sizeof(void*) 且 sizeof p <= sizeof dst 通过，核心却生成两个越界候选，声称复制 32 字节。
对照没有执行目标。证据：隔离目录 .cache/audit_0f9a064/type-probe-result.json。
修复需要真实类型大小或受限声明支持；不支持的复杂声明应保留 unknown，并加入独立反例。

### P1：cJSON 已有库级运行记录，但文档、运行验证接口与最终案例等级尚未闭合

已读取原目录 .cache/cjson-runtime-wsl/runtime/acceptance.json：status=passed、target_executed=true、public_known_case=true、product_reachability=not_established。
矩阵 classification 计数为 library_uaf_observed 4、functional_control_passed 22、构建等 unexpected 3。
tools/cjson_case.py:245-247 安排原版 subtree 三次和独立构建一次。
docs/analysis/CJSON_RUNTIME_CASE_20260915.md:13 却写原版与独立副本“各4次”，需纠正文档或补足真实运行，不可改写旧证据。
该脚本 main 的 verify 分支只调用 verify_prepared，未对 runtime/acceptance.json 全部日志、二进制摘要和分类进行离线重算。
本轮逐日志摘要检查被工具安全检查拦截，未执行，没有换通路重试；不声称完整审验全部 sanitizer 日志，也不声称本轮重新触发。
案例源码明确 automated_detection=false / public_issue_informed_source_review；不能计作自动检测器新发现。

### P1/P2：比赛影响分析与性能证明仍是实质缺口

branch_impact.py 当前核心比较 evidence_id 集合，不能单独证明分支受影响或补丁修复有效。
performance.py 主要生成合成 int x 输入并使用 tracemalloc；不是多引擎、WSL 和真实规模的整机峰值内存证据。
cJSON 文档保留产品可达性未知；zlib 本地记录针对已修复版本的功能对照，不能记作漏洞触发。
授权文件签署栏已有两方签署记录，文件头仍写待签署；需要统一记录，不应再次以笼统“缺授权”阻塞所有开发。

## 下一步（先完整案例，不继续堆通用算法）

1. 团队选定唯一交付分支，保留现有工作；对齐 batch 0.1/0.2、compiler 集成、队列、handoff 和 verify 接口。门槛：全量无失败/错误，旧协议回归保留，一条命令生成并离线复核完整静态交付。
2. 修复已复现的类型大小误判，加入真实 Clang 的指针到数组、数组到指针、嵌套声明与不同布局反例。门槛：当前反例不再生成两个虚假的确定越界候选，未知情况不冒充安全。
3. 以已有 cJSON 为首个库级完整演示包：统一实际重复数、增加 verify-runtime、绑定原始日志/构建/二进制/源码/补丁、第二人独立复现。保持已知公开案例和产品影响未知标签。
4. 固定产品/版本与构建配置，追踪该 API 的实际调用者、输入来源和安全边界；若产品不包含该路径则如实标注，不把库级结果扩张成 OpenHarmony 产品漏洞。
5. 再由案例带动检测改进：将 cJSON 所有权反例作为生命周期检测回归，区分人工选例、规则检出、成熟引擎检出；多组件多漏洞族保留总目标，扩展按独立验证批次执行。
6. 并行完成真实规模耗时/资源测量、版本影响矩阵、修复回归、技术说明、使用手册、视频和可复跑报告包。LLM保持暂停，不是这些工作的前置条件。

当前确需团队决定：唯一交付分支、比赛产品/版本、独立复核与提交责任人。已有授权和工具链记录无需重新索要密钥或泛化授权。

审计完成不等于项目通过验收。本轮没有修复业务代码；以上为已验证问题与下一阶段验收计划。
