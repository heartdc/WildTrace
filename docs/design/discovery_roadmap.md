# WildTrace 0day 发现端补强方案（discovery-side roadmap）

状态：草案 v1（2026-09-21，GLM 起草，待团队评审）
背景：dsoftbus 实战暴露发现端五个缺口（数据流引擎/fuzzing/攻击面/
variant/基准），本方案给出补强路线。验证与证据链（后端）已成熟，
本方案只补"发现"端。

## 总原则

- 每项有硬验收标准（在 OH 原生代码上跑出什么），不做无度量的建设
- 复用现有资产：engine_adapter 的 codeql/joern 适配位、llm_adapter
  （OSLO API）、kb 三层、验证设施（ASan/WSL）、casebook
- 时间盒对齐比赛（10-22 截止）：P0 本周启动，P1 视 P0 结果
- 缝隙打猎线独立继续供工单，不占用本方案资源

## P0-1 数据流引擎接通（三路并行，先通一路）

目标：对 OH C++（引用参数形态）具备过程间污点跟踪能力。

| 路线 | 动作 | 优势 | 风险 |
|---|---|---|---|
| A. CodeQL | codeql CLI（开源仓库免费）+ dsoftbus 数据库 + OH IPC 查询 | 引用参数跟踪完善，查询表达力最强 | C++ 需要 build 命令，OH GN 构建适配可能耗时 |
| B. clang CSA | compile_database.py + bear 拦截 GN/ninja 构建 → compile_commands.json → scan-build | 已有适配层；路径敏感 | OH 容器构建环境；CSA 误报分诊成本 |
| C. joern | 零构建语法级导入 Cpp | 一天可通 | 精度低（无类型敏感），兜底用 |

验收（硬标准）：在 dsoftbus 上追出 ≥1 条经人工确认的
`MessageParcel 读取值 → 内存操作/分配` 完整数据流（不要求是漏洞，
验证引擎能力）；若该路径真无此形态，改在 authentication 模块追
`网络输入 → 定长拷贝` 数据流。

分工：GLM 写查询/脚本+文档；朋友做构建集成（OH docker）；止损线：
任一路线 3 天不通即转下一路。

## P0-2 LLM 生成 fuzz harness 流水线

目标：对 C 解析模块具备自动化模糊测试能力。

进度（2026-09-21）：
- 靶选下钻工具落地：tools/fuzz_targets.py（从 attack_surface 的
  handler 体提取内部转发函数并做纯度评级；dsoftbus 首跑 40 handler
  → 28 内部函数）
- 首靶闭环验证：dfx/anonymize anonymizer.c 提取包
  （D:/cve_data/fuzz_anonymizer/，OH 原文件零改动 + 3 个 stub 头）
  + libFuzzer harness，ASan/UBSan 60s 快测 4.25M execs / 214 cov、
  无崩溃——流水线全链路可用。验收 10 harness 完成 1/10。
- 第二靶（JSON 解析栈，softbus_json_utils + OH cJSON 1.7.19）：
  **harness 在 75s 内独立复现已知 CVE-2026-87933（MergePatch UAF，
  崩溃输入 {"p":2}}）——fuzzer 灵敏度实证**；打 87933 补丁后
  105s/3.25M execs/652 cov 无新崩溃（基线参考值）。验收 2/10。
- 副产品：cJSON 作为 fuzz 依赖引入时经 kb_gap_audit 核验，发现
  CVE-2026-87933 缺口（cases/cjson_mergepatch_uaf/，运行级验证）。

流水线：
1. 靶选：authentication/src 17 个 C 文件的消息解析入口（函数签名
   + 调用方上下文喂 LLM）
2. LLM 产 harness：LLVMFuzzerTestOneInput 构造输入 → 调目标函数
   （llm_adapter 复用；prompt 含"仅回环/无文件副作用"约束）
3. 构建：WSL clang -fsanitize=fuzzer,address,undefined
4. 快测循环：每 harness 60-120s；崩溃按栈哈希去重入桶
5. 分诊：人工/LLM 复核桶 → 真实候选进验证线（2×2 矩阵 + casebook）

验收（硬标准）：≥10 个 harness 构建通过并完成首轮快测；产出崩溃
桶清单（全误报也要有分诊记录）；流水线脚本入库
（tools/fuzz_pipeline/）。

分工：GLM 写 prompt 模板+流水线+分诊记录格式；师弟跑批量；
朋友侧 LLM 审查接口对齐。

## P0-3 IPC 攻击面自动枚举

目标：给 P0-1/P0-2 提供靶心（source 集合），替代 CVE 密度粗代理。

动作：解析 OH 仓的 proxy/stub 对与 IDL 描述（.idl/.xml 注册表），
生成 attack_surface.json：
`子系统 → 接口 → 参数类型 → 实现文件:行`。

验收：dsoftbus + 任一 systemability 完整入口表；P0-1 查询的
source 集合直接引用该表。

分工：GLM 实现生成器；师弟覆盖更多子系统。

## P1（视 P0 结果，第二周起选做）

- P1-4 variant 规则库：l4_batch_ffmpeg.py 泛化——fix diff 特征
  提取 → 规则/查询模板 → 多组件扫描（缝隙线经验反向输出）
- P1-5 OH 原生基准：历史 CVE 修复前代码回放进 dsoftbus 靶场，
  量化各层召回率（benchmark.py 首次喂真实数据），为技术说明书
  提供检出率数字
- 区间域：按原设计文档推进，不因本方案插队

## 时间盒（4 周）

| 周 | 内容 | 出口 |
|---|---|---|
| W1（本周） | P0 三项并行启动 | 周五验收：三硬标准 |
| W2 | P0 迭代 + 收割（引擎产出→验证线） | 首批候选或负结果结论 |
| W3 | P1 选做 + 技术说明书整合 | 文档冻结草案 |
| W4 | 冻结、答辩材料 | 提交 |

## 风险与止损

- CodeQL/CSA 构建适配超时 → 3 天止损转 joern / 纯 LLM 审查模式
- fuzzing 全误报 → 分诊成本>收益时收缩 harness 面，转 LLM 精读
- 比赛主线保障：缝隙线（剩余 23 候选+libxml2/openssl）继续由
  GLM 按日推进，与本方案资源隔离
