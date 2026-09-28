## 当前验收状态（2026-09-28 追加，工具链预检与报告组装器）

- 审计 §89 落地：工具链路径 env 化 + `ohvul.toolchain_preflight`（真实通道探针，required/optional 分级）；engine 传输桥按平台条件化。
- 审计 P1.7 落地：`ohvul.competition_report` 组装器（异构 case.json 防御性投影、完整度矩阵、confirmed 零推断纪律）+ `docs/deliverables/VIDEO_SCRIPT.md` 演示脚本。
- 全量回归 864 项通过。交付缺口现状：视频未录、干净环境独立复跑未做、平台级案例闭环（IPC/KV next_gate）待原构建机执行。

## 当前验收状态（2026-09-28，auth fuzz 双靶收割 + PR 收敛）

- **auth fuzz 双靶收割完毕**：T3 约 1.77 亿执行（cov 3024/ft 14474）、T4 约 2.71 亿执行（cov 2676/ft 12359），累计约 4.5 亿次执行**零崩溃零泄漏**；覆盖判读发现 -O1 内联假象（外部链接单调用点函数 per-symbol 计数误报未覆盖，已插针证伪），方法学规范与 stage-2 暂缓决策见 `docs/analysis/AUTH_FUZZ_HARVEST_20260928.md`（优先级让位于审计 P1.6：IPC/KV 平台级隔离构建验证）。语料与一键重建保留于 ~/fa。
- **PR 收敛**：#54（施工图）、#55（审计机全线工作，本机评审 APPROVED：五项审计问题逐项核验）、#56（台账 15 案 + 本机文档面，Git Data API 构造）、#53（case batch）已合并；master 由 ed32631 推进至 22179b1。遗留 #51/#52 待重叠核对。
- cjson 案 runtime_status 回填 library_level_reproduced（附 09-16 运行矩阵证据指针）；案例台账漂移仅剩 nvdec 提交口径一条待所有者确认。
- 漏洞结论口径不变：确认产品漏洞数 0。

## 当前验收状态（2026-09-24，auth fuzz 双靶挂机 + 审计 P1-1/P0.2 落地）

- **第四靶建成**：`UnpackDeviceInfoMessage`（auth_session_json.c:3388）全链 harness——`fuzz_authdeinfo`。约 25 函数逐字原样 + 全量 NodeInfo（三头链）+ 设备类型转换族；base64 为声明式重实现（mbedtls 契约对齐，偏差已声明）；6 枚种子零崩溃（基线 cov 1422/ft 2496），120s 快测 2,076,080 runs 零崩溃（约 17k exec/s），8h 长跑与 T3 并行挂机。头号嫌疑族（BtV1 `OptInt64` 8 字节写 32 位 netCapacity）种子已构造。
- **T3 状态**：隔夜宿主机休眠中断一次（有效 3.3h，累计 1.223 亿执行零崩溃）；白班重启后 cov 破 3000，双 worker 挂机中。
- **比赛审计（外部文档，另一机器工作集）落地两项**：P1-1 整树快照修复（`12ba819`，全量回归 853 项通过）；P0.2 单一案例台账（`afb34cf`，含三处记录漂移：nvdec 已提交 vs PROJECT_STATE 口径、cjson runtime_status 漏回填、双机工作集分叉）。审计 P1-2/3/4（FFI）代码在对方机器，待落 PR。
- 漏洞结论口径不变：确认产品漏洞数 0；两靶均为"运行中/待分诊"。

## 当前验收状态（2026-09-23，auth fuzz 第一 harness 建成挂机）

- CVE 挖掘 P0-2 第三靶（dsoftbus auth DeviceId 消息链）harness 建成并挂机：`D:/cve_data/fuzz_authdev/`（WSL 镜像 ~/fa）。`UnpackDeviceIdJson`（auth_session_json.c:2107）全链提取 30 函数逐字原样（file:line 标注），双解析器形态完整（`JSON_*` 经真 nlohmann v3.11.3 adapter + 凭证协商子链真 cJSON）；6 枚结构化种子回归通过，120s 快测 1,494,196 runs 零崩溃（cov 2602/ft 9879），12h 长跑（-max_total_time=43200）挂机中，约 12k exec/s。施工记录与方案级偏差（nlohmann 非 cJSON）见 `docs/design/auth_fuzz_extraction_plan.md` §7。
- 第四靶（DeviceInfo 消息，`UnpackDeviceInfoMessage` auth_session_json.c:3388）施工图已论证落盘：`docs/design/deviceinfo_fuzz_extraction_plan.md`。A/C/D 资产全部复用第三靶；头号嫌疑族已标记（UnpackDeviceInfoBtV1 的 `OptInt64` 写 32 位 netCapacity 字段的 8 字节覆写形态——struct 内越界，UBSan 分诊）。
- 漏洞结论口径不变：auth 两靶目前均为"运行中/待分诊"，确认产品漏洞数仍为 0；崩溃分诊走 fuzz_authdev README 命令 + 2×2 验证线。
- 第三靶长跑结束（预计 09-24 凌晨）后的收割动作：取 `-print_final_stats/-print_coverage` 不可达函数清单 → 决定第四靶开工与现靶 stage-2（密钥 stub 换真 AES-GCM）取舍。

## 当前验收状态（2026-09-22，审计对齐与缺口案例落库）

- 全量回归 847 项运行、843 通过、4 项环境跳过；CI（offline-tests：unittest 全量 + 性能冒烟 + 凭据扫描）通过。
- LLM 暂停已于 2026-09-16 解除：z.ai Anthropic 传输通过有界在线评审验收（glm-5.3），gpt-6-astra 加入白名单用于双模型交叉验证；29 组全量评审与双模型运行仍未执行，模型输出仍不作为漏洞结论。
- 案例库扩展至 8 案（均为公开 CVE 缺口案例 new_discovery=false）：cJSON MergePatch（CVE-2026-87933，bubblewrap 矩阵 26/26 + 第二人独立复现 26/26）、curl PSL supercookie（CVE-2026-82209，含运行时验证记录）、curl native CA reuse（CVE-2026-80231）、ffmpeg 五案（CVE-2026-52296/64832/65704/66036/66041；66036/66041 运行时验证通过，64832 源级 L4，65704/52296 源级对照）。产品可达性未建立，确认产品漏洞数仍为 0。
- 已向 OpenHarmony 漏洞奖励计划提交 2 案：OHSA26-092209031（CVE-2026-80231）、OHSA26-092226014（CVE-2026-82209，2026-09-21）；另 5 案 ffmpeg 提交材料已备好（`D:/cve_data/submission_*`）待所有者人工提交；候选 CVE-2026-66038、CVE-2026-70628 待人工 L4 核验成案。
- CVE 知识库运营化：伙伴导入 72 条双审记录、OSV 引用、版本探针（README.OpenSource JSON 数组解析 + 内嵌版本清单名规范化，PR #45）；`tools/kb_gap_audit.py` 四信号 L1-L4 缺口流水线入库。
- 交付物 2 技术说明书初稿 v0.9（`docs/deliverables/TECHNICAL_SPEC.md`）；沙箱设计稿与四信号 triage 设计稿已合并、未实现（待 S1-S5 / A1-A5 主线决策）。
- 全面审计与剩余工作规划见 `docs/status/AUDIT_REMAINING_PLAN_20260922.md`；CHANGELOG 已补录 2026-09-16 至 09-22 断档并清理误嵌入脚本片段。

## 当前验收状态（2026-09-15，恢复验收与整数范围分析）

- 上一批局部值分析已完成恢复验收：专项116项通过，全量661项运行657通过4环境跳过，真实44文件、主CLI、重放通过；外部a336c65提交经字节对账保留，原拒绝记录未被覆盖。
- 新增clang_ranges并接入clang_flow/clang_facts，分析版本3支持有限参数区间、早返回和比较约束、分支包络合并、整数转换及来源记录；未知副作用、循环和析构不沿用旧约束。
- 区分within_known_object、exceeds_known_object、may_exceed_known_object和unknown。仅区间上界超过容量不生成确定越界候选；自然类型范围本身也不构成已检查安全性。
- 最终专项146项通过；全量691项运行687通过4项符号链接环境跳过；真实Clang对照18正例24反例12未知/未确认对照3可能范围观察通过，不能作为真实准确率估计。
- camera3、securec39、hilog2同批完成。camera1处和securec19处调用附带参数范围证据；securec35项内存范围检查仍未知，真实候选和确认漏洞均未增加。原始引擎诊断未改写。
- 主CLI报告/检查点绑定、规范化事实重放、源码/配置/产物一致性和差异检查通过；LLM继续暂停，没有模型API或目标程序执行。没有由本轮宿主提交或回滚Git。
- 统一验收`.cache/range_ef6abb/final/acceptance.json`；恢复对账`recovery-acceptance.json`；审计`docs/analysis/INTEGER_RANGE_AUDIT_20260915.md`；当前规划`docs/status/NEXT_ROADMAP_20260915.md`。
- 下一批优先把新增核心分析纳入组件批处理与复核报告主线，再推进对象容量、关系约束、C++调用、生命周期和独立评测，避免核心算法游离于交付流程。

## 当前核对结果（cJSON具体案例，run_6d4fec3c）

- 已固定OpenHarmony cJSON 1.7.19提交`388cfc96925e4fb41a30735b270736626d26615d`，完成非对象子树别名MergePatch案例源审查、复现C程序、窄补丁及独立副本。公开关联CVE-2026-87933，不计新发现。
- 原版与补丁版均通过Clang `-fsyntax-only`，案例离线契约11项通过。没有执行目标；隔离检查被工具拦截，未以其他通道重试。
- `.cache/cjson-case-6d4f/`含固定输入、源码副本、补丁、候选结果和报告。目标运行、ASan触发、补丁有效性和产品可达性仍待验证；确认产品漏洞数0。
- 当前检出观察为`54d798a`，与历史集成验收版本不同。全量回归762项：733通过、1失败、24错误、4跳过。组件批次实现仅接受0.1，现有集成/交付测试要求0.2，不能继续引用历史绿灯代表当前状态。
- 未修改上述集成模块、删除测试、切换/回滚分支或覆盖协作文件。需在团队选定交付分支上对齐源码与测试。本轮主目标“真实运行漏洞闭环”未完成。
- 具体报告：`docs/analysis/CJSON_MERGEPATCH_CASE_20260915.md`。新代码只服务本案例，不扩展静态规则；LLM继续暂停。

## 历史验收状态（2026-09-14，完成主线与受限编译配置导入）

- 当前策略为先形成完整可交付流程，再优化展示、调度和性能；LLM仍暂停，不要求用户现在补密钥或等待接口修复。
- 新增`ohvul.compile_database`与26项测试，显式arguments导入为独立profile草稿，保留同文件不同配置；不执行command，不静默丢弃未知参数或失败条目。
- 导出草稿经过临时合成Git仓库和既有prepare_profile的实际来源校验；这不是OpenHarmony产品构建，也没有调用分析器或目标程序。
- 最终专项87项通过；全量579项运行、575项通过、4项环境跳过。测试期间Python字节稳定；初始验收因起始HEAD与后续外部整合提交不同而拒绝通过，原记录保留。
- 已核对外部edc065b/0f68447提交范围：包含上一批语义修改及本轮初版导入器，未撤销。最终确认以相同已测试Python字节及测试起始HEAD为准，记录见`.cache/completion_7db5/final-acceptance.json`。
- 真实产品数据库只检查八个明确位置，未发现；不据此断言全树不存在。未增加真实扫描覆盖或漏洞确认数。后续依赖与优先顺序见`NEXT_ROADMAP_20260914.md`。

## 历史验收状态（2026-09-14，暂停LLM后的语义规则与路径边界）

- 用户已明确暂停LLM部分，当前不安排模型接入开发、API重试或凭据操作；原有代码保留，离线回归保护继续运行。
- 本轮修复跨函数串联、嵌套/多行参数、snprintf参数位置、同名定义歧义、虚构来源行、静默读取失败和错误覆盖统计；主CLI接入实际执行记录并复核文件清单。
- 并行的跨平台CI提交已核对保留；额外修复Windows/WSL绝对路径父目录段及本机解析越界回归，没有回滚外部提交。
- 最终专项126项通过；全量553项运行、549项通过、4项符号链接环境跳过。最终日志和源代码版本绑定通过，`git diff --check`通过。
- 三个既有组件共44个文件完成两次一致的离线词法运行：camera 0个、securec 1个、hilog 0个局部候选，均0个跨函数关联；57项未解析事项显式保留，不宣称语义完整或代码安全。
- 原有35条引擎诊断、29组和145项任务未被本轮结果替换；确认漏洞仍为0。没有运行外部分析器、模型或目标程序。
- 最新证据为`.cache/semantic_0e7f/final_r2/acceptance.json`；审计见`docs/analysis/SEMANTIC_BOUNDARY_AUDIT_20260914.md`，契约见`docs/engineering/SEMANTIC_RULE_CONTRACT.md`。
- 后续优先受限编译数据库导入、编译器级事实、多漏洞族对照、无模型复核和性能/交付。LLM由用户后续安排恢复，不作为当前工作的前置条件。

## 历史验收状态（2026-09-14，LLM扩展证据与本地操作入口）

- 新增隐藏密钥本地入口 `tools/llm_local.py`；预检不需要凭据，运行须显式授权，支持300秒socket超时；实际超时与HTTP403分别记录，不自动重试。
- `llm_review --evidence`接入经重建验证的函数/宏/调用语法片段，扩展引用可继续进入交接；旧请求和历史失败记录保持兼容，不自动关闭任务。
- 专项89项通过；全量498项运行、494通过、4项符号链接环境跳过。真实单组与全部29组请求预检通过，0次API调用，131次片段引用，最大22289字节，无新增预算省略。
- 新凭据重试在工具输入阶段被拦截，未发出API请求，进程结束；没有新的403或服务超时数据。用户本机成功反馈未被旧403推翻，线上研判仍未验收。
- 35条原始诊断、29组、145项任务及原有截断/未穷尽标记保持；确认漏洞0。本轮没有静态分析器、模型或目标程序执行，也没有提交或回滚Git。
- 证据：`.cache/llm_operator_0e275/acceptance.json`、`real-plan/plan.json`、`all-groups-plan/plan.json`。本机操作见`docs/engineering/LLM_LOCAL_OPERATOR.md`；审计见`docs/analysis/LLM_OPERATOR_AUDIT_20260914.md`。
- 后续：人工安排首次本机在线运行与回执；自动工程并行修复语义规则边界、规范化构建输入和多漏洞族对照。完整规划见`docs/status/NEXT_ROADMAP_20260914.md`。

## 历史验收状态（2026-09-14，有界本地证据补全）

- 新增 `source_structure` 与 `review_evidence`，修复基础事实的函数归属；支持有界函数、宏和同文件调用语法补证及独立校验，不宣称 AST/CFG 或完整调用图。
- 最终专项53项通过；全量474项运行、470项通过、4项符号链接环境跳过。真实证据生成、独立复核和功能验收的源码/差异检查通过。
- 29组、16个相关文件产生93份证据片段（函数32、宏35、调用语法26）；3份片段截断，9组定义检索未穷尽，均显式记录。
- 44项原补证任务新增局部证据引用，全部145项任务仍待判断，task_id与原hand-off一致；35条原始诊断未改写，确认漏洞0。
- 没有新模型/API/静态分析器调用，没有执行目标程序。基础事实层修复不等于旧跨函数传播规则、产品宏语义或漏洞分析已完整验收。
- 本轮证据：`.cache/evidence_1ca10/acceptance.json`、`expanded.json`；使用约定见`docs/engineering/LOCAL_EVIDENCE.md`；后续规划见`docs/status/NEXT_ROADMAP_20260914.md`。

## 历史验收状态（2026-09-14，离线运行检查与研判交接）

- 用户已反馈服务本机可用；本次同端点单组重试的凭据输入被工具安全检查拦截，尚未发出 API 请求，等待进程已结束。没有新的 403 或成功回答，不推断服务端仍不可用。
- 新增 `llm_review --inspect`，一致的失败记录可核对但仍为 `bound_incomplete`；`--verify` 仍拒绝失败推理。新计划显式约束失败后停止，旧计划只按历史契约解释。
- 新增 `review_handoff`：保留所有组和五类待补证据问题，模型观点单独标为不可信建议，不能执行命令、删除候选或自动关闭任务。
- 本轮真实交接：35 条原始诊断、29 个组、145 项待补证据任务；3 组历史调用失败，26 组历史未选中，29 组均无合格的线上草稿。确认漏洞仍为 0。
- 工程验收：专项 68 项通过，全量 440 项运行、436 项通过、4 项符号链接环境跳过；真实历史记录检查、交接构建及独立验证、字节/HEAD/差异检查通过。
- 证据：`.cache/llm_retry_cbad/acceptance.json` 与 `handoff.json`；说明见 `docs/engineering/REVIEW_HANDOFF.md`、`docs/analysis/LLM_HANDOFF_AUDIT_20260914.md`。线上验收和整个比赛项目仍未完成。
- 不依赖在线调用的上下文补充、证据与研判记录继续推进；不默认缩减组件或漏洞族范围。

## 历史验收状态（2026-09-14，LLM 结构化研判接入）

- 新增显式 LLM plan/run/verify 链路，默认端点为 `https://oslovelace.com/v1`，请求模型标识 `grok-4.6`；运行时凭据不落盘。普通扫描和独立校验仍不请求网络。
- 专项39项全部通过；全量411项运行、407项通过、4项符号链接环境跳过。验证伪造证据引用、错误与用量统计、模型输出拒绝、输入变更、预算和鉴权失败停止。
- 线上实测未通过：对三组真实候选发起三次 API 请求，均收到 HTTP 403，无模型回答或用量。原始35条诊断、29组队列保持不变；所有组仍无合格的线上研判。
- 进一步诊断的工具调用被安全检查拦截，未换路径尝试；服务端模型/凭据/API访问策略需要人工确认，不再次要求粘贴密钥。该阻塞不等于凭据已被证明无效。
- `final_verdict` 仍为 `undetermined`，模型不能改变FSM或执行工具。代码测试通过不代表线上模型、漏洞影响或完整比赛交付通过。
- 证据：`.cache/llm_review_5382/final-acceptance.json` 和 `live/summary.json`；说明见 `docs/engineering/LLM_REVIEW.md`、`docs/analysis/LLM_INTEGRATION_AUDIT_20260914.md`。
- 后续继续推进证据与调用上下文、人工研判记录和离线评测；保持组件与漏洞族总体范围。产品/版本矩阵和隔离验证环境仍独立安排。

## 历史验收状态（2026-09-14，正式复核队列与源码上下文）

- 新增正式 `review_queue` 与 `review_context` 入口，及独立 `--verify`；专项39项通过，全量375项运行、371项通过、4项符号链接环境跳过，差异检查通过。
- 消费上一批三个真实组件的已验收产物，35条原始诊断全部保留为29个复核组；从16个相关文件提取29组原始行号文本窗口，来源快照前后及独立校验通过。未重新运行分析器，未增加本轮扫描覆盖。
- 复核问题、类别和文本窗口均非漏洞结论；所有最终判断仍为undetermined，确认漏洞数0。源码文本标记为不可信数据，不作为模型或工具指令。
- 当前推进点是人工/受控LLM研判的证据输入层；实际模型调用、完整安全影响研判、真实PoC/独立复现、分支修复验证和比赛交付仍未完成。
- 新证据：`.cache/review_33f843/acceptance.json`、`queue.json`、`context.json`；约定与实测见`docs/engineering/REVIEW_QUEUE.md`、`docs/analysis/REVIEW_PIPELINE_AUDIT_20260914.md`。
- 保留组件和漏洞族总体范围；本轮不新增必须人工完成的前置条件。既有产品/版本矩阵与隔离验证环境安排继续独立推进。

## 历史验收状态（2026-09-14，真实组件批次）

- 最新工程验收：多组件批处理入口已落地；专项 90 项全部通过，全量 336 项运行、332 项通过、4 项符号链接测试因环境限制跳过；`git diff --check` 通过。
- 源码访问更新：`C:\Projects\OpenHarmony-complete` 已能实际校验和分析。camera 的 13 个依赖仓库匹配既定提交；本轮没有修改 OpenHarmony 源码树或执行目标程序。
- 真实批次：camera 3 个、安全 C 库 39 个、hilog 2 个源文件，两个真实静态引擎全部完成；预检 3/3 ready，正式批次 3/3 completed。结果、报告和最终摘要哈希一致。
- 发现口径：35 条原始诊断仅归为 29 个复核位置/规则组（27 个 API 提示组、2 个代码质量信号组），原始证据保留；真实漏洞确认数仍为 0。
- 策略更新：按用户最新要求保持组件和漏洞族范围，不把首批三个组件当成永久范围，不再用此前收缩范围的估算作当前交付承诺。
- 最新证据：`.cache/real_components_c0d3/acceptance.json` 与 `batch/summary-0005.json`；说明见 `docs/analysis/REAL_COMPONENT_BATCH_AUDIT_20260914.md`；人工安排见 `docs/status/HUMAN_ACTIONS_20260914.md`。
- 比赛关键缺口仍包括完整产品构建条件、安全影响研判、实际 LLM 业务流程、真实 PoC/独立复现、分支与补丁验证、大规模性能和最终材料。以下为历史记录，不能覆盖本节。

## 历史验收状态（2026-09-14，候选质量批次）

- 最新批次：候选质量、CWE 映射与观察证据校验已完成本地回归；专项 104 项、全量 304 项全部通过，无跳过；真实本地 Clang/clang-tidy 合成静态演示通过。
- 内置规则在本次合成安全对照上的候选从 2 条降为 0 条；三个来源对同一处合成缺陷产生 3 条候选，不计为 3 个漏洞。验收记录中的真实漏洞确认数仍为 0。
- 当前定位：可复跑的本地防御性审计原型，不是已完成比赛成品。真实 OpenHarmony 工作区访问先前受阻；本轮没有绕过限制或执行真实目标程序。
- 比赛关键缺口：真实组件输入与安全影响研判、真实 PoC 和独立复现、分支/修复有效性、实际规模评测、正式手册/视频/交付包；LLM 仍未形成已验证的完整研判流程。
- 最新证据：`.cache/quality_57a_r2_acceptance.json`；详见 `docs/analysis/CANDIDATE_QUALITY_AUDIT_20260914.md` 与 `docs/status/COMPETITION_READINESS_20260914.md`。后者给出条件化人力估算，不承诺发现数量或官方评审时限。
- 以下为历史工程记录。历史 Phase 编号和测试数量不得覆盖本节当前验收口径。

## 历史状态（2026-09-12；不代表当前完成度）

- 阶段：Phase 6 性能评测和交付准备；当前新增完成成熟引擎适配层与受控 Clang 分片闭环，Phase 4、Phase 5 的允许范围闭环已完成，完整比赛成品仍未完成。
- Phase 4：静态证据独立复核、合成 harness、FSM `local_verification`、checkpoint/result/harness 联合校验、源码快照绑定和人工审核门控已完成；真实目标代码执行仍禁止。
- Phase 5：本地固定版本输入契约、Git revision/range 原型、分支影响比较、补丁路径与 SHA-256 校验、影响报告草稿和审核批次接入已完成原型；真实提交区间到补丁有效性的完整闭环仍未完成。
- Phase 6：性能基准、峰值内存、吞吐退化比较、性能快照、CI smoke 和演示文档已完成原型；完整授权 OpenHarmony 子树长期评测、最终用户手册、视频和交付包仍未完成。
- 分析引擎适配：已接入 WSL LLVM 22.1.8 Clang Analyzer plist、clang-tidy 文本诊断、显式文件清单/分片、schema 0.3/EvidenceBundle、主 CLI static_scan 合并和本地 CVE/CWE 交叉匹配；OpenHarmony 当前裁剪快照仍不能代表完整平台构建分析。
- 真实组件输入：原 `C:\Projects\OpenHarmony` 为裁剪快照；已在独立 `C:\Projects\OpenHarmony-complete` 工作区补齐 camera 直接依赖并用显式 GN include/define 参数成功解析 `camera_ability.cpp`（Clang completed，0 条诊断）。该工作区尚未完成产品级全量构建，不能扩展为平台级结论。
- cameraApp 组件验证：`camera_ability.cpp`、`camera_ability_slice.cpp`、`camera_manager.cpp` 在补齐 surface/media/IPC/hilog/securec 头文件路径后 3/3 Clang completed、0 个输入错误、0 条诊断；仍属于组件级静态分析，不是全平台结论。
- 最近验证：`python -m unittest discover -s tests -q`，180 项通过、4 项环境相关跳过。
- 当前结论：项目是可运行的防御性 MVP 和比赛候选原型，不是已完成的比赛成品；候选发现不等于漏洞确认，主机测试不等于 OpenHarmony 平台结论。
- 后续顺序：完成适配层正确性收敛，固定组件 profile 和跨函数工具试验，随后扩展高价值漏洞族、补丁验证、人工评测、真实性能和交付材料。
- Phase 1 适配器正确性检查点：已完成 alert_id 冲突消解、Clang/clang-tidy/Semgrep 来源保留、外部结果 schema 校验、源码根与快照一致性、显式文件/分片路径、WSL 路径归一化及越界拒绝；178 项测试通过、4 项环境相关跳过。该检查点只证明适配器契约，不证明分析器覆盖率或漏洞成立。
- Semgrep profile 增量：profile 可声明源码根内的 `semgrep_rule_files`；仅在 engines 明确包含 `semgrep` 时执行，并通过统一结果合并链保留候选状态。规则文件不得使用绝对路径、`..` 或远程来源。
- 本地 camera Semgrep 试验：在 `C:\Projects\OpenHarmony-complete\tools\wildtrace\camera_pilot.yml` 使用合成 `strcpy` 规则对 camera_ability.cpp 运行本地 Semgrep，规则 SHA-256 为 `CB307513B7BA9C6F00E712BE2C85D0DBBEC7ABEB3F1DF4D5FFBDFEB17B53B5EF`，扫描完成且 0 条诊断；这是组件级静态结果，不是平台漏洞结论。profile 端到端结果仍需单独记录可复现命令输出。
- 新增 `docs/design/camera_semgrep_profile.json`，固定 camera 组件源码提交、规则相对路径和规则哈希；配置状态为 `candidate_only`，执行仍须先在源码根内人工放置并校验规则文件。
- 分析能力增量：新增 `ohvul.semantic_facts`，对显式本地 C/C++ 文件提取函数、调用、分配、释放、复制和解引用事实，输出可序列化结构供后续长度传播/生命周期规则使用；这是保守词法事实层，不等同于编译器 AST，也不直接产生漏洞结论。全量测试 182 项通过、4 项环境相关跳过。
- 长度传播规则增量：新增 `ohvul.semantic_rules.length_candidates`，将显式复制 sink 与附近长度源/边界证据关联，输出 `candidate` 和人工复核问题；修正 sink 行自匹配边界。全量测试 184 项通过、4 项环境相关跳过。
- 跨函数长度传播增量：新增 `cross_function_length_candidates`，在显式文件集合内关联 caller 长度源、callee 参数和复制 sink；仅输出候选证据。专项测试 3 项通过。
- 语义候选证据增量：新增 `candidates_to_audit_result`，将长度传播候选转换为 schema 0.3、EvidenceBundle、源码快照和人工审核可消费的 `candidate` finding；专项测试验证 `validate_result` 联合校验。
- 主 CLI 语义阶段增量：新增显式 `--semantic-files-from`，把本地跨函数长度候选并入标准结果和快照链；默认扫描行为不变，端到端 smoke 已通过。
- 历史记录说明：本文件以下条目为追加式历史记录；如与本节冲突，以本节为准。历史条目不得作为已完成能力的单独证据。

## 本次已完成

新增 ohvul/archive_seal_record.py，复用归档校验再创建标记。输出独立于归档，使用独占创建，拒绝覆盖已有文件，没有 --force 开关。增加 tests/test_seal_record.py 覆盖正常生成/校验、重复写入、源归档保护和无效输入。

从 ohvul/journal_archive_verify.py 提取 validate_archive，使归档校验入口和标记生成使用相同规则。文档更新见 docs/engineering/ARCHIVE_LIFECYCLE.md。

## 当前能力边界

- 本地文本规则扫描、启发式组件识别、精确版本候选匹配、JSON 证据、检查点、日志、报告、人工审核记录及归档均已存在。
- 大多数是原型；没有证据证明高准确率、全面覆盖、真实 OpenHarmony 漏洞确认或提交能力。
- 封存仅是普通 JSON 内容关联标记，不是数字签名、身份验证或文件系统只读控制。
- 标记生成只校验归档结构和事件摘要，不代替源扫描、报告和审核链的联合验证。
- 独占创建不提供多文件事务。写入过程突然中断可能留下不完整新标记；应检查后换新输出路径，不能视为成功。

## 尚未完成的关键项

- FSM 在直接 transition 与恢复入口之间的统一门控、恢复重试预算的端到端保持。
- 源码读取范围的一致性、扫描期间输入变化检测和严格错误报告。
- 报告投影字段与扫描结果的完整一致性、审核身份与批次摘要的可信绑定。
- 元数据库读取与摘要同源、时间筛选的真正日期比较、旧格式迁移契约。
- 构建/语义分析、评测基准、用户手册、最终比赛交付物。
- 持久化的多文件事务、跨进程互斥和目录替换竞争防护。

## 恢复操作

1. 读取本文件、CHANGELOG.md 和相关工程契约。
2. 使用上述命令确认代码基线，不重写过去的测试数量。
3. 本次修改文件：ohvul/archive_seal_record.py、ohvul/journal_archive_verify.py、tests/test_seal_record.py，以及状态/归档生命周期/变更文档。
4. 下一步继续 Phase 3 核心验收：报告投影字段已补强，转向扫描规则与误报基准。

## 阻断与输入

仅使用临时合成 JSON 验证，没有生成真实操作者审核或封存记录。测试临时文件已自动清理。若未来真实路径受阻，应保留错误与最后成功检查点，再选择允许的恢复路径；不得尝试规避限制。

## 报告端到端绑定增量

新增 CLI 回归：同时保存扫描 JSON 和 candidate-only 报告，再用 report_verify 校验绑定。76 项测试，72 通过、2 跳过。

## 扫描期间输入门禁增量

CLI 在扫描前后比较 source_snapshot_sha256；源码扫描期间变化会拒绝生成结果链。76 项测试，72 通过、2 跳过。

## 报告字段投影增量

validate_report_against_result 现在要求候选告警集合、告警 ID、CWE、规则、位置和 evidence_refs 与扫描结果完全一致；76 项测试，72 通过、2 跳过。

## 规则质量小增量

扫描器支持行级 `// ohvul:ignore` 明确抑制某条候选，其他行仍扫描；新增两个回归测试。该注释是人工抑制记录，不是安全证明。

## 静态规则基准增量

新增 docs/design/rule_benchmark.json，覆盖内存复制候选、人工忽略、上下文相关候选和安全控制样例；新增回归测试。76 项测试通过，2 项跳过。

## 基准统计增量

新增 python -m ohvul.benchmark docs/design/rule_benchmark.json，输出候选 TP/FP/FN、precision/recall 和逐例结果，明确免责声明。76 项测试通过，2 项跳过。

## 基准规则扩展增量

增加整数长度和指针解引用候选样例；为避免规则重叠，内存复制行不重复报告 CWE-476。81 项测试，75 通过、2 跳过。

## 安全反例增量

增加已显式判空但仍被启发式指针规则命中的安全反例，作为可解释的 FP 候选；81 项测试通过，2 项跳过。

## 基准原因标注增量

每条合成样例新增 reason，解释候选、人工抑制、安全反例或需要上下文的标注依据；81 项测试通过，2 项跳过。

## 规则重叠统计增量

benchmark 输出 rule_overlap_cases，并为每例输出 rule_overlap 和 reason；用于识别同一行多规则重复命中。81 项测试通过，2 项跳过。

## 基准统计快照增量

生成 docs/design/rule_benchmark_report.json：8 个合成样例，候选 TP=5、FP=2、FN=0、precision≈0.714、recall=1.0、重叠样例 1。该快照仅用于规则回归，不能外推真实准确率。

## 基准分类标签增量

规则基准样例新增 language/component 分类字段，支持后续按 CWE、语言和 OpenHarmony 组件类型分层统计；81 项测试通过，2 项跳过。

## 基准分层统计增量

benchmark 报告新增 groups，按 component::language 汇总 cases、TP、FP、FN；报告快照已重新生成。81 项测试通过，2 项跳过。


## 状态计数校准

以当前工作区实际命令为准：python -m unittest discover -s tests -q 运行 81 项，79 通过，2 跳过。历史增量文字不作为当前计数证据。


## 基准输入契约增量（2026-09-10）

benchmark 在任何临时文件创建前校验数组、字段集合、唯一 ID、标签/CWE 一致性、语言和 CWE 格式；CLI 对无效标注输出 INVALID。样例 ID 仅作为展示元数据，临时文件使用固定安全文件名。新增 5 个回归测试。全套 86 项测试，84 通过、2 跳过。

未完成：基准仍为小规模合成样例，不代表真实准确率；下一步继续扫描规则与误报基准扩展。

## OpenHarmony 受限源码样本扫描（2026-09-10）

用户授权本地源码目录 C:\Projects\OpenHarmony。只读盘点发现约 292,493 个 C/C++ 文件；为避免全仓库扫描造成不可控资源消耗，本次仅扫描 commonlibrary/utils_lite/timer_task 子树。输出 docs/design/openharmony_timer_task_scan.json，verify 校验通过（29 条不同证据记录）。结果仅为候选发现，不代表 OpenHarmony 平台漏洞结论。

未完成：全仓库分片策略、忽略目录契约和误报人工基准仍待设计。下一步为受控分片扫描器设计。

## 受控分片清单增量（2026-09-10）

新增 ohvul.shards.build_manifest：按路径排序、过滤 C/C++ 扩展名、生成固定大小分片及路径列表 SHA-256；不读取源码内容、不执行代码。新增 2 项测试。下一步接入分片扫描调度与资源上限。


## 分片资源门控增量（2026-09-10）

分片清单新增 max_files 上限，非法预算会在扫描前拒绝；新增资源门控回归测试。仍未接入实际分片扫描调度。


## 分片扫描调度增量（2026-09-10）

scan_path 支持显式相对文件集合，新增 scan_shard 仅扫描清单分片；新增 2 项测试。尚未实现跨分片结果合并与超时控制。


## 跨分片合并增量（2026-09-10）

新增 merge_shard_results：绑定源码根目录、按位置和 CWE 确定性排序、去重证据并重新编号告警；新增合并回归测试。尚未进入 Phase 4，仍缺少超时/取消门控和本地独立复现契约。


## 回归校验（2026-09-10）

全套 python -m unittest discover -s tests -q：92 项，90 通过、2 跳过。分片清单、受限扫描和跨分片合并均有回归覆盖；Phase 3 尚未完成，待补合并结果的统一证据验证与本地安全验证契约。


## 分片证据验证增量（2026-09-10）

跨分片合并输出已接入现有 validate_result 回归校验，确认合并结果仍受证据引用和摘要门控约束。分片专项测试 7 项通过。尚未进入 Phase 4。


## 本地独立证据复核增量（2026-09-10）

新增 ohvul.local_recheck.recheck_finding，按授权源码位置重算行哈希并报告可复现性；不执行目标代码、不联网。新增 2 项测试。该步骤仍不构成漏洞确认，Phase 4 入口还需 FSM 门控与隔离 harness 契约。


## Phase 4 入口门控增量（2026-09-10）

新增 verification_gate.can_request_local_verification：仅允许 static_scan 状态且所有候选通过本地证据复核后请求隔离 harness 审查。新增 1 项门控测试。尚未执行 harness，故仍未进入 Phase 4。


## 隔离 harness 契约增量（2026-09-10）

新增 local_harness.evaluate_synthetic，仅接受合成 case，复用验证门控并始终输出 review_required=true、verdict=undetermined；不编译或执行目标代码。新增 2 项测试通过。Phase 4 尚未正式开始，需先完成 FSM 迁移接入和人工审核记录契约。


## 本地验证迁移意图增量（2026-09-10）

验证门控新增 request_local_verification_transition，只有 static_scan 且证据全部可复现时返回 local_verification 迁移意图；实际 FSM 状态枚举尚未扩展，避免破坏既有检查点兼容性。新增回归断言通过。


## FSM 本地验证状态增量（2026-09-10）

FSM 新增 local_verification 状态，static_scan 可显式进入本地验证，再回到 triage 或 blocked；保留原 static_scan->triage 路径。新增状态迁移测试通过。Phase 4 尚未开始，仍需把门控结果写入检查点并定义隔离 harness 记录 schema。


## Harness 记录 schema 增量（2026-09-10）

新增独立 harness_record.validate_record，固定 schema 0.1，要求 undetermined、review_required=true 和布尔 reproducible；拒绝 confirmed 等确定性漏洞结论。新增 2 项测试。Phase 4 入口条件接近，仍需将记录与 FSM local_verification 状态关联。


## Harness 记录关联增量（2026-09-10）

local_harness 新增 to_record，将合成评估结果投影为可校验的人工审核记录；保持 undetermined 和人工审核要求。


## 验证记录持久化关联增量（2026-09-10）

新增 verification_link，将 task_id、checkpoint_sha256 与 harness 记录摘要绑定并可离线校验；不修改旧检查点 schema。新增 1 项测试通过。Phase 4 入口所需关联链已具备，仍需端到端执行并更新阶段状态。


## Phase 4 已开始（2026-09-10）

端到端本地安全验证完成：对 timer_task 受限扫描的 29 条候选逐条重算源码行哈希，全部可复现；通过 static_scan 门控生成 review-only harness 记录和检查点关联，记录 verdict=undetermined、review_required=true。产物 docs/design/openharmony_timer_task_harness_record.json。此结果不是漏洞确认，也不代表 OpenHarmony 平台结论。


## Phase 4 首个闭环验收（2026-09-10）

独立校验 harness 记录 schema 与摘要关联通过；全套回归 101 项，99 通过、2 跳过。当前 Phase 4 仅完成静态证据复核和合成 harness 闭环，未执行目标代码，不能宣称漏洞复现。下一步继续做隔离环境输入/输出契约。


## 隔离 I/O 契约增量（2026-09-10）

新增 isolation_contract，限制 harness 输入为标量合成值，输出必须保持 undetermined、review_required=true、no_target_execution=true；新增 2 项测试通过。


## Phase 4 隔离契约回归（2026-09-10）

全套测试 103 项，101 通过、2 跳过；隔离输入输出契约与证据链兼容。Phase 4 当前闭环仍限于静态复核和合成 harness，未执行目标代码。


## 隔离资源预算增量（2026-09-10）

隔离输入契约新增 max_bytes（1..1MiB）和 timeout_ms（1..60s）预算校验；新增边界测试通过。


## 隔离预算执行校验增量（2026-09-10）

max_bytes 预算现在实际约束字符串/字节合成输入长度，新增超限回归测试；避免仅声明预算而不执行。


## Phase 4 回归核对（2026-09-10）

全套回归 103 项，101 通过、2 跳过；隔离预算与 harness/FSM 链路保持稳定。未执行目标代码，未生成真实攻击输入。


## Harness 输出即时门控增量（2026-09-10）

local_harness.evaluate_synthetic 现在生成结果后立即调用 isolation_contract.validate_output，确保 review-only 和 no_target_execution 约束不会被绕过。专项测试 4 项通过。


## Phase 4 回归稳定性（2026-09-10）

全套测试 103 项，101 通过、2 跳过；harness 输出即时门控修复后整体稳定。


## 隔离输入实际门控（2026-09-10）

evaluate_synthetic 现在强制调用 validate_input，预算与标量输入约束在运行入口实际生效；专项测试通过。


## Phase 4 回归确认（2026-09-10）

全套测试 103 项，101 通过、2 跳过；隔离输入门控修复后无回归。


## Phase 4 契约文档（2026-09-10）

新增 docs/engineering/PHASE4_LOCAL_VALIDATION.md，统一记录输入、输出、资源、证据绑定和验收边界。


## Harness 记录安全落盘增量（2026-09-10）

save_record 使用独占创建、拒绝符号链接和覆盖，记录先经 schema 校验；新增覆盖保护测试通过。


## Phase 4 全量回归（2026-09-10）

全套测试 104 项，102 通过、2 跳过；安全落盘与现有工作流兼容。


## 深入审计修复：符号链接一致性（2026-09-10）

审计发现 scanner 会跟随符号链接，与 source_snapshot 跳过策略不一致；现已显式跳过 symlink，并新增回归测试。专项测试 4 项，3 通过、1 跳过。


## LLM 运行时适配器增量（2026-09-10）

新增 ohvul.llm_adapter，仅在调用时从 OSLOVELACE_API_KEY 读取 key，默认不联网；请求内容明确限制为候选证据分析草稿，返回 final_verdict=undetermined。仓库与日志不保存 key。


## LLM 适配器离线安全回归（2026-09-10）

新增 mock 网络测试，验证运行时 key 仅进入授权请求头，不进入返回结果，且 final_verdict 始终为 undetermined。


## LLM 上下文边界增量（2026-09-10）

LLM 适配器现在只接受结构化 dict 且限制序列化上下文不超过 64 KiB，拒绝大规模源码误传；新增 2 项边界测试。


## LLM 超时资源门控（2026-09-10）

LLM 适配器 timeout 现在限制为 1..60 秒，与隔离资源契约一致；新增边界测试通过。


## LLM 运行时配置文档（2026-09-10）

README 新增可选 LLM 适配器配置说明，明确环境变量读取、显式调用和 review-only 输出边界。


## LLM 模型白名单增量（2026-09-10）

适配器新增模型白名单，当前仅允许已验证的 grok-4.6；新增未授权模型拒绝测试。


## LLM HTTPS 边界增量（2026-09-10）

LLM 适配器拒绝非 HTTPS Base URL，新增离线测试；避免 key 通过明文 HTTP 传输。


## LLM 响应 schema 校验增量（2026-09-10）

适配器对 choices/message/content 做结构化校验，异常响应拒绝进入分析链，草稿必须为文本；专项测试通过。


## LLM 输出大小门控增量（2026-09-10）

适配器限制模型草稿不超过 16 KiB，避免异常响应污染后续证据链；编译检查通过。


## CI 离线回归增量（2026-09-10）

新增 .github/workflows/offline-tests.yml，在 push/PR 上运行本地 unittest；不使用 secrets、不联网扫描目标。


## CI 密钥形态门禁增量（2026-09-10）

离线 CI 新增 sk- 形态凭据扫描，防止未来提交意外包含 API key；仅扫描仓库内容，不访问网络。


## 本地凭据忽略规则增量（2026-09-10）

.gitignore 新增 .env、密钥和 secrets 文件模式，与 CI 凭据扫描共同降低误提交风险。


## CI 最小权限增量（2026-09-10）

离线测试工作流新增 contents: read 最小权限声明，减少 CI 任务写入仓库的能力。


## 跨平台 CI 验证（2026-09-11）

GitHub Actions offline-tests 在 Ubuntu 上对提交 beadf8d 执行成功；本地 Windows 全套测试仍为 108 项，105 通过、3 跳过。


## 可交付打包元数据增量（2026-09-10）

新增 pyproject.toml，声明 WildTrace 包元数据和 CLI 入口；无运行时联网依赖。


## 本地打包验证（2026-09-10）

editable 安装（--no-deps）成功，wildtrace --help 可用；生成目录已加入忽略规则。原清理命令受环境策略阻断，未重复尝试。


## 本地安装文档增量（2026-09-10）

README 补充无 key 的本地安装和离线测试命令，并说明仅显式调用 LLM 适配器时配置环境变量。


## 公开仓库安全策略文档（2026-09-10）

新增 SECURITY.md，明确授权范围、候选结论边界和禁止提交真实攻击材料的规则。


## 协作者审核规则增量（2026-09-10）

新增 .github/CODEOWNERS，所有路径默认请求项目维护者 AerGap 审核。


## 验证关联安全持久化增量（2026-09-10）

save_link 将 checkpoint/harness 关联记录安全写入独立文件，先校验摘要和 review-only 约束，拒绝覆盖及符号链接；新增测试通过。


## 分片合并资源门控增量（2026-09-10）

merge_shard_results 新增 max_shards 上限，防止超大源码树结果无界合并；专项测试通过。


## 扫描网络隔离回归（2026-09-10）

新增测试确认普通 scan_path 流程不会调用 urllib 或 LLM；网络仅存在于显式适配器入口。


## 验证摘要格式门控增量（2026-09-10）

verification_link.validate_link 现在严格要求 checkpoint_sha256 为 64 位小写十六进制摘要；新增伪造摘要拒绝测试。


## 分片证据冲突门控增量（2026-09-10）

跨分片合并遇到相同 evidence_id 但内容不同的记录现在明确拒绝，防止证据替换；新增冲突测试通过。


## Phase 4 验收清单（2026-09-10）

新增 PHASE4_ACCEPTANCE.md，按证据列出本地复核、隔离契约、FSM、检查点关联、合成 harness 和回归状态，并明确未执行目标代码、未确认漏洞。


## 验证关联恢复增量（2026-09-10）

新增 load_link，重启后从磁盘读取并重新校验 harness 摘要绑定；新增恢复读取断言通过。

## 当前有效检查点说明（2026-09-10）

文档前部的历史条目保留作记录；当前有效状态以文档末尾最新检查点为准：Phase 4 已开始，验证链和 CI 已通过，后续聚焦隔离 harness 与检查点进一步集成。

## Phase 4 闭环检查点（2026-09-11）

Phase 4 的允许范围已完成：静态证据独立复核、合成 harness、输入输出预算、FSM local_verification、检查点摘要关联、冲突拒绝、恢复读取、跨平台回归和 CI 门禁均已验证。真实 OpenHarmony 目标代码执行仍被禁止，因此不产生漏洞确认结论。下一阶段为 Phase 5：分支影响、补丁验证和报告。


## Phase 5 分支影响比较增量（2026-09-11）

新增 branch_impact.compare_findings，仅比较本地保存结果的 evidence_id，输出新增/消失候选并要求人工审核；不访问远程 Git。新增测试通过。


## Phase 5 补丁范围门控增量（2026-09-11）

新增 validate_patch_scope，限制补丁路径在授权源码根目录内，拒绝路径穿越；新增测试通过。


## Phase 5 结果 schema 门控增量（2026-09-11）

分支影响比较器严格要求扫描结果 schema 0.3，拒绝旧格式；测试通过。


## Phase 5 本地路径门控增量（2026-09-11）

补丁范围校验明确拒绝 URL 形式路径，确保仅处理本地路径；新增测试通过。


## Phase 5 源码根目录绑定增量（2026-09-11）

分支影响比较器现在拒绝不同源码根目录的扫描结果，避免跨项目误比较；测试通过。


## Phase 5 本地来源门控回归（2026-09-11）

新增测试确保分支影响比较拒绝非 local_only 扫描结果；专项测试 3 项通过。


## Phase 5 findings 结构门控增量（2026-09-11）

分支影响比较器校验 findings 结构和 evidence_id 类型，损坏输入明确拒绝；新增测试通过。


## Phase 5 分支影响 CLI 增量（2026-09-11）

branch_impact 支持 python -m ohvul.branch_impact 对两份本地 JSON 结果做离线比较，错误输入输出 INVALID；不访问远程 Git。


## Phase 5 CLI 回归覆盖增量（2026-09-11）

新增分支影响 CLI 成功路径测试，验证本地 JSON 比较输出可解析；专项测试 5 项通过。


## Phase 5 CLI 安装入口增量（2026-09-11）

pyproject 新增 wildtrace-impact 入口，调用离线分支影响比较器；不访问远程 Git。


## Phase 5 JSON 根类型门控增量（2026-09-11）

分支影响比较器明确拒绝非对象 JSON 根值，避免未捕获属性异常；专项测试通过。


## Phase 5 补丁摘要校验增量（2026-09-11）

新增 verify_patch_hashes，对授权源码根目录内文件进行 SHA-256 校验，拒绝越界和摘要不匹配；测试通过。


## Phase 4 联合文件校验入口增量（2026-09-11）

新增 validate_joint_files，联合读取 checkpoint、scan result 和 harness record，校验检查点摘要、任务 ID、结果 evidence 及 harness link；编译与相关测试通过。


## 验证 link 生成格式一致性（2026-09-11）

make_link 与 validate_link 统一要求小写十六进制 SHA-256 摘要，生成端不再产生必然无效的 link；相关测试通过。


## Phase 5 补丁摘要格式门控（2026-09-11）

verify_patch_hashes 严格要求期望摘要为 64 位小写十六进制 SHA-256；新增格式拒绝测试。


## Phase 5 影响草稿投影增量（2026-09-11）

新增 make_impact_draft，将本地分支影响比较投影为 candidate_only 审核草稿，confirmed_vulnerabilities 固定为 0；测试通过。


## Phase 4 联合验证 CLI 增量（2026-09-11）

新增 verify-joint / python -m ohvul.verify_joint，直接调用联合文件校验并输出 OK/INVALID；不联网、不执行目标代码。


## Phase 5 影响草稿 schema 校验（2026-09-11）

新增 validate_impact_draft，分支影响草稿固定 candidate_only、confirmed_vulnerabilities=0 和 review_required=true；测试通过。Phase 5 尚未完成，仍需正式报告绑定与补丁前后证据闭环。


## Phase 5 影响报告投影增量（2026-09-11）

新增 impact_report，绑定 base/revised 扫描结果摘要并嵌入 review-only 影响草稿；输出 verdict=undetermined。新增测试通过。Phase 5 仍需与正式报告/审核批次链路集成。


## Phase 5 审核报告投影增量（2026-09-11）

impact_report 新增 project_for_review，为现有审核 API 添加 task/report 工作流封装，保持 candidate_only、confirmed_vulnerabilities=0；测试通过。


## Phase 5 任务关联校验（2026-09-11）

影响报告投影新增无效 task ID 拒绝测试，确保审核链任务关联合法。


## Phase 5 审核 API 接入验证（2026-09-11）

验证影响报告投影可直接进入 create_review/validate_review，且审核记录仍保持 final_vulnerability_verdict=false；测试通过。


## Phase 4 联合输入 symlink 门控增量（2026-09-11）

validate_joint_files 统一拒绝 checkpoint/result/harness 符号链接输入，与扫描器和快照策略一致；新增测试通过。


## Phase 5 审核批次接入增量（2026-09-11）

新增 create_impact_review_batch，将影响报告投影接入现有 review/review_batch 链路；批次 final_vulnerability_verdict 固定为 false。专项测试通过。

## Phase 5 允许范围闭环（2026-09-11）

分支影响比较、补丁路径和 SHA-256 校验、影响报告草稿、任务绑定、人工审核批次接入及回归门禁均已完成并通过 123 项测试（119 通过、4 跳过）。这些能力只处理本地保存结果，不证明真实分支影响或漏洞成立。正式进入 Phase 6：性能评测、演示和交付准备。


## Phase 6 性能评测增量（2026-09-11）

新增 performance.benchmark_scan，在边界内生成合成 C 源码并统计扫描耗时/吞吐；结果标记 local_only、no_execution。新增 2 项测试通过。


## Phase 6 性能 CLI 增量（2026-09-11）

新增 wildtrace-perf 安装入口和 CLI JSON 回归测试；性能基准仍限于合成源码和明确资源预算。


## Phase 6 性能 CLI 回归（2026-09-11）

性能专项 3 项和全量测试 126 项均通过（122 通过、4 跳过）；性能 CLI 不触发目标代码执行或网络扫描。


## Phase 6 性能契约文档（2026-09-11）

新增 PHASE6_PERFORMANCE.md，记录合成基准命令、资源范围、输出字段和不可外推限制。


## Phase 6 多规模性能矩阵增量（2026-09-11）

新增 benchmark_matrix，在 1..10000 文件边界内执行合成扫描矩阵，输出各规模吞吐；新增测试通过。


## Phase 6 CI 性能 smoke 增量（2026-09-11）

CI 新增 python -m ohvul.performance --files 1 --lines 1 smoke test，验证性能入口可运行且使用受限合成输入。


## Phase 6 性能退化比较增量（2026-09-11）

新增 compare_throughput，比较本地基线吞吐并在退化超过阈值时标记失败；结果要求人工审核，不自动改变安全结论。


## Phase 6 本地演示文档增量（2026-09-11）

新增 LOCAL_DEMO.md，串联安装、扫描、证据验证、分支影响、联合验证和性能基准命令，明确候选不等于漏洞确认。

## Phase 4 FSM 联合校验门控（2026-09-11）

`local_verification -> triage` 现在必须提供 checkpoint/result/harness 三个文件；FSM 会调用联合校验，并在失败时保持原状态不变。相关专项 47 项测试通过（1 项跳过）。


## Phase 6 性能结果 schema 增量（2026-09-11）

新增 validate_performance_result，校验性能结果 schema、耗时类型及 local_only/no_execution 安全字段；测试通过。


## Phase 6 吞吐字段门控增量（2026-09-11）

性能结果校验新增 files_per_second 非负数检查，拒绝异常吞吐记录；测试通过。


## Phase 6 性能 CLI 即时 schema 门控（2026-09-11）

性能 CLI 输出前立即调用 validate_performance_result，确保 schema 和安全字段实际生效；专项测试通过。


## Phase 6 受控分片调度增量（2026-09-11）

新增 scan_manifest，按清单顺序逐片扫描并通过 max_shards 门控后合并结果；新增调度测试通过。尚未覆盖长期性能和取消/超时。


## Phase 4 源码快照联合门控（2026-09-12）

validate_joint_files 现在核对 checkpoint 与扫描结果的 source_snapshot_sha256，快照不一致时拒绝；新增测试通过。

## Phase 4 快照联合门控回归（2026-09-12）

全套测试 135 项，131 通过、4 跳过。source_snapshot_sha256 联合校验与完整工作流无回归；仍未执行真实目标代码。


## Phase 6 峰值内存评测增量（2026-09-12）

性能基准新增 tracemalloc 峰值内存 peak_memory_bytes 指标及非负校验；性能专项测试通过。


## Phase 6 性能结果安全落盘（2026-09-12）

save_performance_result 先校验性能 schema，再独占创建 JSON，拒绝覆盖和符号链接；测试通过。


## Phase 6 性能结果恢复增量（2026-09-12）

新增 load_performance_result，读取后重新执行性能 schema 校验，支持基线安全恢复；测试通过。


## Phase 6 性能报告格式化增量（2026-09-12）

新增 format_performance_report，将性能矩阵格式化为包含耗时、吞吐、峰值内存和候选数的 Markdown；报告明确为合成本地测量。


## Phase 6 性能基线快照（2026-09-12）

生成 docs/design/performance_baseline.md，记录 1/5/10 文件合成基准的耗时、吞吐、峰值内存和候选数；仅用于同环境回归，不代表真实平台性能。


## 本地漏洞知识库增量（2026-09-12）

新增 knowledge_base.load_records，校验版本化本地 CVE/CWE 记录、组件、受影响/修复版本和来源，并生成 records_sha256；不联网加载。新增 2 项测试通过。


## 知识库资源管理修复（2026-09-12）

知识库加载改用 Path.read_text，消除未关闭文件句柄警告；ResourceWarning 严格测试通过。


## 知识库精确匹配增量（2026-09-12）

新增 match_records，按组件和受影响版本执行确定性 exact 匹配，未命中返回空候选；测试通过。


## 知识库 unresolved 匹配增量（2026-09-12）

组件已知但版本未精确匹配时返回 unresolved 候选，避免静默漏报并保留人工复核入口；测试通过。


## 知识库来源摘要绑定增量（2026-09-12）

知识库匹配结果新增 knowledge_base_sha256 和 source_record_sha256，绑定整体数据库与具体源记录摘要；测试通过。


## 本地漏洞知识库契约文档（2026-09-12）

新增 LOCAL_KNOWLEDGE_BASE.md，明确字段、exact/unresolved 匹配、摘要绑定和人工审核边界。


## 知识库文本字段门控增量（2026-09-12）

知识库校验新增 summary/component/source 非空约束，拒绝不完整来源记录；测试通过。


## 知识库文件大小门控增量（2026-09-12）

知识库加载新增 16 MiB 文件大小上限，超限输入在解析前拒绝；测试通过。


## Phase 5 本地固定版本输入契约增量（2026-09-12）

新增 git_scope.validate_scope，校验本地 source_root、revision/branch、日期范围和组件范围，拒绝 URL/远程引用；新增 2 项测试。


## Phase 5 本地 Git adapter 增量（2026-09-12）

新增 git_scope.inspect_revision，使用无 shell 的本地 git 命令读取 commit、父提交和变更文件；新增本地 HEAD 检查测试。


## Phase 5 Git scope 摘要绑定增量（2026-09-12）

Git adapter 记录 observed_branch 和 changed_files，并生成 scope_sha256 绑定范围记录；测试通过。


## Phase 5 本地提交区间增量（2026-09-12）

新增 git_scope.inspect_range，按固定日期范围读取本地提交列表和变更文件；测试通过。
## 当前运行级案例状态（2026-09-15）

- 固定 cJSON 提交 `388cfc96925e4fb41a30735b270736626d26615d` 的本地 MergePatch 案例已在已签署授权范围内完成 bubblewrap 隔离运行：原版/独立副本出现预期 `library_uaf_observed`，补丁与控制组通过功能控制。
- 运行矩阵为 `passed`，但这是公开已知库案例；OpenHarmony 产品可达性未建立，确认产品漏洞数仍为 0。详见 `docs/analysis/CJSON_RUNTIME_CASE_20260915.md`。
