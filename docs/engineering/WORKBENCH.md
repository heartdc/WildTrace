# WildTrace 本地审计工作台

本工作台提供扫描、候选复核、案例证据、模型建议、cJSON 隔离验证和报告导出。它使用仓库真实数据；候选、库级复现、产品影响和官方接受分别记录。开发分支为 `codex/frontend-workbench`。

React 版使用 `frontend/` 和 `ohvul/workbench/`，与仓库中的 Vue 版 `web/`、`ohvul.webapp` 分别启动。React 版默认端口 8765，数据保存在 `.cache/workbench/`；两版的本地数据格式没有自动同步。

## 源码项目与案例编辑

“源码项目”支持 Windows 绝对目录及 WSL 分发版内的 `/home/...` 路径。可以浏览目录、保存组件名、固定 Git 提交、选择子目录或文件、排除构建目录。WSL 项目通过该分发版中的 Python 执行静态扫描，任务保存选择范围和文件摘要；不执行源码。

扫描输入副本只纳入 C/C++ 源码及相关构建元数据，单文件上限 20 MiB、单次上限 1 GiB 或 50000 个文件。超限或选择范围不存在时明确失败。案例源码提取要求干净的 Git 检出，一次最多 400 行；记录提交、文件摘要及行号。

候选详情支持创建本地案例和关联已有案例。“材料编辑与关联”支持字段编辑、历史版本查看、文本附件关联、固定源码提取和关联任务。编辑只追加到工作台数据库，不改写仓库原始案例；并发编辑会检查版本号，旧版本不能覆盖新版本。

每个案例分别显示材料缺项、附件摘要校验、关联运行观察及尚缺的独立复跑记录。填入命令或上传日志不会自动变成运行通过。报告及 ZIP 使用选定案例版本，并带入关联任务和附件摘要。文本材料单项不超过 512 KiB。

## 启动

要求 Windows、Python 3.10+、Node.js 22.12+ 和 npm。在仓库根执行：

```powershell
.\Start-Workbench.ps1
```

脚本创建 `.venv`、安装 `.[workbench]`、执行 `npm ci` 和前端生产构建，随后启动本机服务。默认地址是 `http://127.0.0.1:8765`；端口占用时自动选择空闲端口，以终端输出为准。后续无需重装时执行 `Start-Workbench.ps1 -SkipInstall`。停止终端中的服务会结束当前工作进程。

前端源代码位于 `frontend/`，FastAPI 接口位于 `ohvul/workbench/`。生产模式前后端同源。单独开发前端时仍需通过同源后端验收，不把开发服务器暴露到局域网。

## 数据与状态

- `.cache/workbench/workbench.db` 保存任务索引、设置及追加式人工复核记录；`tasks/<id>/` 保存请求计划、原始结果、日志及运行附件。
- `WILDTRACE_DATA` 或启动模块的 `--data-dir` 可以指定独立数据目录。比较不同前端版本时，分别使用独立目录和相同源码提交。
- `cases/` 及原始证据不由界面修改。导入 JSON 证据标为 `imported_unverified`，不会自动提升验证等级。
- 任务状态为 queued、running、completed、failed、cancelling、cancelled、interrupted。服务重启将未完成任务标记为 interrupted，不自动重跑；取消后的重跑产生新任务 ID。
- SSE 提供日志事件序号，断线后从 Last-Event-ID 续读。长任务在独立进程中串行执行，保留退出码；日志超过 2 MiB 或任务超时会停止任务。
- 分支矩阵默认只接受有提交及引用的 `branch_evidence`。上游版本判断放在 `upstream_predictions`，不能作为 OH 分支实证。历史工具若需要旧投影，可显式传入 `strict_evidence=False`；工作台不会使用此兼容选项。

## 模型

设置页面提供现有适配器支持的服务地址、模型、超时和输出 token 上限。临时 API Key 仅保存在后端内存，不回显、不写入数据库或日志，重启后清除。页面没有自动调用模型的行为。

在候选列表选择至多 5 项，打开模型分析，生成请求预览。页面显示实际发送的 system/user 内容、源码范围、模型和服务地址；点击发送后才创建串行调用任务。预览摘要及源码摘要在启动前重新核验。首次传输错误即停止，不自动重试。

模型生成的 PoC 始终为草稿，结构检查与编译、执行验证分开。草稿不能进入 cJSON 运行队列。当前在线传输验收使用模拟服务覆盖成功、拒绝、超时及截断；真实调用需要在界面配置有效密钥后主动启动。

## cJSON 验证

首版运行入口只接受已登记路径 `C:/Projects/OpenHarmony/third_party/cJSON`，提交必须为 `388cfc96925e4fb41a30735b270736626d26615d`，并满足案例文件中的源码哈希和干净工作区要求。环境为 WSL Ubuntu、`/usr/bin/bwrap`、`/home/airgap/llvm/bin/clang`。

工作台依次调用已有 cJSON 驱动的准备、隔离自检、构建、运行和离线校验。源码只读，补丁作用于任务副本；隔离自检失败后不回退宿主运行。执行过程记录原版、独立构建和补丁版的 26 项对照，结论只限库级证据。

其他案例可以浏览原始证据、下载仓库附件、导入新证据，但执行驱动尚未适配。它们不会显示可点击的运行按钮。

## 演示流程

1. 打开总览和案例库，说明候选、复现记录与确认产品漏洞数分别统计。
2. 在扫描任务填写已配置的 cJSON 源码目录，启动 Autopilot；查看日志、阶段和实际耗时。
3. 打开候选，检查源码摘要、CWE、原始记录；填写复核依据，保存为待验证。
4. 选择候选打开模型请求预览。未配置密钥时只演示预览；需要在线调用时配置密钥并明确发送。
5. 在运行验证执行环境预检，然后启动 cJSON 隔离验证。展示原版 UAF 与补丁、正常对照的实际结果。
6. 在报告中心选择案例和本次任务，预览缺项，导出 Markdown、JSON 或证据 ZIP。缺项不会被隐藏，附件包附 SHA-256 清单。

## 验证命令

```powershell
.\.venv\Scripts\python.exe -X utf8 -m unittest discover -s tests -q
cd frontend
npm ci
npm run build
npx playwright install chromium
npx playwright test
```

浏览器测试默认连接 `127.0.0.1:8765`。候选和真实运行结果的集成测试依赖一次源码扫描及成功的 cJSON 运行；没有对应任务时明确跳过。截图保存在 `frontend/test-results/`，目录已忽略。

## 接口摘要

- `GET /api/cases`、`GET /api/cases/{id}`：真实案例及证据；`POST /api/cases/{id}/evidence`：导入未核验证据。
- `POST /api/tasks/scan`、`GET /api/tasks/{id}`、`POST /api/tasks/{id}/cancel`、`GET /api/tasks/{id}/events`：任务与日志。
- `GET /api/findings`、`GET /api/findings/{id}`、`POST /api/reviews/{id}`：候选、源码上下文和人工复核。
- `PUT /api/model/connection`、`POST /api/model/preview`、`POST /api/model/run`：临时连接和明确启动的模型批次。
- `POST /api/runtime/preflight`、`POST /api/runtime/cjson`：已登记案例的验证流程。
- `POST /api/reports`：通过 format 选择 preview、markdown、json 或 zip。

写入接口要求 `X-Workbench: 1`；请求来源和 Host 限制为本机同源。服务不提供任意命令执行接口，文件下载限制在案例附件及任务产物范围。
