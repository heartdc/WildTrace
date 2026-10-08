# WildTrace 本地工作台（web/）

三页闭环：**扫描**（发起 autopilot 管线、看进度与历史）→ **分诊**（lead 列表 + 详情 + 保留/误报/备注）
→ **产出**（结果摘要、findings.md/PoC 预览、lead → case.json 骨架）。

## 运行

```sh
# 后端（仅绑 127.0.0.1；工作目录 .webwork/，案例骨架落 webcases/）
python -m ohvul.webapp            # 默认端口 8765

# 前端二选一：
#   生产：直接开 http://127.0.0.1:8765/（dist 已构建并随仓库分发）
#   开发：cd web && npm install && npm run dev  （5173 端口，/api 代理到 8765）
```

依赖：后端核心（ohvul.webapp_core）纯标准库；API 层需本地 `pip install fastapi uvicorn`
（CI 无此依赖时相关测试自动跳过）。前端为 Vue 3 + Vite，`npm run build` 产物在 `web/dist/`。

口径与安全约定（与工具一致）：仅本地读取、不执行目标代码、不联网；finding 一律是
candidate（lead ≠ 漏洞）；案例骨架 status=lead、next_gate=manual_review，升级走
源码等价复现 → 真库验证（T3）阶梯，不在工作台内做任何结论升级。
