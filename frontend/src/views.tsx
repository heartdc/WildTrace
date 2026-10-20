import { useEffect, useState } from "react";
import { CandidateCaseActions, CaseEditor } from "./case-editor";
import { Donut, BarList, Histogram, Timeline, frequencies } from "./charts";
import {
  CheckList,
  KeyValue,
  RawJson,
  EmptyState,
  LoadingState,
  PreflightDetails,
  LaneCounts,
  MessagePreview,
  EvidenceDetails,
} from "./ui";
import {
  Alert,
  Button,
  Input,
  InputNumber,
  Modal,
  Select,
  Space,
  Table,
  Tabs,
  Tag,
  message,
} from "antd";
import {
  Download,
  FileCheck2,
  FolderSearch,
  Gauge,
  Play,
  RefreshCw,
  ShieldCheck,
  Sparkles,
  Square,
  TerminalSquare,
  Upload,
} from "lucide-react";
import {
  api,
  post,
  useApi,
  Status,
  ErrorBox,
  route,
  query,
  downloadReport,
  stateLabels,
  type Row,
} from "./client";

const terminal = ["completed", "failed", "cancelled", "interrupted"];
function Title({ eyebrow, title, children }: Row) {
  return (
    <div className="toolbar">
      <div>
        <span className="eyebrow">{eyebrow}</span>
        <h2>{title}</h2>
      </div>
      <Space>{children}</Space>
    </div>
  );
}

export function Overview() {
  const c = useApi<Row[]>("/api/cases", []),
    t = useApi<Row[]>("/api/tasks", []),
    f = useApi<Row[]>("/api/findings", []);
  if (c.loading || t.loading || f.loading)
    return <LoadingState label="加载审计数据" />;
  const pending = f.value.filter(
    (x) =>
      !x.review ||
      ["needs_verification", "approved_for_verification"].includes(
        x.review.decision,
      ),
  ).length;
  const reproduced = c.value.filter((x) =>
    [
      "library_level_reproduced",
      "real_library_reproduction_confirmed",
    ].includes(x.status),
  ).length;
  const confirmed = c.value.filter(
    (x) => x.raw?.confirmed_vulnerability === true,
  ).length;
  const official = c.value.filter(
    (x) => x.evidence_dimensions?.official_acceptance === true,
  ).length;
  const statusColors: Row = {
    completed: "var(--ev-product)",
    failed: "var(--danger)",
    running: "var(--ev-lib)",
    queued: "var(--ev-candidate)",
    interrupted: "var(--ev-pending)",
    cancelled: "var(--text-3)",
  };
  const taskStates = frequencies(
    t.value.map((x) => x.status || "unknown"),
    100,
  ).map((d) => ({
    ...d,
    label: stateLabels[d.label] || d.label,
    color: statusColors[d.label],
  }));
  const recent = [...t.value]
    .sort(
      (a, b) =>
        (Date.parse(b.created_at) || 0) - (Date.parse(a.created_at) || 0),
    )
    .slice(0, 5);
  const dateText = (value: string) =>
    value && !Number.isNaN(Date.parse(value))
      ? new Date(value).toLocaleString()
      : "未记录";
  const chartEmpty = (
    <EmptyState
      title="尚无扫描候选"
      action="新建扫描"
      onAction={() => route("scans")}
    />
  );
  const metrics = [
    {
      icon: FolderSearch,
      label: "案例记录",
      value: c.value.length,
      detail: `${c.value.filter((x) => !x.complete).length} 个案例仍有缺项`,
    },
    {
      icon: ShieldCheck,
      label: "扫描候选",
      value: f.value.length,
      detail: "与案例记录分别统计",
    },
    {
      icon: TerminalSquare,
      label: "任务记录",
      value: t.value.length,
      detail: `${t.value.filter((x) => x.status === "completed").length} 个已完成`,
    },
    {
      icon: Gauge,
      label: "已确认产品漏洞",
      value: c.value.filter((x) => x.raw.confirmed_vulnerability === true)
        .length,
      detail: "仅统计明确确认记录",
    },
  ];
  return (
    <>
      <ErrorBox error={c.error || t.error || f.error} />
      <Title eyebrow="WORKSPACE / LOCAL" title="审计概览">
        <Button onClick={() => route("cases")} icon={<FileCheck2 size={15} />}>
          案例库
        </Button>
        <Button
          type="primary"
          icon={<Play size={15} />}
          onClick={() => route("scans")}
        >
          新建扫描
        </Button>
      </Title>
      <div className="metric-grid">
        {metrics.map((m, index) => (
          <div className="metric" key={m.label}>
            <div
              className={`metric-icon ${["", "candidate", "lib", "product"][index]}`}
            >
              <m.icon />
            </div>
            <div>
              <small>{m.label}</small>
              <strong>{m.value}</strong>
              <span>{m.detail}</span>
            </div>
          </div>
        ))}
      </div>
      <section className="section evidence-tiers">
        <div className="section-head">
          <h3>证据分层</h3>
          <span className="hint">不同记录集合独立计数，不代表逐级转化率</span>
        </div>
        <div className="tier-grid">
          {[
            [
              "candidate",
              "扫描候选",
              c.error || f.error ? "—" : f.value.length,
              "扫描结果条目",
            ],
            [
              "pending",
              "待验证",
              f.error ? "—" : pending,
              "未复核、待验证或可进入验证",
            ],
            [
              "lib",
              "库级复现",
              c.error ? "—" : reproduced,
              "仅计明确库级复现状态",
            ],
            [
              "product",
              "已确认产品漏洞",
              c.error ? "—" : confirmed,
              "仅计明确确认记录",
            ],
            [
              "official",
              "官方接受",
              c.error ? "—" : official,
              "以记录中的接受状态为准",
            ],
          ].map(([key, label, value, detail]) => (
            <div key={String(key)} className={`tier-item ${key}`}>
              <span className="tier-label">{label}</span>
              <strong>{value}</strong>
              <span className="hint">{detail}</span>
            </div>
          ))}
        </div>
      </section>
      <div className="dashboard-charts">
        <section className="chart-section">
          <div className="section-head">
            <h3>缺失项频次</h3>
            <span className="hint">按案例统计</span>
          </div>
          {c.error ? (
            <EmptyState title="案例数据加载失败" />
          ) : (
            <BarList
              label="缺失项频次"
              data={frequencies(c.value.flatMap((x) => x.missing || []))}
              empty={c.value.length ? "当前没有登记的材料缺项" : "暂无案例记录"}
            />
          )}
        </section>
        <section className="chart-section">
          <div className="section-head">
            <h3>任务状态</h3>
            <span className="hint">{t.value.length} 条任务记录</span>
          </div>
          {t.error ? (
            <EmptyState title="任务数据加载失败" />
          ) : (
            <Donut data={taskStates} label="任务状态分布" />
          )}
        </section>
        <section className="chart-section">
          <div className="section-head">
            <h3>候选 CWE 分布</h3>
            <span className="hint">Top 8 · 按告警条目计数</span>
          </div>
          {f.value.length ? (
            <BarList
              label="候选 CWE 分布"
              data={frequencies(
                f.value.flatMap((x) =>
                  Array.isArray(x.cwe) ? x.cwe : [x.cwe || "未知"],
                ),
              )}
            />
          ) : (
            chartEmpty
          )}
        </section>
        <section className="chart-section">
          <div className="section-head">
            <h3>候选组件分布</h3>
            <span className="hint">Top 8 · 不合并不同任务</span>
          </div>
          {f.value.length ? (
            <BarList
              label="候选组件分布"
              data={frequencies(f.value.map((x) => x.component || "未知组件"))}
            />
          ) : (
            chartEmpty
          )}
        </section>
        <section className="chart-section">
          <div className="section-head">
            <h3>置信度分布</h3>
            <span className="hint">规则排序分</span>
          </div>
          <Histogram
            label="候选置信度分布"
            values={f.value.map((x) => x.confidence)}
          />
        </section>
        <section className="chart-section">
          <div className="section-head">
            <h3>最近任务</h3>
            <Button type="link" onClick={() => route("scans")}>
              扫描任务
            </Button>
          </div>
          <Timeline
            label="最近任务时间线"
            items={recent.map((x) => ({
              id: x.id,
              label: `${x.kind} ${stateLabels[x.status] || x.status}`,
              title: (
                <>
                  {x.kind} · {x.id.slice(0, 10)} <Status value={x.status} />
                </>
              ),
              detail: (
                <>
                  <span>创建 {dateText(x.created_at)}</span>
                  <br />
                  <span>
                    结束 {x.finished_at ? dateText(x.finished_at) : "尚未结束"}
                  </span>
                </>
              ),
              color: statusColors[x.status],
              onClick: () => route("scans", { task: x.id }),
            }))}
          />
        </section>
      </div>
      <section className="section">
        <div className="section-head">
          <div>
            <span className="eyebrow">EVIDENCE COVERAGE</span>
            <h3>案例证据完整度</h3>
          </div>
          <Tag>{c.value.length} 个案例</Tag>
        </div>
        <div className="evidence-grid">
          {[
            ["source_verification", "源码核验", "green"],
            ["equivalent_or_runtime_reproduction", "复现记录", "blue"],
            ["product_impact", "产品影响", "orange"],
            ["official_acceptance", "官方接受", "red"],
          ].map(([key, label, color]) => {
            const n = c.value.filter((x) => x.evidence_dimensions[key]).length;
            return (
              <div className="evidence" key={key}>
                <div>
                  <span>{label}</span>
                  <b>
                    {n}/{c.value.length}
                  </b>
                </div>
                <div className={"progress " + color}>
                  <i
                    style={{
                      width: `${c.value.length ? (100 * n) / c.value.length : 0}%`,
                    }}
                  />
                </div>
              </div>
            );
          })}
        </div>
      </section>
      <section className="section">
        <div className="section-head">
          <h3>待补充案例</h3>
          <Button type="link" onClick={() => route("reports")}>
            报告检查 →
          </Button>
        </div>
        <Table
          loading={c.loading}
          locale={{
            emptyText: (
              <EmptyState
                title={c.value.length ? "当前没有待补充案例" : "暂无案例记录"}
                action="案例库"
                onAction={() => route("cases")}
              />
            ),
          }}
          size="small"
          rowKey="id"
          dataSource={c.value.filter((x) => x.missing.length).slice(0, 6)}
          pagination={false}
          columns={[
            {
              title: "案例 / 组件",
              render: (_, r) => (
                <a onClick={() => route("cases", { case: r.id })}>
                  {r.title}
                  <small className="table-sub">{r.component}</small>
                </a>
              ),
            },
            {
              title: "证据缺项",
              render: (_, r) =>
                r.missing.map((m: string) => <Tag key={m}>{m}</Tag>),
            },
            {
              title: "运行状态",
              dataIndex: "status",
              render: (x) => <Status value={x} />,
            },
          ]}
        />
      </section>
    </>
  );
}

export function TaskDetail({ id }: { id: string }) {
  const [task, setTask] = useState<Row>(),
    [events, setEvents] = useState<Row[]>([]),
    [error, setError] = useState(""),
    [tick, setTick] = useState(Date.now());
  const assets = useApi<Row[]>(`/api/tasks/${id}/files`, []);
  const triage = useApi<Row>(`/api/tasks/${id}/triage`, {
    candidate_count: 0,
    group_count: 0,
    lane_counts: {},
    groups: [],
  });
  useEffect(() => {
    setEvents([]);
    setTask(undefined);
    api(`/api/tasks/${id}`)
      .then(setTask)
      .catch((e) => setError(e.message));
    const es = new EventSource(`/api/tasks/${id}/events`);
    es.addEventListener("log", (e: MessageEvent) => {
      const v = JSON.parse(e.data);
      setEvents((x) =>
        x.some((r) => r.id === v.id) ? x : [...x.slice(-299), v],
      );
    });
    es.addEventListener("state", (e: MessageEvent) =>
      setTask((t) => ({ ...t, ...JSON.parse(e.data) })),
    );
    es.addEventListener("done", () => {
      es.close();
      api(`/api/tasks/${id}`)
        .then(setTask)
        .catch((e) => setError(e.message));
      assets.reload();
      triage.reload();
    });
    es.onerror = () => {
      if (es.readyState === EventSource.CLOSED) return;
      setError("日志连接中断，正在自动重连");
    };
    es.onopen = () => setError("");
    const timer = setInterval(() => setTick(Date.now()), 1000);
    return () => {
      es.close();
      clearInterval(timer);
    };
  }, [id]);
  if (!task)
    return (
      <>
        <ErrorBox error={error} />
        <LoadingState />
      </>
    );
  const elapsed = task.started_at
    ? Math.max(
        0,
        Math.round(
          ((task.finished_at ? Date.parse(task.finished_at) : tick) -
            Date.parse(task.started_at)) /
            1000,
        ),
      )
    : 0;
  return (
    <>
      <ErrorBox error={error || task.error} />
      <div className="task-top">
        <Space>
          <Status value={task.status} />
          <strong>{task.stage}</strong>
          <span>{elapsed}s</span>
        </Space>
        <Space>
          {!terminal.includes(task.status) && (
            <Button
              danger
              icon={<Square size={13} />}
              onClick={() =>
                post(`/api/tasks/${id}/cancel`, {})
                  .then(setTask)
                  .catch((e) => setError(e.message))
              }
            >
              取消任务
            </Button>
          )}
          {task.kind === "scan" && terminal.includes(task.status) && (
            <Button
              icon={<RefreshCw size={13} />}
              onClick={() =>
                post("/api/tasks/scan", task.params)
                  .then((x) => route("scans", { task: x.id }))
                  .catch((e) => setError(e.message))
              }
            >
              重新运行
            </Button>
          )}
        </Space>
      </div>
      <Tabs
        items={[
          {
            key: "log",
            label: "运行日志",
            children: (
              <div className="log">
                {events.map((e) => (
                  <div key={e.id}>
                    <time>{new Date(e.time).toLocaleTimeString()}</time>
                    {e.text}
                  </div>
                ))}
                {!events.length && "等待日志"}
              </div>
            ),
          },
          {
            key: "triage",
            label: "复核队列",
            children: (
              <>
                <Alert
                  type="info"
                  title="分组用于减少重复审查，不会删除候选或确认漏洞"
                  description={
                    <>
                      <span>{`候选 ${triage.value.candidate_count} 条 · 分组 ${triage.value.group_count} 组`}</span>
                      <LaneCounts counts={triage.value.lane_counts} />
                    </>
                  }
                />
                <ErrorBox error={triage.error} />
                <Table<Row>
                  loading={triage.loading}
                  locale={{
                    emptyText: (
                      <EmptyState
                        title="暂无复核队列"
                        detail="任务尚未产生可用候选时，队列保持为空。"
                      />
                    ),
                  }}
                  rowKey="id"
                  size="small"
                  dataSource={triage.value.groups || []}
                  expandable={{
                    expandedRowRender: (group) => (
                      <>
                        <p>{group.reason}</p>
                        <Space wrap>
                          {group.references.map((ref: Row) => (
                            <Button
                              key={ref.id}
                              size="small"
                              onClick={() =>
                                route("findings", { finding: ref.id })
                              }
                            >
                              第 {ref.line} 行 ·{" "}
                              {ref.review ? "已记录复核" : "未复核"}
                            </Button>
                          ))}
                        </Space>
                      </>
                    ),
                  }}
                  columns={[
                    {
                      title: "队列",
                      dataIndex: "lane",
                      render: (x) =>
                        ({
                          manual_review: "人工审查",
                          needs_context: "待补上下文",
                          syntax_only: "待固定源码",
                          test_support: "测试与支持代码",
                        })[x as string] || x,
                    },
                    { title: "文件", dataIndex: "file" },
                    { title: "规则", dataIndex: "rule" },
                    { title: "函数", dataIndex: "function" },
                    { title: "引用数", render: (_, r) => r.references.length },
                    {
                      title: "复核记录",
                      render: (_, r) =>
                        `${r.reviewed_count}/${r.references.length}`,
                    },
                    {
                      title: "处理",
                      render: (_, r) => (
                        <Status
                          value={r.review?.decision || "needs_verification"}
                        />
                      ),
                    },
                  ]}
                />
              </>
            ),
          },
          {
            key: "result",
            label: "结果",
            children: task.result ? (
              <>
                <KeyValue
                  items={[
                    { label: "任务类型", value: task.kind },
                    {
                      label: "任务状态",
                      value: <Status value={task.status} />,
                    },
                    { label: "退出码", value: task.exit_code ?? "未记录" },
                    { label: "耗时", value: `${elapsed}s` },
                    {
                      label: "结果状态",
                      value: <Status value={task.result.status || "unknown"} />,
                    },
                    {
                      label: "候选数量",
                      value: Array.isArray(task.result.findings)
                        ? task.result.findings.length
                        : "不适用",
                    },
                  ]}
                />
                {task.result.summary && (
                  <KeyValue
                    items={[
                      {
                        label: "高优先级候选",
                        value: task.result.summary.high ?? "未记录",
                      },
                      {
                        label: "中优先级候选",
                        value: task.result.summary.medium ?? "未记录",
                      },
                    ]}
                  />
                )}
                {task.kind === "model" && (
                  <>
                    <Tag className="draft-banner">草稿 · 待人工复核</Tag>
                    {(task.result.results || []).map((r: Row, i: number) => (
                      <section className="model-result" key={i}>
                        <KeyValue
                          items={[
                            { label: "候选", value: r.finding_id },
                            {
                              label: "模型",
                              value: r.model || r.requested_model || "未记录",
                            },
                          ]}
                        />
                        {(r.code || r.content) && (
                          <pre>{r.code || r.content}</pre>
                        )}
                      </section>
                    ))}
                  </>
                )}
                {task.kind === "cjson" && (
                  <>
                    <Alert type="info" title="库级运行证据，产品可达性未建立" />
                    <Table
                      locale={{
                        emptyText: <EmptyState title="暂无运行对照记录" />,
                      }}
                      rowKey={(_, i) => String(i)}
                      size="small"
                      dataSource={task.result.rows || []}
                      columns={[
                        { title: "阶段", dataIndex: "phase" },
                        { title: "版本", dataIndex: "variant" },
                        { title: "对照", dataIndex: "case" },
                        { title: "退出码", dataIndex: "exit_code" },
                        { title: "观察", dataIndex: "classification" },
                        {
                          title: "符合预期",
                          dataIndex: "passed",
                          render: (x) =>
                            x === undefined ? "—" : x ? "是" : "否",
                        },
                      ]}
                    />
                  </>
                )}
                <RawJson value={task.result} />
              </>
            ) : (
              <Alert
                type="info"
                title="暂无可用结果；失败诊断保留在日志及附件中"
              />
            ),
          },
          {
            key: "files",
            label: "任务附件",
            children: assets.loading ? (
              <LoadingState />
            ) : assets.error ? (
              <ErrorBox error={assets.error} />
            ) : !assets.value.length ? (
              <EmptyState title="暂无任务附件" />
            ) : (
              assets.value.map((x) => (
                <div className="asset" key={x.path}>
                  <a
                    href={`/api/tasks/${id}/file?path=${encodeURIComponent(x.path)}`}
                    download
                  >
                    {x.path}
                  </a>
                  <span>{x.bytes} bytes</span>
                </div>
              ))
            ),
          },
        ]}
      />
    </>
  );
}

export function Scans() {
  const tasks = useApi<Row[]>("/api/tasks", []),
    settings = useApi<Row>("/api/settings", { source_roots: [] });
  const [root, setRoot] = useState(""),
    [projectId, setProjectId] = useState<string | undefined>(
      query("project") || undefined,
    ),
    [mode, setMode] = useState("autopilot"),
    [confidence, setConfidence] = useState(0),
    [error, setError] = useState(""),
    [busy, setBusy] = useState(false),
    [id, setId] = useState(query("task"));
  const projects = useApi<Row[]>("/api/projects", []);
  useEffect(() => {
    const fn = () => {
      setId(query("task"));
      setProjectId(query("project") || undefined);
    };
    addEventListener("hashchange", fn);
    return () => removeEventListener("hashchange", fn);
  }, []);
  useEffect(() => {
    const timer = setInterval(tasks.reload, 4000);
    return () => clearInterval(timer);
  }, []);
  const start = async () => {
    setBusy(true);
    setError("");
    try {
      const t = await post("/api/tasks/scan", {
        source_root: root || settings.value.source_roots[0],
        project_id: projectId,
        mode,
        min_confidence: confidence,
      });
      route("scans", { task: t.id });
      tasks.reload();
    } catch (e: any) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  };
  return (
    <>
      <Title eyebrow="STATIC ANALYSIS" title="扫描任务">
        <Button icon={<RefreshCw size={15} />} onClick={tasks.reload}>
          刷新
        </Button>
        <Button
          type="primary"
          loading={busy}
          icon={<Play size={15} />}
          onClick={start}
        >
          启动扫描
        </Button>
      </Title>
      <ErrorBox error={error || tasks.error || settings.error} />
      <div className="panel">
        <label>源码项目</label>
        <Select
          aria-label="扫描源码项目"
          loading={projects.loading}
          allowClear
          style={{ width: "100%" }}
          placeholder="选择已保存项目，或使用下方本机目录"
          value={projectId}
          onChange={setProjectId}
          options={projects.value.map((p) => ({
            value: p.id,
            label: `${p.name} · ${p.environment} · ${p.root}`,
          }))}
        />
        {!projectId && (
          <>
            <label>源码目录</label>
            <Input
              value={root}
              onChange={(e) => setRoot(e.target.value)}
              placeholder={settings.value.source_roots[0] || "配置源码根目录"}
            />
          </>
        )}
        {projectId && (
          <p className="hint">按项目保存的选择范围、排除目录和固定提交执行。</p>
        )}
        <div className="form-row">
          <div>
            <label>扫描模式</label>
            <Select
              style={{ width: 240 }}
              value={mode}
              onChange={setMode}
              options={[
                { value: "autopilot", label: "Autopilot · 多层候选扫描" },
                { value: "builtin", label: "基础扫描 · 证据校验" },
              ]}
            />
          </div>
          {mode === "autopilot" && (
            <div>
              <label>最低置信度</label>
              <InputNumber
                min={0}
                max={100}
                value={confidence}
                onChange={(x) => setConfidence(x || 0)}
              />
            </div>
          )}
        </div>
      </div>
      <div className="panel">
        <Table
          rowKey="id"
          loading={tasks.loading}
          rowClassName="clickable"
          locale={{
            emptyText: (
              <EmptyState
                title="暂无扫描任务"
                detail="选择已登记的项目后可启动扫描。"
              />
            ),
          }}
          dataSource={tasks.value}
          onRow={(r) => ({ onClick: () => route("scans", { task: r.id }) })}
          columns={[
            {
              title: "任务",
              render: (_, r) => (
                <>
                  <code>{r.id.slice(0, 12)}</code>
                  <small className="table-sub">{r.params.source_root}</small>
                </>
              ),
            },
            { title: "类型", dataIndex: "kind" },
            {
              title: "状态",
              dataIndex: "status",
              render: (x) => <Status value={x} />,
            },
            { title: "阶段", dataIndex: "stage" },
            {
              title: "创建时间",
              dataIndex: "created_at",
              render: (x) => new Date(x).toLocaleString(),
            },
          ]}
        />
      </div>
      <Modal
        width={1100}
        open={!!id}
        title="任务详情"
        footer={null}
        onCancel={() => route("scans")}
      >
        {id && <TaskDetail key={id} id={id} />}
      </Modal>
    </>
  );
}

function Review({ item, after }: { item: string; after: () => void }) {
  const [decision, setDecision] = useState("needs_verification"),
    [reviewer, setReviewer] = useState("本地审查员"),
    [note, setNote] = useState(""),
    [error, setError] = useState("");
  const save = () =>
    post(`/api/reviews/${encodeURIComponent(item)}`, {
      decision,
      reviewer,
      note,
    })
      .then(() => {
        message.success("复核记录已追加");
        after();
      })
      .catch((e) => setError(e.message));
  return (
    <div className="review-form">
      <h4>人工复核</h4>
      <ErrorBox error={error} />
      <Select
        value={decision}
        onChange={setDecision}
        options={[
          { value: "needs_verification", label: "待验证" },
          { value: "rejected_candidate", label: "拒绝候选" },
          { value: "approved_for_verification", label: "可进入验证" },
        ]}
      />
      <Input
        aria-label="复核人"
        value={reviewer}
        onChange={(e) => setReviewer(e.target.value)}
      />
      <Input.TextArea
        placeholder="复核依据"
        value={note}
        onChange={(e) => setNote(e.target.value)}
        rows={3}
      />
      <Button onClick={save}>保存复核记录</Button>
    </div>
  );
}

function ModelDialog({ ids, close }: { ids: string[]; close: () => void }) {
  const [action, setAction] = useState("analysis"),
    [preview, setPreview] = useState<Row>(),
    [error, setError] = useState(""),
    [busy, setBusy] = useState(false);
  const request = { finding_ids: ids, action };
  async function prepare() {
    setError("");
    setBusy(true);
    try {
      setPreview(await post("/api/model/preview", request));
    } catch (e: any) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  }
  async function run() {
    setBusy(true);
    try {
      const t = await post("/api/model/run", {
        ...request,
        preview_sha256: preview?.preview_sha256,
      });
      close();
      route("scans", { task: t.id });
    } catch (e: any) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  }
  return (
    <Modal
      width={950}
      open
      title="模型调用预览"
      onCancel={close}
      footer={
        <Space>
          <Button loading={busy} onClick={prepare}>
            生成请求预览
          </Button>
          <Button
            type="primary"
            disabled={!preview}
            loading={busy}
            onClick={run}
          >
            发送 {ids.length} 个请求
          </Button>
        </Space>
      }
    >
      <ErrorBox error={error} />
      <Select
        value={action}
        onChange={(v) => {
          setAction(v);
          setPreview(undefined);
        }}
        options={[
          { value: "analysis", label: "模型辅助分析" },
          { value: "poc", label: "生成 PoC 草稿" },
        ]}
      />
      <p>当前批次 {ids.length}/5 个候选 · 串行调用 · 首次传输错误即停止</p>
      {preview ? (
        <>
          <Tag>{preview.connection.model}</Tag>
          <Tag className="draft-banner">草稿 · 待人工复核</Tag>
          <code>{preview.connection.base_url}</code>
          <p>以下内容将发送至所选模型服务：</p>
          {preview.items.map((x: Row) => (
            <div key={x.id}>
              <strong>
                {x.file}:{x.line}
              </strong>
              <MessagePreview messages={x.messages} />
              <RawJson value={x.messages} />
            </div>
          ))}
        </>
      ) : (
        <Alert type="info" title="先检查将发送的源码范围和请求内容" />
      )}
    </Modal>
  );
}

export function Findings() {
  const all = useApi<Row[]>("/api/findings", []);
  const [search, setSearch] = useState(""),
    [component, setComponent] = useState<string>(),
    [cwe, setCwe] = useState<string>(),
    [review, setReview] = useState<string>(),
    [confidence, setConfidence] = useState(0),
    [selected, setSelected] = useState<React.Key[]>([]),
    [id, setId] = useState(query("finding")),
    [modelIds, setModelIds] = useState<string[]>([]);
  const [item, setItem] = useState<Row>(),
    [error, setError] = useState("");
  useEffect(() => {
    const fn = () => setId(query("finding"));
    addEventListener("hashchange", fn);
    return () => removeEventListener("hashchange", fn);
  }, []);
  const load = () => {
    if (id)
      api(`/api/findings/${id}`)
        .then(setItem)
        .catch((e) => setError(e.message));
  };
  useEffect(() => {
    setItem(undefined);
    load();
  }, [id]);
  const rows = all.value.filter(
    (x) =>
      (!search ||
        `${x.file} ${x.rule} ${x.description}`
          .toLowerCase()
          .includes(search.toLowerCase())) &&
      (!component || x.component === component) &&
      (!cwe || x.cwe === cwe) &&
      (!review || (x.review?.decision || "needs_verification") === review) &&
      (x.confidence == null || x.confidence >= confidence),
  );
  return (
    <>
      <Title eyebrow="CANDIDATE REVIEW" title="候选审查">
        <Button icon={<RefreshCw size={15} />} onClick={all.reload}>
          刷新
        </Button>
        <Button
          icon={<Sparkles size={15} />}
          disabled={!selected.length || selected.length > 5}
          onClick={() => setModelIds(selected.map(String))}
        >
          模型分析 {selected.length ? `(${selected.length})` : ""}
        </Button>
      </Title>
      <ErrorBox error={all.error || error} />
      <div className="form-row" style={{ marginBottom: 18 }}>
        <Input.Search
          style={{ width: 260 }}
          placeholder="文件、规则或描述"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
        />
        <Select
          allowClear
          placeholder="组件"
          style={{ width: 140 }}
          value={component}
          onChange={setComponent}
          options={[...new Set(all.value.map((x) => x.component))].map(
            (value) => ({ value, label: value }),
          )}
        />
        <Select
          allowClear
          placeholder="CWE"
          style={{ width: 140 }}
          value={cwe}
          onChange={setCwe}
          options={[...new Set(all.value.map((x) => x.cwe))].map((value) => ({
            value,
            label: value,
          }))}
        />
        <Select
          allowClear
          placeholder="复核状态"
          style={{ width: 140 }}
          value={review}
          onChange={setReview}
          options={[
            { value: "needs_verification", label: "待验证" },
            { value: "rejected_candidate", label: "拒绝候选" },
            { value: "approved_for_verification", label: "可进入验证" },
          ]}
        />
        <span>置信度 ≥</span>
        <InputNumber
          min={0}
          max={100}
          value={confidence}
          onChange={(v) => setConfidence(v || 0)}
        />
      </div>
      <div className="panel">
        <Table
          rowKey="id"
          size="small"
          loading={all.loading}
          locale={{
            emptyText: (
              <EmptyState
                title={
                  all.value.length ? "没有符合筛选条件的候选" : "暂无扫描候选"
                }
                action={all.value.length ? undefined : "新建扫描"}
                onAction={() => route("scans")}
              />
            ),
          }}
          rowSelection={{ selectedRowKeys: selected, onChange: setSelected }}
          dataSource={rows}
          columns={[
            {
              title: "源码位置",
              render: (_, r) => (
                <a onClick={() => route("findings", { finding: r.id })}>
                  {r.file}:{r.line}
                </a>
              ),
            },
            {
              title: "规则 / CWE",
              render: (_, r) => (
                <>
                  {r.rule}
                  <small className="table-sub">{r.cwe}</small>
                </>
              ),
            },
            {
              title: "置信度",
              dataIndex: "confidence",
              render: (x) => (x == null ? "未知" : `${x}%`),
            },
            {
              title: "扫描状态",
              dataIndex: "task_status",
              render: (x) => <Status value={x} />,
            },
            {
              title: "复核状态",
              render: (_, r) => (
                <Status value={r.review?.decision || "needs_verification"} />
              ),
            },
          ]}
        />
      </div>
      <Modal
        width={1100}
        open={!!id}
        title="候选详情"
        footer={null}
        onCancel={() => route("findings")}
      >
        {!item ? (
          error ? (
            <ErrorBox error={error} />
          ) : (
            <LoadingState />
          )
        ) : (
          <Tabs
            items={[
              {
                key: "source",
                label: "源码与复核",
                children: (
                  <div className="detail-grid">
                    <div>
                      <strong>
                        {item.file}:{item.line}
                      </strong>
                      <p>{item.description}</p>
                      <Alert
                        className="source-state"
                        type={
                          item.source.status === "matched"
                            ? "success"
                            : "warning"
                        }
                        title={
                          {
                            matched: "源码摘要匹配",
                            unbound: "没有绑定源码摘要",
                            changed: "源码已变更",
                            missing: "源码缺失",
                            too_large: "源码超过显示上限",
                          }[item.source.status as string] || item.source.status
                        }
                      />
                      <pre className="source">
                        {item.source.lines.map((x: Row) => (
                          <span
                            className={
                              "source-line " +
                              (x.number === item.line ? "highlight" : "")
                            }
                            key={x.number}
                          >
                            {String(x.number).padStart(5)} {x.text}
                          </span>
                        ))}
                      </pre>
                    </div>
                    <div className="detail-side">
                      <CandidateCaseActions item={item} after={load} />
                      <Button
                        icon={<Sparkles size={15} />}
                        onClick={() => setModelIds([item.id])}
                      >
                        模型建议 / PoC 草稿
                      </Button>
                      <Review
                        item={item.id}
                        after={() => {
                          load();
                          all.reload();
                        }}
                      />
                      {item.reviews.map((r: Row, i: number) => (
                        <div key={i}>
                          <Status value={r.decision} />
                          <small>{r.reviewer}</small>
                          <p>{r.note}</p>
                        </div>
                      ))}
                    </div>
                  </div>
                ),
              },
              {
                key: "models",
                label: `模型结果 (${item.model_results.length})`,
                children: item.model_results.length ? (
                  item.model_results.map((r: Row, i: number) => (
                    <div className="model-result" key={i}>
                      <Tag>{r.model || r.requested_model}</Tag>
                      <Tag>
                        {r.status === "draft"
                          ? "PoC 草稿 · 未执行"
                          : "待复核建议"}
                      </Tag>
                      <Tag>草稿 · 未作为确认结论</Tag>
                      {(r.code || r.content) && (
                        <pre>{r.code || r.content}</pre>
                      )}
                      <RawJson value={r} />
                    </div>
                  ))
                ) : (
                  <EmptyState
                    title="尚未调用模型"
                    detail="只有明确发送请求后，才会产生待复核的模型草稿。"
                  />
                ),
              },
              {
                key: "raw",
                label: "原始记录",
                children: <RawJson value={item.raw} />,
              },
            ]}
          />
        )}
      </Modal>
      {modelIds.length > 0 && (
        <ModelDialog ids={modelIds} close={() => setModelIds([])} />
      )}
    </>
  );
}

export function Cases() {
  const all = useApi<Row[]>("/api/cases", []);
  const [id, setId] = useState(query("case")),
    [item, setItem] = useState<Row>(),
    [search, setSearch] = useState(""),
    [error, setError] = useState("");
  const load = () => {
    if (id)
      api(`/api/cases/${id}`)
        .then(setItem)
        .catch((e) => setError(e.message));
  };
  useEffect(() => {
    const fn = () => setId(query("case"));
    addEventListener("hashchange", fn);
    return () => removeEventListener("hashchange", fn);
  }, []);
  useEffect(() => {
    setItem(undefined);
    load();
  }, [id]);
  async function importEvidence(file?: File) {
    if (!file || !id) return;
    try {
      const record = JSON.parse(await file.text());
      await post(`/api/cases/${id}/evidence`, { name: file.name, record });
      load();
      message.success("证据已导入，状态为未核验");
    } catch (e: any) {
      setError(e.message);
    }
  }
  const assetPane = (kinds: string[]) => {
    if (!item) return <LoadingState />;
    const assets =
      item?.assets.filter((a: Row) => kinds.some((k) => a.name.endsWith(k))) ||
      [];
    if (!assets.length)
      return (
        <EmptyState
          title={kinds.includes(".patch") ? "尚未关联补丁" : "暂无相关附件"}
          detail="缺失项保留在案例材料检查中。"
        />
      );
    return assets.map((a: Row) => (
      <div className="asset" key={a.asset_id || a.path}>
        <div className="asset-head">
          <code>{a.path || a.name}</code>
          <a
            href={`/api/cases/${item.id}/attachment?asset_id=${encodeURIComponent(a.asset_id || a.path)}&revision=${item.revision}`}
            download
          >
            <Download size={15} /> 下载
          </a>
        </div>
        <span>SHA-256 {a.sha256}</span>
        {a.text && <pre>{a.text}</pre>}
      </div>
    ));
  };
  return (
    <>
      <Title eyebrow="CASE LIBRARY" title={`案例库 · ${all.value.length}`}>
        <Input.Search
          placeholder="案例、组件或 CVE"
          style={{ width: 280 }}
          onChange={(e) => setSearch(e.target.value)}
        />
      </Title>
      <ErrorBox error={error || all.error} />
      <div className="panel">
        <Table
          rowKey="id"
          loading={all.loading}
          locale={{
            emptyText: (
              <EmptyState title={search ? "没有匹配的案例" : "暂无案例记录"} />
            ),
          }}
          dataSource={all.value.filter((x) =>
            `${x.title} ${x.component} ${x.cve}`
              .toLowerCase()
              .includes(search.toLowerCase()),
          )}
          columns={[
            {
              title: "案例 / 组件",
              render: (_, r) => (
                <a onClick={() => route("cases", { case: r.id })}>
                  {r.title}
                  <small className="table-sub">{r.component}</small>
                </a>
              ),
            },
            {
              title: "CVE / CWE",
              render: (_, r) => (
                <>
                  {r.cve}
                  <small className="table-sub">{r.cwe.join(", ")}</small>
                </>
              ),
            },
            {
              title: "运行记录",
              dataIndex: "status",
              render: (x) => <Status value={x} />,
            },
            {
              title: "材料完整度",
              render: (_, r) => (
                <Tag color={r.complete ? "green" : "orange"}>
                  {r.complete ? "字段齐全" : `缺 ${r.missing.length} 项`}
                </Tag>
              ),
            },
          ]}
        />
      </div>
      <Modal
        width={1150}
        open={!!id}
        title={item?.title || "案例详情"}
        footer={null}
        onCancel={() => route("cases")}
      >
        {!item ? (
          error ? (
            <ErrorBox error={error} />
          ) : (
            <LoadingState />
          )
        ) : (
          <Tabs
            items={[
              {
                key: "overview",
                label: "概览",
                children: (
                  <div className="case-detail">
                    <div>
                      <h3>{item.description}</h3>
                      <h4>源码定位</h4>
                      <code>
                        {item.rendered.source_file}:{item.rendered.source_lines}
                      </code>
                      <h4>触发条件</h4>
                      <p>{item.rendered.trigger_conditions}</p>
                      <h4>影响路径</h4>
                      <p>{item.rendered.attack_path}</p>
                      <h4>修复建议</h4>
                      <p>{item.rendered.fix_recommendation}</p>
                    </div>
                    <div className="detail-side">
                      <Status value={item.status} />
                      <Alert
                        type="warning"
                        title={`材料缺项 ${item.missing.length}`}
                        description={item.missing.join("、")}
                      />
                      <h4>平台记录</h4>
                      <p>
                        {item.submission.ticket}
                        <br />
                        {item.submission.status} ·{" "}
                        {item.submission.official_status}
                      </p>
                      {item.runtime_supported ? (
                        <Button
                          type="primary"
                          icon={<Play size={15} />}
                          onClick={() => route("runtime")}
                        >
                          cJSON 隔离验证
                        </Button>
                      ) : (
                        <Tag>执行驱动未适配</Tag>
                      )}
                      <Review item={"case:" + id} after={load} />
                    </div>
                  </div>
                ),
              },
              {
                key: "materials",
                label: "材料编辑与关联",
                children: (
                  <CaseEditor
                    item={item}
                    after={() => {
                      load();
                      all.reload();
                    }}
                  />
                ),
              },
              {
                key: "poc",
                label: "PoC 与附件",
                children: (
                  <>
                    {assetPane([".c", ".h", ".md", ".txt", ".zip"])}
                    <h4>复现说明</h4>
                    <p>{item.rendered.poc_usage}</p>
                  </>
                ),
              },
              {
                key: "patch",
                label: "补丁",
                children: assetPane([".patch", ".diff"]),
              },
              {
                key: "impact",
                label: "版本影响",
                children: (
                  <>
                    <Alert
                      type="info"
                      title="分支实证与上游版本推测分别记录；未知不代表安全"
                    />
                    <Table
                      rowKey="branch"
                      loading={all.loading}
                      locale={{
                        emptyText: <EmptyState title="暂无分支影响证据" />,
                      }}
                      pagination={false}
                      dataSource={Object.keys(item.impact.branches).map(
                        (branch) => ({
                          branch,
                          verdict: item.impact.branches[branch],
                          prediction: item.impact.upstream_predictions[branch],
                          evidence: item.impact.branch_evidence?.[branch],
                        }),
                      )}
                      columns={[
                        { title: "分支", dataIndex: "branch" },
                        {
                          title: "分支实证",
                          dataIndex: "verdict",
                          render: (x) => <Status value={x} />,
                        },
                        {
                          title: "上游版本推测",
                          dataIndex: "prediction",
                          render: (x) => <Tag>{x || "unknown"}</Tag>,
                        },
                        {
                          title: "证据引用",
                          dataIndex: "evidence",
                          render: (x) =>
                            x ? <EvidenceDetails value={x} /> : "未记录",
                        },
                      ]}
                    />
                  </>
                ),
              },
              {
                key: "evidence",
                label: "验证记录",
                children: (
                  <>
                    <label className="ant-btn">
                      <Upload size={14} /> 导入 JSON 证据
                      <input
                        aria-label="导入 JSON 证据"
                        type="file"
                        accept=".json"
                        style={{ display: "none" }}
                        onChange={(e) => importEvidence(e.target.files?.[0])}
                      />
                    </label>
                    <EvidenceDetails
                      value={
                        item.raw.validation_evidence ||
                        item.raw.runtime_evidence
                      }
                    />
                    {item.imported_evidence.map((e: Row, i: number) => (
                      <div key={i}>
                        <Tag>导入 · 未核验</Tag>
                        <strong>{e.name}</strong>
                        <EvidenceDetails value={e.record} />
                      </div>
                    ))}
                  </>
                ),
              },
              {
                key: "raw",
                label: "原始案例",
                children: <RawJson value={item.raw} />,
              },
            ]}
          />
        )}
      </Modal>
    </>
  );
}

export function Runtime() {
  const [root, setRoot] = useState("C:/Projects/OpenHarmony/third_party/cJSON"),
    [preflight, setPreflight] = useState<Row>(),
    [busy, setBusy] = useState(false),
    [error, setError] = useState("");
  const tasks = useApi<Row[]>("/api/tasks", []);
  async function check() {
    setBusy(true);
    setError("");
    try {
      setPreflight(await post("/api/runtime/preflight", { source_root: root }));
    } catch (e: any) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  }
  async function run() {
    setBusy(true);
    try {
      const t = await post("/api/runtime/cjson", { source_root: root });
      route("scans", { task: t.id });
    } catch (e: any) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  }
  return (
    <>
      <Title eyebrow="ISOLATED VERIFICATION" title="运行验证">
        <Button onClick={check} loading={busy}>
          环境预检
        </Button>
        <Button
          type="primary"
          icon={<Play size={15} />}
          disabled={!preflight?.ready}
          loading={busy}
          onClick={run}
        >
          启动 cJSON 隔离验证
        </Button>
      </Title>
      <ErrorBox error={error} />
      <div className="panel">
        <Tag color="cyan">cJSON · CVE-2026-87933</Tag>
        <h3>MergePatch 非对象子树别名</h3>
        <label>已登记的源码目录</label>
        <Input
          value={root}
          onChange={(e) => {
            setRoot(e.target.value);
            setPreflight(undefined);
          }}
        />
        <p>原版 / 独立构建 / 补丁版 · ASan / UBSan · bubblewrap</p>
        <Alert
          type="info"
          title="库级复现与产品漏洞确认分别记录"
          description="本次运行只执行已有审查记录的案例驱动，模型生成代码不进入运行队列。"
        />
      </div>
      {preflight && (
        <div className="panel">
          <Alert
            type={preflight.ready ? "success" : "error"}
            title={preflight.ready ? "环境及源码指纹预检通过" : "预检未通过"}
            description={preflight.error}
          />
          <PreflightDetails data={preflight} />
        </div>
      )}
      <section className="section">
        <h3>历史验证任务</h3>
        <Table
          rowKey="id"
          loading={tasks.loading}
          locale={{ emptyText: <EmptyState title="暂无历史验证任务" /> }}
          dataSource={tasks.value.filter((x) => x.kind === "cjson")}
          columns={[
            {
              title: "任务",
              render: (_, r) => (
                <a onClick={() => route("scans", { task: r.id })}>
                  {r.id.slice(0, 12)}
                </a>
              ),
            },
            {
              title: "状态",
              dataIndex: "status",
              render: (x) => <Status value={x} />,
            },
            { title: "阶段", dataIndex: "stage" },
            {
              title: "时间",
              dataIndex: "created_at",
              render: (x) => new Date(x).toLocaleString(),
            },
          ]}
        />
      </section>
    </>
  );
}

export function Reports() {
  const cases = useApi<Row[]>("/api/cases", []),
    tasks = useApi<Row[]>("/api/tasks", []);
  const [ids, setIds] = useState<string[]>([]),
    [tids, setTids] = useState<string[]>([]),
    [preview, setPreview] = useState<Row>(),
    [error, setError] = useState(""),
    [busy, setBusy] = useState(false);
  async function build(format = "preview") {
    setBusy(true);
    setError("");
    try {
      const body = { case_ids: ids, task_ids: tids, format };
      if (format === "preview") setPreview(await post("/api/reports", body));
      else {
        await downloadReport(body);
        message.success("报告已导出");
      }
    } catch (e: any) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  }
  return (
    <>
      <Title eyebrow="DELIVERY CHECK" title="报告中心">
        <Button loading={busy} onClick={() => build()}>
          检查并预览
        </Button>
        <Button
          loading={busy}
          icon={<Download size={15} />}
          onClick={() => build("markdown")}
        >
          Markdown
        </Button>
        <Button loading={busy} onClick={() => build("json")}>
          JSON
        </Button>
        <Button type="primary" loading={busy} onClick={() => build("zip")}>
          证据附件包
        </Button>
      </Title>
      <ErrorBox error={error} />
      <div className="panel">
        <label>案例</label>
        <Select
          mode="multiple"
          loading={cases.loading}
          style={{ width: "100%" }}
          placeholder="选择案例"
          value={ids}
          onChange={(x) => {
            setIds(x);
            setPreview(undefined);
          }}
          options={cases.value.map((c) => ({ value: c.id, label: c.title }))}
        />
        <label>任务及运行记录</label>
        <Select
          mode="multiple"
          loading={tasks.loading}
          style={{ width: "100%" }}
          placeholder="选择任务"
          value={tids}
          onChange={(x) => {
            setTids(x);
            setPreview(undefined);
          }}
          options={tasks.value.map((t) => ({
            value: t.id,
            label: `${t.kind} · ${t.id.slice(0, 10)} · ${t.status}`,
          }))}
        />
      </div>
      {!preview && !busy && (
        <EmptyState
          title="尚未生成报告预览"
          detail="选择案例或任务后检查材料完整度，缺失项会单独列出。"
        />
      )}
      {preview && (
        <>
          <Alert
            type={preview.complete ? "success" : "warning"}
            title={
              preview.complete
                ? "字段齐全；不代表漏洞已确认"
                : "待补充，不能作为完整交付"
            }
          />
          {Object.entries(preview.missing).map(([id, gaps]) => (
            <section className="report-gaps" key={id}>
              <h4>{cases.value.find((c) => c.id === id)?.title || id}</h4>
              <CheckList
                items={(gaps as string[]).map((label) => ({
                  label,
                  status: false,
                  detail: "待补充",
                }))}
              />
            </section>
          ))}
          <pre className="report-preview">{preview.markdown}</pre>
        </>
      )}
    </>
  );
}

export function Settings() {
  const s = useApi<Row>("/api/settings", {}),
    m = useApi<Row>("/api/model/connection", {});
  const [roots, setRoots] = useState(""),
    [distribution, setDistribution] = useState("Ubuntu"),
    [timeout, setTimeoutValue] = useState(1800),
    [url, setUrl] = useState(""),
    [model, setModel] = useState(""),
    [key, setKey] = useState(""),
    [modelTimeout, setModelTimeout] = useState(60),
    [tokens, setTokens] = useState(2048),
    [saving, setSaving] = useState(false),
    [error, setError] = useState("");
  useEffect(() => {
    setRoots((s.value.source_roots || []).join("\n"));
    setDistribution(s.value.distribution || "Ubuntu");
    setTimeoutValue(s.value.timeout || 1800);
  }, [s.value]);
  useEffect(() => {
    setUrl(m.value.base_url || "");
    setModel(m.value.model || "");
    setModelTimeout(m.value.timeout || 60);
    setTokens(m.value.max_tokens || 2048);
  }, [m.value]);
  async function save() {
    setSaving(true);
    try {
      await api("/api/settings", {
        method: "PUT",
        body: JSON.stringify({
          source_roots: roots
            .split("\n")
            .map((x) => x.trim())
            .filter(Boolean),
          distribution,
          timeout,
        }),
      });
      await api("/api/model/connection", {
        method: "PUT",
        body: JSON.stringify({
          base_url: url,
          model,
          api_key: key,
          timeout: modelTimeout,
          max_tokens: tokens,
        }),
      });
      setKey("");
      m.reload();
      message.success("设置已保存");
      setError("");
    } catch (e: any) {
      setError(e.message);
    } finally {
      setSaving(false);
    }
  }
  if (s.loading || m.loading) return <LoadingState label="正在加载设置" />;
  return (
    <>
      <Title eyebrow="LOCAL SETTINGS" title="设置" />
      <ErrorBox error={error || s.error || m.error} />
      <div className="settings-grid">
        <div className="panel">
          <h3>源码与任务</h3>
          <label>允许的源码根目录</label>
          <Input.TextArea
            aria-label="源码根目录"
            rows={6}
            value={roots}
            onChange={(e) => setRoots(e.target.value)}
          />
          <label>WSL 分发版</label>
          <Input
            value={distribution}
            onChange={(e) => setDistribution(e.target.value)}
          />
          <label>任务超时（秒）</label>
          <InputNumber
            min={30}
            max={7200}
            value={timeout}
            onChange={(v) => setTimeoutValue(v || 1800)}
          />
        </div>
        <div className="panel">
          <h3>
            模型连接{" "}
            <Tag color={m.value.has_key ? "green" : "default"}>
              {m.value.has_key ? "已配置临时 Key" : "未配置 Key"}
            </Tag>
          </h3>
          <label>服务地址</label>
          <Select
            style={{ width: "100%" }}
            value={url}
            onChange={setUrl}
            options={(m.value.endpoints || []).map((x: string) => ({
              value: x,
              label: x,
            }))}
          />
          <label>模型</label>
          <Select
            style={{ width: "100%" }}
            value={model}
            onChange={setModel}
            options={(m.value.models || []).map((x: string) => ({
              value: x,
              label: x,
            }))}
          />
          <label>临时 API Key</label>
          <Input.Password
            autoComplete="off"
            aria-label="临时 API Key"
            value={key}
            onChange={(e) => setKey(e.target.value)}
            placeholder="后端内存保存；重启后失效"
          />
          <div className="form-row">
            <div>
              <label>请求超时（秒）</label>
              <InputNumber
                min={1}
                max={300}
                value={modelTimeout}
                onChange={(v) => setModelTimeout(v || 60)}
              />
            </div>
            <div>
              <label>最大输出 tokens</label>
              <InputNumber
                min={128}
                max={4096}
                value={tokens}
                onChange={(v) => setTokens(v || 2048)}
              />
            </div>
          </div>
          <Button
            style={{ marginTop: 18 }}
            onClick={() =>
              api("/api/model/connection/key", { method: "DELETE" })
                .then(() => {
                  setKey("");
                  m.reload();
                })
                .catch((e) => setError(e.message))
            }
          >
            清除临时密钥
          </Button>
        </div>
      </div>
      <div className="form-foot">
        <Button type="primary" onClick={save} loading={saving}>
          保存设置
        </Button>
      </div>
    </>
  );
}
