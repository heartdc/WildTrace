import { useEffect, useState } from "react";
import {
  Alert,
  Button,
  Input,
  InputNumber,
  Select,
  Space,
  Table,
  Tabs,
  Tag,
  message,
} from "antd";
import { Download, FilePlus2, Link, Upload } from "lucide-react";
import { CheckList, KeyValue, RawJson, EmptyState } from "./ui";
import {
  api,
  post,
  useApi,
  route,
  ErrorBox,
  Status,
  downloadReport,
  type Row,
} from "./client";

const authorDefault = "本地审查员";
export function CandidateCaseActions({
  item,
  after,
}: {
  item: Row;
  after: () => void;
}) {
  const cases = useApi<Row[]>("/api/cases", []);
  const [cid, setCid] = useState<string>(),
    [error, setError] = useState(""),
    [busy, setBusy] = useState(false);
  async function create() {
    setBusy(true);
    try {
      const c = await post("/api/cases", {
        finding_id: item.id,
        author: authorDefault,
      });
      route("cases", { case: c.id });
      message.success("案例已创建");
    } catch (e: any) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  }
  async function link() {
    if (!cid) return;
    setBusy(true);
    try {
      const c = await api("/api/cases/" + cid);
      await post(`/api/cases/${cid}/links`, {
        revision: c.revision,
        finding_ids: [item.id],
        author: authorDefault,
      });
      after();
      message.success("已关联案例与扫描任务");
    } catch (e: any) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  }
  return (
    <>
      <h4>案例关联</h4>
      <ErrorBox error={error} />
      <Button icon={<FilePlus2 size={14} />} loading={busy} onClick={create}>
        从候选创建案例
      </Button>
      <Select
        loading={cases.loading}
        showSearch
        optionFilterProp="label"
        allowClear
        placeholder="选择已有案例"
        value={cid}
        onChange={setCid}
        options={cases.value.map((c) => ({ value: c.id, label: c.title }))}
      />
      <Button
        icon={<Link size={14} />}
        disabled={!cid}
        loading={busy}
        onClick={link}
      >
        关联已有案例
      </Button>
      {(item.linked_cases || []).map((c: Row) => (
        <a key={c.id} onClick={() => route("cases", { case: c.id })}>
          {c.title}
        </a>
      ))}
    </>
  );
}

const editable = [
  ["title", "案例标题"],
  ["description", "详细描述"],
  ["component", "组件"],
  ["cwe", "CWE（逗号分隔）"],
  ["cve", "CVE"],
  ["source_file", "源码文件"],
  ["source_lines", "源码行号"],
  ["trigger_conditions", "触发条件"],
  ["attack_path", "影响路径"],
  ["severity", "严重程度与依据"],
  ["function_module", "功能模块"],
  ["fix_recommendation", "修复建议"],
  ["dependencies", "依赖与环境"],
  ["reproduction_commands", "复现命令与预期结果"],
];
export function CaseEditor({ item, after }: { item: Row; after: () => void }) {
  const [fields, setFields] = useState<Row>({}),
    [author, setAuthor] = useState(authorDefault),
    [note, setNote] = useState(""),
    [error, setError] = useState(""),
    [busy, setBusy] = useState(false);
  const [pid, setPid] = useState<string>(),
    [file, setFile] = useState(""),
    [start, setStart] = useState<number>(1),
    [end, setEnd] = useState<number>(20);
  const [role, setRole] = useState("document"),
    [name, setName] = useState(""),
    [text, setText] = useState(""),
    [taskIds, setTaskIds] = useState<string[]>([]),
    [historic, setHistoric] = useState<Row>();
  const projects = useApi<Row[]>("/api/projects", []),
    tasks = useApi<Row[]>("/api/tasks", []);
  const inventory = useApi<Row[]>(`/api/cases/${item.id}/inventory`, []);
  function selectMaterial(path: string) {
    const asset = inventory.value.find((a) => a.path === path);
    if (!asset) return;
    setName(asset.name);
    setText(asset.text);
    setRole(
      asset.name.endsWith(".c")
        ? "poc"
        : asset.name.endsWith(".diff") || asset.name.endsWith(".patch")
          ? "patch"
          : "document",
    );
  }
  useEffect(() => {
    setFields({
      ...item.rendered,
      title: item.title,
      cwe: item.cwe.join(", "),
      dependencies: "",
      reproduction_commands: "",
      severity: "",
      ...item.fields,
    });
    setFile(item.rendered.source_file === "—" ? "" : item.rendered.source_file);
  }, [item]);
  async function action(fn: () => Promise<any>) {
    setBusy(true);
    setError("");
    try {
      await fn();
      after();
      message.success("新版本已保存");
    } catch (e: any) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  }
  async function upload(f?: File) {
    if (!f) return;
    if (f.size > 512 * 1024) {
      setError("文本附件超过 512 KiB");
      return;
    }
    setName(f.name);
    setText(await f.text());
  }
  const base = { revision: item.revision, author };
  function saveFields() {
    return action(() =>
      api(`/api/cases/${item.id}`, {
        method: "PUT",
        body: JSON.stringify({
          ...base,
          note,
          fields: Object.fromEntries(
            editable.map(([key]) => [key, fields[key] || ""]),
          ),
        }),
      }),
    );
  }
  return (
    <>
      <ErrorBox error={error} />
      <div className="form-row">
        <Tag color="blue">当前版本 v{item.revision}</Tag>
        <Tag>
          {item.complete ? "材料字段齐全" : `材料缺项 ${item.missing.length}`}
        </Tag>
        <Tag color={item.run_matches_expectation ? "green" : "default"}>
          {item.run_matches_expectation
            ? "关联运行符合预期"
            : "无已核验关联运行"}
        </Tag>
        <Input
          aria-label="材料编辑人"
          style={{ width: 170 }}
          value={author}
          onChange={(e) => setAuthor(e.target.value)}
        />
      </div>
      <Tabs
        items={[
          {
            key: "edit",
            label: "编辑字段",
            children: (
              <>
                <div className="case-fields">
                  {editable.map(([key, label]) => (
                    <div
                      key={key}
                      className={
                        [
                          "description",
                          "trigger_conditions",
                          "attack_path",
                          "fix_recommendation",
                          "dependencies",
                          "reproduction_commands",
                        ].includes(key)
                          ? "wide"
                          : ""
                      }
                    >
                      <label>{label}</label>
                      <Input.TextArea
                        aria-label={label}
                        autoSize={{ minRows: 1, maxRows: 8 }}
                        value={fields[key] || ""}
                        onChange={(e) =>
                          setFields((x) => ({ ...x, [key]: e.target.value }))
                        }
                      />
                    </div>
                  ))}
                </div>
                <label>修改说明</label>
                <Input value={note} onChange={(e) => setNote(e.target.value)} />
                <Button
                  style={{ marginTop: 16 }}
                  type="primary"
                  loading={busy}
                  onClick={saveFields}
                >
                  保存案例新版本
                </Button>
              </>
            ),
          },
          {
            key: "source",
            label: "固定源码片段",
            children: (
              <>
                <label>源码项目</label>
                <Select
                  loading={projects.loading}
                  style={{ width: "100%" }}
                  value={pid}
                  placeholder="选择固定提交的项目"
                  onChange={setPid}
                  options={projects.value.map((p) => ({
                    value: p.id,
                    label: `${p.name} · ${p.environment}`,
                  }))}
                />
                <label>项目内文件路径</label>
                <Input
                  aria-label="提取源码文件"
                  value={file}
                  onChange={(e) => setFile(e.target.value)}
                />
                <div className="form-row">
                  <div>
                    <label>起始行</label>
                    <InputNumber
                      aria-label="起始行"
                      min={1}
                      value={start}
                      onChange={(v) => setStart(v || 1)}
                    />
                  </div>
                  <div>
                    <label>结束行</label>
                    <InputNumber
                      aria-label="结束行"
                      min={start}
                      max={start + 399}
                      value={end}
                      onChange={(v) => setEnd(v || start)}
                    />
                  </div>
                </div>
                <Button
                  style={{ marginTop: 16 }}
                  disabled={!pid || !file}
                  loading={busy}
                  onClick={() =>
                    action(() =>
                      post(`/api/cases/${item.id}/capture`, {
                        ...base,
                        project_id: pid,
                        file,
                        start,
                        end,
                      }),
                    )
                  }
                >
                  提取并保存源码证据
                </Button>
                <p className="hint">
                  记录 Git
                  提交、文件摘要和准确行号；源码不干净或固定提交不匹配时停止。
                </p>
                {item.assets
                  .filter((a: Row) => a.capture)
                  .map((a: Row) => (
                    <div key={a.sha256}>
                      <Tag>{a.capture.commit.slice(0, 12)}</Tag>
                      <code>
                        {a.capture.file}:{a.capture.start}-{a.capture.end}
                      </code>
                      <pre>{a.text}</pre>
                    </div>
                  ))}
              </>
            ),
          },
          {
            key: "attachments",
            label: "关联材料",
            children: (
              <>
                <label>仓库已有材料</label>
                <Select
                  loading={inventory.loading}
                  style={{ width: "100%", marginBottom: 14 }}
                  placeholder="选择已有文档或程序，再确认类别并保存"
                  showSearch
                  optionFilterProp="label"
                  onChange={selectMaterial}
                  options={inventory.value.map((a) => ({
                    value: a.path,
                    label: a.path,
                  }))}
                />
                <div className="form-row">
                  <Select
                    value={role}
                    style={{ width: 180 }}
                    onChange={setRole}
                    options={[
                      { value: "document", label: "说明文档" },
                      { value: "poc", label: "验证程序源码" },
                      { value: "patch", label: "补丁" },
                      { value: "build-log", label: "构建日志" },
                      { value: "run-log", label: "运行日志" },
                      { value: "source", label: "未固定来源片段" },
                    ]}
                  />
                  <label className="ant-btn">
                    <Upload size={14} /> 选择文本文件
                    <input
                      aria-label="选择材料文件"
                      type="file"
                      accept=".c,.cpp,.h,.md,.txt,.log,.json,.diff,.patch"
                      style={{ display: "none" }}
                      onChange={(e) => upload(e.target.files?.[0])}
                    />
                  </label>
                </div>
                <label>附件文件名</label>
                <Input
                  aria-label="附件文件名"
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                />
                <label>附件内容</label>
                <Input.TextArea
                  aria-label="附件内容"
                  rows={8}
                  value={text}
                  onChange={(e) => setText(e.target.value)}
                />
                <Button
                  style={{ marginTop: 16 }}
                  loading={busy}
                  disabled={!name || !text}
                  onClick={() =>
                    action(() =>
                      post(`/api/cases/${item.id}/attachments`, {
                        ...base,
                        name,
                        text,
                        role,
                      }),
                    )
                  }
                >
                  保存附件版本
                </Button>
                <Table<Row>
                  size="small"
                  rowKey={(_, i) => String(i)}
                  pagination={false}
                  dataSource={item.material_checks || []}
                  locale={{ emptyText: <EmptyState title="暂无材料附件" /> }}
                  columns={[
                    { title: "材料", dataIndex: "name" },
                    {
                      title: "存在",
                      dataIndex: "present",
                      render: (x) => (x ? "是" : "否"),
                    },
                    {
                      title: "摘要核验",
                      dataIndex: "digest_verified",
                      render: (x) => (
                        <Tag color={x ? "green" : "red"}>
                          {x ? "通过" : "失败"}
                        </Tag>
                      ),
                    },
                    {
                      title: "来源绑定",
                      dataIndex: "meaning_verified",
                      render: (x) => (x ? "固定提交提取" : "未核验语义"),
                    },
                  ]}
                />
              </>
            ),
          },
          {
            key: "links",
            label: "关联记录",
            children: (
              <>
                <label>关联扫描、模型或运行任务</label>
                <Select
                  loading={tasks.loading}
                  mode="multiple"
                  style={{ width: "100%" }}
                  value={taskIds}
                  onChange={setTaskIds}
                  options={tasks.value.map((t) => ({
                    value: t.id,
                    label: `${t.kind} · ${t.id.slice(0, 10)} · ${t.status}`,
                  }))}
                />
                <Button
                  style={{ marginTop: 12 }}
                  disabled={!taskIds.length}
                  loading={busy}
                  onClick={() =>
                    action(() =>
                      post(`/api/cases/${item.id}/links`, {
                        ...base,
                        task_ids: taskIds,
                      }),
                    )
                  }
                >
                  保存任务关联
                </Button>
                <Table<Row>
                  loading={tasks.loading}
                  rowKey={(r) => r.kind + r.id}
                  pagination={false}
                  dataSource={item.links || []}
                  locale={{
                    emptyText: <EmptyState title="尚未关联任务或候选" />,
                  }}
                  columns={[
                    { title: "类型", render: (_, r) => r.task_kind || r.kind },
                    {
                      title: "记录",
                      render: (_, r) => (
                        <a
                          onClick={() =>
                            route(
                              r.kind === "finding" ? "findings" : "scans",
                              r.kind === "finding"
                                ? { finding: r.id }
                                : { task: r.id },
                            )
                          }
                        >
                          {r.id.slice(0, 16)}
                        </a>
                      ),
                    },
                    {
                      title: "状态",
                      dataIndex: "status",
                      render: (x) => <Status value={x} />,
                    },
                    {
                      title: "运行判读",
                      render: (_, r) =>
                        r.run_matches_expectation
                          ? "本案例运行符合预期"
                          : "不自动提升案例结论",
                    },
                  ]}
                />
                <Alert
                  style={{ marginTop: 14 }}
                  type="info"
                  title="核验待办"
                  description={item.validation_gaps?.join("；")}
                />
              </>
            ),
          },
          {
            key: "history",
            label: "版本与导出",
            children: (
              <>
                <Table<Row>
                  size="small"
                  rowKey="revision"
                  dataSource={[...(item.versions || [])].reverse()}
                  locale={{
                    emptyText: <EmptyState title="暂无本地编辑版本" />,
                  }}
                  columns={[
                    {
                      title: "版本",
                      dataIndex: "revision",
                      render: (x) => `v${x}`,
                    },
                    { title: "编辑人", dataIndex: "author" },
                    { title: "说明", dataIndex: "note" },
                    {
                      title: "时间",
                      dataIndex: "time",
                      render: (x) => new Date(x).toLocaleString(),
                    },
                    {
                      title: "操作",
                      render: (_, v) => (
                        <Space>
                          <Button
                            size="small"
                            onClick={() =>
                              api(
                                `/api/cases/${item.id}?revision=${v.revision}`,
                              )
                                .then(setHistoric)
                                .catch((e) => setError(e.message))
                            }
                          >
                            查看
                          </Button>
                          <Button
                            size="small"
                            icon={<Download size={13} />}
                            onClick={() =>
                              downloadReport({
                                case_ids: [item.id],
                                revisions: { [item.id]: v.revision },
                                format: "zip",
                              })
                                .then(() =>
                                  message.success("本版本证据附件包已导出"),
                                )
                                .catch((e) => setError(e.message))
                            }
                          >
                            导出本版本
                          </Button>
                        </Space>
                      ),
                    },
                  ]}
                />
                {historic && (
                  <>
                    <Tag>历史版本 v{historic.revision} · 只读</Tag>
                    <KeyValue
                      items={Object.entries(historic.fields || {}).map(
                        ([key, value]) => ({
                          label: editable.find(([k]) => k === key)?.[1] || key,
                          value: String(value),
                        }),
                      )}
                    />
                    <CheckList
                      items={(historic.missing || []).map((label: string) => ({
                        label,
                        status: false,
                        detail: "该版本材料缺项",
                      }))}
                    />
                    <RawJson
                      value={{
                        fields: historic.fields,
                        missing: historic.missing,
                        links: historic.links,
                      }}
                    />
                  </>
                )}
              </>
            ),
          },
        ]}
      />
    </>
  );
}
