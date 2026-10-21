import { useState } from "react";
import {
  Alert,
  Button,
  Input,
  Modal,
  Select,
  Space,
  Table,
  Tag,
  message,
} from "antd";
import { FolderOpen, Plus, Play, RefreshCw } from "lucide-react";
import { api, post, useApi, route, ErrorBox, type Row } from "./client";
import { EmptyState, PreflightDetails } from "./ui";

const initial = {
  name: "",
  environment: "windows",
  distribution: "Ubuntu",
  root: "",
  component: "",
  expected_commit: "",
  include: [],
  exclude: [".git", ".cache", "out", "build", "node_modules", "__pycache__"],
};
export function Projects() {
  const projects = useApi<Row[]>("/api/projects", []);
  const [draft, setDraft] = useState<Row>(),
    [error, setError] = useState(""),
    [busy, setBusy] = useState(false);
  const [browser, setBrowser] = useState<Row>(),
    [probe, setProbe] = useState<Row>();
  function field(key: string, value: unknown) {
    setDraft((d) => ({ ...d, [key]: value }));
  }
  async function save() {
    if (!draft) return;
    setBusy(true);
    setError("");
    try {
      await api("/api/projects" + (draft.id ? "/" + draft.id : ""), {
        method: draft.id ? "PUT" : "POST",
        body: JSON.stringify(draft),
      });
      setDraft(undefined);
      projects.reload();
      message.success("源码项目已保存");
    } catch (e: any) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  }
  async function browse(root?: string) {
    if (!draft) return;
    setBusy(true);
    try {
      const config = {
        ...draft,
        name: draft.name || "目录选择",
        root: root || draft.root,
      };
      const result = await post("/api/projects/browse", config);
      setBrowser({ ...result, root: config.root });
    } catch (e: any) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  }
  async function preflight(p: Row) {
    setBusyId(p.id);
    try {
      setProbe(await post(`/api/projects/${p.id}/preflight`, {}));
      projects.reload();
    } catch (e: any) {
      setError(e.message);
    } finally {
      setBusyId(undefined);
    }
  }
  const [busyId, setBusyId] = useState<string>();
  return (
    <>
      <div className="toolbar">
        <div>
          <span className="eyebrow">SOURCE PROJECTS</span>
          <h2>源码项目</h2>
        </div>
        <Button
          type="primary"
          icon={<Plus size={15} />}
          onClick={() => {
            setError("");
            setDraft({ ...initial });
          }}
        >
          添加项目
        </Button>
      </div>
      <ErrorBox error={error || projects.error} />
      <div className="panel">
        <Table<Row>
          loading={projects.loading}
          locale={{
            emptyText: (
              <EmptyState
                title="暂无源码项目"
                detail="登记源码目录后，可在这里检查环境并发起扫描。"
              />
            ),
          }}
          rowKey="id"
          dataSource={projects.value}
          columns={[
            {
              title: "项目",
              render: (_, p) => (
                <>
                  <strong>{p.name}</strong>
                  <small className="table-sub">{p.component}</small>
                </>
              ),
            },
            {
              title: "源码目录",
              render: (_, p) => (
                <>
                  <Tag>
                    {p.environment === "wsl"
                      ? `WSL · ${p.distribution}`
                      : "Windows"}
                  </Tag>
                  <code>{p.root}</code>
                </>
              ),
            },
            {
              title: "固定提交 / 范围",
              render: (_, p) => (
                <>
                  <code>{p.expected_commit?.slice(0, 12) || "未固定提交"}</code>
                  <small className="table-sub">
                    {p.include.length ? p.include.join(", ") : "项目内源码"}
                  </small>
                </>
              ),
            },
            {
              title: "操作",
              render: (_, p) => (
                <Space>
                  <Button size="small" onClick={() => setDraft(p)}>
                    编辑
                  </Button>
                  <Button
                    size="small"
                    loading={busyId === p.id}
                    disabled={!!busyId && busyId !== p.id}
                    icon={<RefreshCw size={12} />}
                    onClick={() => preflight(p)}
                  >
                    预检
                  </Button>
                  <Button
                    size="small"
                    icon={<Play size={12} />}
                    onClick={() => route("scans", { project: p.id })}
                  >
                    扫描
                  </Button>
                </Space>
              ),
            },
          ]}
        />
      </div>
      <Modal
        width={820}
        open={!!draft}
        title={draft?.id ? "编辑源码项目" : "添加源码项目"}
        onCancel={() => {
          setDraft(undefined);
          setBrowser(undefined);
        }}
        onOk={save}
        confirmLoading={busy}
        okText="保存项目"
      >
        {draft && (
          <>
            <ErrorBox error={error} />
            <div className="form-row">
              <div className="grow">
                <label>项目名称</label>
                <Input
                  aria-label="项目名称"
                  value={draft.name}
                  onChange={(e) => field("name", e.target.value)}
                />
              </div>
              <div>
                <label>执行环境</label>
                <Select
                  aria-label="执行环境"
                  value={draft.environment}
                  style={{ width: 170 }}
                  onChange={(x) => field("environment", x)}
                  options={[
                    { value: "windows", label: "Windows 本机" },
                    { value: "wsl", label: "WSL 原生扫描" },
                  ]}
                />
              </div>
            </div>
            {draft.environment === "wsl" && (
              <>
                <label>WSL 分发版</label>
                <Input
                  value={draft.distribution}
                  onChange={(e) => field("distribution", e.target.value)}
                />
              </>
            )}
            <label>源码根目录</label>
            <Space.Compact style={{ width: "100%" }}>
              <Input
                aria-label="项目源码根目录"
                value={draft.root}
                placeholder={
                  draft.environment === "wsl"
                    ? "/home/airgap/project"
                    : "C:\\Projects\\OpenHarmony"
                }
                onChange={(e) => field("root", e.target.value)}
              />
              <Button
                icon={<FolderOpen size={14} />}
                loading={busy}
                onClick={() => browse()}
              >
                浏览目录
              </Button>
            </Space.Compact>
            <label>组件名称</label>
            <Input
              value={draft.component}
              onChange={(e) => field("component", e.target.value)}
            />
            <label>固定 Git 提交（可选，完整 40 位）</label>
            <Input
              value={draft.expected_commit}
              onChange={(e) => field("expected_commit", e.target.value)}
            />
            <label>
              选择子目录或文件（每行一个相对路径，留空选择项目内源码）
            </label>
            <Input.TextArea
              aria-label="选择范围"
              rows={3}
              value={draft.include.join("\n")}
              onChange={(e) =>
                field("include", e.target.value.split("\n").filter(Boolean))
              }
            />
            <label>排除目录或模式（每行一项）</label>
            <Input.TextArea
              aria-label="排除范围"
              rows={3}
              value={draft.exclude.join("\n")}
              onChange={(e) =>
                field("exclude", e.target.value.split("\n").filter(Boolean))
              }
            />
            <p className="hint">
              扫描记录会保留项目配置、实际选择的文件清单和源码摘要。
            </p>
          </>
        )}
      </Modal>
      <Modal
        width={700}
        open={!!browser}
        title="选择源码目录"
        onCancel={() => setBrowser(undefined)}
        onOk={() => {
          field("root", browser?.root);
          setBrowser(undefined);
        }}
        okText="使用当前目录"
      >
        {browser && (
          <>
            <code>{browser.root}</code>
            {browser.truncated && (
              <Alert type="warning" title="仅显示前 500 项" />
            )}
            <Table<Row>
              loading={busy}
              locale={{
                emptyText: <EmptyState title="当前目录没有可选择的子项" />,
              }}
              rowKey="path"
              pagination={{ pageSize: 8 }}
              dataSource={browser.entries}
              columns={[
                {
                  title: "名称",
                  render: (_, e) => (
                    <Space>
                      {e.directory && <FolderOpen size={14} />}
                      <span>{e.name}</span>
                    </Space>
                  ),
                },
                {
                  title: "",
                  render: (_, e) =>
                    e.directory && (
                      <Button
                        size="small"
                        onClick={() =>
                          browse(
                            browser.root.replace(/[\\/]$/, "") + "/" + e.name,
                          )
                        }
                      >
                        进入
                      </Button>
                    ),
                },
              ]}
            />
          </>
        )}
      </Modal>
      <Modal
        width={700}
        open={!!probe}
        title="项目预检"
        footer={null}
        onCancel={() => setProbe(undefined)}
      >
        {probe && (
          <>
            <Alert
              type={probe.ready ? "success" : "error"}
              title={probe.ready ? "目录和提交检查通过" : "检查未通过"}
            />
            <PreflightDetails data={probe} />
          </>
        )}
      </Modal>
    </>
  );
}
