import { useEffect, useState } from "react";
import { createRoot } from "react-dom/client";
import { ConfigProvider, Tag } from "antd";
import zhCN from "antd/locale/zh_CN";
import {
  Activity,
  FileText,
  FolderGit2,
  FlaskConical,
  LayoutDashboard,
  Library,
  Radar,
  Settings2,
  ShieldCheck,
} from "lucide-react";
import {
  Overview,
  Scans,
  Findings,
  Cases,
  Runtime,
  Reports,
  Settings,
} from "./views";
import { api, route } from "./client";
import { Projects } from "./projects";
import "./styles.css";

const navigation = [
  {
    id: "overview",
    label: "总览",
    icon: LayoutDashboard,
    component: Overview,
    desc: "案例、候选与任务的证据分层概况",
  },
  {
    id: "projects",
    label: "源码项目",
    icon: FolderGit2,
    component: Projects,
    desc: "登记本地源码根目录，预检后发起扫描",
  },
  {
    id: "scans",
    label: "扫描任务",
    icon: Radar,
    component: Scans,
    desc: "静态扫描任务、运行日志与复核队列",
  },
  {
    id: "findings",
    label: "候选审查",
    icon: ShieldCheck,
    component: Findings,
    desc: "逐条人工复核扫描候选，候选不等同于漏洞",
  },
  {
    id: "cases",
    label: "案例库",
    icon: Library,
    component: Cases,
    desc: "案例材料、证据完整度与版本导出",
  },
  {
    id: "runtime",
    label: "运行验证",
    icon: FlaskConical,
    component: Runtime,
    desc: "隔离环境下的库级复现验证",
  },
  {
    id: "reports",
    label: "报告中心",
    icon: FileText,
    component: Reports,
    desc: "检查缺失项并导出审计报告",
  },
  {
    id: "settings",
    label: "设置",
    icon: Settings2,
    component: Settings,
    desc: "模型服务与本地工作区配置",
  },
];

function Workbench() {
  const [page, setPage] = useState(
    location.hash.slice(1).split("?")[0] || "overview",
  );
  const [version, setVersion] = useState("workbench-1");
  useEffect(() => {
    const update = () =>
      setPage(location.hash.slice(1).split("?")[0] || "overview");
    addEventListener("hashchange", update);
    return () => removeEventListener("hashchange", update);
  }, []);
  useEffect(() => {
    // 读取后端真实版本号；接口不可用时保留默认值
    api("/api/health")
      .then((h) => {
        if (h && typeof h.version === "string" && h.version)
          setVersion(h.version);
      })
      .catch(() => {});
  }, []);
  const selected = navigation.find((n) => n.id === page) || navigation[0];
  const View = selected.component;
  return (
    <div className="app">
      <aside>
        <div className="brand">
          <div className="brand-mark">
            <Activity size={19} />
          </div>
          <div>
            <strong>WildTrace</strong>
            <small>本地审计工作台</small>
          </div>
        </div>
        <nav>
          {navigation.map((n) => (
            <button
              aria-label={n.label}
              aria-current={selected.id === n.id ? "page" : undefined}
              title={n.label}
              className={selected.id === n.id ? "active" : ""}
              onClick={() => route(n.id)}
              key={n.id}
            >
              <n.icon size={17} aria-hidden="true" />
              {n.label}
            </button>
          ))}
        </nav>
        <div className="side-foot">
          <span className="dot" aria-hidden="true" />
          仅本机运行
        </div>
      </aside>
      <main>
        <header>
          <div>
            <span className="eyebrow">OpenHarmony 代码安全</span>
            <h1>{selected.label}</h1>
            <p className="page-desc">{selected.desc}</p>
          </div>
          <div className="header-actions">
            <Tag color="green">本地工作区</Tag>
            <span className="version">{version}</span>
          </div>
        </header>
        <div className="content">
          <View />
        </div>
      </main>
    </div>
  );
}

const tokens = getComputedStyle(document.documentElement);
const token = (name: string) => tokens.getPropertyValue(name).trim();

createRoot(document.getElementById("root")!).render(
  <ConfigProvider
    locale={zhCN}
    theme={{
      token: {
        colorPrimary: token("--brand"),
        colorText: token("--text"),
        colorTextSecondary: token("--text-2"),
        colorTextTertiary: token("--text-3"),
        colorTextPlaceholder: token("--text-3"),
        colorBorder: token("--border-strong"),
        colorBorderSecondary: token("--border"),
        colorBgLayout: token("--bg"),
        colorBgContainer: token("--surface"),
        colorError: token("--danger"),
        colorSuccess: token("--brand"),
        colorInfo: token("--ev-lib"),
        motion: !window.matchMedia("(prefers-reduced-motion: reduce)").matches,
        borderRadius: 6,
        fontFamily: token("--font"),
        fontSize: 14,
        fontSizeSM: 12,
      },
      components: {
        Table: { cellPaddingBlock: 14, fontSize: 13 },
        Button: { controlHeight: 34 },
      },
    }}
  >
    <Workbench />
  </ConfigProvider>,
);
