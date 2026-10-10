import { useEffect, useState } from "react";
import { createRoot } from "react-dom/client";
import { ConfigProvider, Tag } from "antd";
import zhCN from "antd/locale/zh_CN";
import {
  Activity,
  FileCheck2,
  FolderSearch,
  FlaskConical,
  LayoutDashboard,
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
import { route } from "./client";
import { Projects } from "./projects";
import "./styles.css";

const navigation = [
  { id: "overview", label: "总览", icon: LayoutDashboard, component: Overview },
  {
    id: "projects",
    label: "源码项目",
    icon: FolderSearch,
    component: Projects,
  },
  { id: "scans", label: "扫描任务", icon: FolderSearch, component: Scans },
  { id: "findings", label: "候选审查", icon: ShieldCheck, component: Findings },
  { id: "cases", label: "案例库", icon: FileCheck2, component: Cases },
  { id: "runtime", label: "运行验证", icon: FlaskConical, component: Runtime },
  { id: "reports", label: "报告中心", icon: FileCheck2, component: Reports },
  { id: "settings", label: "设置", icon: Settings2, component: Settings },
];

function Workbench() {
  const [page, setPage] = useState(
    location.hash.slice(1).split("?")[0] || "overview",
  );
  useEffect(() => {
    const update = () =>
      setPage(location.hash.slice(1).split("?")[0] || "overview");
    addEventListener("hashchange", update);
    return () => removeEventListener("hashchange", update);
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
              title={n.label}
              className={selected.id === n.id ? "active" : ""}
              onClick={() => route(n.id)}
              key={n.id}
            >
              <n.icon size={17} />
              {n.label}
            </button>
          ))}
        </nav>
        <div className="side-foot">
          <span className="dot" />
          仅本机运行
        </div>
      </aside>
      <main>
        <header>
          <div>
            <span className="eyebrow">OpenHarmony 代码安全</span>
            <h1>{selected.label}</h1>
          </div>
          <div className="header-actions">
            <Tag color="green">本地工作区</Tag>
            <span className="version">workbench-1</span>
          </div>
        </header>
        <div className="content">
          <View />
        </div>
      </main>
    </div>
  );
}

createRoot(document.getElementById("root")!).render(
  <ConfigProvider
    locale={zhCN}
    theme={{
      token: {
        colorPrimary: "#11866a",
        borderRadius: 6,
        fontFamily: "'Segoe UI', 'Microsoft YaHei', sans-serif",
        fontSize: 13,
      },
      components: {
        Table: { cellPaddingBlock: 14 },
        Button: { controlHeight: 34 },
      },
    }}
  >
    <Workbench />
  </ConfigProvider>,
);
