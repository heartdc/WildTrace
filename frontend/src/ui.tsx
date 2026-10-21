import type { ReactNode } from "react";
import { Button, Descriptions, Skeleton, Tag } from "antd";
import { CheckCircle2, CircleHelp, FolderOpen, XCircle } from "lucide-react";
import { stateLabels, type Row } from "./client";

export type Check = {
  label: string;
  status: boolean | null;
  detail?: ReactNode;
};
export function CheckList({ items }: { items: Check[] }) {
  return (
    <ul className="checklist">
      {items.map((item, i) => {
        const Icon =
          item.status === true
            ? CheckCircle2
            : item.status === false
              ? XCircle
              : CircleHelp;
        return (
          <li
            key={i}
            className={
              item.status === true
                ? "ok"
                : item.status === false
                  ? "bad"
                  : "info"
            }
          >
            <Icon size={17} aria-hidden="true" />
            <div>
              <span className="ck-label">{item.label}</span>
              <span className="check-state">
                {item.status === true
                  ? "通过"
                  : item.status === false
                    ? "未通过"
                    : "待核验"}
              </span>
              {item.detail != null && (
                <span className="ck-detail">{item.detail}</span>
              )}
            </div>
          </li>
        );
      })}
    </ul>
  );
}

export function KeyValue({
  items,
}: {
  items: { label: string; value: ReactNode }[];
}) {
  return (
    <Descriptions
      size="small"
      column={{ xs: 1, sm: 1, md: 2 }}
      items={items.map((i, key) => ({
        key,
        label: i.label,
        children: i.value ?? "未记录",
      }))}
    />
  );
}

export function RawJson({ value }: { value: unknown }) {
  return (
    <details className="raw-json">
      <summary>原始数据</summary>
      <pre>{JSON.stringify(value, null, 2) ?? "未记录"}</pre>
    </details>
  );
}

export function EmptyState({
  title,
  detail,
  action,
  onAction,
}: {
  title: string;
  detail?: string;
  action?: string;
  onAction?: () => void;
}) {
  return (
    <div className="empty-state">
      <FolderOpen size={26} aria-hidden="true" />
      <p>{title}</p>
      {detail && <p className="hint">{detail}</p>}
      {action && onAction && <Button onClick={onAction}>{action}</Button>}
    </div>
  );
}

export function LoadingState({ label = "正在加载" }: { label?: string }) {
  return (
    <div className="loading-state" role="status" aria-label={label}>
      <span>{label}</span>
      <Skeleton active paragraph={{ rows: 4 }} />
    </div>
  );
}

export function PreflightDetails({ data }: { data: Row }) {
  const check = (value: unknown): boolean | null =>
    typeof value === "boolean" ? value : null;
  const items: Check[] = [];
  if ("bwrap" in data)
    items.push({
      label: "bubblewrap",
      status: check(data.bwrap),
      detail: "隔离工具可用性",
    });
  if ("clang" in data)
    items.push({
      label: "Clang",
      status: check(data.clang),
      detail: data.clang_version,
    });
  if (data.root || data.source_root)
    items.push({
      label: "源码目录",
      status: data.error ? null : true,
      detail: data.root || data.source_root,
    });
  const commit = data.source_commit ?? data.commit;
  items.push({
    label: "提交一致性",
    status: data.expected_commit ? commit === data.expected_commit : null,
    detail: data.expected_commit
      ? `当前 ${commit || "未记录"}；期望 ${data.expected_commit}`
      : `未配置固定提交；当前 ${commit || "未记录"}`,
  });
  items.push({ label: "工作区干净", status: check(data.clean) });
  for (const [file, ok] of Object.entries(data.source_hashes || {}))
    items.push({ label: file, status: check(ok), detail: "源码摘要匹配" });
  if (data.isolation)
    items.push({ label: "隔离检查", status: null, detail: data.isolation });
  return (
    <>
      <CheckList items={items} />
      <KeyValue
        items={[
          {
            label: "环境",
            value: data.distribution || data.environment || "未记录",
          },
          { label: "Python", value: data.python || "未记录" },
          ...(data.warning ? [{ label: "备注", value: data.warning }] : []),
        ]}
      />
      <RawJson value={data} />
    </>
  );
}

export const laneLabels: Row = {
  manual_review: "人工审查",
  needs_context: "待补上下文",
  syntax_only: "待固定源码",
  test_support: "测试与支持代码",
};
export function LaneCounts({ counts }: { counts: Row }) {
  return (
    <div className="lane-tags">
      {Object.entries(counts).map(([key, count]) => (
        <Tag key={key}>
          {laneLabels[key] || key} · {String(count)}
        </Tag>
      ))}
    </div>
  );
}

function displayValue(value: unknown): ReactNode {
  if (value === null || value === undefined || value === "") return "未记录";
  if (typeof value === "boolean") return value ? "是" : "否";
  if (Array.isArray(value))
    return value.length ? (
      <ul className="evidence-list">
        {value.map((v, i) => (
          <li key={i}>{displayValue(v)}</li>
        ))}
      </ul>
    ) : (
      "未记录"
    );
  if (typeof value === "object")
    return (
      <dl className="evidence-dl">
        {Object.entries(value as Row).map(([k, v]) => (
          <div key={k}>
            <dt>{fieldLabels[k] || k}</dt>
            <dd>{displayValue(v)}</dd>
          </div>
        ))}
      </dl>
    );
  return (
    <span className="evidence-value">
      {stateLabels[String(value)] || String(value)}
    </span>
  );
}
const fieldLabels: Row = {
  date: "日期",
  when: "记录日期",
  result: "观察结果",
  status: "状态",
  record: "证据记录",
  records: "证据引用",
  library: "库文件",
  reference: "证据引用",
  source_commit: "源码提交",
  verdict: "判断",
  real_library_reproduction: "真实库复现记录",
  equivalent_reproduction: "等价复现记录",
  caveats: "适用边界",
  scope: "验证范围",
  what: "记录内容",
  product_binary_linked: "产品二进制关联",
  platform_binary_linked: "平台二进制关联",
  frame_attribution: "栈帧归属",
  asan: "Sanitizer 观察",
  evidence_zip_sha256: "证据包摘要",
  time: "时间",
  note: "备注",
  reviewer: "复核人",
  author: "记录人",
};
export function EvidenceDetails({ value }: { value: unknown }) {
  if (
    value == null ||
    (typeof value === "object" && Object.keys(value).length === 0)
  )
    return <EmptyState title="尚无证据记录" />;
  return (
    <>
      <div className="evidence-details">{displayValue(value)}</div>
      <RawJson value={value} />
    </>
  );
}

export function MessagePreview({ messages }: { messages: Row[] }) {
  return (
    <>
      {messages.map((m, i) => (
        <article className="msg-card" key={i}>
          <div>
            <strong>
              {(
                {
                  system: "系统要求",
                  user: "候选与源码",
                  assistant: "模型输出",
                } as Row
              )[m.role] || m.role}
            </strong>
            <span>{m.role}</span>
          </div>
          <pre>{formatMessage(m.content)}</pre>
        </article>
      ))}
    </>
  );
}

function formatMessage(content: unknown): string {
  if (typeof content !== "string") return JSON.stringify(content, null, 2);
  try {
    return JSON.stringify(JSON.parse(content), null, 2);
  } catch {
    return content;
  }
}
