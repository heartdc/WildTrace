import type { ReactNode } from "react";
import { EmptyState } from "./ui";

export type Datum = { label: string; value: number; color?: string };
const palette = [
  "var(--ev-product)",
  "var(--ev-lib)",
  "var(--ev-candidate)",
  "var(--ev-official)",
  "var(--danger)",
  "#526e82",
  "#946247",
  "#3d7472",
];
const positive = (value: number) =>
  Number.isFinite(value) && value > 0 ? value : 0;
export function Donut({ data, label }: { data: Datum[]; label: string }) {
  const total = data.reduce((sum, d) => sum + positive(d.value), 0);
  if (!total) return <EmptyState title="暂无任务状态数据" />;
  let offset = 0;
  return (
    <div className="donut-wrap">
      <svg
        width="160"
        height="160"
        viewBox="0 0 160 160"
        role="img"
        aria-label={`${label}：${data.map((d) => `${d.label} ${d.value}`).join("，")}`}
      >
        <circle
          cx="80"
          cy="80"
          r="58"
          fill="none"
          stroke="var(--border)"
          strokeWidth="20"
        />
        {data.map((d, i) => {
          const fraction = (positive(d.value) / total) * 100;
          const start = offset;
          offset += fraction;
          return (
            <circle
              key={i}
              cx="80"
              cy="80"
              r="58"
              fill="none"
              stroke={d.color || palette[i % palette.length]}
              strokeWidth="20"
              pathLength="100"
              strokeDasharray={`${fraction} ${100 - fraction}`}
              strokeDashoffset={-start}
              transform="rotate(-90 80 80)"
            >
              <title>
                {d.label}: {d.value}
              </title>
            </circle>
          );
        })}
        <text
          x="80"
          y="80"
          textAnchor="middle"
          dominantBaseline="middle"
          className="donut-total"
        >
          {total}
        </text>
        <text x="80" y="105" textAnchor="middle" className="donut-caption">
          任务
        </text>
      </svg>
      <ul className="chart-legend">
        {data.map((d, i) => (
          <li key={i}>
            <i
              style={{ background: d.color || palette[i % palette.length] }}
              aria-hidden="true"
            />
            {d.label}
            <b>{d.value}</b>
          </li>
        ))}
      </ul>
    </div>
  );
}

export function BarList({
  data,
  label,
  empty = "暂无可统计数据",
}: {
  data: Datum[];
  label: string;
  empty?: string;
}) {
  if (!data.length || !data.some((d) => positive(d.value)))
    return <EmptyState title={empty} />;
  const maximum = Math.max(...data.map((d) => positive(d.value)), 1);
  return (
    <ul className="barlist" aria-label={label}>
      {data.map((d, i) => (
        <li key={i}>
          <span className="label" title={d.label}>
            {d.label}
          </span>
          <svg
            className="bar-track"
            viewBox="0 0 100 10"
            preserveAspectRatio="none"
            role="img"
            aria-label={`${d.label}：${d.value}`}
          >
            <rect width="100" height="10" rx="3" fill="var(--border)" />
            <rect
              width={(positive(d.value) / maximum) * 100}
              height="10"
              rx="3"
              fill={d.color || palette[i % palette.length]}
            />
          </svg>
          <b className="value">{d.value}</b>
        </li>
      ))}
    </ul>
  );
}

export function Histogram({
  values,
  label,
}: {
  values: unknown[];
  label: string;
}) {
  const bins = [0, 0, 0, 0, 0];
  let unknown = 0;
  for (const value of values) {
    if (
      typeof value !== "number" ||
      !Number.isFinite(value) ||
      value < 0 ||
      value > 100
    )
      unknown++;
    else bins[Math.min(Math.floor(value / 20), 4)]++;
  }
  const maximum = Math.max(...bins, 1);
  const names = ["0–19", "20–39", "40–59", "60–79", "80–100"];
  if (!values.length) return <EmptyState title="暂无候选置信度数据" />;
  return (
    <div className="histogram">
      <svg
        viewBox="0 0 320 120"
        role="img"
        aria-label={`${label}：${names.map((n, i) => `${n} 分 ${bins[i]} 条`).join("，")}，未知 ${unknown} 条`}
        preserveAspectRatio="none"
      >
        {[0, 1, 2].map((i) => (
          <line
            key={i}
            x1="0"
            x2="320"
            y1={10 + i * 50}
            y2={10 + i * 50}
            stroke="var(--border)"
            strokeDasharray="3 4"
          />
        ))}
        {bins.map((n, i) => (
          <rect
            key={i}
            x={i * 64 + 13}
            y={110 - (n / maximum) * 100}
            width="38"
            height={(n / maximum) * 100}
            rx="3"
            fill="var(--ev-lib)"
          >
            <title>
              {names[i]}: {n}
            </title>
          </rect>
        ))}
      </svg>
      <ol className="histogram-legend">
        {names.map((n, i) => (
          <li key={n}>
            <strong>{bins[i]}</strong>
            <span>{n}</span>
          </li>
        ))}
      </ol>
      <p className="hint">
        未知 / 未提供：{unknown} 条。置信度为规则排序分，不代表漏洞准确率。
      </p>
    </div>
  );
}

export type TimelineItem = {
  id: string;
  title: ReactNode;
  detail: ReactNode;
  label: string;
  color?: string;
  onClick?: () => void;
};
export function Timeline({
  items,
  label,
}: {
  items: TimelineItem[];
  label: string;
}) {
  if (!items.length) return <EmptyState title="暂无时间记录" />;
  return (
    <ol className="activity-timeline" aria-label={label}>
      {items.map((item, i) => (
        <li key={item.id}>
          <svg
            width="16"
            height="48"
            viewBox="0 0 16 48"
            role="img"
            aria-label={item.label}
          >
            {i < items.length - 1 && (
              <line
                x1="8"
                y1="15"
                x2="8"
                y2="48"
                stroke="var(--border-strong)"
              />
            )}
            <circle cx="8" cy="9" r="4" fill={item.color || "var(--ev-lib)"} />
          </svg>
          <div>
            <div className="tl-title">
              {item.onClick ? (
                <button className="text-action" onClick={item.onClick}>
                  {item.title}
                </button>
              ) : (
                item.title
              )}
            </div>
            <div className="tl-meta">{item.detail}</div>
          </div>
        </li>
      ))}
    </ol>
  );
}

export function frequencies(values: string[], limit = 8): Datum[] {
  const counts = new Map<string, number>();
  for (const value of values) counts.set(value, (counts.get(value) || 0) + 1);
  return [...counts]
    .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
    .slice(0, limit)
    .map(([label, value]) => ({ label, value }));
}
