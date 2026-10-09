import { useEffect, useState } from "react";
import { Alert, Tag } from "antd";

export type Row = Record<string, any>;
export const headers = {
  "Content-Type": "application/json",
  "X-Workbench": "1",
};
export async function api(path: string, options: RequestInit = {}) {
  const response = await fetch(path, {
    ...options,
    headers: { ...headers, ...(options.headers || {}) },
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok)
    throw new Error(
      typeof data.detail === "string"
        ? data.detail
        : JSON.stringify(data.detail),
    );
  return data;
}
export const post = (path: string, data: unknown) =>
  api(path, { method: "POST", body: JSON.stringify(data) });
export function useApi<T>(path: string, initial: T) {
  const [value, setValue] = useState<T>(initial),
    [error, setError] = useState(""),
    [loading, setLoading] = useState(true);
  const reload = () => {
    setError("");
    return api(path)
      .then(setValue)
      .catch((e) => setError(e.message));
  };
  useEffect(() => {
    let active = true;
    setLoading(true);
    api(path)
      .then((x) => {
        if (active) setValue(x);
      })
      .catch((e) => {
        if (active) setError(e.message);
      })
      .finally(() => {
        if (active) setLoading(false);
      });
    return () => {
      active = false;
    };
  }, [path]);
  return { value, error, reload, loading };
}
export const stateLabels: Row = {
  queued: "等待执行",
  running: "执行中",
  completed: "已完成",
  failed: "失败",
  cancelled: "已取消",
  cancelling: "取消中",
  interrupted: "已中断",
  passed: "验证通过",
  unknown: "未知",
  not_run: "未运行",
  library_level_reproduced: "库级复现",
  real_library_reproduction_confirmed: "真库复现",
  needs_verification: "待验证",
  rejected_candidate: "拒绝候选",
  approved_for_verification: "可进入验证",
  not_established: "未建立",
  imported_unverified: "导入，未核验",
};
export function Status({ value = "unknown" }: { value?: string }) {
  const color: Row = {
    completed: "green",
    passed: "green",
    running: "blue",
    queued: "gold",
    failed: "red",
    interrupted: "red",
    library_level_reproduced: "cyan",
    real_library_reproduction_confirmed: "cyan",
    rejected_candidate: "red",
    approved_for_verification: "blue",
  };
  return <Tag color={color[value]}>{stateLabels[value] || value}</Tag>;
}
export function ErrorBox({ error }: { error?: string }) {
  return error ? (
    <Alert className="error-box" type="error" showIcon title={error} />
  ) : null;
}
export function route(page: string, params: Row = {}) {
  location.hash =
    page +
    (Object.keys(params).length
      ? "?" + new URLSearchParams(params).toString()
      : "");
}
export function query(name: string) {
  return new URLSearchParams(location.hash.split("?")[1] || "").get(name);
}
export async function downloadReport(body: Row) {
  const r = await fetch("/api/reports", {
    method: "POST",
    headers,
    body: JSON.stringify(body),
  });
  if (!r.ok) throw new Error((await r.json()).detail);
  const url = URL.createObjectURL(await r.blob());
  const a = document.createElement("a");
  a.href = url;
  a.download = `wildtrace-report.${body.format === "markdown" ? "md" : body.format}`;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
