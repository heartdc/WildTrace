import { test, expect } from "@playwright/test";

test("source project can be saved, browsed and selected for a scan", async ({
  page,
  request,
}) => {
  const projectName = `UI 源码目录检查 ${Date.now()}`;
  const health = await (await request.get("/api/health")).json();
  await page.goto("/#projects");
  await page.getByRole("button", { name: "添加项目" }).click();
  await page.getByLabel("项目名称", { exact: true }).fill(projectName);
  await page.getByLabel("项目源码根目录").fill(health.repository + "/bench");
  await page.getByRole("button", { name: "保存项目", exact: true }).click();
  await expect(page.getByText(projectName, { exact: true })).toBeVisible();
  const row = page.getByRole("row").filter({ hasText: projectName });
  await row.getByRole("button", { name: "预检", exact: true }).click();
  await expect(page.getByText("目录和提交检查通过")).toBeVisible();
  await page.keyboard.press("Escape");
  await expect(page.getByRole("dialog")).not.toBeVisible();
  await row.getByRole("button", { name: "扫描", exact: true }).click();
  await expect(
    page.getByText("按项目保存的选择范围、排除目录和固定提交执行。"),
  ).toBeVisible();
});

test("case field edits keep history and appear in report preview", async ({
  page,
  request,
}) => {
  await page.goto("/#cases?case=cjson_merge_alias");
  await page.getByRole("tab", { name: "材料编辑与关联" }).click();
  const before = await (
    await request.get("/api/cases/cjson_merge_alias")
  ).json();
  const description = "UI 验收记录：案例字段与报告同步";
  await page.getByLabel("详细描述", { exact: true }).fill(description);
  await page.getByRole("button", { name: "保存案例新版本" }).click();
  await expect(
    page.getByText(`当前版本 v${before.revision + 1}`),
  ).toBeVisible();
  await page.getByRole("tab", { name: "版本与导出" }).click();
  await expect(
    page.getByRole("button", { name: "导出本版本" }).first(),
  ).toBeVisible();
  const report = await request.post("/api/reports", {
    headers: { "X-Workbench": "1" },
    data: { case_ids: ["cjson_merge_alias"], format: "preview" },
  });
  expect((await report.json()).markdown).toContain(description);
  const current = await (
    await request.get("/api/cases/cjson_merge_alias")
  ).json();
  await request.put("/api/cases/cjson_merge_alias", {
    headers: { "X-Workbench": "1" },
    data: {
      revision: current.revision,
      author: "UI 验收",
      note: "恢复原描述",
      fields: { description: before.description },
    },
  });
});
