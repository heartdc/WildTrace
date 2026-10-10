import { test, expect } from "@playwright/test";

test('review queue preserves references and opens candidate details', async ({page, request}) => {
  const tasks = await (await request.get('/api/tasks')).json();
  const task = tasks.find((t:any) => t.kind === 'scan' && t.status === 'completed');
  test.skip(!task, 'Requires a saved scan result');
  const queue = await (await request.get(`/api/tasks/${task.id}/triage`)).json();
  test.skip(!queue.group_count, 'Requires saved candidate records');
  expect(queue.groups.flatMap((g:any)=>g.references).length).toBe(queue.candidate_count);
  await page.goto('/#scans?task='+task.id);
  await page.getByRole('tab',{name:'复核队列'}).click();
  await expect(page.getByText(`候选 ${queue.candidate_count} 条`,{exact:false})).toBeVisible();
  await page.getByRole('dialog').locator('.ant-table-row-expand-icon').first().click();
  await page.screenshot({path:'test-results/review-queue.png',animations:'disabled'});
  await page.getByRole('button',{name:/^第 \d+ 行/}).first().click();
  await expect(page.getByRole('dialog')).toContainText('候选详情');
});

test("candidate detail has source, review, and exact model request preview", async ({
  page,
  request,
}) => {
  const candidates = await (await request.get("/api/findings")).json();
  test.skip(
    !candidates.length,
    "Run a source scan before this integration test",
  );
  await page.goto("/#findings?finding=" + candidates[0].id);
  await expect(page.getByRole("dialog")).toContainText("源码摘要匹配");
  await page.getByRole("button", { name: "模型建议 / PoC 草稿" }).click();
  await page.getByRole("button", { name: "生成请求预览" }).click();
  await expect(page.getByText("以下内容将发送至所选模型服务：")).toBeVisible();
  await expect(
    page.getByRole("button", { name: "发送 1 个请求" }),
  ).toBeEnabled();
  await page.screenshot({
    path: "test-results/model-preview.png",
    fullPage: false,
    animations: "disabled",
  });
});

test("report preview and actual ZIP download", async ({ page }) => {
  await page.goto("/#reports");
  const select = page.getByRole("combobox").first();
  await select.fill("cjson");
  await page
    .locator(".ant-select-item-option-content")
    .filter({ hasText: "cjson-merge-nonobject-alias" })
    .click();
  await select.press("Escape");
  await page.getByRole("button", { name: "检查并预览" }).click();
  await expect(page.getByText("待补充，不能作为完整交付")).toBeVisible();
  const download = page.waitForEvent("download");
  await page.getByRole("button", { name: "证据附件包" }).click();
  const file = await download;
  expect(file.suggestedFilename()).toMatch(/\.zip$/);
  expect(await file.failure()).toBeNull();
});

test("existing verification task shows runtime matrix and survives refresh", async ({
  page,
  request,
}) => {
  const tasks = await (await request.get("/api/tasks")).json();
  const task = tasks.find(
    (t: any) => t.kind === "cjson" && t.status === "completed",
  );
  test.skip(!task, "A real cJSON run is needed for this integration test");
  await page.goto("/#scans?task=" + task.id);
  await page.getByRole("tab", { name: "结果", exact: true }).click();
  await expect(page.getByText("库级运行证据，产品可达性未建立")).toBeVisible();
  await page.reload();
  await expect(page.getByRole("dialog")).toBeVisible();
});
