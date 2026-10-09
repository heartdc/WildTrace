import { test, expect } from "@playwright/test";

test("overview, real case, impact and attachment export", async ({ page }) => {
  const errors: string[] = [];
  page.on("pageerror", (e) => errors.push(e.message));
  await page.goto("/");
  await expect(page.getByText("案例证据完整度")).toBeVisible();
  await expect(page.locator(".metric").first()).toContainText("19");
  await page.screenshot({
    path: "test-results/desktop-overview.png",
    fullPage: true,
  });
  await page.goto("/#cases?case=hiappevent_ffi_watcher_null_filter");
  await expect(page.getByRole("dialog")).toContainText("hiappevent");
  await page.getByRole("tab", { name: "PoC 与附件" }).click();
  await expect(page.getByRole("dialog")).toContainText(
    "hiappevent_null_watcher.c",
  );
  const download = page.waitForEvent("download");
  await page
    .getByRole("dialog")
    .getByText("下载", { exact: false })
    .last()
    .click();
  expect((await download).suggestedFilename()).toContain(".c");
  await page.getByRole("tab", { name: "版本影响" }).click();
  await expect(page.getByRole("dialog")).toContainText("未知");
  await page.screenshot({
    path: "test-results/desktop-case.png",
    fullPage: true,
  });
  await page.reload();
  await expect(page.getByRole("dialog")).toBeVisible();
  expect(errors).toEqual([]);
});

test("navigation, settings, runtime and report empty state", async ({
  page,
}) => {
  await page.goto("/#settings");
  await expect(page.getByLabel("临时 API Key")).toBeVisible();
  await expect(page.getByLabel("源码根目录")).not.toHaveValue("");
  await page.getByRole("button", { name: "运行验证", exact: true }).click();
  await expect(
    page.getByRole("button", { name: "启动 cJSON 隔离验证" }),
  ).toBeDisabled();
  await page.getByRole("button", { name: "报告中心", exact: true }).click();
  await page.getByRole("button", { name: "检查并预览" }).click();
  await expect(page.getByText("请选择至少一个案例或任务")).toBeVisible();
  await page.goto("/#findings");
  await expect(
    page.getByRole("heading", { name: "候选审查", exact: true }).last(),
  ).toBeVisible();
});

test("mobile viewport has no document overflow", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  for (const view of [
    "overview",
    "cases",
    "scans",
    "settings",
    "runtime",
    "reports",
  ]) {
    await page.goto("/#" + view);
    await expect(page.locator("main h1")).toBeVisible();
    await page.waitForTimeout(300);
    expect(
      await page.evaluate(
        () => document.documentElement.scrollWidth <= innerWidth + 1,
      ),
      view,
    ).toBeTruthy();
  }
  await page.goto("/#overview");
  await expect(page.locator(".metric").first()).toContainText("19");
  await page.screenshot({
    path: "test-results/mobile-overview.png",
    fullPage: true,
  });
});
