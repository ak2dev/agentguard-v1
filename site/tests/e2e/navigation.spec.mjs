// Page-to-page navigation: the new page's first frame (the one the view
// transition reveals) must already use the site font, so nothing in the header
// shifts afterwards. Regression test for the nav "glitch" when Inter loaded late.
import { test, expect } from "@playwright/test";

test.beforeEach(async ({ page }) => {
  await page.addInitScript(() => {
    addEventListener("pagereveal", () => {
      const scan = document.querySelector("nav.main a");
      sessionStorage.setItem("reveal", JSON.stringify({
        interReady: document.fonts.check('16px "Inter Variable"'),
        navLeft: scan ? scan.getBoundingClientRect().left : null,
      }));
    });
  });
});

for (const [from, to] of [["/docs/", "/rules/"], ["/scan/", "/docs/"], ["/rules/", "/coverage/"]]) {
  test(`${from} → ${to}: the header is final on the first frame`, async ({ page }) => {
    await page.goto(from);
    await page.waitForLoadState("load");
    await page.click(`nav.main a[href='${to}']`);
    await page.waitForURL(`**${to}`);
    await page.waitForLoadState("load");
    await page.evaluate(() => document.fonts.ready);
    const { reveal, settled } = await page.evaluate(() => ({
      reveal: JSON.parse(sessionStorage.getItem("reveal") || "null"),
      settled: document.querySelector("nav.main a").getBoundingClientRect().left,
    }));
    expect(reveal, "pagereveal fired").not.toBeNull();
    expect(reveal.interReady, "Inter was ready when the page was revealed").toBe(true);
    expect(Math.abs(reveal.navLeft - settled), "nav did not move after reveal").toBeLessThan(0.5);
  });
}
