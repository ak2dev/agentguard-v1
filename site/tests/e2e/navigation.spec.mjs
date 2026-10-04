// Page-to-page navigation must not shift the header after the page is revealed
// (the nav "glitch" when Inter loaded late: ~17 px). Inter uses font-display: swap,
// so whether it is ready for a navigation's first frame is a race; instead the
// "Inter Fallback" face in global.css is metric-matched, so the header has the same
// geometry in either font. The first test checks that bound without any timing;
// the second checks real cross-document navigations against it.
import { test, expect } from "@playwright/test";

// The fallback matches widths on average, not per glyph: header boxes differ by
// up to ~2.4 px between the two fonts (17 px with the system fallback).
const TOLERANCE = 3;

function headerBoxes() {
  const els = [document.querySelector("header.site .brand span"),
    ...document.querySelectorAll("nav.main a"), ...document.querySelectorAll(".bar-actions a")];
  return els.map((el) => {
    const { left, top, width, height } = el.getBoundingClientRect();
    return { el: el.textContent.trim(), left, top, width, height };
  });
}

function expectSameGeometry(actual, expected, what) {
  expect(actual.map((b) => b.el), `${what}: same header elements`).toEqual(expected.map((b) => b.el));
  actual.forEach((box, i) => {
    for (const k of ["left", "top", "width", "height"]) {
      expect(Math.abs(box[k] - expected[i][k]), `${what}: "${box.el}" ${k}`).toBeLessThan(TOLERANCE);
    }
  });
}

for (const width of [1280, 820, 390]) {
  test(`${width}px: the header has the same geometry in Inter and in its fallback`, async ({ browser }) => {
    const measure = async (blockInter) => {
      const page = await browser.newPage({ viewport: { width, height: 800 } });
      if (blockInter) await page.route(/\/inter-[^/]*\.woff2$/, (route) => route.abort());
      await page.goto("/rules/");
      await page.evaluate(() => document.fonts.ready);
      const result = {
        ...await page.evaluate(() => ({
          inter: document.fonts.check('16px "Inter Variable"'),
          fallback: [...document.fonts].filter((f) => f.family === "Inter Fallback" && f.status === "loaded").length,
        })),
        boxes: await page.evaluate(headerBoxes),
      };
      await page.close();
      return result;
    };
    const inter = await measure(false);
    const fallback = await measure(true);
    expect(inter.inter, "Inter loads").toBe(true);
    expect(fallback.inter, "Inter is blocked").toBe(false);
    expect(fallback.fallback, "a local font (Arial or Liberation Sans) backs Inter Fallback").toBeGreaterThan(0);
    expectSameGeometry(fallback.boxes, inter.boxes, "fallback vs Inter");
  });
}

test.describe("cross-document navigation", () => {
  test.beforeEach(async ({ page }) => {
    await page.addInitScript({
      content: `addEventListener("pagereveal", () => sessionStorage.setItem("reveal", JSON.stringify((${headerBoxes})())));`,
    });
  });

  for (const [from, to] of [["/docs/", "/rules/"], ["/scan/", "/docs/"], ["/rules/", "/coverage/"]]) {
    test(`${from} → ${to}: the header does not move after the page is revealed`, async ({ page }) => {
      await page.goto(from);
      await page.waitForLoadState("load");
      await page.click(`nav.main a[href='${to}']`);
      await page.waitForURL(`**${to}`);
      await page.waitForLoadState("load");
      await page.evaluate(() => document.fonts.ready);
      const reveal = await page.evaluate(() => JSON.parse(sessionStorage.getItem("reveal") || "null"));
      expect(reveal, "pagereveal fired").not.toBeNull();
      expectSameGeometry(await page.evaluate(headerBoxes), reveal, "settled vs revealed");
    });
  }
});
