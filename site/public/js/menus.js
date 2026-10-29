// Header dropdowns: hovering a nav item that carries data-menu opens its panel (after a
// short pause, so a pointer passing over the bar does not flash them), moving to another
// one swaps panels at once, and leaving both the item and the panel closes it after
// another short pause. The panels fade and grow in from the top (see .menu in global.css).
// Keyboard: ArrowDown on the item opens the panel and focuses its first link; Escape
// closes it and returns to the item. The items stay plain links that navigate on click.
(function () {
  const OPEN_DELAY = 60, CLOSE_DELAY = 120;
  const run = () => {
    const header = document.querySelector("header.site");
    if (!header) return;
    const triggers = [...header.querySelectorAll("nav.main a[data-menu]")];
    const panels = new Map([...header.querySelectorAll("[data-menu-panel]")].map((p) => [p.dataset.menuPanel, p]));
    if (!triggers.length) return;
    const wide = matchMedia("(min-width: 900px)");
    const trigger = (name) => triggers.find((t) => t.dataset.menu === name);
    let current = null, openTimer = 0, closeTimer = 0;

    const hide = (name, instant) => {
      const panel = panels.get(name), item = trigger(name);
      if (!panel) return;
      if (instant) panel.classList.add("instant");
      panel.classList.remove("open");
      item.classList.remove("menu-open");
      item.setAttribute("aria-expanded", "false");
      if (instant) { void panel.offsetWidth; panel.classList.remove("instant"); }
    };
    const show = (name) => {
      clearTimeout(closeTimer);
      if (current === name || !wide.matches) return;
      if (current) hide(current, true);
      current = name;
      panels.get(name).classList.add("open");
      trigger(name).classList.add("menu-open");
      trigger(name).setAttribute("aria-expanded", "true");
    };
    const close = () => { if (current) { hide(current, false); current = null; } };
    const later = (fn, ms) => { clearTimeout(openTimer); clearTimeout(closeTimer); return setTimeout(fn, ms); };

    for (const item of triggers) {
      const name = item.dataset.menu;
      item.addEventListener("pointerenter", (e) => {
        if (e.pointerType !== "mouse") return;
        openTimer = later(() => show(name), current ? 0 : OPEN_DELAY);
      });
      item.addEventListener("pointerleave", (e) => { if (e.pointerType === "mouse") closeTimer = later(close, CLOSE_DELAY); });
      item.addEventListener("keydown", (e) => {
        if (e.key !== "ArrowDown") return;
        e.preventDefault();
        show(name);
        const first = panels.get(name).querySelector("a");
        if (first) first.focus();
      });
    }
    // other nav links close an open panel, as the pointer has moved on
    for (const link of header.querySelectorAll("nav.main a:not([data-menu])")) {
      link.addEventListener("pointerenter", (e) => { if (e.pointerType === "mouse" && current) closeTimer = later(close, 0); });
    }
    for (const [name, panel] of panels) {
      panel.addEventListener("pointerenter", () => { clearTimeout(closeTimer); clearTimeout(openTimer); });
      panel.addEventListener("pointerleave", (e) => { if (e.pointerType === "mouse") closeTimer = later(close, CLOSE_DELAY); });
      panel.addEventListener("keydown", (e) => {
        if (e.key !== "Escape") return;
        hide(name, false);
        current = null;
        trigger(name).focus();
      });
      panel.addEventListener("focusout", (e) => {
        if (current === name && !panel.contains(e.relatedTarget) && e.relatedTarget !== trigger(name)) close();
      });
    }
    document.addEventListener("keydown", (e) => { if (e.key === "Escape") close(); });
    wide.addEventListener("change", close);
  };
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", run);
  else run();
})();
