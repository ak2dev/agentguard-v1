// Progressive enhancement for segmented tabs ([data-tabs]). Without JavaScript
// every panel is shown, labelled; with it, one panel at a time.
(function () {
  document.documentElement.classList.add("js");
  for (const host of document.querySelectorAll("[data-tabs]")) {
    const list = host.querySelector('[role="tablist"]');
    if (!list) continue;
    const tabs = [...list.querySelectorAll('[role="tab"]')];
    const panels = tabs.map((t) => document.getElementById(t.getAttribute("aria-controls")));
    list.hidden = false;
    const select = (i, focus) => {
      tabs.forEach((t, j) => {
        t.setAttribute("aria-selected", String(i === j));
        t.tabIndex = i === j ? 0 : -1;
        if (panels[j]) panels[j].hidden = i !== j;
      });
      if (focus) tabs[i].focus();
    };
    tabs.forEach((t, i) => {
      t.addEventListener("click", () => select(i, false));
      t.addEventListener("keydown", (e) => {
        const d = { ArrowRight: 1, ArrowLeft: -1, Home: -i, End: tabs.length - 1 - i }[e.key];
        if (d === undefined) return;
        e.preventDefault();
        select((i + d + tabs.length) % tabs.length, true);
      });
    });
    select(0, false);
  }
})();
