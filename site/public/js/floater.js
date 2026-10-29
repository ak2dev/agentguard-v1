// Once the header has scrolled away, keep the logo and the call to action on screen
// (.floater), and turn each one white while it sits over an orange band.
(function () {
  const run = () => {
    const floater = document.querySelector("[data-floater]");
    const header = document.querySelector("header.site");
    if (!floater || !header || !window.IntersectionObserver) return;
    const parts = [...floater.querySelectorAll(".mark, .btn")];
    const orange = () => document.querySelectorAll(".hero, .cta-band, .tile.orange, .split .after");
    let queued = false;

    const tone = () => {
      queued = false;
      if (!floater.classList.contains("show")) return;
      const bands = [...orange()].map((el) => el.getBoundingClientRect());
      for (const el of parts) {
        const r = el.getBoundingClientRect(), x = r.left + r.width / 2, y = r.top + r.height / 2;
        el.classList.toggle("on-orange", bands.some((b) => x >= b.left && x <= b.right && y >= b.top && y <= b.bottom));
      }
    };
    const schedule = () => { if (!queued) { queued = true; requestAnimationFrame(tone); } };

    new IntersectionObserver(([e]) => {
      floater.classList.toggle("show", !e.isIntersecting);
      schedule();
    }).observe(header);
    addEventListener("scroll", schedule, { passive: true });
    addEventListener("resize", schedule);
  };
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", run);
  else run();
})();
