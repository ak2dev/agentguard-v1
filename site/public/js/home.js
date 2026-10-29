// Landing-page motion: the client carousel, the headings that retype their last words,
// the counter in the "with Agent Guard" panel, the dot waveform and the scan queue.
// Everything here is decoration over content that is already in the page; without
// JavaScript (or with reduced motion) the page reads the same, standing still.
(function () {
  const still = matchMedia("(prefers-reduced-motion: reduce)").matches;
  const onView = (el, fn, threshold = 0.35) => {
    if (!window.IntersectionObserver) return fn(true);
    new IntersectionObserver(([e]) => fn(e.isIntersecting), { threshold }).observe(el);
  };

  // ---- client carousel -------------------------------------------------------------
  // Each card colours its words in, one by one; then the next tab slides to the front.
  const host = document.querySelector("[data-carousel]");
  if (host) {
    const track = host.querySelector(".q-track");
    const tabs = [...host.querySelectorAll(".q-tab")];
    const cards = tabs.map((t) => document.getElementById(t.getAttribute("aria-controls")));
    const pause = host.querySelector(".q-pause");
    const PER_WORD = 180, HOLD = 2000;
    for (const card of cards) {
      const p = card.querySelector("blockquote p");
      const words = p.textContent.trim().split(/\s+/);
      p.textContent = "";
      words.forEach((w, i) => {
        const s = document.createElement("span");
        s.className = "w";
        s.textContent = w;
        p.append(s, i < words.length - 1 ? " " : "");
      });
    }
    host.classList.add("live");
    let cur = 0, start = 0, paused = still, inView = false, raf = 0, shifting = false;

    const show = (i, focus) => {
      cur = i;
      tabs.forEach((t, j) => {
        t.setAttribute("aria-selected", String(i === j));
        t.tabIndex = i === j ? 0 : -1;
        t.style.setProperty("--p", "0");
        cards[j].hidden = i !== j;
      });
      for (const w of cards[i].querySelectorAll(".w")) w.classList.toggle("on", still);
      start = performance.now();
      if (focus) tabs[i].focus();
      // slide the selected tab to the front of the strip, then move the ones it passed to the end
      const lead = track.firstElementChild;
      const dx = tabs[i].offsetLeft - lead.offsetLeft;
      if (!dx) return;
      shifting = true;
      track.style.transition = still ? "none" : "transform .5s cubic-bezier(.2,.8,.2,1)";
      track.style.transform = `translateX(${-dx}px)`;
      const settle = () => {
        track.removeEventListener("transitionend", settle);
        while (track.firstElementChild !== tabs[i]) track.append(track.firstElementChild);
        track.style.transition = "none";
        track.style.transform = "none";
        shifting = false;
      };
      if (still) settle();
      else track.addEventListener("transitionend", settle);
    };

    const tick = (now) => {
      raf = 0;
      if (paused || !inView) return;
      const words = cards[cur].querySelectorAll(".w");
      const total = words.length * PER_WORD + HOLD, el = now - start;
      const lit = Math.floor(el / PER_WORD);
      words.forEach((w, k) => w.classList.toggle("on", k < lit));
      tabs[cur].style.setProperty("--p", Math.min(1, el / total).toFixed(3));
      if (el >= total && !shifting) show((cur + 1) % tabs.length, false);
      raf = requestAnimationFrame(tick);
    };
    const run = () => { if (!raf && !paused && inView) { start = performance.now() - elapsed; raf = requestAnimationFrame(tick); } };
    let elapsed = 0;

    tabs.forEach((t, i) => {
      t.addEventListener("click", () => { elapsed = 0; show(i, false); run(); });
      t.addEventListener("keydown", (e) => {
        const d = { ArrowRight: 1, ArrowLeft: -1, Home: -i, End: tabs.length - 1 - i }[e.key];
        if (d === undefined) return;
        e.preventDefault();
        elapsed = 0;
        show((i + d + tabs.length) % tabs.length, true);
        run();
      });
    });
    const setPaused = (p) => {
      paused = p;
      pause.setAttribute("aria-pressed", String(p));
      pause.setAttribute("aria-label", p ? "Play" : "Pause");
      pause.innerHTML = p
        ? '<svg viewBox="0 0 14 14" aria-hidden="true"><path d="M4 2.5v9l7.5-4.5z" fill="currentColor"/></svg>'
        : '<svg viewBox="0 0 14 14" aria-hidden="true"><rect x="3" y="2" width="2.6" height="10" rx=".6" fill="currentColor"/><rect x="8.4" y="2" width="2.6" height="10" rx=".6" fill="currentColor"/></svg>';
      if (p) elapsed = performance.now() - start;
      else run();
    };
    pause.addEventListener("click", () => setPaused(!paused));
    setPaused(still);
    show(0, false);
    onView(host, (v) => {
      inView = v;
      if (v) run();
      else elapsed = performance.now() - start;
    }, 0.2);
  }

  // ---- typed headings ---------------------------------------------------------------
  // Deletes the current words, then types the new ones in, highlighted until done.
  const typer = (el) => {
    let job = 0;
    return (text) => {
      const id = ++job;
      if (still) { el.textContent = text; return; }
      el.classList.add("typing");
      const step = () => {
        if (id !== job) return;
        const now = el.textContent;
        if (!text.startsWith(now)) { el.textContent = now.slice(0, -1); return setTimeout(step, 18); }
        if (now.length < text.length) { el.textContent = text.slice(0, now.length + 1); return setTimeout(step, 42); }
        setTimeout(() => { if (id === job) el.classList.remove("typing"); }, 700);
      };
      step();
    };
  };
  const tabsHost = document.querySelector("[data-tabs]");
  const headWord = document.querySelector("[data-typed]");
  if (tabsHost && headWord) {
    const type = typer(headWord);
    let shown = headWord.textContent;
    tabsHost.addEventListener("tabchange", (e) => {
      const phrase = e.detail.panel && e.detail.panel.dataset.phrase;
      if (phrase && phrase !== shown) { shown = phrase; type(phrase); }
    });
  }
  // Types out once when it first scrolls into view; left alone if it is on screen at load.
  for (const el of document.querySelectorAll("[data-type-once]")) {
    if (still || el.getBoundingClientRect().top < innerHeight) continue;
    const text = el.textContent, type = typer(el);
    el.textContent = "";
    let done = false;
    onView(el.parentElement, (v) => {
      if (!v || done) return;
      done = true;
      type(text);
    }, 1);
  }

  // ---- the counter in the orange panel -------------------------------------------------
  const calm = document.querySelector("[data-calm] span");
  if (calm && !still) {
    const lines = [[25, "Reviewed ", " skills today"], [12, "Pinned ", " servers in agentguard.lock"], [3, "Stopped ", " pipe-to-shell installs"]];
    let k = 0, timer = 0;
    const roll = () => {
      const [n, a, b] = lines[k];
      k = (k + 1) % lines.length;
      const t0 = performance.now();
      const frame = (now) => {
        const f = Math.min(1, (now - t0) / 900);
        calm.innerHTML = "";
        calm.append(a, Object.assign(document.createElement("b"), { className: "n", textContent: String(Math.round(n * (1 - (1 - f) ** 3))) }), b);
        if (f < 1) requestAnimationFrame(frame);
      };
      requestAnimationFrame(frame);
    };
    onView(calm, (v) => {
      clearInterval(timer);
      if (v) { roll(); timer = setInterval(roll, 3600); }
    });
  }

  // ---- dot waveform behind "Installing on trust" ---------------------------------------
  const wave = document.querySelector(".split .wave");
  if (wave && wave.getContext) {
    const ctx = wave.getContext("2d");
    let W = 0, H = 0, dpr = 1, raf = 0, t = 0, last = 0, live = false;
    const size = () => {
      dpr = Math.min(2, devicePixelRatio || 1);
      W = wave.clientWidth; H = wave.clientHeight;
      wave.width = Math.round(W * dpr); wave.height = Math.round(H * dpr);
    };
    const draw = () => {
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      ctx.clearRect(0, 0, W, H);
      const gap = 5, mid = H / 2;
      for (let x = 2, i = 0; x < W; x += gap, i++) {
        const env = Math.sin((x / W) * Math.PI) ** 0.6;
        const a = Math.sin(i * 0.37 + t * 1.7) * 0.5 + Math.sin(i * 0.11 - t * 0.9) * 0.35 + Math.sin(i * 1.3 + t * 3.1) * 0.15;
        const h = (0.18 + 0.82 * Math.abs(a)) * env * (H / 2 - 4);
        for (let y = -h; y <= h; y += 4) {
          const o = 0.18 + 0.5 * (1 - Math.abs(y) / (h + 1));
          ctx.fillStyle = `rgba(248,98,24,${o.toFixed(2)})`;
          ctx.fillRect(x, mid + y, 1.6, 1.6);
        }
      }
    };
    const loop = (now) => {
      t += last ? Math.min(0.05, (now - last) / 1000) : 0;
      last = now;
      draw();
      raf = live ? requestAnimationFrame(loop) : 0;
    };
    size();
    draw();
    new ResizeObserver(() => { size(); draw(); }).observe(wave);
    if (!still) onView(wave, (v) => { live = v; if (v && !raf) { last = 0; raf = requestAnimationFrame(loop); } }, 0);
  }

  // ---- the scan queue: a new row drops in at the top every few seconds -------------------
  const queue = document.querySelector("[data-queue]");
  if (queue && !still) {
    const items = [
      ["skills/pdf-tools", "Scanning"], ["~/.claude.json", "Scanning"], ["skills/notion-sync", "Scanning"],
      [".vscode/mcp.json", "Scanning"], ["servers/github-mcp", "Scanning"],
    ];
    const tick = '<i class="tick"><svg viewBox="0 0 12 12"><path d="M2.5 6.3 5 8.6 9.5 3.6" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/></svg></i>';
    const results = ["Nothing at HIGH+", "1 high", "Tools locked", "2 medium", "Nothing at HIGH+"];
    let k = 0, timer = 0;
    const add = () => {
      // finish the rows that were scanning, then add a new one above them
      for (const row of queue.children) {
        if (!row.children[2].textContent.includes("Scanning")) continue;
        if (row.children[1].textContent === "Queued") row.children[1].textContent = results[k % results.length];
        row.children[2].innerHTML = "Done " + tick;
      }
      const [name, state] = items[k % items.length];
      k++;
      const li = document.createElement("li");
      li.className = "new";
      li.innerHTML = '<span></span><span>Queued</span><span class="state"></span>';
      li.children[0].textContent = name;
      li.children[2].innerHTML = state + ' <i class="spin dash"></i>';
      queue.prepend(li);
      while (queue.children.length > 5) queue.lastElementChild.remove();
    };
    onView(queue, (v) => {
      clearInterval(timer);
      if (v) timer = setInterval(add, 2600);
    }, 0.2);
  }
})();
