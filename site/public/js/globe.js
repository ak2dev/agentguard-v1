// "See the whole session": a slowly turning Earth drawn in orange land dots, with the
// toxic-flow nodes pinned to it and each callout following its node. Canvas 2D, no
// libraries; the land mask is data/globe-land.bin, built by scripts/make-globe-land.mjs.
// Without JavaScript only the callouts show (see .graph in global.css).
(function () {
  const host = document.querySelector("[data-globe]");
  const canvas = host && host.querySelector("canvas");
  if (!canvas || !canvas.getContext || !window.Path2D) return;
  const ctx = canvas.getContext("2d");
  const landUrl = new URL("../data/globe-land.bin", document.currentScript.src);
  const still = matchMedia("(prefers-reduced-motion: reduce)").matches;

  const DEG = Math.PI / 180;
  const TILT = 14 * DEG;           // latitude at the centre of the view
  const SPEED = 3.6 * DEG;         // per second, west to east as the Earth turns
  const START = -66 * DEG;         // centre longitude when it starts turning
  const REST = -78 * DEG;          // centre longitude with reduced motion
  const STEP = 1.45;               // degrees between land dots
  const ACCENT = "255,122,51", DOTS = "248,98,24";
  const LIGHT = norm([0.55, 0.35, 0.76]);
  // Paths from components/Icon.astro (24×24, stroked).
  const ICONS = {
    globe: ["M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18z", "M3 12h18", "M12 3c2.5 2.6 3.8 5.6 3.8 9s-1.3 6.4-3.8 9c-2.5-2.6-3.8-5.6-3.8-9S9.5 5.6 12 3z"],
    lock: ["M6 11h12v10H6z", "M8.5 11V8a3.5 3.5 0 0 1 7 0v3"],
    send: ["M21 3 3 10.5l7 2.5 2.5 7L21 3z", "M10 13l5-5"],
    plus: ["M12 6v12", "M6 12h12"],
  };
  // `at` is when each piece appears, in seconds after the globe first scrolls into view.
  const nodes = [
    { id: "fetch", label: "web-fetch", lat: 56, lon: -114, icon: "globe", at: 0.5 },
    { id: "agent", label: "agent", lat: 41, lon: -76, icon: "plus", at: 0.8, active: true },
    { id: "files", label: "filesystem", lat: 8, lon: -94, icon: "lock", at: 1.0 },
    { id: "slack", label: "slack", lat: 18, lon: -42, icon: "send", at: 1.2 },
  ];
  const byId = {};
  for (const n of nodes) {
    n.v = unit(n.lat, n.lon);
    n.path = new Path2D(ICONS[n.icon].join(" "));
    n.o = 0;
    byId[n.id] = n;
  }
  const links = [["fetch", "agent", 1.1], ["files", "agent", 1.4], ["agent", "slack", 1.7]]
    .map(([a, b, at]) => ({ pts: arc(byId[a].v, byId[b].v), at }));
  const callouts = [...host.querySelectorAll(".callout[data-anchor]")].map((el, i) => ({
    el, node: byId[el.dataset.anchor], side: el.dataset.side, at: 2.1 + i * 0.3, w: 0,
  }));
  const grid = graticule();

  let W = 0, H = 0, R = 0, cx = 0, cy = 0, pin = 0, dpr = 1, room = [0, 0];
  let land = null, landAt = 0, t = still ? 99 : 0, last = 0, raf = 0, visible = false;

  function unit(lat, lon) {
    const p = lat * DEG, l = lon * DEG;
    return [Math.cos(p) * Math.sin(l), Math.sin(p), Math.cos(p) * Math.cos(l)];
  }
  function norm(v) {
    const m = Math.hypot(v[0], v[1], v[2]);
    return [v[0] / m, v[1] / m, v[2] / m];
  }
  const ease = (x) => (x <= 0 ? 0 : x >= 1 ? 1 : 1 - (1 - x) ** 3);
  const smooth = (a, b, x) => { const k = Math.min(1, Math.max(0, (x - a) / (b - a))); return k * k * (3 - 2 * k); };

  // A great-circle arc from a to b, lifted off the surface towards its middle.
  function arc(a, b) {
    const w = Math.acos(Math.min(1, a[0] * b[0] + a[1] * b[1] + a[2] * b[2])), lift = 0.14 * w, pts = [];
    for (let i = 0; i <= 48; i++) {
      const f = i / 48, s0 = Math.sin((1 - f) * w) / Math.sin(w), s1 = Math.sin(f * w) / Math.sin(w);
      const h = 1 + lift * Math.sin(Math.PI * f);
      pts.push([(a[0] * s0 + b[0] * s1) * h, (a[1] * s0 + b[1] * s1) * h, (a[2] * s0 + b[2] * s1) * h]);
    }
    return pts;
  }
  // Meridians every 30° and parallels every 30°, as polylines of unit vectors.
  function graticule() {
    const lines = [];
    for (let lon = -180; lon < 180; lon += 30) {
      const l = [];
      for (let lat = -90; lat <= 90; lat += 3) l.push(unit(lat, lon));
      lines.push(l);
    }
    for (let lat = -60; lat <= 60; lat += 30) {
      const l = [];
      for (let lon = -180; lon <= 180; lon += 3) l.push(unit(lat, lon));
      lines.push(l);
    }
    return lines;
  }

  function draw() {
    const lon = still ? REST : START - SPEED * t;
    const ca = Math.cos(-lon), sa = Math.sin(-lon), ct = Math.cos(TILT), st = Math.sin(TILT);
    const view = (v) => {
      const x = v[0] * ca + v[2] * sa, z = -v[0] * sa + v[2] * ca;
      return [x, v[1] * ct - z * st, v[1] * st + z * ct];
    };
    const fade = ease(t / 0.9);
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, W, H);
    if (!fade) return;

    // The sphere: a faint body, the back of the grid seen through it, then the rim.
    ctx.globalAlpha = fade;
    const body = ctx.createRadialGradient(cx + R * 0.35, cy - R * 0.3, R * 0.05, cx, cy, R);
    body.addColorStop(0, "rgba(255,255,255,0.05)");
    body.addColorStop(1, "rgba(255,255,255,0.012)");
    ctx.fillStyle = body;
    ctx.beginPath();
    ctx.arc(cx, cy, R, 0, 2 * Math.PI);
    ctx.fill();
    const front = new Path2D(), back = new Path2D();
    for (const line of grid) {
      let prev = null;
      for (const v of line) {
        const p = view(v);
        if (prev) {
          const path = prev[2] + p[2] >= 0 ? front : back;
          path.moveTo(cx + prev[0] * R, cy - prev[1] * R);
          path.lineTo(cx + p[0] * R, cy - p[1] * R);
        }
        prev = p;
      }
    }
    ctx.lineWidth = 1;
    ctx.strokeStyle = "rgba(255,255,255,0.035)";
    ctx.stroke(back);
    ctx.strokeStyle = "rgba(255,255,255,0.11)";
    ctx.stroke(front);
    ctx.strokeStyle = "rgba(255,255,255,0.16)";
    ctx.beginPath();
    ctx.arc(cx, cy, R, 0, 2 * Math.PI);
    ctx.stroke();

    // Land dots, lit from the upper right and dimmed towards the limb, batched by brightness.
    if (land) {
      const s = Math.max(1.4, R * 0.0088), half = s / 2, levels = 12, buckets = [];
      for (let k = 0; k < levels; k++) buckets.push(new Path2D());
      for (let i = 0; i < land.length; i += 3) {
        const x = land[i], y = land[i + 1], z0 = land[i + 2];
        const X = x * ca + z0 * sa, z = -x * sa + z0 * ca, Z = y * st + z * ct;
        if (Z <= 0) continue;
        const Y = y * ct - z * st, sy = cy - Y * R;
        if (sy > H + s) continue;
        const lit = Math.max(0, X * LIGHT[0] + Y * LIGHT[1] + Z * LIGHT[2]);
        const b = (0.13 + 0.87 * lit) * Math.min(1, Z / 0.2);
        buckets[Math.min(levels - 1, (b * levels) | 0)].rect(cx + X * R - half, sy - half, s, s);
      }
      const dots = fade * ease((t - landAt) / 0.9);
      for (let k = 0; k < levels; k++) {
        ctx.fillStyle = `rgba(${DOTS},${(((k + 0.5) / levels) * dots).toFixed(3)})`;
        ctx.fill(buckets[k]);
      }
    }
    ctx.globalAlpha = 1;

    // Arcs, drawn in from their source; any part behind the globe is hidden.
    ctx.lineWidth = 1.6;
    ctx.lineCap = "round";
    ctx.lineJoin = "round";
    ctx.strokeStyle = `rgba(${ACCENT},0.85)`;
    for (const l of links) {
      const n = Math.round(ease((t - l.at) / 0.9) * (l.pts.length - 1));
      if (!n) continue;
      ctx.beginPath();
      let pen = false;
      for (let i = 0; i <= n; i++) {
        const [X, Y, Z] = view(l.pts[i]);
        if (Z < 0 && X * X + Y * Y < 1) { pen = false; continue; }
        if (pen) ctx.lineTo(cx + X * R, cy - Y * R);
        else ctx.moveTo(cx + X * R, cy - Y * R);
        pen = true;
      }
      ctx.stroke();
    }

    // Pins: outlined, except the agent, which is filled, glows and pulses.
    ctx.font = '600 13px "Inter Variable", "Inter Fallback", sans-serif';
    ctx.textAlign = "center";
    for (const n of nodes) {
      const [X, Y, Z] = view(n.v);
      const pop = ease((t - n.at) / 0.5);
      n.x = cx + X * R;
      n.y = cy - Y * R;
      n.o = pop * smooth(0.04, 0.32, Z);
      if (!n.o) continue;
      const r = pin * (0.75 + 0.25 * pop) * (n.active ? 1.35 : 1);
      ctx.globalAlpha = n.o;
      if (n.active) {
        if (!still) {
          const q = (t % 2.4) / 2.4;
          ctx.strokeStyle = `rgba(${ACCENT},${(0.55 * (1 - q)).toFixed(3)})`;
          ctx.lineWidth = 1.5;
          ctx.beginPath();
          ctx.arc(n.x, n.y, r * (1 + 0.9 * q), 0, 2 * Math.PI);
          ctx.stroke();
        }
        ctx.save();
        ctx.shadowColor = "rgba(248,98,24,0.8)";
        ctx.shadowBlur = r * 1.4;
        ctx.fillStyle = "#f2621c";
        ctx.beginPath();
        ctx.arc(n.x, n.y, r, 0, 2 * Math.PI);
        ctx.fill();
        ctx.restore();
        icon(n, r * 0.95, "#fff");
      } else {
        ctx.fillStyle = "rgba(14,13,12,0.92)";
        ctx.strokeStyle = `rgb(${ACCENT})`;
        ctx.lineWidth = 1.5;
        ctx.beginPath();
        ctx.arc(n.x, n.y, r, 0, 2 * Math.PI);
        ctx.fill();
        ctx.stroke();
        icon(n, r * 0.95, `rgb(${ACCENT})`);
      }
      ctx.fillStyle = "#d8d1c8";
      ctx.fillText(n.label, n.x, n.y + r + 18);
    }
    ctx.globalAlpha = 1;

    // Callouts sit beside their node and fade with it, or as they run out of room in
    // the section (they may overhang the canvas into its margins).
    for (const c of callouts) {
      const n = c.node, want = c.side === "left" ? n.x - pin - 24 - c.w : n.x + pin + 26;
      const x = Math.max(room[0], Math.min(room[1] - c.w, want));
      const o = Math.min(n.o, ease((t - c.at) / 0.6)) * (1 - smooth(0, 60, Math.abs(want - x)));
      const y = c.side === "left" ? n.y + pin + 26 : n.y - pin - 22;
      c.el.style.setProperty("--x", `${x.toFixed(1)}px`);
      c.el.style.setProperty("--y", `${y.toFixed(1)}px`);
      c.el.style.setProperty("--o", o.toFixed(3));
    }
  }

  function icon(n, size, color) {
    const k = size / 24;
    ctx.save();
    ctx.translate(n.x - size / 2, n.y - size / 2);
    ctx.scale(k, k);
    ctx.strokeStyle = color;
    ctx.lineWidth = 2 / (k * 1.35);
    ctx.stroke(n.path);
    ctx.restore();
  }

  function loop(now) {
    t += last ? Math.min(0.05, (now - last) / 1000) : 0;
    last = now;
    draw();
    raf = visible ? requestAnimationFrame(loop) : 0;
  }

  function resize() {
    const w = host.clientWidth, d = Math.min(2, window.devicePixelRatio || 1);
    if (w === W && d === dpr) return;
    W = w;
    dpr = d;
    R = Math.min(W * (W < 700 ? 0.44 : 0.29), 300);
    pin = Math.max(14, R * 0.068);
    cx = W / 2;
    cy = R + 30;
    H = Math.round(cy + R * 0.62);
    canvas.width = Math.round(W * dpr);
    canvas.height = Math.round(H * dpr);
    const box = host.getBoundingClientRect(), section = (host.parentElement || host).getBoundingClientRect();
    room = [Math.min(0, section.left - box.left + 16), Math.max(W, section.right - box.left - 16)];
    for (const c of callouts) c.w = c.el.offsetWidth;
    draw();
  }

  host.classList.add("live");
  resize();
  new ResizeObserver(resize).observe(host);
  new IntersectionObserver(([e]) => {
    visible = e.isIntersecting;
    if (still) draw();
    else if (visible && !raf) { last = 0; raf = requestAnimationFrame(loop); }
  }, { threshold: 0.15 }).observe(host);

  fetch(landUrl)
    .then((r) => (r.ok ? r.arrayBuffer() : Promise.reject(new Error(r.statusText))))
    .then((buf) => {
      const bits = new Uint8Array(buf), pts = [];
      for (let lat = -56; lat <= 84; lat += STEP) {
        const n = Math.round((360 * Math.cos(lat * DEG)) / STEP);
        const row = Math.floor((90 - lat) * 2);
        for (let i = 0; i < n; i++) {
          const lon = -180 + ((i + 0.5) * 360) / n, k = row * 720 + Math.floor((lon + 180) * 2);
          if (bits[k >> 3] & (0x80 >> (k & 7))) pts.push(...unit(lat, lon));
        }
      }
      land = new Float32Array(pts);
      landAt = still ? 0 : t;
      draw();
    })
    .catch(() => {});
})();
