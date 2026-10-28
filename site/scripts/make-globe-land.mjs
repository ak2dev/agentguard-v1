// Builds public/data/globe-land.bin, the land mask the home-page globe draws its
// continent dots from: one bit per half-degree cell (720 columns from 180°W, 360 rows
// from 90°N), set when the cell's centre is on land, rows packed MSB-first.
// Source: land-50m.json from the world-atlas npm package (Natural Earth, public domain).
// Usage: node scripts/make-globe-land.mjs path/to/land-50m.json
import fs from "node:fs";

const COLS = 720, ROWS = 360, STEP = 0.5;
const topo = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));

// TopoJSON arcs are quantized and delta-encoded; decode them to [lon, lat] rings.
const [sx, sy] = topo.transform.scale, [tx, ty] = topo.transform.translate;
const arcs = topo.arcs.map((arc) => {
  let x = 0, y = 0;
  return arc.map(([dx, dy]) => [(x += dx) * sx + tx, (y += dy) * sy + ty]);
});
const ring = (ids) => ids.flatMap((i, k) => {
  const a = i < 0 ? arcs[~i].slice().reverse() : arcs[i];
  return k ? a.slice(1) : a;
});
const rings = [];
for (const g of topo.objects.land.geometries) {
  const polys = g.type === "Polygon" ? [g.arcs] : g.arcs;
  for (const p of polys) for (const r of p) rings.push(ring(r));
}

// Even-odd scanline fill at each row's centre latitude.
const bits = new Uint8Array((COLS * ROWS) / 8);
for (let row = 0; row < ROWS; row++) {
  const lat = 90 - (row + 0.5) * STEP;
  const xs = [];
  for (const r of rings) {
    for (let i = 0, j = r.length - 1; i < r.length; j = i++) {
      const [x1, y1] = r[i], [x2, y2] = r[j];
      if ((y1 > lat) !== (y2 > lat)) xs.push(x1 + ((lat - y1) / (y2 - y1)) * (x2 - x1));
    }
  }
  xs.sort((a, b) => a - b);
  for (let k = 0; k + 1 < xs.length; k += 2) {
    const c0 = Math.ceil((xs[k] + 180) / STEP - 0.5), c1 = Math.floor((xs[k + 1] + 180) / STEP - 0.5);
    for (let c = Math.max(0, c0); c <= Math.min(COLS - 1, c1); c++) {
      const n = row * COLS + c;
      bits[n >> 3] |= 0x80 >> (n & 7);
    }
  }
}

const out = new URL("../public/data/globe-land.bin", import.meta.url);
fs.mkdirSync(new URL(".", out), { recursive: true });
fs.writeFileSync(out, bits);
console.log(`wrote ${bits.length} bytes to ${out.pathname}`);
