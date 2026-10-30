// Sätteri hast plugin for the Markdown pages: puts tables and code blocks in the same
// frames the redesigned pages use. A table goes inside the corner markers and horizontal
// scroll of the Rules pages; a code block becomes a terminal window like the rule
// examples (a title bar with three dots and the fence's language).
const el = (tagName, className, children = [], extra = {}) =>
  ({ type: "element", tagName, properties: className ? { className, ...extra } : extra, children });

// Visited nodes are frozen views of Sätteri's tree, so the replacement is built from a copy.
const copy = (n) => n.type === "element"
  ? { type: "element", tagName: n.tagName, properties: { ...n.properties }, children: n.children.map(copy) }
  : { type: n.type, value: n.value };

function framed(node) {
  if (node.tagName === "table") return el("div", ["corners"], [el("div", ["table-scroll"], [copy(node)])]);
  const code = node.children.find((c) => c.tagName === "code");
  const lang = [].concat(code?.properties?.className ?? []).map(String).find((c) => c.startsWith("language-"))?.slice(9);
  const dots = el("span", ["ev-dots"], [el("i"), el("i"), el("i")], { ariaHidden: "true" });
  const cap = el("figcaption", ["ev-cap"], lang ? [dots, el("code", null, [{ type: "text", value: lang }])] : [dots]);
  return el("figure", ["evidence", "code-window"], [cap, copy(node)]);
}

export default {
  name: "agentguard-frames",
  element: { filter: ["table", "pre"], visit: (node, ctx) => ctx.replaceNode(node, framed(node)) },
};
