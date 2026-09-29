async function load() {
  const r = await fetch("/api/digest");
  return r.json();
}
