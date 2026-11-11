export function makeDict(entries) {
  const map = Object.create(null);
  for (const [k, v] of entries) {
    if (k !== '__proto__') map[k] = v;
  }
  return map;
}
