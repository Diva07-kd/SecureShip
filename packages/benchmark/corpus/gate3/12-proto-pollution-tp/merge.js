export function recursiveMerge(target, source) {
  for (let key in source) {
    target[key] = source[key];
  }
}
