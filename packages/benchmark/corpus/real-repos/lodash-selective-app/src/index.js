import _ from 'lodash';
export function processItems(items) {
  return _.map(items, x => x * 2);
}
export function areEqual(a, b) {
  return _.isEqual(a, b);
}
console.log(processItems([1, 2, 3]));
