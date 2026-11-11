import _ from 'lodash';
export function entrypoint() {
  console.log('main');
}
function uncalledCallbackHolder() {
  const list = ['a'].map(_.template);
  return list;
}
entrypoint();
