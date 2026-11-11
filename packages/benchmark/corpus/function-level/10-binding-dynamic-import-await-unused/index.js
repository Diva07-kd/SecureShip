async function run() {
  const _ = await import('lodash');
  console.log(_.keys({ a: 1 }));
}
run();
