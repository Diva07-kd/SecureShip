const _ = require('lodash');
const res = _.chain({ a: 1 }).template().value();
console.log(res);
