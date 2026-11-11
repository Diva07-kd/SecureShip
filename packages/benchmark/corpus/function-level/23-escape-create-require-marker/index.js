import { createRequire } from 'module';
import _ from 'lodash';
const req = createRequire(import.meta.url);
console.log(_.map([1], x => x));
