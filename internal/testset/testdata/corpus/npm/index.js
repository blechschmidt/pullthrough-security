// Minimal program exercising the one real dependency pulled through the proxy.
const isNumber = require('is-number');
if (!isNumber(42)) {
  process.exit(1);
}
console.log('is-number ok');
