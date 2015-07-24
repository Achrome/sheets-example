import GAuth from './lib/google-auth';
const co = require('co');

let a = new GAuth('config/creds.json', ['drive']);
co(function* () {
  const token = yield a.getToken();
  console.log(token);
});
