import GAuth from './lib/google-auth';
const co = require('co');
const request = require('co-request');

co(function* () {
  let a = new GAuth('config/creds.json', ['drive.readonly']);
  const token = yield a.getToken();
  const req = {
    url: 'https://www.googleapis.com/drive/v2/files/?maxResults=5',
    method: 'GET',
    headers: {
      'Authorization': `Bearer ${token}`
    }
  };
  const resp = yield request(req);
  console.log(JSON.parse(resp.body));
}).catch(console.log);
