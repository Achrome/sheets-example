const request = require('co-request');
const fs = require('fs');
const JWS = require('jws');
const R = require('ramda');

const API_URL = 'https://www.googleapis.com/';
const AUTH_URL = API_URL + 'oauth2/v3/token';
const SCOPE_URL = API_URL + 'auth/';

export default class GAuth {
  constructor(configFile = '', scopes = []) {
    this.authPayload = {};
    this.parseFile(configFile);
    this.authPayload.scope = R.map(scope => SCOPE_URL + scope, scopes).join(' ');
    this.authPayload.aud = AUTH_URL;
  }

  parseFile(configFile) {
    const config = JSON.parse(fs.readFileSync(configFile, 'utf-8'));
    this.authPayload.iss = config.client_email;
    this.key = config.private_key;
  }

  * getAccessToken() {
    const iat = Math.floor(Date.now() / 1000);
    this.authPayload.iat = iat;
    this.authPayload.exp = iat + 3600;
    const signedJWT = JWS.sign({
      header: { alg: 'RS256', typ: 'JWT' },
      payload: this.authPayload,
      secret: this.key
    });
    const req = {
      url: AUTH_URL,
      method: 'POST',
      strictSSL: false,
      form: {
        'grant_type': 'urn:ietf:params:oauth:grant-type:jwt-bearer',
        'assertion': signedJWT
      },
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
      }
    };
    const resp = yield request(req);
    this.accessToken = JSON.parse(resp.body).access_token;
    this.expiry = this.authPayload.exp * 1000;
  }

  get shouldRefresh() {
    return !this.expiry || Date.now() > this.expiry;
  }

  * getToken() {
    if (this.shouldRefresh) {
      yield this.getAccessToken();
    }
    return this.accessToken;
  }
}
