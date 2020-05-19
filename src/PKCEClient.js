import '@babel/runtime/regenerator'
import generateRandomChallengePair from './generateRandomChallengePair';
import parse from 'url-parse';
import {
  boundMethod
} from 'autobind-decorator'
import cryptoRandomString from 'crypto-random-string'

const qs = parse.qs;
/*
  Generic JavaScript PKCE Client, you can subclass this for React-Native,
  Cordova, Chrome, Some Other Environment which has its own handling for
  OAuth flows (like Windows?)
*/

class PKCEClient {
  // These params will never change
  constructor(domain, clientId) {
    this.domain = domain;
    this.clientId = clientId;
  }

  async getAuthResult(url, interactive) {
    throw new Error('Must be implemented by a sub-class');
  }

  getRedirectURL() {
    throw new Error('Must be implemented by a sub-class');
  }

  @boundMethod
  async exchangeCodeForToken(code, verifier, estate) {
    const {
      domain,
      clientId
    } = this;
    if (localStorage.authzeroState !== estate) throw Error("state does not match")
    const body = JSON.stringify({
      redirect_uri: this.getRedirectURL(),
      grant_type: 'authorization_code',
      code_verifier: verifier,
      client_id: clientId,
      code
    });
    const result = await fetch(`https://${domain}/oauth/token`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body
    });

    if (result.ok)
      return result.json();

    throw Error(result.statusText);
  }

  @boundMethod
  async refreshToken(refreshToken) {
    const {
      domain,
      clientId
    } = this;
    if (refreshToken) {

      const result = await fetch(`https://${domain}/oauth/token`, {
        method: 'POST',
        headers: {
          'content-type': 'application/json'
        },
        body: JSON.stringify({
          grant_type: 'refresh_token',
          client_id: clientId,
          refresh_token: refreshToken,
        })
      });
      if (result.ok)
        return result.json();

      throw Error(result.statusText);
    } else throw Error("refresh_token is empty")
  }

  extractCode(resultUrl) {
    const response = parse(resultUrl, true).query;

    if (response.error) {
      throw new Error(response.error_description || response.error);
    }

    return {
      code: response.code,
      state: response.state
    };
  }

  @boundMethod
  async authenticate(options = {}, interactive = true) {
    const {
      domain,
      clientId
    } = this;
    const {
      secret,
      hashed
    } = generateRandomChallengePair();
    localStorage.authzeroState = cryptoRandomString({
      length: 10
    });

    const authOptions = Object.assign({}, options, {
      client_id: clientId,
      code_challenge: hashed,
      redirect_uri: this.getRedirectURL(),
      code_challenge_method: 'S256',
      response_type: 'code',
      state: localStorage.authzeroState
    });

    const url = `https://${domain}/authorize?${qs.stringify(authOptions)}`;
    const resultUrl = await this.getAuthResult(url, interactive);
    const {
      code,
      state
    } = this.extractCode(resultUrl);
    return this.exchangeCodeForToken(code, secret, state);
  }
}

export default PKCEClient;