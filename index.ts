const createError = require('http-errors');

import * as bluebird from 'bluebird';

import { NappJSService } from 'nappjs';
import fetch from 'node-fetch';

const jwt = bluebird.promisifyAll(require('jsonwebtoken'));

interface JWTConfig {
  secret: string;
  options: { [key: string]: any };
}

let _configsCache: JWTConfig[] | null = null;

export default class NappJSJWT extends NappJSService {
  public async getToken(req, verify = true) {
    if (!(await this.isEnabled())) {
      return null;
    }

    if (req.jwt_cache) {
      return req.jwt_cache;
    }
    let token = req.query.access_token || req.headers.authorization;

    if (!token) {
      throw createError(401, 'access token missing');
    }

    token = token.replace('Bearer ', '');
    if (verify) {
      try {
        let configs = await this.getConfigs();

        let latestError = null;
        for (let config of configs) {
          try {
            let res = await jwt.verifyAsync(
              token,
              config.secret,
              config.options
            );
            req.jwt_cache = res;
            return res;
          } catch (e) {
            latestError = e;
          }
        }
        throw latestError;
      } catch (e) {
        throw createError(401, e.message);
      }
    } else {
      let res = await jwt.decode(token);
      return res;
    }
  }

  public async checkJWTPermissions(req, resource): Promise<Boolean> {
    if (!(await this.isEnabled())) {
      return true;
    }

    let info = await this.getToken(req);

    if (!info.permissions && !info.user) {
      return false;
    }

    let permissions = info.permissions || info.user.permissions;

    if (!permissions) {
      return false;
    }

    permissions = permissions.split('\n');

    let valid = false;
    for (let permission of permissions) {
      let [_rule, _resource] = permission.split('|');
      if (!_rule || !_resource) continue;
      let regepx = new RegExp('^' + _resource.replace(/\*/g, '.*') + '$');
      if (regepx.test(resource)) {
        if (_rule == 'deny') {
          return false;
        } else {
          valid = true;
        }
      }
    }

    return valid;
  }

  private async isEnabled(): Promise<Boolean> {
    let configs = await this.getConfigs();
    return configs.length > 0;
  }

  private async getConfigs(): Promise<JWTConfig[]> {
    if (_configsCache) {
      return _configsCache;
    }
    let configs: JWTConfig[] = [];

    const JWT_SECRET = process.env.JWT_SECRET;
    const JWT_CERTS_URL = process.env.JWT_CERTS_URL;
    const JWT_PUBLIC_CERT = process.env.JWT_PUBLIC_CERT;

    if (typeof JWT_SECRET !== 'undefined') {
      configs.push({ secret: JWT_SECRET, options: { algorhitm: 'HS256' } });
    }
    if (typeof JWT_PUBLIC_CERT !== 'undefined') {
      configs.push({
        secret: JWT_PUBLIC_CERT,
        options: { algorhitm: 'RS256' }
      });
    }
    if (typeof JWT_CERTS_URL !== 'undefined') {
      let res = await fetch(JWT_CERTS_URL);
      let content = await res.json();
      configs = configs.concat(
        content.map(cert => {
          return {
            secret: new Buffer(cert.key, 'base64'),
            options: { algorhitm: 'RS256' }
          };
        })
      );
    }

    _configsCache = configs;
    return configs;
  }
}
