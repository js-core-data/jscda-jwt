const createError = require("http-errors");
import * as bluebird from "bluebird";
import fetch from "node-fetch";
const jwt = bluebird.promisifyAll(require("jsonwebtoken"));

import { NappJSService } from "nappjs";

interface JWTConfig {
  secret: string;
  options: { [key: string]: any };
}

export default class NappJSJWT extends NappJSService {
  public async getToken(req) {
    let token = req.query.access_token || req.headers.authorization;

    if (!token) {
      throw createError(401, "access token missing");
    }

    token = token.replace("Bearer ", "");
    try {
      let configs = await this.getConfigs();

      if (configs.length == 0) {
        throw new Error("invalid environment cofiguration");
      }

      let latestError = null;
      for (let config of configs) {
        try {
          let res = await jwt.verifyAsync(token, config.secret, config.options);
          return res;
        } catch (e) {
          latestError = e;
        }
      }
      throw latestError;
    } catch (e) {
      throw createError(401, e.message);
    }
  }

  public async checkJWTPermissions(req, resource) {
    let info = await this.getToken(req);
    if (!info.permissions && !info.user) {
      return false;
    }

    let permissions = info.permissions || info.user.permissions;

    if (!permissions) {
      return false;
    }

    permissions = permissions.split("\n");

    let valid = false;
    for (let permission of permissions) {
      let [_rule, _resource] = permission.split("|");
      if (!_rule || !_resource) continue;
      let regepx = new RegExp("^" + _resource.replace(/\*/g, ".*") + "$");
      if (regepx.test(resource)) {
        if (_rule == "deny") {
          return false;
        } else {
          valid = true;
        }
      }
    }

    return valid;
  }

  private async getConfigs(): Promise<JWTConfig[]> {
    let configs: JWTConfig[] = [];

    const JWT_SECRET = process.env.JWT_SECRET;
    const JWT_CERTS_URL = process.env.JWT_CERTS_URL;
    const JWT_PUBLIC_CERT = process.env.JWT_PUBLIC_CERT;

    if (typeof JWT_SECRET !== "undefined") {
      configs.push({ secret: JWT_SECRET, options: { algorhitm: "HS256" } });
    }
    if (typeof JWT_PUBLIC_CERT !== "undefined") {
      configs.push({
        secret: JWT_PUBLIC_CERT,
        options: { algorhitm: "RS256" }
      });
    }
    if (typeof JWT_CERTS_URL !== "undefined") {
      let res = await fetch(JWT_CERTS_URL);
      let content = await res.json();
      configs.push(
        content.map(cert => {
          return { secret: cert.key, options: { algorhitm: "RS256" } };
        })
      );
    }

    return configs;
  }
}
