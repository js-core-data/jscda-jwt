const Router = require("express").Router;
const createError = require("http-errors");
const Promise = require("bluebird");
const jwt = Promise.promisifyAll(require("jsonwebtoken"));

const JWT_SECRET = process.env.JWT_SECRET || "JWT_SECRET";

const getToken = async req => {
  let token = req.query.access_token || req.headers.authorization;

  if (!token) {
    throw createError(401, "access token missing");
  }

  token = token.replace("Bearer ", "");
  try {
    return await jwt.verifyAsync(token, JWT_SECRET);
  } catch (e) {
    throw createError(401, e.message);
  }
};

const checkJWTPermissions = async (req, resource) => {
  let info = await req.app.locals.getJWT(req);
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
};

module.exports = app => {
  app.locals.getJWT = getToken;
  app.locals.checkJWTPermissions = checkJWTPermissions;
};
