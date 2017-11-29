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

module.exports = database => {
  let app = new Router();

  app.use((req, res, next) => {
    req.getJWT = () => {
      return getToken(req);
    };
    next();
  });

  return app;
};
