const assert = require("assert");
const supertest = require("supertest");
const express = require("express");
const createError = require("http-errors");

const app = require("js-core-data-app")();
const jwtMiddleware = require("../");

const api = express();
api.use(jwtMiddleware(app.database));

api.get("/test", (req, res, next) => {
  req
    .getJWT()
    .then(result => {
      res.send(result);
    })
    .catch(next);
});

api.use((err, req, res, next) => {
  res.status(err.statusCode || 400).send(err.message);
});

const test = supertest(api);

const tokens = {
  valid:
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjp7InVzZXJuYW1lIjoiYWRtaW5AZXhhbXBsZS5jb20iLCJmaXJzdG5hbWUiOiJKb2huIiwibGFzdG5hbWUiOiJEb2UifSwiaWF0IjoxNTExOTIzNDI0fQ.upp30Okt4I1vjw90UXKRg1SnpZQreGYK90s3Crfjh_g"
};

describe("jwt", () => {
  after(() => {
    return app.database.closeAllConnections();
  });

  it("should accept valid access token", () => {
    return test
      .get(`/test?access_token=${tokens.valid}`)
      .expect(200)
      .expect(res => {
        assert.ok(res.body.iat);
        assert.equal(res.body.user.username, "admin@example.com");
        assert.equal(res.body.user.firstname, "John");
        assert.equal(res.body.user.lastname, "Doe");
      });
  });

  it("should fail to accept invalid access token", () => {
    return test.get(`/test?access_token=blah`).expect(401);
  });

  it("should fail to accept missing access token", () => {
    return test.get(`/test`).expect(401);
  });
});
