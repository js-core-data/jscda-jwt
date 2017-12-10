const assert = require("assert");
const supertest = require("supertest");
const express = require("express");
const createError = require("http-errors");
const jwt = require("jsonwebtoken");

const app = require("js-core-data-app")();
const jwtMiddleware = require("../");

const api = express();
jwtMiddleware(api);

api.get("/test", (req, res, next) => {
  api.locals
    .getJWT(req)
    .then(result => {
      res.send(result);
    })
    .catch(next);
});

api.get("/validate", (req, res, next) => {
  api.locals
    .checkJWTPermissions(req, req.query.resource)
    .then(result => {
      res.send({ result: result });
    })
    .catch(next);
});

api.use((err, req, res, next) => {
  res.status(err.statusCode || 400).send(err.message);
});

const test = supertest(api);

const payload = {
  user: {
    username: "admin@example.com",
    firstname: "John",
    lastname: "Doe"
  },
  permissions: "allow|*\ndeny|blah\ndeny|test*:a*",
  iat: 1511923424
};

const tokens = {
  valid: jwt.sign(payload, "JWT_SECRET")
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

  describe("permissions validation", () => {
    it("should validate foo", () => {
      return test
        .get(`/validate?resource=foo&access_token=${tokens.valid}`)
        .expect(200)
        .expect(res => {
          assert.equal(res.body.result, true);
        });
    });

    it("should validate test:bbb", () => {
      return test
        .get(`/validate?resource=test:bbb&access_token=${tokens.valid}`)
        .expect(200)
        .expect(res => {
          assert.equal(res.body.result, true);
        });
    });

    it("should not validate blah", () => {
      return test
        .get(`/validate?resource=blah&access_token=${tokens.valid}`)
        .expect(200)
        .expect(res => {
          assert.equal(res.body.result, false);
        });
    });

    it("should not validate test:aaa", () => {
      return test
        .get(`/validate?resource=test:aaa&access_token=${tokens.valid}`)
        .expect(200)
        .expect(res => {
          assert.equal(res.body.result, false);
        });
    });
  });
});
