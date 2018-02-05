const assert = require("assert");
// const supertest = require("supertest");
// const express = require("express");
const createError = require("http-errors");
const jwt = require("jsonwebtoken");
const selfsigned = require("selfsigned");

const NappJSJWT = require("../").default;

// const app = require("nappjs").NewNappJS();
// const jwtMiddleware = require("../");

// const api = express();
// jwtMiddleware(api);

// api.get("/test", (req, res, next) => {
//   api.locals
//     .getJWT(req)
//     .then(result => {
//       res.send(result);
//     })
//     .catch(next);
// });

// api.get("/validate", (req, res, next) => {
//   api.locals
//     .checkJWTPermissions(req, req.query.resource)
//     .then(result => {
//       res.send({ result: result });
//     })
//     .catch(next);
// });

// api.use((err, req, res, next) => {
//   res.status(err.statusCode || 400).send(err.message);
// });

const service = new NappJSJWT();

// const test = supertest(api);

const payload = {
  user: {
    username: "admin@example.com",
    firstname: "John",
    lastname: "Doe"
  },
  permissions: "allow|*\ndeny|blah\ndeny|test*:a*",
  iat: 1511923424
};

const cert = selfsigned.generate();

const tokens = {
  valid: jwt.sign(payload, "JWT_SECRET", { algorithm: "HS256" }),
  cert: jwt.sign(payload, cert.private, { algorithm: "RS256" })
};

process.env.JWT_SECRET = "JWT_SECRET";
process.env.JWT_PUBLIC_CERT = cert.public;

describe("jwt", () => {
  // after(() => {
  //   return app.database.closeAllConnections();
  // });

  it("should accept valid access token", async () => {
    let fakeReq = {
      query: {},
      headers: { authorization: `Bearer ${tokens.valid}` }
    };
    let token = await service.getToken(fakeReq);
    assert.ok(token);
    assert.ok(token.iat);
    assert.equal(token.user.username, "admin@example.com");
    assert.equal(token.user.firstname, "John");
    assert.equal(token.user.lastname, "Doe");
  });

  it("should accept valid access token from certificate", async () => {
    let fakeReq = {
      query: {},
      headers: { authorization: `Bearer ${tokens.cert}` }
    };
    let token = await service.getToken(fakeReq);
    assert.ok(token.iat);
    assert.equal(token.user.username, "admin@example.com");
    assert.equal(token.user.firstname, "John");
    assert.equal(token.user.lastname, "Doe");
  });

  it("should fail to accept invalid access token", async () => {
    let fakeReq = {
      query: {},
      headers: { authorization: `Bearer blah` }
    };
    try {
      await service.getToken(fakeReq);
    } catch (e) {
      assert.equal(e.message, "jwt malformed");
    }
  });

  it("should fail to accept missing access token", async () => {
    let fakeReq = {
      query: {},
      headers: {}
    };
    try {
      await service.getToken(fakeReq);
    } catch (e) {
      assert.equal(e.message, "access token missing");
    }
  });

  describe("permissions validation", () => {
    let fakeReq = {
      query: {},
      headers: { authorization: `Bearer ${tokens.valid}` }
    };

    it("should validate foo", async () => {
      assert.ok(await service.checkJWTPermissions(fakeReq, "foo"));
    });

    it("should validate test:bbb", async () => {
      assert.ok(await service.checkJWTPermissions(fakeReq, "test:bbb"));
    });

    it("should not validate blah", async () => {
      assert.equal(await service.checkJWTPermissions(fakeReq, "blah"), false);
    });

    it("should not validate test:aaa", async () => {
      assert.equal(
        await service.checkJWTPermissions(fakeReq, "test:aaa"),
        false
      );
    });
  });
});
