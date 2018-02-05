"use strict";
var __extends = (this && this.__extends) || (function () {
    var extendStatics = Object.setPrototypeOf ||
        ({ __proto__: [] } instanceof Array && function (d, b) { d.__proto__ = b; }) ||
        function (d, b) { for (var p in b) if (b.hasOwnProperty(p)) d[p] = b[p]; };
    return function (d, b) {
        extendStatics(d, b);
        function __() { this.constructor = d; }
        d.prototype = b === null ? Object.create(b) : (__.prototype = b.prototype, new __());
    };
})();
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : new P(function (resolve) { resolve(result.value); }).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __generator = (this && this.__generator) || function (thisArg, body) {
    var _ = { label: 0, sent: function() { if (t[0] & 1) throw t[1]; return t[1]; }, trys: [], ops: [] }, f, y, t, g;
    return g = { next: verb(0), "throw": verb(1), "return": verb(2) }, typeof Symbol === "function" && (g[Symbol.iterator] = function() { return this; }), g;
    function verb(n) { return function (v) { return step([n, v]); }; }
    function step(op) {
        if (f) throw new TypeError("Generator is already executing.");
        while (_) try {
            if (f = 1, y && (t = y[op[0] & 2 ? "return" : op[0] ? "throw" : "next"]) && !(t = t.call(y, op[1])).done) return t;
            if (y = 0, t) op = [0, t.value];
            switch (op[0]) {
                case 0: case 1: t = op; break;
                case 4: _.label++; return { value: op[1], done: false };
                case 5: _.label++; y = op[1]; op = [0]; continue;
                case 7: op = _.ops.pop(); _.trys.pop(); continue;
                default:
                    if (!(t = _.trys, t = t.length > 0 && t[t.length - 1]) && (op[0] === 6 || op[0] === 2)) { _ = 0; continue; }
                    if (op[0] === 3 && (!t || (op[1] > t[0] && op[1] < t[3]))) { _.label = op[1]; break; }
                    if (op[0] === 6 && _.label < t[1]) { _.label = t[1]; t = op; break; }
                    if (t && _.label < t[2]) { _.label = t[2]; _.ops.push(op); break; }
                    if (t[2]) _.ops.pop();
                    _.trys.pop(); continue;
            }
            op = body.call(thisArg, _);
        } catch (e) { op = [6, e]; y = 0; } finally { f = t = 0; }
        if (op[0] & 5) throw op[1]; return { value: op[0] ? op[1] : void 0, done: true };
    }
};
Object.defineProperty(exports, "__esModule", { value: true });
var createError = require("http-errors");
var bluebird = require("bluebird");
var node_fetch_1 = require("node-fetch");
var jwt = bluebird.promisifyAll(require("jsonwebtoken"));
var nappjs_1 = require("nappjs");
var NappJSJWT = (function (_super) {
    __extends(NappJSJWT, _super);
    function NappJSJWT() {
        return _super !== null && _super.apply(this, arguments) || this;
    }
    NappJSJWT.prototype.getToken = function (req) {
        return __awaiter(this, void 0, void 0, function () {
            var token, configs, latestError, _i, configs_1, config, res, e_1, e_2;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        token = req.query.access_token || req.headers.authorization;
                        if (!token) {
                            throw createError(401, "access token missing");
                        }
                        token = token.replace("Bearer ", "");
                        _a.label = 1;
                    case 1:
                        _a.trys.push([1, 9, , 10]);
                        return [4, this.getConfigs()];
                    case 2:
                        configs = _a.sent();
                        if (configs.length == 0) {
                            throw new Error("invalid environment cofiguration");
                        }
                        latestError = null;
                        _i = 0, configs_1 = configs;
                        _a.label = 3;
                    case 3:
                        if (!(_i < configs_1.length)) return [3, 8];
                        config = configs_1[_i];
                        _a.label = 4;
                    case 4:
                        _a.trys.push([4, 6, , 7]);
                        return [4, jwt.verifyAsync(token, config.secret, config.options)];
                    case 5:
                        res = _a.sent();
                        return [2, res];
                    case 6:
                        e_1 = _a.sent();
                        latestError = e_1;
                        return [3, 7];
                    case 7:
                        _i++;
                        return [3, 3];
                    case 8: throw latestError;
                    case 9:
                        e_2 = _a.sent();
                        throw createError(401, e_2.message);
                    case 10: return [2];
                }
            });
        });
    };
    NappJSJWT.prototype.checkJWTPermissions = function (req, resource) {
        return __awaiter(this, void 0, void 0, function () {
            var info, permissions, valid, _i, permissions_1, permission, _a, _rule, _resource, regepx;
            return __generator(this, function (_b) {
                switch (_b.label) {
                    case 0: return [4, this.getToken(req)];
                    case 1:
                        info = _b.sent();
                        if (!info.permissions && !info.user) {
                            return [2, false];
                        }
                        permissions = info.permissions || info.user.permissions;
                        if (!permissions) {
                            return [2, false];
                        }
                        permissions = permissions.split("\n");
                        valid = false;
                        for (_i = 0, permissions_1 = permissions; _i < permissions_1.length; _i++) {
                            permission = permissions_1[_i];
                            _a = permission.split("|"), _rule = _a[0], _resource = _a[1];
                            if (!_rule || !_resource)
                                continue;
                            regepx = new RegExp("^" + _resource.replace(/\*/g, ".*") + "$");
                            if (regepx.test(resource)) {
                                if (_rule == "deny") {
                                    return [2, false];
                                }
                                else {
                                    valid = true;
                                }
                            }
                        }
                        return [2, valid];
                }
            });
        });
    };
    NappJSJWT.prototype.getConfigs = function () {
        return __awaiter(this, void 0, void 0, function () {
            var configs, JWT_SECRET, JWT_CERTS_URL, JWT_PUBLIC_CERT, res, content;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        configs = [];
                        JWT_SECRET = process.env.JWT_SECRET;
                        JWT_CERTS_URL = process.env.JWT_CERTS_URL;
                        JWT_PUBLIC_CERT = process.env.JWT_PUBLIC_CERT;
                        if (typeof JWT_SECRET !== "undefined") {
                            configs.push({ secret: JWT_SECRET, options: { algorhitm: "HS256" } });
                        }
                        if (typeof JWT_PUBLIC_CERT !== "undefined") {
                            configs.push({
                                secret: JWT_PUBLIC_CERT,
                                options: { algorhitm: "RS256" }
                            });
                        }
                        if (!(typeof JWT_CERTS_URL !== "undefined")) return [3, 3];
                        return [4, node_fetch_1.default(JWT_CERTS_URL)];
                    case 1:
                        res = _a.sent();
                        return [4, res.json()];
                    case 2:
                        content = _a.sent();
                        configs.push(content.map(function (cert) {
                            return { secret: cert.key, options: { algorhitm: "RS256" } };
                        }));
                        _a.label = 3;
                    case 3: return [2, configs];
                }
            });
        });
    };
    return NappJSJWT;
}(nappjs_1.NappJSService));
exports.default = NappJSJWT;
//# sourceMappingURL=index.js.map