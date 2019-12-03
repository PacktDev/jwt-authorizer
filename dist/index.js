"use strict";

var cov_lqa5ntiw6 = function () {
  var path = "/home/chrisk@packtpub.net/code/packt-internal/jwt-authorizer/src/index.js";
  var hash = "0073ca4a8b754cb0fe5a1412270fcd33b58fcfa7";
  var global = new Function("return this")();
  var gcv = "__coverage__";
  var coverageData = {
    path: "/home/chrisk@packtpub.net/code/packt-internal/jwt-authorizer/src/index.js",
    statementMap: {},
    fnMap: {},
    branchMap: {},
    s: {},
    f: {},
    b: {},
    _coverageSchema: "43e27e138ebf9cfc5966b082cf9a028302ed4184",
    hash: "0073ca4a8b754cb0fe5a1412270fcd33b58fcfa7"
  };
  var coverage = global[gcv] || (global[gcv] = {});

  if (coverage[path] && coverage[path].hash === hash) {
    return coverage[path];
  }

  return coverage[path] = coverageData;
}();

Object.defineProperty(exports, "__esModule", {
  value: true
});
Object.defineProperty(exports, "PermissionManager", {
  enumerable: true,
  get: function () {
    return _permissionManager.default;
  }
});
Object.defineProperty(exports, "AuthHelper", {
  enumerable: true,
  get: function () {
    return _authHelper.default;
  }
});

var _permissionManager = _interopRequireDefault(require("./permission-manager"));

var _authHelper = _interopRequireDefault(require("./auth-helper"));

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }