"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.getLogger = exports.error = exports.info = exports.trace = exports.LOGGER_NAMESPACE = void 0;

var _debug = _interopRequireDefault(require("debug"));

var _package = require("../../package.json");

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

// automatically set logger namespace to package.json name
const LOGGER_NAMESPACE = _package.name;
exports.LOGGER_NAMESPACE = LOGGER_NAMESPACE;
const logger = (0, _debug.default)(LOGGER_NAMESPACE);

const trace = namespace => logger.extend(`trace:${namespace}`);

exports.trace = trace;

const info = namespace => logger.extend(`info:${namespace}`);

exports.info = info;

const error = namespace => logger.extend(`error:${namespace}`);

exports.error = error;

const getLogger = namespace => ({
  trace: trace(namespace),
  info: info(namespace),
  error: error(namespace)
});

exports.getLogger = getLogger;