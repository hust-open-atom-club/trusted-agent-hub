function isAllowedOrigin(origin, host) {
  return origin === "http://" + host;
}

module.exports = { isAllowedOrigin };
