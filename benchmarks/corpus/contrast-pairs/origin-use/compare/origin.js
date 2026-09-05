function acceptsOrigin(origin, configuredOrigin) {
  return origin === configuredOrigin;
}

module.exports = { acceptsOrigin };
