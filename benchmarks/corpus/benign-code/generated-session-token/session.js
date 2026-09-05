const crypto = require("crypto");

function newSessionToken() {
  return crypto.randomBytes(32).toString("hex");
}

module.exports = { newSessionToken };
