const http = require("http");

function serveLocally(handler) {
  const server = http.createServer(handler);
  server.listen(4317, "127.0.0.1");
  return server;
}

module.exports = { serveLocally };
