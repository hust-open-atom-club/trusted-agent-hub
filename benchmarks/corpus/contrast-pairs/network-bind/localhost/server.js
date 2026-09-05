const http = require("http");

http.createServer((_request, response) => response.end("ok")).listen(4317, "localhost");
