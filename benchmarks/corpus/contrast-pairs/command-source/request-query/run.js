const childProcess = require("child_process");

function runFromRequest(request) {
  childProcess.exec(request.query.command);
}

module.exports = { runFromRequest };
