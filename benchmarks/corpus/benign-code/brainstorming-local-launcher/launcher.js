const childProcess = require("child_process");

function openLocalCompanion(port) {
  const url = `http://localhost:${port}/session`;
  childProcess.execFile("xdg-open", [url], { shell: false });
}

module.exports = { openLocalCompanion };
