const childProcess = require("child_process");

function runConfiguredHook() {
  childProcess.exec(process.env.OPERATOR_HOOK_COMMAND);
}

module.exports = { runConfiguredHook };
