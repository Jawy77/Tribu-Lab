// Fixtures de src/auditgate/rules/javascript/auditgate-node.yml
const express = require("express");
const cp = require("child_process");
const { exec, execFile, execSync } = require("child_process");
const app = express();

app.get("/ping", (req, res) => {
  // ruleid: auditgate.node.command-injection-child-process
  exec("ping -c 1 " + req.query.host, (err, out) => res.send(out));
});

app.post("/run", (req, res) => {
  const name = req.body.name;
  // ruleid: auditgate.node.command-injection-child-process
  cp.execSync(`ls ${name}`);
  res.end();
});

app.get("/safe", (req, res) => {
  // ok: auditgate.node.command-injection-child-process
  execFile("ping", ["-c", "1", req.query.host], (err, out) => res.send(out));
});

app.get("/uptime", (req, res) => {
  // ok: auditgate.node.command-injection-child-process
  exec("uptime", (err, out) => res.send(out));
});
