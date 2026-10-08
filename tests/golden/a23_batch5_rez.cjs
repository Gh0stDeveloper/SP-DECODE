#!/usr/bin/env node
"use strict";
/**
 * Authorized synthetic REZ/REZL golden generator. Extracts ONLY the historical
 * Tea.encrypt primitive (not CLI, FS or parsing) from the versioned repo file.
 * Executes that slice in a sandbox with no process, require, network, or fs.
 * This proves the script's own roundtrip, NOT an independent crypto reference.
 */
const fs = require("fs");
const vm = require("vm");
const path = require("path");
const original = fs.readFileSync(path.resolve(__dirname, "../../decoders/JavaScript/rez.js"), "utf8");
const start = original.indexOf("var Tea = {};");
const end = original.indexOf("\nvar date = Tea.decrypt(");
if (start < 0 || end <= start) throw new Error("REZ source layout changed");
const snippet = original.slice(start, end);
const sandbox = {module: {exports: {}}};
vm.runInNewContext(snippet, sandbox, {timeout: 2000, filename: "repo-rez-tea-fixture.js"});
const clear = JSON.stringify({
  PSInstall: "A23 synthetic",
  RootBlock: false,
  MobileData: true,
  ExpireDate: "none",
  Message: "offline",
  Payload: "GET",
  isDirect: true,
  isSSL: false,
  isWS: false,
  isDNS: false,
  Server: "example.org"
});
process.stdout.write(sandbox.Tea.encrypt(clear, "@technore24 2022"));
