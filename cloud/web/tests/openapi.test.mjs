import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import path from "node:path";
import { fileURLToPath } from "node:url";

const directory = path.dirname(fileURLToPath(import.meta.url));
const document = JSON.parse(readFileSync(path.resolve(directory, "../../contracts/v1/openapi.json"), "utf8"));

test("all v1 OpenAPI contract paths are backed by Next.js route handlers", () => {
  assert.equal(document.openapi, "3.1.0");
  assert.equal(Object.keys(document.paths).length, 12);
  for (const [pathname, methods] of Object.entries(document.paths)) {
    const relative = pathname.replace(/^\/api\/v1\//, "").replace("{id}", "[id]");
    const routeFile = path.resolve(directory, "../app/api/v1", relative, "route.js");
    const source = readFileSync(routeFile, "utf8");
    for (const method of Object.keys(methods)) {
      assert.match(source, new RegExp("export function " + method.toUpperCase() + "\\("), pathname);
    }
  }
});

test("C3 contract documents success only where an authenticated service exists", () => {
  for (const [pathname, methods] of Object.entries(document.paths)) {
    for (const [method, operation] of Object.entries(methods)) {
      if (method === "post" || method === "delete" || pathname.includes("/jobs/")) {
        assert.ok(operation.responses["503"], pathname + ": must fail closed without credentials");
      }
    }
  }
  assert.ok(document.paths["/api/v1/session/challenge"].post.responses["201"]);
  assert.ok(document.paths["/api/v1/session"].post.responses["201"]);
  for (const pathname of ["/api/v1/decode/file", "/api/v1/decode/text", "/api/v1/decode/import/catalog"]) {
    assert.ok(document.paths[pathname].post.responses["200"], pathname);
    assert.ok(document.paths[pathname].post.responses["401"], pathname);
  }
  assert.deepEqual(Object.keys(document.paths["/api/v1/decode/import/cloud"].post.responses), ["503"]);
  assert.deepEqual(Object.keys(document.paths["/api/v1/jobs"].post.responses), ["503"]);
});
