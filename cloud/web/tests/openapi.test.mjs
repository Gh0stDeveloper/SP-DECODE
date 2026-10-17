import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import path from "node:path";
import { fileURLToPath } from "node:url";

const directory = path.dirname(fileURLToPath(import.meta.url));
const document = JSON.parse(readFileSync(path.resolve(directory, "../../contracts/v1/openapi.json"), "utf8"));

test("all v1 OpenAPI contract paths are backed by Next.js route handlers", () => {
  assert.equal(document.openapi, "3.1.0");
  assert.equal(Object.keys(document.paths).length, 11);
  for (const [pathname, methods] of Object.entries(document.paths)) {
    const relative = pathname.replace(/^\/api\/v1\//, "").replace("{id}", "[id]");
    const routeFile = path.resolve(directory, "../app/api/v1", relative, "route.js");
    const source = readFileSync(routeFile, "utf8");
    for (const method of Object.keys(methods)) {
      assert.match(source, new RegExp("export function " + method.toUpperCase() + "\\("), pathname);
    }
  }
});

test("every mutation endpoint documents only 503 in C1", () => {
  for (const [pathname, methods] of Object.entries(document.paths)) {
    for (const [method, operation] of Object.entries(methods)) {
      if (method === "post" || method === "delete" || pathname.includes("/jobs/")) {
        assert.deepEqual(Object.keys(operation.responses), ["503"], pathname);
      }
    }
  }
});
