import test from "node:test";
import assert from "node:assert/strict";
import { loadSource } from "./load-source.mjs";
const { exportMode, exportTaskParams, rememberedExport, restoreExport } = await loadSource("jsonExportNavigation");

test("returning to JSON export restores the source and task without retaining input or tokens", () => {
  for (const mode of ["manual", "group", "paste"]) {
    const params = exportTaskParams(mode, "task-123");
    params.set("password", "PrivateFixturePassword"); params.set("token", "PrivateFixtureToken");
    const saved = rememberedExport(params), restored = restoreExport(saved);
    assert.deepEqual(JSON.parse(saved), { source: mode, id: "task-123" });
    assert.equal(exportMode(restored), mode);
    assert.equal(restored.toString(), exportTaskParams(mode, "task-123").toString());
  }
});

test("malformed storage cannot become navigation or inject query parameters", () => {
  for (const value of ["bad", "null", '{"source":"paste","id":"&password=secret"}', '{"source":"other","id":"ok"}', '{"source":"paste","id":4}'])
    assert.equal(restoreExport(value), null);
  assert.equal(rememberedExport(new URLSearchParams("source=group")), null);
});
