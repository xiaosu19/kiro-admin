import { after } from "node:test";
import {
  mkdtempSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import ts from "typescript";

// Compile the real source with existing project dependencies, including on Node 22.
const output = mkdtempSync(join(tmpdir(), "kiro-frontend-tests-"));
writeFileSync(join(output, "package.json"), '{"type":"module"}');
symlinkSync(
  fileURLToPath(new URL("../node_modules", import.meta.url)),
  join(output, "node_modules"),
  "dir",
);
function compile(name, input) {
  return ts.transpileModule(input, {
    compilerOptions: { target: ts.ScriptTarget.ES2020, module: ts.ModuleKind.ESNext, jsx: ts.JsxEmit.ReactJSX },
    fileName: name,
  }).outputText.replace(/from "(\.\/[^".]+)"/g, 'from "$1.js"');
}
for (const name of [
  "selectionSearch.ts",
  "provisioningLogic.ts",
  "provisioningRequests.ts",
  "Provisioning.tsx",
  "SearchableSelect.tsx",
  "LoginExportMenu.tsx",
  "AccountBindings.tsx",
  "api.ts",
  "groupsLogic.ts",
  "groupRequests.ts",
  "groupObservationRequests.ts",
  "groupMemberLogic.ts",
  "groupMemberRequests.ts",
  "GroupAwsObservation.tsx",
  "GroupMembers.tsx",
  "nativeSubscriptionsLogic.ts",
  "nativeSubscriptionRequests.ts",
  "NativeSubscriptions.tsx",
  "authLogic.ts",
  "authRequests.ts",
  "planChangeRequests.ts",
  "planChangesLogic.ts",
  "PlanChangeManager.tsx",
  "AuthBatches.tsx",
  "RetryStatus.tsx",
  "AuthSelection.tsx",
  "JsonExport.tsx",
  "jsonExportNavigation.ts",
  "AiSettings.tsx",
  "GroupJsonExport.tsx",
  "groupJsonRequests.ts",
  "ExternalJsonExport.tsx",
  "externalExportLogic.ts",
  "externalExportRequests.ts",
  "CascadeDeletion.tsx",
  "cascadeRequests.ts",
  "PasswordBatches.tsx",
  "StopSchedule.tsx",
  "Groups.tsx",
  "Proxies.tsx",
  "AwsReports.tsx",
  "App.tsx",
]) {
  const source = compile(name, readFileSync(new URL(`../src/${name}`, import.meta.url), "utf8"));
  writeFileSync(join(output, name.replace(/\.tsx?$/, ".js")), source);
}
// Mount the actual detail component in the hook host; only router navigation is
// stubbed, while its reads, mutations, effects and rendered controls stay real.
writeFileSync(join(output, "router-stub.js"), 'export const NavLink = "a"; export function useSearchParams() { return [new URLSearchParams(), () => {}]; }');
writeFileSync(join(output, "GroupDetails-test.js"), compile("Groups.tsx",
  readFileSync(new URL("../src/Groups.tsx", import.meta.url), "utf8")
    .replace("function GroupDetails(", "export function GroupDetails(")
    .replace('from "react-router-dom"', 'from "./router-stub"')));
writeFileSync(join(output, "RecordManager-test.js"), compile("App.tsx",
  readFileSync(new URL("../src/App.tsx", import.meta.url), "utf8")
    .replace("function RecordManager(", "export function RecordManager(")
    .replace("const useApp = () => useContext(AppContext);", 'const useApp = () => ({ user: { id: 7, role: "member" }, capabilities: { plan_changes_enabled: false }, notify() {} });')));
writeFileSync(join(output, "export-router-stub.js"), `
export const NavLink = "a", Navigate = "a", Route = "div", Routes = "div";
const params = new URLSearchParams("aws_account_id=2&owner_id=7&group_id=g-a&status=active");
export function useNavigate() { return () => {}; }
export function useSearchParams() { return [params, () => {}]; }
`);
writeFileSync(join(output, "LoginExports-test.js"), compile("App.tsx",
  readFileSync(new URL("../src/App.tsx", import.meta.url), "utf8")
    .replace("function Records(", "export function Records(")
    .replace("function BatchProgress(", "export function BatchProgress(")
    .replace('from "react-router-dom"', 'from "./export-router-stub"')
    .replace("const useApp = () => useContext(AppContext);", 'const useApp = () => ({ user: { id: 7, role: "member" }, notify() {} });')));
after(() => rmSync(output, { recursive: true, force: true }));
export const loadSource = (name) =>
  import(pathToFileURL(join(output, `${name}.js`)).href);
