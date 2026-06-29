"use strict";
// Loads the dashboard app.js in a stubbed DOM and runs render() against a
// sample report. Catches undefined-reference / runtime errors (like a missing
// card function) that `node --check` cannot see. Used by test_dashboard_render.py.
//
//   node render_check.js <app.js> <report.json>
//
// Exits 0 and prints "RENDER OK" on success; non-zero otherwise.
const fs = require("fs");

const el = () => ({
  classList: { add() {}, remove() {}, toggle() {} },
  addEventListener() {}, appendChild() {},
  querySelector: () => el(), querySelectorAll: () => [],
  style: {}, dataset: {}, checked: false, value: "",
  set innerHTML(v) {}, get innerHTML() { return ""; },
  set textContent(v) {}, get textContent() { return ""; },
});
global.document = {
  documentElement: { setAttribute() {}, getAttribute() { return "dark"; } },
  querySelector: () => el(), getElementById: () => el(), querySelectorAll: () => [],
};
global.window = { scrollTo() {} };
global.localStorage = { getItem() { return null; }, setItem() {} };
global.EventSource = function () { return { addEventListener() {}, close() {} }; };

const [appPath, reportPath] = process.argv.slice(2);
let code = fs.readFileSync(appPath, "utf8") + "\nglobalThis.__render = render;";
try {
  eval(code);
} catch (e) {
  console.error("LOAD FAILED:", e.message);
  process.exit(1);
}

const report = JSON.parse(fs.readFileSync(reportPath, "utf8"));
try {
  globalThis.__render(report);
  console.log("RENDER OK");
} catch (e) {
  console.error("RENDER FAILED:", e.message);
  console.error((e.stack || "").split("\n").slice(1, 3).join(" | "));
  process.exit(2);
}
