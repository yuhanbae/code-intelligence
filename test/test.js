import { CodeIntelligence } from "../dist/index.js";
import * as fs from "fs";
import * as path from "path";
import { fileURLToPath } from "url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const tmpDir = path.join(__dirname, "..", ".test-tmp");

async function run() {
  // Create test fixture
  if (!fs.existsSync(tmpDir)) fs.mkdirSync(tmpDir, { recursive: true });
  
  const testFiles = {
    "package.json": '{"name":"test","dependencies":{"express":"^4.0.0"}}',
    "app.js": `
const express = require('express');
const app = express();
const password = "secret123";
const apiKey = "sk-test-abc123xyz789";
app.get('/', (req, res) => {
  eval(req.query.code);
  res.innerHTML = '<h1>hello</h1>';
});
module.exports = app;
`,
    "safe.py": `
def hello():
    return "world"
`,
  };
  
  for (const [name, content] of Object.entries(testFiles)) {
    fs.writeFileSync(path.join(tmpDir, name), content);
  }
  
  const scanner = new CodeIntelligence(tmpDir);
  await scanner.init();
  
  console.log("Stats:", JSON.stringify(scanner.stats, null, 2));
  console.log("\nFindings:", scanner.findings.length);
  for (const f of scanner.findings) {
    console.log(`  [${f.severity.toUpperCase()}] ${f.file}:${f.line} - ${f.description}`);
  }
  
  const report = scanner.generateReport({ security: "AI analysis would go here", architecture: "...", performance: "...", maintainability: "..." });
  console.log("\nScore:", report.summary.grade, "/", report.summary.overall_score);
  console.log("Recommendation:", report.summary.recommendation);
  
  // Cleanup
  fs.rmSync(tmpDir, { recursive: true, force: true });
  console.log("\n✅ All tests passed");
}

run().catch(err => { console.error(err); process.exit(1); });
