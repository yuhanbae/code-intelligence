#!/usr/bin/env node
/**
 * CodeIntelligence - AI-Powered Code Analysis Engine
 * Security scanning + AI-driven architectural review
 */
import { execSync } from "child_process";
import * as fs from "fs";
import * as path from "path";

const AGNES_KEY = "sk-flobCnWjwxo0kn8654xRP3b8QO1LRWPgF5OxswgPFuA5Zooc";
const AGNES_URL = "https://apihub.agnes-ai.com/v1/chat/completions";

class CodeIntelligence {
  constructor(repoPath) {
    this.repoPath = repoPath.replace(/\/$/, "");
    this.findings = [];
    this.stats = { files: 0, lines: 0, languages: {}, dependencies: 0, commitCount: 0, branchCount: 0 };
  }

  async init() {
    console.error("[CodeIntel] Scanning:", this.repoPath);
    this._scanFiles();
    this._collectMetrics();
    return this;
  }

  _scanFiles() {
    const walk = (dir) => {
      if (fs.lstatSync(dir).size > 500 * 1024 * 1024) return; // skip >500MB dirs
      try {
        for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
          const full = path.join(dir, entry.name);
          if (entry.isDirectory()) {
            if (!entry.name.startsWith(".") && entry.name !== "node_modules" && entry.name !== ".git" && entry.name !== ".venv") walk(full);
          } else if (entry.isFile()) {
            this.stats.files++;
            const ext = path.extname(entry.name).toLowerCase();
            const content = fs.readFileSync(full, "utf-8");
            this.stats.lines += content.split("\n").length;
            const langMap = { ".py": "python", ".js": "javascript", ".ts": "typescript", ".tsx": "typescript", ".jsx": "javascript", ".go": "go", ".rs": "rust", ".c": "c", ".cpp": "cpp", ".h": "c", ".hpp": "cpp", ".java": "java", ".rb": "ruby", ".sh": "bash", ".md": "markdown", ".json": "json", ".yaml": "yaml", ".yml": "yaml", ".toml": "toml", ".sql": "sql", ".html": "html", ".css": "css" };
            const lang = langMap[ext] || "other";
            this.stats.languages[lang] = (this.stats.languages[lang] || 0) + 1;
            this._signatureScan(full, content, ext);
          }
        }
      } catch (e) { /* permission denied on some dirs is normal */ }
    };
    walk(this.repoPath);
  }

  _signatureScan(file, content, ext) {
    if (ext === ".png" || ext === ".jpg" || ext === ".jpeg" || ext === ".gif" || ext === ".ico" || ext === ".woff" || ext === ".woff2" || ext === ".ttf" || ext === ".eot" || ext === ".svg" || ext === ".zip" || ext === ".tar" || ext === ".gz" || ext === ".bin") return;
    const signatures = [
      { pattern: /password\s*[:=]\s*["'][^"'']{4,}/i, sev: "high", desc: "Hardcoded password detected" },
      { pattern: /api[_-]?key\s*[:=]\s*["'][^"'']{8,}/i, sev: "high", desc: "Hardcoded API key detected" },
      { pattern: /secret\s*[:=]\s*["'][^"'']{8,}/i, sev: "high", desc: "Hardcoded secret/token detected" },
      { pattern: /PRIVATE.?KEY|BEGIN RSA|BEGIN EC|BEGIN OPENSSH/i, sev: "high", desc: "Private key material in source" },
      { pattern: /aws[_-]?access[_-]?key[_-]?id/i, sev: "high", desc: "AWS credential reference" },
      { pattern: /\beval\s*\(/, sev: "high", desc: "eval() — code injection risk" },
      { pattern: /\bexec\s*\(\s*[^"']+[\"']/, sev: "medium", desc: "exec() with string argument" },
      { pattern: /\.innerHTML\s*=/, sev: "medium", desc: "innerHTML assignment (XSS vector)" },
      { pattern: /document\.write\s*\(/, sev: "low", desc: "document.write() usage" },
      { pattern: /console\.log.*(?:process\.env|apiKey|token|secret|password)/i, sev: "medium", desc: "Logging sensitive environment values" },
      { pattern: /TODO.*hack|FIXME.*hack|XXX.*workaround/i, sev: "low", desc: "Technical debt marker (hack/workaround)" },
      { pattern: /[\"']SELECT[\"'].*%[sd]|\.format\(.*SELECT|f[\"'].*SELECT/i, sev: "high", desc: "Potential SQL injection via string formatting" },
      { pattern: /new\s+Function\s*\(/, sev: "high", desc: "Function() constructor — dynamic code evaluation" },
      { pattern: /atob\s*\(\s*[\"']?[A-Za-z0-9+/]{20,}/, sev: "medium", desc: "Base64 encoded string (possible embedded secret)" },
      { pattern: /bcrypt|argon2|scrypt.*cost\s*[:=]\s*[1-9]/i, sev: "info", desc: "Password hashing configuration detected" },
      { pattern: /cors\s*[:=]\s*true|\*:\s*\*/i, sev: "low", desc: "Overly permissive CORS configuration" },
    ];
    for (const sig of signatures) {
      try {
        const matches = content.match(sig.pattern);
        if (matches) {
          const lineNum = content.substring(0, content.indexOf(matches[0])).split("\n").length;
          this.findings.push({
            file: file.replace(this.repoPath + "/", ""),
            line: lineNum,
            severity: sig.sev,
            category: "security",
            description: sig.desc,
            snippet: matches[0].substring(0, 100),
          });
        }
      } catch (_) { /* regex error on binary content */ }
    }
  }

  _collectMetrics() {
    try {
      const pkgPath = path.join(this.repoPath, "package.json");
      if (fs.existsSync(pkgPath)) {
        const deps = JSON.parse(fs.readFileSync(pkgPath, "utf-8"));
        this.stats.dependencies = Object.keys({...deps.dependencies || {}, ...deps.devDependencies || {}}).length;
      }
      const requirementsPath = path.join(this.repoPath, "requirements.txt");
      if (fs.existsSync(requirementsPath)) {
        this.stats.dependencies += fs.readFileSync(requirementsPath, "utf-8").split("\n").filter(l => l.trim()  && !l.startsWith("#")).length;
      }
      this.stats.hasTests = ["test", "tests", "__tests__", "spec", "specs", "Test"].some(d => fs.existsSync(path.join(this.repoPath, d)));
      this.stats.hasLicense = fs.existsSync(path.join(this.repoPath, "LICENSE"));
      this.stats.hasReadme = fs.existsSync(path.join(this.repoPath, "README.md")) || fs.existsSync(path.join(this.repoPath, "readme.md"));
      try {
        this.stats.commitCount = parseInt(execSync("git log --oneline 2>/dev/null | wc -l", { cwd: this.repoPath }).trim());
        this.stats.branchCount = parseInt(execSync("git branch -a 2>/dev/null | wc -l", { cwd: this.repoPath }).trim());
      } catch {}
    } catch (_) {}
  }

  async aiReview(prompt) {
    const topFiles = (() => {
      try { return execSync('find . -type f \\( -name "*.js" -o -name "*.ts" -o -name "*.py" -o -name "*.go" -o -name "*.rs" \\) -exec wc -l {} + 2>/dev/null | sort -rn | head -15', { cwd: this.repoPath }).toString().trim(); } catch { return "(unable to scan)"; }
    })();
    
    const context = [
      "=== REPOSITORY CONTEXT ===",
      `Path: ${this.repoPath}`,
      `Files: ${this.stats.files} | Lines: ${this.stats.lines}`,
      `Languages: ${JSON.stringify(this.stats.languages)}`,
      `Dependencies: ${this.stats.dependencies}`,
      `Has tests: ${this.stats.hasTests} | Has LICENSE: ${this.stats.hasLicense}`,
      `Git commits: ${this.stats.commitCount} | Branches: ${this.stats.branchCount}`,
      "",
      "=== TOP FILES BY SIZE ===",
      topFiles,
      "",
      "=== SECURITY FINDINGS ===",
      this.findings.length === 0 ? "No signature matches found" : JSON.stringify(this.findings.slice(0, 30), null, 2),
      "",
      "=== TASK ===",
      prompt,
    ].join("\n");

    const body = JSON.stringify({
      model: "agnes-2.5-flash",
      messages: [
        { role: "system", content: "You are a principal software engineer and security architect with 15+ years experience. You analyze production codebases for real-world risks. Your reviews are actionable: cite exact file paths and line numbers, explain WHY something is problematic, and provide concrete fixes with code examples. Prioritize by impact. Be direct and specific — no filler." },
        { role: "user", content: context },
      ],
      max_tokens: 4000,
      temperature: 0.3,
    });

    const resp = await fetch(AGNES_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json", "Authorization": `Bearer ${AGNES_KEY}` },
      body,
    });
    
    if (!resp.ok) throw new Error(`Agnes API ${resp.status}: ${await resp.text()}`);
    const data = await resp.json();
    const choice = data.choices?.[0]?.message || {};
    return choice.content || choice.reasoning_content || "[empty response]";
  }

  async runFullAnalysis() {
    const prompts = [
      { name: "security_deep", prompt: "Perform a deep security audit beyond surface-level findings. For each vulnerability identified, provide: (1) CVE or CWE classification, (2) exploit scenario, (3) affected components, (4) remediation with patched code. Focus on logic flaws, authentication bypasses, authorization gaps, and supply chain risks." },
      { name: "architecture", prompt: "Analyze the codebase architecture holistically. Evaluate module boundaries, dependency direction, coupling vs cohesion, error handling consistency, and test coverage gaps. Identify the most fragile modules and recommend refactoring priorities with estimated effort." },
      { name: "performance", prompt: "Identify performance bottlenecks across the codebase. Consider time complexity of hot paths, memory allocation patterns, unnecessary re-renders/computations, I/O blocking operations, and caching opportunities. Provide a ranked list of optimizations with expected impact." },
      { name: "maintainability", prompt: "Assess long-term maintainability. Evaluate naming conventions, documentation quality, code duplication, abstraction levels, and adherence to DRY/SOLID principles. Rate the team velocity risk and suggest concrete cleanup tasks ordered by ROI." },
    ];

    const results = {};
    for (const p of prompts) {
      try {
        const t0 = Date.now();
        results[p.name] = await this.aiReview(p.prompt);
        console.error(`[CodeIntel] ${p.name}: ${(Date.now()-t0)/1000}s`);
      } catch (e) {
        results[p.name] = `ERROR: ${e.message}`;
      }
    }
    return results;
  }

  generateReport(results) {
    const high = this.findings.filter(f => f.severity === "high").length;
    const med = this.findings.filter(f => f.severity === "medium").length;
    const low = this.findings.filter(f => f.severity === "low").length;
    const info = this.findings.filter(f => f.severity === "info").length;
    const score = Math.max(0, Math.min(100, 100 - high * 15 - med * 5 - low * 2));
    const grade = score >= 90 ? "A" : score >= 80 ? "B" : score >= 70 ? "C" : score >= 60 ? "D" : "F";
    return {
      metadata: { tool: "CodeIntelligence", version: "1.0.0", generated: new Date().toISOString(), engine: "agnes-2.5-flash" },
      summary: { score, grade, total_findings: this.findings.length, critical: high, medium: med, low, informational: info, recommendation: score >= 80 ? "Codebase is in good shape. Address medium-severity findings during next sprint." : score >= 60 ? "Moderate risk detected. Prioritize security fixes before release." : "High risk. Block release until critical and high findings are resolved." },
      statistics: this.stats,
      findings: [...this.findings].sort((a, b) => ({ high: 0, medium: 1, low: 2, info: 3 }[a.severity] ?? 4) - ({ high: 0, medium: 1, low: 2, info: 3 }[b.severity] ?? 4)),
      ai_analysis: results,
    };
  }
}

// CLI
if (import.meta.url === `file://${process.argv[1]}`) {
  const args = process.argv.slice(2);
  let repoPath = ".";
  let outputPath = "report.json";
  let fullAnalysis = false;

  for (let i = 0; i < args.length; i++) {
    if (args[i] === "-o" || args[i] === "--output") outputPath = args[++i];
    else if (args[i] === "--full") fullAnalysis = true;
    else if (args[i].startsWith("-")) continue;
    else repoPath = args[i];
  }

  repoPath = path.resolve(repoPath);
  
  console.error("\n" + "=".repeat(60));
  console.error("  CodeIntelligence v1.0.0 — AI-Powered Code Analysis");
  console.error("=".repeat(60));
  console.error(`  Target:   ${repoPath}`);
  console.error(`  Output:   ${outputPath}`);
  console.error(`  Full AI:  ${fullAnalysis ? "yes (~2min)" : "no (signatures only, instant)"}`);
  console.error("=".repeat(60) + "\n");

  const scanner = new CodeIntelligence(repoPath);
  await scanner.init();
  
  console.error(`  Files:     ${scanner.stats.files}`);
  console.error(`  Lines:     ${scanner.stats.lines.toLocaleString()}`);
  console.error(`  Languages: ${Object.entries(scanner.stats.languages).map(([l,c])=>`${l}(${c})`).join(", ")}`);
  console.error(`  Signatures:${scanner.findings.length} potential issues`);
  
  if (fullAnalysis) {
    console.error("\n  Running AI analysis (requires internet)...\n");
    const results = await scanner.runFullAnalysis();
    const report = scanner.generateReport(results);
    fs.writeFileSync(outputPath, JSON.stringify(report, null, 2));
    console.error(`\n  Score: ${report.summary.grade} (${report.summary.score}/100)`);
    console.error(`  Recommendations: ${report.summary.recommendation}`);
  } else {
    const report = scanner.generateReport({});
    fs.writeFileSync(outputPath, JSON.stringify(report, null, 2));
    console.error(`\n  Quick score: ${report.summary.grade} (${report.summary.score}/100)`);
  }
  
  console.error(`\n  Report saved: ${outputPath}\n`);
}

export { CodeIntelligence };
