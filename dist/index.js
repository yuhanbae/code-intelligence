#!/usr/bin/env node
/**
 * AI-Powered Code Intelligence Service
 * Scans code repositories for security vulnerabilities, 
 * performance issues, and architectural problems.
 * Uses Agnes AI for intelligent analysis.
 */
import { execSync } from "child_process";
import * as fs from "fs";
import * as path from "path";
import { fileURLToPath } from "url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const AGNES_KEY = "sk-flobCnWjwxo0kn8654xRP3b8QO1LRWPgF5OxswgPFuA5Zooc";
const AGNES_URL = "https://apihub.agnes-ai.com/v1/chat/completions";

class CodeIntelligence {
  constructor(repoPath) {
    this.repoPath = repoPath;
    this.findings = [];
    this.stats = { files: 0, lines: 0, languages: {} };
  }

  async init() {
    console.error("[CodeIntel] Initializing scan of", this.repoPath);
    this._scanFiles();
    this._collectMetrics();
    return this;
  }

  _scanFiles() {
    const walk = (dir) => {
      try {
        for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
          const full = path.join(dir, entry.name);
          if (entry.isDirectory()) {
            if (!entry.name.startsWith(".") && entry.name !== "node_modules" && entry.name !== ".git") walk(full);
          } else if (entry.isFile()) {
            this.stats.files++;
            const ext = path.extname(entry.name).toLowerCase();
            const content = fs.readFileSync(full, "utf-8");
            const lines = content.split("\n").length;
            this.stats.lines += lines;
            const langMap = { ".py": "python", ".js": "javascript", ".ts": "typescript", ".go": "go", ".rs": "rust", ".c": "c", ".cpp": "cpp", ".java": "java", ".rb": "ruby", ".sh": "bash", ".md": "markdown" };
            const lang = langMap[ext] || "other";
            this.stats.languages[lang] = (this.stats.languages[lang] || 0) + 1;
            // Quick signature scan for sensitive patterns
            this._signatureScan(full, content, ext);
          }
        }
      } catch (e) { /* skip unreadable dirs */ }
    };
    walk(this.repoPath);
  }

  _signatureScan(file, content, ext) {
    const signatures = [
      { pattern: /password\s*[:=]\s*["'][^"'']{4,}/i, sev: "high", desc: "Hardcoded password" },
      { pattern: /api[_-]?key\s*[:=]\s*["'][^"'']{8,}/i, sev: "high", desc: "Hardcoded API key" },
      { pattern: /secret\s*[:=]\s*["'][^"'']{8,}/i, sev: "high", desc: "Hardcoded secret" },
      { pattern: /private[_-]?key/i, sev: "medium", desc: "Private key reference" },
      { pattern: /aws[_-]?access/i, sev: "high", desc: "AWS credential reference" },
      { pattern: /eval\s*\(/, sev: "high", desc: "eval() usage" },
      { pattern: /exec\s*\(/, sev: "medium", desc: "exec() usage" },
      { pattern: /innerHTML\s*=/, sev: "medium", desc: "innerHTML assignment (XSS)" },
      { pattern: /document\.write\s*\(/, sev: "low", desc: "document.write usage" },
      { pattern: /console\.log.*process\.env/, sev: "medium", desc: "Logging environment variables" },
      { pattern: /TODO.*hack|workaround.*hack/i, sev: "low", desc: "Hack/workaround TODO" },
      { pattern: /\bsql\s*=\s*['"`].*\%s|format\b.*SELECT/i, sev: "high", desc: "Potential SQL injection" },
    ];
    for (const sig of signatures) {
      if (sig.pattern.test(content)) {
        const matches = content.match(sig.pattern) || [];
        for (const match of matches.slice(0, 3)) {
          this.findings.push({
            file: file.replace(this.repoPath + "/", ""),
            line: content.substring(0, content.indexOf(match)).split("\n").length,
            severity: sig.sev,
            category: "security",
            description: sig.desc,
            snippet: match.substring(0, 80),
          });
        }
      }
    }
  }

  _collectMetrics() {
    try {
      const deps = JSON.parse(fs.readFileSync(path.join(this.repoPath, "package.json"), "utf-8") || "{}");
      this.stats.dependencies = Object.keys({...deps.dependencies, ...deps.devDependencies}).length;
      this.stats.hasTests = fs.existsSync(path.join(this.repoPath, "test")) || fs.existsSync(path.join(this.repoPath, "tests")) || fs.existsSync(path.join(this.repoPath, "__tests__"));
      this.stats.hasLicense = fs.existsSync(path.join(this.repoPath, "LICENSE"));
      this.stats.hasReadme = fs.existsSync(path.join(this.repoPath, "README.md"));
      this.stats.commitCount = parseInt(execSync("git log --oneline 2>/dev/null | wc -l", { cwd: this.repoPath }).trim());
      this.stats.branchCount = parseInt(execSync("git branch -a 2>/dev/null | wc -l", { cwd: this.repoPath }).trim());
    } catch { this.stats.dependencies = 0; }
  }

  async aiReview(prompt) {
    const context = `Repository Analysis Context:
- Path: ${this.repoPath}
- Files: ${this.stats.files}
- Lines of code: ${this.stats.lines}
- Languages: ${JSON.stringify(this.stats.languages)}
- Dependencies: ${this.stats.dependencies}
- Security findings: ${this.findings.filter(f=>f.severity==="high").length} high, ${this.findings.filter(f=>f.severity==="medium").length} medium, ${this.findings.filter(f=>f.severity==="low").length} low
- Has tests: ${this.stats.hasTests}
- Has LICENSE: ${this.stats.hasLicense}
- Git commits: ${this.stats.commitCount}
- Git branches: ${this.stats.branchCount}

Top files by size:
${execSync("find . -type f \\( -name '*.js' -o -name '*.ts' -o -name '*.py' -o -name '*.go' -o -name '*.rs' \\) -exec wc -l {} + 2>/dev/null | sort -rn | head -20", {cwd:this.repoPath}).toString().trim()}

Security findings detail:
${JSON.stringify(this.findings.slice(0, 20), null, 2)}`;

    const body = JSON.stringify({
      model: "agnes-2.5-flash",
      messages: [
        { role: "system", content: "You are a senior security engineer and architect. Analyze code repositories professionally. Be specific, cite file paths and line numbers, and prioritize actionable fixes. Your reviews are used for production code decisions." },
        { role: "user", content: `${context}\n\nTask: ${prompt}` },
      ],
      max_tokens: 4000,
    });

    const req = new Promise((resolve, reject) => {
      const data = Buffer.from(body);
      const options = new URL(AGNES_URL);
      const mod = options.protocol === "https:" ? await import("https") : await import("http");
      const r = mod.request(options, { method: "POST", headers: { "Content-Type": "application/json", "Authorization": `Bearer ${AGNES_KEY}`, "Content-Length": data.length }}, (res) => {
        let d = "";
        res.on("data", c => d += c);
        res.on("end", () => { try { resolve(JSON.parse(d)); } catch(e) { reject(e); } });
      });
      r.on("error", reject);
      r.write(data);
      r.end();
    });

    const resp = await req;
    if (resp.statusCode !== 200) throw new Error(`API error ${resp.statusCode}: ${await new Promise((r,e)=>{let d="";resp.on("data",c=>d+=c);resp.on("end",()=>r(d));})}`);
    const choice = resp.choices?.[0]?.message || {};
    return choice.content || choice.reasoning_content || "";
  }

  async runFullAnalysis() {
    console.error("[CodeIntel] Running AI analysis...");
    const prompts = [
      { name: "security", prompt: "Perform a comprehensive security audit. Identify all vulnerabilities ranked by severity (critical > high > medium > low). For each finding provide: exact location, vulnerability type (CVE if applicable), impact assessment, and a concrete fix with code example." },
      { name: "architecture", prompt: "Analyze the codebase architecture. Evaluate: module cohesion, coupling patterns, dependency management, error handling strategy, and testability. Recommend structural improvements prioritized by impact." },
      { name: "performance", prompt: "Identify performance bottlenecks and optimization opportunities. Consider: algorithmic complexity, memory usage patterns, I/O efficiency, caching opportunities, and redundant computations. Provide before/after comparisons." },
      { name: "maintainability", prompt: "Assess code maintainability: naming consistency, documentation coverage, complexity metrics, code duplication, abstraction layers, and adherence to established patterns. Rate overall maintainability and list top improvement actions." },
    ];

    const results = {};
    for (const p of prompts) {
      try {
        const t0 = Date.now();
        results[p.name] = await this.aiReview(p.prompt);
        console.error(`[CodeIntel] ${p.name} complete in ${(Date.now()-t0)/1000}s`);
      } catch (e) {
        results[p.name] = `Error: ${e.message}`;
      }
    }
    return results;
  }

  generateReport(results) {
    const totalFindings = this.findings.length;
    const critical = this.findings.filter(f => f.severity === "high").length;
    const medium = this.findings.filter(f => f.severity === "medium").length;
    const low = this.findings.filter(f => f.severity === "low").length;
    
    const score = Math.max(0, 100 - critical * 20 - medium * 8 - low * 3);
    
    return {
      metadata: {
        repo: this.repoPath,
        generated: new Date().toISOString(),
        scanner_version: "1.0.0",
        engine: "CodeIntelligence AI",
      },
      summary: {
        overall_score: score,
        grade: score >= 90 ? "A" : score >= 80 ? "B" : score >= 70 ? "C" : score >= 60 ? "D" : "F",
        total_findings,
        critical_findings: critical,
        medium_findings: medium,
        low_findings: low,
        recommendation: score >= 80 ? "Good baseline — address medium+ findings" : score >= 60 ? "Moderate risk — prioritize security fixes" : "High risk — immediate remediation required",
      },
      statistics: this.stats,
      findings: this.findings.sort((a,b) => ({high:0,medium:1,low:2}[a.severity]||3) - ({high:0,medium:1,low:2}[b.severity]||3)),
      ai_analysis: results,
    };
  }
}

// CLI entry point
if (import.meta.url === `file://${process.argv[1]}`) {
  const repo = process.argv[2] || ".";
  const output = process.argv[3] || "report.json";
  
  console.error(`\n🔍 CodeIntelligence v1.0.0`);
  console.error(`   Scanning: ${repo}`);
  console.error(`   Output: ${output}\n`);

  const scanner = new CodeIntelligence(repo);
  await scanner.init();
  
  console.error(`📊 Found ${scanner.stats.files} files, ${scanner.stats.lines} LOC`);
  console.error(`🔴 Security signatures: ${scanner.findings.length} potential issues`);
  
  const results = await scanner.runFullAnalysis();
  const report = scanner.generateReport(results);
  
  fs.writeFileSync(output, JSON.stringify(report, null, 2));
  console.error(`\n✅ Report saved to ${output}`);
  console.error(`   Score: ${report.summary.grade} (${report.summary.overall_score}/100)`);
  console.error(`   Findings: ${report.summary.critical_findings} critical, ${report.summary.medium_findings} medium, ${report.summary.low_findings} low\n`);
}

export { CodeIntelligence };
