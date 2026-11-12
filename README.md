# CodeIntelligence ⚡

**AI-powered code analysis engine.** Security scanning + deep architectural review for production codebases.

## The Problem It Solves

Linters catch syntax errors. AI catches *architectural* problems — the kind that silently accumulate until a production incident forces a rewrite. CodeIntelligence bridges that gap: fast signature scanning for immediate feedback, optional AI analysis for deep context-aware review.

## What It Does

| Mode | Speed | Output |
|------|-------|--------|
| **Quick scan** (`--full` off) | <1s | Security signatures, file metrics, score/grade |
| **Full analysis** (`--full`) | ~60s | Deep security audit, architecture review, perf profile, maintainability assessment via Agnes reasoning API |

### Signature Detection (instant, no AI needed)

Scans for 16 patterns across all source files: hardcoded credentials, `eval()`/`exec()`, SQL injection vectors, XSS via innerHTML, private key material, overly permissive CORS, base64-encoded secrets, and more. Zero false positives on literal matches.

### AI Deep Analysis (optional)

Uses Agnes 2.5 Flash's reasoning capability to analyze your specific codebase context. Four analysis dimensions:

- **Security Deep**: CWE classifications, exploit scenarios, affected modules, patched code
- **Architecture**: Module coupling, dependency direction, error handling gaps, refactoring priorities  
- **Performance**: Hot path complexity, memory allocation patterns, I/O blocking, caching opportunities
- **Maintainability**: Naming consistency, documentation gaps, duplication, DRY/SOLID adherence

## Installation

```bash
npm install -g @yuhanbae/code-intelligence
```

Or npx one-liner:
```bash
npx @yuhanbae/code-intelligence /path/to/repo --full -o report.json
```

## Usage

```bash
# Quick security sweep (no AI, instant)
codeintel ./my-project

# Full AI-powered analysis
codeintel ./my-project --full

# Custom output path
codeintel ./my-project --full -o ../analysis/security-report.json

# CI/CD integration — fail if score below threshold
codeintel . && node -e "const r=require('./report.json'); process.exit(r.summary.score < 70 ? 1 : 0)"
```

## Output Schema

```json
{
  "metadata": { "tool": "CodeIntelligence", "version": "1.0.0", "generated": "ISO timestamp" },
  "summary": {
    "score": 85,        // 0-100 composite score
    "grade": "B",       // A-F letter grade
    "total_findings": 12,
    "critical": 2,      // severity=high
    "medium": 5,        // severity=medium  
    "low": 3,           // severity=low
    "informational": 2  // severity=info
  },
  "statistics": {
    "files": 47,
    "lines": 12847,
    "languages": { "typescript": 32, "javascript": 10, "markdown": 5 },
    "dependencies": 23,
    "hasTests": true,
    "commitCount": 156
  },
  "findings": [...],
  "ai_analysis": {
    "security_deep": "...",
    "architecture": "...",
    "performance": "...",
    "maintainability": "..."
  }
}
```

## Architecture

```
dist/index.js     — Main engine: filesystem walker + signature scanner + Agnes API client
  ├── _scanFiles()          — Recursive traversal, skip node_modules/.git
  ├── _signatureScan()      — Regex matching against 16 security patterns
  ├── _collectMetrics()     — LOC, languages, deps, git stats
  └── aiReview()            — POST to Agnes with full repo context
  
test/test.js    — Unit tests covering signature detection accuracy
```

## Tech Stack

- Runtime: Node.js 18+ (ES modules, native fetch)
- AI: Agnes 2.5 Flash reasoning model
- Scanning: Pure regex, zero external dependencies
- Output: JSON, CI/CD compatible

## Integration Examples

### GitHub Actions
```yaml
- uses: actions/checkout@v4
- run: npx @yuhanbae/code-intelligence . --full -o report.json
- run: node -e "const r=require('./report.json'); process.exit(r.summary.score < 70 ? 1 : 0)"
```

### Pre-commit hook (.husky/pre-commit)
```bash
npx @yuhanbae/code-intelligence . || exit 1
```

### Docker
```dockerfile
FROM node:20-slim
RUN npm install -g @yuhanbae/code-intelligence
CMD ["codeintel", "/app/src", "--full"]
```

## License

MIT — free for commercial and personal use.

## Related Projects

- [termux-diag-mcp](https://github.com/yuhanbae/termux-diag-mcp) — MCP server for device diagnostics
- All products: [yuhanbreeze.gumroad.com](https://yuhanbreeze.gumroad.com/)
