# MCPGuard

**Enterprise-grade MCP security & governance layer**

> "The S in MCP Stands for Security"

MCPGuard scans your MCP (Model Context Protocol) server configurations for security vulnerabilities, helping you deploy AI agents safely.

## Features

- **Prompt Injection Detection** - Detects common prompt injection patterns in tool configurations
- **CVE Database** - Checks against known MCP vulnerabilities (CVE-2025-49596, etc.)
- **Tool Poisoning Detection** - Identifies suspicious commands and shell access
- **Missing Authentication Warnings** - Flags servers without proper auth configuration
- **Trusted Registry** - Validates servers against a curated list of safe, audited servers
- **Composite Risk Scoring** - Weighted scoring algorithm for accurate risk assessment
- **CI/CD Integration** - JSON output and exit codes for automated pipelines

## Installation

```bash
# Run directly with npx
npx mcpguard scan ./claude_desktop_config.json

# Or install globally
npm install -g mcpguard
```

## Usage

### Scan a Configuration

```bash
# Basic scan
mcpguard scan ./claude_desktop_config.json

# JSON output for CI/CD
mcpguard scan ./config.json --output json

# Fail if high-severity issues found
mcpguard scan ./config.json --fail-on high
```

### Check a Server

```bash
# Check specific server against CVE database
mcpguard check @anthropic-ai/mcp-server-fetch
mcpguard check suspicious-mcp-server
```

### Audit All Configs

```bash
# Auto-detect and scan all MCP configs
mcpguard audit

# Watch mode for continuous monitoring
mcpguard audit --watch
```

## Output Example

```
  MCPGuard Security Scan v1.0.0
  "The S in MCP Stands for Security"

  Scanning: 3 MCP servers

  !!! HIGH RISK: malicious-server
     - CRIT Prompt Injection Vector Detected
       (CVE-2025-49596)
     - HIGH Suspicious Command Execution
     Risk Score: 0.92

  !! MEDIUM RISK: localhost-server
     - MED Localhost Exposure Without Authentication
     Risk Score: 0.52

  * LOW RISK: filesystem
     - No issues detected
     Risk Score: 0.08

  ──────────────────────────────────────────────────

  Summary
  Servers: 1 high, 1 medium, 1 low risk
  Total findings: 3

  Action Required: Review high-risk servers before deployment
```

## Detection Rules

| ID | Name | Severity | Description |
|----|------|----------|-------------|
| MCPG-001 | Prompt Injection | Critical | Detects prompt injection patterns in configurations |
| MCPG-002 | Tool Poisoning | High | Identifies suspicious shell/exec commands |
| MCPG-003 | Localhost Exposure | Medium | Flags localhost without authentication |
| MCPG-004 | Missing Auth | High | Warns when no authentication is configured |
| MCPG-005 | Metadata Issues | Medium | Detects unsafe content in tool metadata |
| MCPG-006 | Sensitive Env Vars | Medium | Flags exposed secrets in environment |
| MCPG-007 | File System Access | High | Detects unrestricted file system access |

## CI/CD Integration

### GitHub Actions

```yaml
name: MCP Security Check
on: [push, pull_request]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run MCPGuard
        run: npx mcpguard scan ./mcp-config.json --fail-on high
```

### Exit Codes

- `0` - No high-risk issues found
- `1` - High-risk issues detected or scan failed

## Risk Scoring

MCPGuard uses a composite scoring algorithm inspired by industry best practices:

```
Risk Score = (0.35 × Vulnerability) + (0.30 × Configuration) + (0.25 × Behavioral) - (0.10 × Trust)
```

- **Vulnerability (35%)**: Known CVE matches
- **Configuration (30%)**: Auth and network exposure issues
- **Behavioral (25%)**: Suspicious patterns in config
- **Trust (10%)**: Bonus reduction for verified servers

### Risk Levels

- **HIGH** (≥0.7): Block deployment, immediate action required
- **MEDIUM** (≥0.4): Review recommended before production
- **LOW** (<0.4): Acceptable risk level

## Known CVEs

MCPGuard includes detection for:

- **CVE-2025-49596**: Prompt injection via tool descriptions
- **CVE-2025-49597**: Tool poisoning via malicious registries
- **CVE-2025-49598**: Dynamic tool modification (rug pull)
- **CVE-2025-49599**: Cross-server data exfiltration
- **CVE-2025-49600**: Token exhaustion attacks

## Trusted Registry

Servers from these sources receive trust bonuses:

- `@anthropic-ai/*` - Official Anthropic MCP servers
- `@modelcontextprotocol/*` - Official MCP SDK servers

## Development

```bash
# Clone and install
git clone https://github.com/yksanjo/mcpguard.git
cd mcpguard
npm install

# Development mode
npm run dev scan ./tests/fixtures/vulnerable-config.json

# Build
npm run build

# Test
npm test
```

## License

MIT

## Contributing

Contributions welcome! Please read our contributing guidelines before submitting PRs.

---

**Built with security in mind for the AI agent era.**
