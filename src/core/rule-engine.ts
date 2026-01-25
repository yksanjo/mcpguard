import type {
  SecurityRule,
  PatternMatcher,
  Finding,
  MCPServerConfig,
  ThreatType,
  Severity,
  Condition,
} from '../types/index.js';
import { flattenServerConfig } from '../utils/config-parser.js';

export class RuleEngine {
  private rules: SecurityRule[] = [];

  constructor(rules: SecurityRule[] = []) {
    this.rules = rules.filter(r => r.enabled);
  }

  addRules(rules: SecurityRule[]): void {
    this.rules.push(...rules.filter(r => r.enabled));
  }

  evaluate(serverName: string, config: MCPServerConfig): Finding[] {
    const findings: Finding[] = [];
    const flatConfig = flattenServerConfig(serverName, config);

    for (const rule of this.rules) {
      const matched = this.evaluateRule(rule, flatConfig, config);
      if (matched.isMatch) {
        findings.push({
          server_name: serverName,
          rule_id: rule.id,
          severity: rule.severity,
          threat_type: rule.threat_type,
          title: rule.name,
          description: rule.description,
          evidence: matched.evidence,
          remediation: rule.remediation,
          cve_ref: rule.cve_ref,
        });
      }
    }

    return findings;
  }

  private evaluateRule(
    rule: SecurityRule,
    flatConfig: Record<string, unknown>,
    rawConfig: MCPServerConfig
  ): { isMatch: boolean; evidence?: string } {
    for (const pattern of rule.patterns) {
      const result = this.evaluatePattern(pattern, flatConfig, rawConfig);
      if (result.isMatch) {
        return result;
      }
    }
    return { isMatch: false };
  }

  private evaluatePattern(
    pattern: PatternMatcher,
    flatConfig: Record<string, unknown>,
    rawConfig: MCPServerConfig
  ): { isMatch: boolean; evidence?: string } {
    switch (pattern.type) {
      case 'regex':
        return this.evaluateRegex(pattern, flatConfig);
      case 'keyword':
        return this.evaluateKeywords(pattern, flatConfig);
      case 'absence':
        return this.evaluateAbsence(pattern, flatConfig);
      case 'config':
        return this.evaluateConfigConditions(pattern, flatConfig, rawConfig);
      case 'composite':
        return this.evaluateComposite(pattern, flatConfig, rawConfig);
      default:
        return { isMatch: false };
    }
  }

  private evaluateRegex(
    pattern: PatternMatcher,
    flatConfig: Record<string, unknown>
  ): { isMatch: boolean; evidence?: string } {
    if (!pattern.pattern || !pattern.target) {
      return { isMatch: false };
    }

    const targetValue = this.getTargetValue(pattern.target, flatConfig);
    if (typeof targetValue !== 'string') {
      return { isMatch: false };
    }

    const flags = pattern.flags || 'i';
    const regex = new RegExp(pattern.pattern, flags);
    const match = regex.exec(targetValue);

    if (match) {
      return { isMatch: true, evidence: match[0] };
    }
    return { isMatch: false };
  }

  private evaluateKeywords(
    pattern: PatternMatcher,
    flatConfig: Record<string, unknown>
  ): { isMatch: boolean; evidence?: string } {
    if (!pattern.keywords || !pattern.target) {
      return { isMatch: false };
    }

    const targetValue = this.getTargetValue(pattern.target, flatConfig);
    if (typeof targetValue !== 'string') {
      return { isMatch: false };
    }

    const lowerValue = targetValue.toLowerCase();
    for (const keyword of pattern.keywords) {
      if (lowerValue.includes(keyword.toLowerCase())) {
        return { isMatch: true, evidence: keyword };
      }
    }
    return { isMatch: false };
  }

  private evaluateAbsence(
    pattern: PatternMatcher,
    flatConfig: Record<string, unknown>
  ): { isMatch: boolean; evidence?: string } {
    if (!pattern.conditions) {
      return { isMatch: false };
    }

    for (const condition of pattern.conditions) {
      const value = this.getTargetValue(condition.field, flatConfig);
      if (value !== undefined && value !== null && value !== '') {
        return { isMatch: false };
      }
    }

    return { isMatch: true, evidence: 'Missing required fields' };
  }

  private evaluateConfigConditions(
    pattern: PatternMatcher,
    flatConfig: Record<string, unknown>,
    rawConfig: MCPServerConfig
  ): { isMatch: boolean; evidence?: string } {
    if (!pattern.conditions) {
      return { isMatch: false };
    }

    let allMatch = true;
    const evidence: string[] = [];

    for (const condition of pattern.conditions) {
      const result = this.evaluateCondition(condition, flatConfig, rawConfig);
      if (!result.isMatch) {
        allMatch = false;
        break;
      }
      if (result.evidence) {
        evidence.push(result.evidence);
      }
    }

    return { isMatch: allMatch, evidence: evidence.join(', ') };
  }

  private evaluateComposite(
    pattern: PatternMatcher,
    flatConfig: Record<string, unknown>,
    rawConfig: MCPServerConfig
  ): { isMatch: boolean; evidence?: string } {
    if (!pattern.conditions) {
      return { isMatch: false };
    }

    const evidence: string[] = [];
    let matchCount = 0;

    for (const condition of pattern.conditions) {
      const result = this.evaluateCondition(condition, flatConfig, rawConfig);
      if (result.isMatch) {
        matchCount++;
        if (result.evidence) {
          evidence.push(result.evidence);
        }
      }
    }

    // Composite patterns require all conditions to match
    const allMatch = matchCount === pattern.conditions.length;
    return { isMatch: allMatch, evidence: evidence.join(', ') };
  }

  private evaluateCondition(
    condition: Condition,
    flatConfig: Record<string, unknown>,
    rawConfig: MCPServerConfig
  ): { isMatch: boolean; evidence?: string } {
    const value = this.getTargetValue(condition.field, flatConfig);

    switch (condition.operator) {
      case 'matches': {
        if (typeof value !== 'string' || typeof condition.value !== 'string') {
          return { isMatch: false };
        }
        const regex = new RegExp(condition.value, 'i');
        const match = regex.test(value);
        return { isMatch: match, evidence: match ? value : undefined };
      }

      case 'contains': {
        if (typeof value !== 'string' || typeof condition.value !== 'string') {
          return { isMatch: false };
        }
        const contains = value.toLowerCase().includes(condition.value.toLowerCase());
        return { isMatch: contains, evidence: contains ? condition.value : undefined };
      }

      case 'equals': {
        const isEqual = value === condition.value;
        return { isMatch: isEqual, evidence: isEqual ? String(value) : undefined };
      }

      case 'absent': {
        const isAbsent = value === undefined || value === null || value === '';
        return { isMatch: isAbsent, evidence: isAbsent ? `${condition.field} is missing` : undefined };
      }

      case 'contains_key': {
        if (typeof value !== 'object' || value === null || typeof condition.value !== 'string') {
          return { isMatch: false };
        }
        const hasKey = condition.value in (value as Record<string, unknown>);
        return { isMatch: hasKey, evidence: hasKey ? `has key: ${condition.value}` : undefined };
      }

      default:
        return { isMatch: false };
    }
  }

  private getTargetValue(target: string, flatConfig: Record<string, unknown>): unknown {
    // Direct lookup first
    if (target in flatConfig) {
      return flatConfig[target];
    }

    // Handle nested paths (e.g., "server.env.API_KEY")
    const parts = target.split('.');
    let current: unknown = flatConfig;

    for (const part of parts) {
      if (current === null || current === undefined) {
        return undefined;
      }
      if (typeof current === 'object') {
        current = (current as Record<string, unknown>)[part];
      } else {
        return undefined;
      }
    }

    return current;
  }
}

// Create default rules
export function getDefaultRules(): SecurityRule[] {
  return [
    // MCPG-001: Prompt Injection Detection
    {
      id: 'MCPG-001',
      name: 'Prompt Injection Vector Detected',
      category: 'injection',
      severity: 'critical',
      description: 'Server configuration or tool definitions contain patterns commonly used for prompt injection attacks.',
      threat_type: 'prompt_injection' as ThreatType,
      patterns: [
        {
          type: 'regex',
          target: 'server.args',
          pattern: '(ignore\\s+(previous|all|above)\\s+(instructions?|prompts?)|disregard\\s+|forget\\s+(previous|all))',
          flags: 'i',
        },
        {
          type: 'keyword',
          target: 'server.args',
          keywords: ['<|im_start|>', '<|im_end|>', '[INST]', '[/INST]', '### System', '### Human', '### Assistant'],
        },
        {
          type: 'regex',
          target: 'server.all_config',
          pattern: '(ignore\\s+(previous|all|above)\\s+(instructions?|prompts?)|\\bact\\s+as\\b|\\bpretend\\s+to\\s+be\\b)',
          flags: 'i',
        },
      ],
      cve_ref: 'CVE-2025-49596',
      remediation: 'Review and sanitize all tool descriptions and arguments for injection markers. Implement input validation.',
      enabled: true,
    },

    // MCPG-002: Direct Shell Access
    {
      id: 'MCPG-002',
      name: 'Direct Shell Access',
      category: 'poisoning',
      severity: 'high',
      description: 'Server uses direct shell commands (bash, sh, cmd) which can enable arbitrary code execution.',
      threat_type: 'tool_poisoning' as ThreatType,
      patterns: [
        {
          type: 'regex',
          target: 'server.command',
          pattern: '^(sh|bash|zsh|fish|cmd|cmd\\.exe|powershell|pwsh)$',
          flags: 'i',
        },
      ],
      remediation: 'Use dedicated MCP server packages instead of direct shell execution. If shell is required, restrict the commands that can be executed.',
      enabled: true,
    },

    // MCPG-003: Localhost Exposure
    {
      id: 'MCPG-003',
      name: 'Localhost Exposure Without Authentication',
      category: 'network',
      severity: 'medium',
      description: 'Server exposes localhost endpoints without authentication, potentially allowing unauthorized access from other processes.',
      threat_type: 'localhost_exposure' as ThreatType,
      patterns: [
        {
          type: 'config',
          conditions: [
            { field: 'server.url', operator: 'matches', value: '(localhost|127\\.0\\.0\\.1|0\\.0\\.0\\.0)' },
            { field: 'server.auth', operator: 'absent', value: true },
          ],
        },
      ],
      remediation: 'Add authentication to localhost servers or restrict access to trusted processes only.',
      enabled: true,
    },

    // MCPG-004: No Credentials for HTTP Server
    {
      id: 'MCPG-004',
      name: 'HTTP Server Without Credentials',
      category: 'authentication',
      severity: 'high',
      description: 'HTTP-based MCP server lacks authentication, which may expose sensitive operations.',
      threat_type: 'missing_auth' as ThreatType,
      patterns: [
        {
          type: 'config',
          conditions: [
            { field: 'server.url', operator: 'matches', value: '^https?://' },
            { field: 'server.auth', operator: 'absent', value: true },
            { field: 'headers.Authorization', operator: 'absent', value: true },
          ],
        },
      ],
      remediation: 'Configure authentication credentials using headers or auth configuration for HTTP servers.',
      enabled: true,
    },

    // MCPG-005: Metadata/Script Injection
    {
      id: 'MCPG-005',
      name: 'Potentially Unsafe Metadata',
      category: 'metadata',
      severity: 'medium',
      description: 'Server arguments contain HTML, scripts, or data URIs that could be exploited.',
      threat_type: 'metadata_issue' as ThreatType,
      patterns: [
        {
          type: 'regex',
          target: 'server.args',
          pattern: '(<script|javascript:|data:text/html|on\\w+\\s*=\\s*["\'])',
          flags: 'i',
        },
      ],
      remediation: 'Sanitize all metadata and remove any HTML or script content from tool configurations.',
      enabled: true,
    },

    // MCPG-006: Hardcoded Credentials
    {
      id: 'MCPG-006',
      name: 'Hardcoded Credentials Detected',
      category: 'authentication',
      severity: 'critical',
      description: 'Configuration contains hardcoded credentials instead of environment variable references.',
      threat_type: 'metadata_issue' as ThreatType,
      patterns: [
        {
          type: 'regex',
          target: 'server.env',
          pattern: '"(password|secret|private_key)"\\s*:\\s*"[^$\\{][^"]+"',
          flags: 'i',
        },
        {
          type: 'regex',
          target: 'server.env',
          pattern: '(sk-[a-zA-Z0-9]{20,}|ghp_[a-zA-Z0-9]{36}|xox[baprs]-[a-zA-Z0-9-]+)',
          flags: 'i',
        },
      ],
      remediation: 'Use environment variable references (e.g., "${API_KEY}") instead of hardcoded credentials.',
      enabled: true,
    },

    // MCPG-007: System Directory Access
    {
      id: 'MCPG-007',
      name: 'System Directory Access',
      category: 'poisoning',
      severity: 'medium',
      description: 'Server is granted access to sensitive system directories.',
      threat_type: 'tool_poisoning' as ThreatType,
      patterns: [
        {
          type: 'regex',
          target: 'server.args',
          pattern: '(\\s|^)(/etc|/var/log|/usr/bin|/System|C:\\\\Windows|C:\\\\Program\\s*Files)($|\\s|/)',
          flags: 'i',
        },
      ],
      remediation: 'Restrict file system access to user directories needed for the MCP server functionality.',
      enabled: true,
    },

    // MCPG-008: Dangerous Commands in Args
    {
      id: 'MCPG-008',
      name: 'Dangerous Commands in Arguments',
      category: 'poisoning',
      severity: 'high',
      description: 'Server arguments contain dangerous shell commands or operators.',
      threat_type: 'suspicious_command' as ThreatType,
      patterns: [
        {
          type: 'regex',
          target: 'server.args',
          pattern: '(;|\\||&&|`|\\$\\(|\\bsudo\\b|\\brm\\s+-rf|\\bchmod\\s+777)',
          flags: 'i',
        },
      ],
      remediation: 'Remove shell operators and dangerous commands from server arguments.',
      enabled: true,
    },
  ];
}
