import type {
  Finding,
  RiskScore,
  RiskLevel,
  Severity,
  MCPServerConfig,
} from '../types/index.js';
import { isTrustedServer, getTrustLevel } from '../data/trusted-registry.js';
import { findCVEByPattern } from '../data/cve-db.js';

// Scoring weights (inspired by TopoGuard's composite scoring pattern)
const WEIGHTS = {
  vulnerability: 0.35, // CVE matches have highest weight
  configuration: 0.30, // Config issues (auth, exposure)
  behavioral: 0.25, // Suspicious patterns
  trust: 0.10, // Trusted registry (reduces risk)
};

// Severity multipliers (inspired by TinyGuardian)
const SEVERITY_WEIGHTS: Record<Severity, number> = {
  critical: 1.0,
  high: 0.8,
  medium: 0.5,
  low: 0.2,
  info: 0.05,
};

// Risk thresholds
const RISK_THRESHOLDS = {
  HIGH: 0.7,
  MEDIUM: 0.4,
};

export class RiskScorer {
  computeRiskScore(
    serverName: string,
    config: MCPServerConfig,
    findings: Finding[]
  ): RiskScore {
    const vulnerabilityScore = this.computeVulnerabilityScore(findings, config);
    const configurationScore = this.computeConfigurationScore(findings);
    const behavioralScore = this.computeBehavioralScore(findings);
    const trustScore = this.computeTrustScore(serverName, config);

    // Weighted combination (TopoGuard pattern)
    let totalScore =
      WEIGHTS.vulnerability * vulnerabilityScore +
      WEIGHTS.configuration * configurationScore +
      WEIGHTS.behavioral * behavioralScore -
      WEIGHTS.trust * trustScore; // Trust reduces risk

    // Clamp to [0, 1]
    totalScore = Math.max(0, Math.min(1, totalScore));

    // Compute confidence based on number and quality of signals
    const confidence = this.computeConfidence(findings, trustScore);

    return {
      total: totalScore,
      confidence,
      components: {
        vulnerability: vulnerabilityScore,
        configuration: configurationScore,
        behavioral: behavioralScore,
        trust: trustScore,
      },
    };
  }

  getRiskLevel(score: number): RiskLevel {
    if (score >= RISK_THRESHOLDS.HIGH) return 'HIGH';
    if (score >= RISK_THRESHOLDS.MEDIUM) return 'MEDIUM';
    return 'LOW';
  }

  private computeVulnerabilityScore(
    findings: Finding[],
    config: MCPServerConfig
  ): number {
    // Check for CVE matches in config
    const configString = JSON.stringify(config);
    const cveMatches = findCVEByPattern(configString);

    // Also check findings for CVE references
    const cveFindings = findings.filter(f => f.cve_ref);

    if (cveMatches.length === 0 && cveFindings.length === 0) {
      return 0;
    }

    // Use the max severity from CVE matches
    let maxSeverity = 0;
    for (const cve of cveMatches) {
      maxSeverity = Math.max(maxSeverity, SEVERITY_WEIGHTS[cve.severity]);
    }

    for (const finding of cveFindings) {
      maxSeverity = Math.max(maxSeverity, SEVERITY_WEIGHTS[finding.severity]);
    }

    // Add count penalty
    const totalCVEs = cveMatches.length + cveFindings.length;
    const countPenalty = Math.min(0.2, totalCVEs * 0.05);

    return Math.min(1.0, maxSeverity + countPenalty);
  }

  private computeConfigurationScore(findings: Finding[]): number {
    // Filter for configuration-related findings
    const configCategories = ['authentication', 'network'];
    const configFindings = findings.filter(
      f =>
        configCategories.includes(this.getCategoryForThreat(f.threat_type))
    );

    if (configFindings.length === 0) {
      return 0;
    }

    // Use max severity + count penalty
    const maxSeverity = Math.max(
      ...configFindings.map(f => SEVERITY_WEIGHTS[f.severity])
    );
    const countPenalty = Math.min(0.2, configFindings.length * 0.05);

    return Math.min(1.0, maxSeverity + countPenalty);
  }

  private computeBehavioralScore(findings: Finding[]): number {
    // Filter for behavioral/pattern-related findings
    const behavioralCategories = ['injection', 'poisoning', 'metadata'];
    const behavioralFindings = findings.filter(
      f =>
        behavioralCategories.includes(this.getCategoryForThreat(f.threat_type))
    );

    if (behavioralFindings.length === 0) {
      return 0;
    }

    const maxSeverity = Math.max(
      ...behavioralFindings.map(f => SEVERITY_WEIGHTS[f.severity])
    );
    const countPenalty = Math.min(0.2, behavioralFindings.length * 0.05);

    return Math.min(1.0, maxSeverity + countPenalty);
  }

  private computeTrustScore(serverName: string, config: MCPServerConfig): number {
    // Check if server is in trusted registry
    if (isTrustedServer(serverName)) {
      const trustLevel = getTrustLevel(serverName);
      return trustLevel === 'high' ? 1.0 : 0.5;
    }

    // Check if command is an official package
    if (config.command) {
      const cmd = config.command.toLowerCase();
      if (cmd.includes('@anthropic-ai/') || cmd.includes('anthropic')) {
        return 0.8;
      }
    }

    // Check args for official packages
    if (config.args) {
      const argsStr = config.args.join(' ').toLowerCase();
      if (argsStr.includes('@anthropic-ai/') || argsStr.includes('@modelcontextprotocol/')) {
        return 0.7;
      }
    }

    return 0;
  }

  private computeConfidence(findings: Finding[], trustScore: number): number {
    // Base confidence from number of signals
    let confidence = 0.5;

    // More findings = higher confidence in assessment
    if (findings.length > 0) {
      confidence += Math.min(0.3, findings.length * 0.1);
    }

    // High trust score increases confidence
    if (trustScore > 0) {
      confidence += 0.1;
    }

    // CVE matches increase confidence significantly
    const hasCVE = findings.some(f => f.cve_ref);
    if (hasCVE) {
      confidence += 0.1;
    }

    return Math.min(1.0, confidence);
  }

  private getCategoryForThreat(threatType: string): string {
    const mapping: Record<string, string> = {
      prompt_injection: 'injection',
      tool_poisoning: 'poisoning',
      metadata_issue: 'metadata',
      localhost_exposure: 'network',
      missing_auth: 'authentication',
      known_cve: 'cve',
      rate_limit_missing: 'rate_limiting',
      suspicious_command: 'poisoning',
      unknown: 'unknown',
    };
    return mapping[threatType] || 'unknown';
  }
}

// Helper function to determine if scan should fail based on risk level
export function shouldFailOnRisk(
  findings: Finding[],
  failOnSeverity?: Severity
): boolean {
  if (!failOnSeverity) {
    return false;
  }

  const severityOrder: Severity[] = ['info', 'low', 'medium', 'high', 'critical'];
  const failIndex = severityOrder.indexOf(failOnSeverity);

  return findings.some(f => {
    const findingIndex = severityOrder.indexOf(f.severity);
    return findingIndex >= failIndex;
  });
}
