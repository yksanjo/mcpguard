import { randomUUID } from 'crypto';
import type {
  MCPConfig,
  MCPServerConfig,
  ServerScanResult,
  ScanReport,
  ScanSummary,
  Finding,
  Severity,
  ScanOptions,
} from '../types/index.js';
import { RuleEngine, getDefaultRules } from './rule-engine.js';
import { RiskScorer, shouldFailOnRisk } from './scorer.js';

const VERSION = '1.0.0';

export class Scanner {
  private ruleEngine: RuleEngine;
  private scorer: RiskScorer;

  constructor() {
    this.ruleEngine = new RuleEngine(getDefaultRules());
    this.scorer = new RiskScorer();
  }

  scan(config: MCPConfig, configPath: string, options?: ScanOptions): ScanReport {
    const scanId = randomUUID();
    const scanTimestamp = new Date().toISOString();

    const servers: ServerScanResult[] = [];

    for (const [serverName, serverConfig] of Object.entries(config.mcpServers)) {
      const result = this.scanServer(serverName, serverConfig);

      // Filter by severity if specified
      if (options?.severity) {
        result.findings = this.filterBySeverity(result.findings, options.severity);
      }

      servers.push(result);
    }

    const summary = this.computeSummary(servers);

    return {
      scan_id: scanId,
      config_path: configPath,
      scan_timestamp: scanTimestamp,
      mcpguard_version: VERSION,
      servers,
      summary,
    };
  }

  scanServer(serverName: string, config: MCPServerConfig): ServerScanResult {
    // Evaluate rules
    const findings = this.ruleEngine.evaluate(serverName, config);

    // Compute risk score
    const riskScore = this.scorer.computeRiskScore(serverName, config, findings);
    const riskLevel = this.scorer.getRiskLevel(riskScore.total);

    return {
      server_name: serverName,
      config,
      findings,
      risk_score: riskScore,
      risk_level: riskLevel,
      scan_timestamp: new Date().toISOString(),
    };
  }

  private computeSummary(servers: ServerScanResult[]): ScanSummary {
    const high_risk = servers.filter(s => s.risk_level === 'HIGH').length;
    const medium_risk = servers.filter(s => s.risk_level === 'MEDIUM').length;
    const low_risk = servers.filter(s => s.risk_level === 'LOW').length;

    const allFindings = servers.flatMap(s => s.findings);
    const findings_by_severity: Record<Severity, number> = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0,
    };

    for (const finding of allFindings) {
      findings_by_severity[finding.severity]++;
    }

    // Determine overall risk level
    let overall_risk_level: 'HIGH' | 'MEDIUM' | 'LOW' = 'LOW';
    if (high_risk > 0) {
      overall_risk_level = 'HIGH';
    } else if (medium_risk > 0) {
      overall_risk_level = 'MEDIUM';
    }

    return {
      total_servers: servers.length,
      high_risk,
      medium_risk,
      low_risk,
      total_findings: allFindings.length,
      findings_by_severity,
      overall_risk_level,
    };
  }

  private filterBySeverity(findings: Finding[], minSeverity: Severity): Finding[] {
    const severityOrder: Severity[] = ['info', 'low', 'medium', 'high', 'critical'];
    const minIndex = severityOrder.indexOf(minSeverity);

    return findings.filter(f => {
      const findingIndex = severityOrder.indexOf(f.severity);
      return findingIndex >= minIndex;
    });
  }

  // Check if scan should trigger failure exit code
  shouldFail(report: ScanReport, failOnSeverity?: Severity): boolean {
    const allFindings = report.servers.flatMap(s => s.findings);
    return shouldFailOnRisk(allFindings, failOnSeverity);
  }
}
