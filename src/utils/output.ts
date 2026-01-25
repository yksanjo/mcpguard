import chalk from 'chalk';
import type { ScanReport, ServerScanResult, Finding, Severity, RiskLevel } from '../types/index.js';

const SEVERITY_COLORS: Record<Severity, (text: string) => string> = {
  critical: chalk.bgRed.white.bold,
  high: chalk.red.bold,
  medium: chalk.yellow,
  low: chalk.blue,
  info: chalk.gray,
};

const RISK_ICONS: Record<RiskLevel, string> = {
  HIGH: chalk.red('!!!'),
  MEDIUM: chalk.yellow('!!'),
  LOW: chalk.green('*'),
};

const SEVERITY_ICONS: Record<Severity, string> = {
  critical: chalk.bgRed.white(' CRIT '),
  high: chalk.red('HIGH'),
  medium: chalk.yellow('MED'),
  low: chalk.blue('LOW'),
  info: chalk.gray('INFO'),
};

export function printBanner(): void {
  console.log();
  console.log(chalk.cyan.bold('  MCPGuard Security Scan v1.0.0'));
  console.log(chalk.gray('  "The S in MCP Stands for Security"'));
  console.log();
}

export function printScanStart(serverCount: number): void {
  console.log(chalk.gray(`  Scanning: ${serverCount} MCP server${serverCount !== 1 ? 's' : ''}`));
  console.log();
}

export function printServerResult(result: ServerScanResult): void {
  const icon = RISK_ICONS[result.risk_level];
  const riskColor = result.risk_level === 'HIGH' ? chalk.red.bold :
                    result.risk_level === 'MEDIUM' ? chalk.yellow.bold :
                    chalk.green.bold;

  console.log(`  ${icon} ${riskColor(result.risk_level + ' RISK')}: ${chalk.white.bold(result.server_name)}`);

  if (result.findings.length > 0) {
    for (const finding of result.findings) {
      const severityBadge = SEVERITY_ICONS[finding.severity];
      console.log(`     ${chalk.gray('-')} ${severityBadge} ${finding.title}`);
      if (finding.cve_ref) {
        console.log(`       ${chalk.gray(`(${finding.cve_ref})`)}`);
      }
    }
  } else {
    console.log(`     ${chalk.gray('-')} No issues detected`);
  }

  console.log(`     ${chalk.gray(`Risk Score: ${result.risk_score.total.toFixed(2)}`)}`);
  console.log();
}

export function printSummary(summary: ScanReport['summary']): void {
  console.log(chalk.gray('  ' + '─'.repeat(50)));
  console.log();
  console.log(chalk.bold('  Summary'));

  const parts = [];
  if (summary.high_risk > 0) {
    parts.push(chalk.red.bold(`${summary.high_risk} high`));
  }
  if (summary.medium_risk > 0) {
    parts.push(chalk.yellow.bold(`${summary.medium_risk} medium`));
  }
  if (summary.low_risk > 0) {
    parts.push(chalk.green(`${summary.low_risk} low`));
  }

  console.log(`  Servers: ${parts.join(', ')} risk`);
  console.log(`  Total findings: ${summary.total_findings}`);
  console.log();

  if (summary.overall_risk_level === 'HIGH') {
    console.log(chalk.red.bold('  Action Required: Review high-risk servers before deployment'));
  } else if (summary.overall_risk_level === 'MEDIUM') {
    console.log(chalk.yellow('  Recommendation: Consider reviewing medium-risk servers'));
  } else {
    console.log(chalk.green('  Status: All servers within acceptable risk levels'));
  }
  console.log();
}

export function printFinding(finding: Finding): void {
  const severityBadge = SEVERITY_COLORS[finding.severity](` ${finding.severity.toUpperCase()} `);

  console.log();
  console.log(`${severityBadge} ${chalk.bold(finding.title)}`);
  console.log(chalk.gray(`Rule: ${finding.rule_id}`));
  console.log();
  console.log(finding.description);

  if (finding.evidence) {
    console.log();
    console.log(chalk.gray('Evidence:'));
    console.log(chalk.yellow(`  ${finding.evidence}`));
  }

  console.log();
  console.log(chalk.cyan('Remediation:'));
  console.log(`  ${finding.remediation}`);

  if (finding.cve_ref) {
    console.log();
    console.log(chalk.gray(`Reference: ${finding.cve_ref}`));
  }
}

export function printJsonReport(report: ScanReport): void {
  console.log(JSON.stringify(report, null, 2));
}

export function printQuietSummary(report: ScanReport): void {
  const { summary } = report;
  if (summary.high_risk > 0) {
    console.log(chalk.red(`FAIL: ${summary.high_risk} high-risk server(s) detected`));
  } else if (summary.medium_risk > 0) {
    console.log(chalk.yellow(`WARN: ${summary.medium_risk} medium-risk server(s) detected`));
  } else {
    console.log(chalk.green('PASS: All servers within acceptable risk levels'));
  }
}

export function printError(message: string): void {
  console.error(chalk.red.bold('Error:'), message);
}

export function printWarning(message: string): void {
  console.warn(chalk.yellow('Warning:'), message);
}

export function printInfo(message: string): void {
  console.log(chalk.cyan('Info:'), message);
}
