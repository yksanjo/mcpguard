import chalk from 'chalk';
import type { CheckOptions, CVEEntry } from '../types/index.js';
import {
  findCVEsByPackage,
  getAllCVEs,
} from '../data/cve-db.js';
import {
  isTrustedServer,
  getTrustedServerInfo,
} from '../data/trusted-registry.js';

interface CheckCommandOptions {
  output: string;
  cache?: boolean;
}

export async function checkCommand(
  serverIdentifier: string,
  options: CheckCommandOptions
): Promise<void> {
  const outputFormat = (options.output as 'console' | 'json') || 'console';

  // Check against trusted registry first
  const isTrusted = isTrustedServer(serverIdentifier);
  const trustedInfo = getTrustedServerInfo(serverIdentifier);

  // Check against CVE database
  // For trusted servers, only show specific CVEs (not wildcard matches)
  let cves = findCVEsByPackage(serverIdentifier);
  if (isTrusted) {
    // Filter out CVEs that only match via wildcard (*)
    cves = cves.filter(cve =>
      cve.affected_packages.some(pkg =>
        pkg !== '*' && (pkg === serverIdentifier || serverIdentifier.includes(pkg.replace('*', '')))
      )
    );
  }

  // Build result
  const result = {
    server: serverIdentifier,
    trusted: isTrusted,
    trusted_info: trustedInfo || null,
    cves: cves,
    cve_count: cves.length,
    risk_assessment: assessRisk(cves, isTrusted),
  };

  // Output
  if (outputFormat === 'json') {
    console.log(JSON.stringify(result, null, 2));
  } else {
    printCheckResult(result);
  }

  // Exit with appropriate code
  if (result.risk_assessment === 'HIGH') {
    process.exit(1);
  }

  process.exit(0);
}

function assessRisk(
  cves: CVEEntry[],
  isTrusted: boolean
): 'HIGH' | 'MEDIUM' | 'LOW' | 'UNKNOWN' {
  if (cves.some(cve => cve.severity === 'critical')) {
    return 'HIGH';
  }
  if (cves.some(cve => cve.severity === 'high')) {
    return isTrusted ? 'MEDIUM' : 'HIGH';
  }
  if (cves.length > 0) {
    return 'MEDIUM';
  }
  if (isTrusted) {
    return 'LOW';
  }
  return 'UNKNOWN';
}

interface CheckResult {
  server: string;
  trusted: boolean;
  trusted_info: {
    name: string;
    npm_package?: string;
    github_url?: string;
    verified_by: string;
    last_audit: string;
    trust_level: 'high' | 'medium';
  } | null;
  cves: CVEEntry[];
  cve_count: number;
  risk_assessment: 'HIGH' | 'MEDIUM' | 'LOW' | 'UNKNOWN';
}

function printCheckResult(result: CheckResult): void {
  console.log();
  console.log(chalk.cyan.bold('  MCPGuard Server Check'));
  console.log();
  console.log(`  Server: ${chalk.white.bold(result.server)}`);
  console.log();

  // Trust status
  if (result.trusted) {
    console.log(chalk.green(`  Trusted: Yes`));
    if (result.trusted_info) {
      console.log(chalk.gray(`    Verified by: ${result.trusted_info.verified_by}`));
      console.log(chalk.gray(`    Last audit: ${result.trusted_info.last_audit}`));
      console.log(chalk.gray(`    Trust level: ${result.trusted_info.trust_level}`));
    }
  } else {
    console.log(chalk.yellow(`  Trusted: No (not in verified registry)`));
  }
  console.log();

  // CVE status
  if (result.cve_count === 0) {
    console.log(chalk.green(`  Known CVEs: None`));
  } else {
    console.log(chalk.red(`  Known CVEs: ${result.cve_count}`));
    console.log();

    for (const cve of result.cves) {
      const severityColor =
        cve.severity === 'critical' ? chalk.bgRed.white.bold :
        cve.severity === 'high' ? chalk.red.bold :
        chalk.yellow;

      console.log(`    ${severityColor(cve.id)} - ${cve.title}`);
      console.log(chalk.gray(`      ${cve.description.slice(0, 100)}...`));
      console.log();
    }
  }

  // Risk assessment
  const riskColor =
    result.risk_assessment === 'HIGH' ? chalk.red.bold :
    result.risk_assessment === 'MEDIUM' ? chalk.yellow.bold :
    result.risk_assessment === 'LOW' ? chalk.green :
    chalk.gray;

  console.log(`  Risk Assessment: ${riskColor(result.risk_assessment)}`);
  console.log();

  // Recommendation
  if (result.risk_assessment === 'HIGH') {
    console.log(chalk.red.bold('  Recommendation: DO NOT USE this server in production'));
  } else if (result.risk_assessment === 'MEDIUM') {
    console.log(chalk.yellow('  Recommendation: Review CVEs and apply mitigations before use'));
  } else if (result.risk_assessment === 'LOW') {
    console.log(chalk.green('  Recommendation: Safe for production use'));
  } else {
    console.log(chalk.gray('  Recommendation: Verify server legitimacy before use'));
  }
  console.log();
}
