import { existsSync } from 'fs';
import { join } from 'path';
import { homedir, platform } from 'os';
import chalk from 'chalk';
import type { AuditOptions, ScanReport } from '../types/index.js';
import { parseConfigFile, ConfigParseError } from '../utils/config-parser.js';
import { Scanner } from '../core/scanner.js';
import {
  printBanner,
  printScanStart,
  printServerResult,
  printSummary,
  printJsonReport,
  printError,
  printInfo,
  printWarning,
} from '../utils/output.js';

interface AuditCommandOptions {
  watch?: boolean;
  configDir?: string;
  output: string;
  interval?: string;
}

// Default config locations by platform
function getDefaultConfigPaths(): string[] {
  const home = homedir();
  const os = platform();

  const paths: string[] = [];

  // Claude Desktop config locations
  if (os === 'darwin') {
    paths.push(join(home, 'Library', 'Application Support', 'Claude', 'claude_desktop_config.json'));
  } else if (os === 'win32') {
    paths.push(join(home, 'AppData', 'Roaming', 'Claude', 'claude_desktop_config.json'));
  } else {
    // Linux
    paths.push(join(home, '.config', 'claude', 'claude_desktop_config.json'));
  }

  // Also check common locations
  paths.push(join(home, '.claude', 'claude_desktop_config.json'));
  paths.push(join(process.cwd(), 'claude_desktop_config.json'));
  paths.push(join(process.cwd(), '.mcp.json'));
  paths.push(join(process.cwd(), 'mcp.json'));

  return paths;
}

export async function auditCommand(options: AuditCommandOptions): Promise<void> {
  const outputFormat = (options.output as 'console' | 'json' | 'sarif') || 'console';

  // Find config files
  let configPaths: string[] = [];

  if (options.configDir) {
    // Scan custom directory
    const customPath = join(options.configDir, 'claude_desktop_config.json');
    if (existsSync(customPath)) {
      configPaths.push(customPath);
    } else {
      printError(`Config file not found in: ${options.configDir}`);
      process.exit(1);
    }
  } else {
    // Auto-detect config locations
    const defaultPaths = getDefaultConfigPaths();
    configPaths = defaultPaths.filter(p => existsSync(p));
  }

  if (configPaths.length === 0) {
    if (outputFormat === 'json') {
      console.log(JSON.stringify({ error: 'No MCP config files found', searched: getDefaultConfigPaths() }, null, 2));
    } else {
      printWarning('No MCP config files found in default locations:');
      for (const path of getDefaultConfigPaths()) {
        console.log(chalk.gray(`  - ${path}`));
      }
    }
    process.exit(0);
  }

  // Run audit
  if (options.watch) {
    await runWatchMode(configPaths, outputFormat, parseInt(options.interval || '5', 10));
  } else {
    await runSingleAudit(configPaths, outputFormat);
  }
}

async function runSingleAudit(
  configPaths: string[],
  outputFormat: 'console' | 'json' | 'sarif'
): Promise<void> {
  const scanner = new Scanner();
  const allReports: ScanReport[] = [];
  let hasHighRisk = false;

  if (outputFormat !== 'json') {
    printBanner();
    printInfo(`Found ${configPaths.length} config file(s) to audit`);
    console.log();
  }

  for (const configPath of configPaths) {
    try {
      const config = parseConfigFile(configPath);
      const report = scanner.scan(config, configPath);
      allReports.push(report);

      if (report.summary.high_risk > 0) {
        hasHighRisk = true;
      }

      if (outputFormat !== 'json') {
        console.log(chalk.cyan.bold(`  Config: ${configPath}`));
        printScanStart(report.summary.total_servers);

        for (const server of report.servers) {
          printServerResult(server);
        }

        printSummary(report.summary);
        console.log();
      }
    } catch (error) {
      if (error instanceof ConfigParseError) {
        if (outputFormat === 'json') {
          allReports.push({
            scan_id: 'error',
            config_path: configPath,
            scan_timestamp: new Date().toISOString(),
            mcpguard_version: '1.0.0',
            servers: [],
            summary: {
              total_servers: 0,
              high_risk: 0,
              medium_risk: 0,
              low_risk: 0,
              total_findings: 0,
              findings_by_severity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
              overall_risk_level: 'LOW',
            },
          });
        } else {
          printError(`Failed to parse ${configPath}: ${error.message}`);
        }
      } else {
        throw error;
      }
    }
  }

  if (outputFormat === 'json') {
    console.log(JSON.stringify({ audited_configs: allReports }, null, 2));
  }

  process.exit(hasHighRisk ? 1 : 0);
}

async function runWatchMode(
  configPaths: string[],
  outputFormat: 'console' | 'json' | 'sarif',
  intervalSeconds: number
): Promise<void> {
  if (outputFormat !== 'json') {
    printBanner();
    printInfo(`Watch mode enabled. Polling every ${intervalSeconds} seconds.`);
    printInfo('Press Ctrl+C to stop.');
    console.log();
  }

  const scanner = new Scanner();

  const runCheck = async () => {
    const timestamp = new Date().toISOString();

    if (outputFormat !== 'json') {
      console.log(chalk.gray(`[${timestamp}] Running audit...`));
    }

    for (const configPath of configPaths) {
      if (!existsSync(configPath)) {
        continue;
      }

      try {
        const config = parseConfigFile(configPath);
        const report = scanner.scan(config, configPath);

        if (report.summary.high_risk > 0 || report.summary.medium_risk > 0) {
          if (outputFormat === 'json') {
            console.log(JSON.stringify({ timestamp, configPath, report }, null, 2));
          } else {
            console.log(chalk.yellow(`[${timestamp}] Issues detected in ${configPath}:`));
            for (const server of report.servers) {
              if (server.risk_level !== 'LOW') {
                printServerResult(server);
              }
            }
          }
        } else if (outputFormat !== 'json') {
          console.log(chalk.green(`[${timestamp}] ${configPath}: OK`));
        }
      } catch (error) {
        if (error instanceof ConfigParseError) {
          if (outputFormat !== 'json') {
            console.log(chalk.red(`[${timestamp}] Error parsing ${configPath}: ${error.message}`));
          }
        }
      }
    }
  };

  // Initial check
  await runCheck();

  // Set up polling
  setInterval(runCheck, intervalSeconds * 1000);

  // Keep process running
  await new Promise(() => {});
}
