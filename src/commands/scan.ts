import { resolve } from 'path';
import type { ScanOptions, Severity } from '../types/index.js';
import { parseConfigFile, ConfigParseError } from '../utils/config-parser.js';
import { Scanner } from '../core/scanner.js';
import {
  printBanner,
  printScanStart,
  printServerResult,
  printSummary,
  printJsonReport,
  printQuietSummary,
  printError,
} from '../utils/output.js';

interface ScanCommandOptions {
  output: string;
  rules?: string;
  severity?: string;
  failOn?: string;
  color?: boolean;
  verbose?: boolean;
  quiet?: boolean;
}

export async function scanCommand(
  configPath: string,
  options: ScanCommandOptions
): Promise<void> {
  const resolvedPath = resolve(configPath);

  // Parse config
  let config;
  try {
    config = parseConfigFile(resolvedPath);
  } catch (error) {
    if (error instanceof ConfigParseError) {
      printError(error.message);
      process.exit(1);
    }
    throw error;
  }

  // Build scan options
  const scanOptions: ScanOptions = {
    output: (options.output as 'console' | 'json' | 'sarif') || 'console',
    severity: options.severity as Severity | undefined,
    failOn: options.failOn as Severity | undefined,
    verbose: options.verbose,
    quiet: options.quiet,
  };

  // Run scan
  const scanner = new Scanner();
  const report = scanner.scan(config, resolvedPath, scanOptions);

  // Output results based on format
  if (scanOptions.output === 'json') {
    printJsonReport(report);
  } else if (scanOptions.quiet) {
    printQuietSummary(report);
  } else {
    printBanner();
    printScanStart(report.summary.total_servers);

    for (const server of report.servers) {
      printServerResult(server);
    }

    printSummary(report.summary);
  }

  // Determine exit code
  if (scanOptions.failOn && scanner.shouldFail(report, scanOptions.failOn)) {
    process.exit(1);
  }

  // Also exit with 1 if there are any high-risk servers by default
  if (report.summary.high_risk > 0) {
    process.exit(1);
  }

  process.exit(0);
}
