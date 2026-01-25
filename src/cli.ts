#!/usr/bin/env node

import { Command } from 'commander';
import { scanCommand } from './commands/scan.js';
import { checkCommand } from './commands/check.js';
import { auditCommand } from './commands/audit.js';

const VERSION = '1.0.0';

const program = new Command();

program
  .name('mcpguard')
  .description('Enterprise-grade MCP security & governance layer')
  .version(VERSION);

program
  .command('scan')
  .description('Scan MCP server configurations for security vulnerabilities')
  .argument('<config-path>', 'Path to MCP config file (e.g., claude_desktop_config.json)')
  .option('-o, --output <format>', 'Output format: console|json|sarif', 'console')
  .option('-r, --rules <path>', 'Custom rules file path')
  .option('--severity <level>', 'Minimum severity to report: critical|high|medium|low|info', 'low')
  .option('--fail-on <level>', 'Exit with code 1 if findings at or above this level')
  .option('--no-color', 'Disable colored output')
  .option('-v, --verbose', 'Show detailed analysis information')
  .option('-q, --quiet', 'Only show summary')
  .action(scanCommand);

program
  .command('check')
  .description('Check a specific MCP server against the vulnerability database')
  .argument('<server-identifier>', 'Server name, npm package, or URL')
  .option('-o, --output <format>', 'Output format: console|json', 'console')
  .option('--no-cache', 'Skip local CVE cache lookup')
  .action(checkCommand);

program
  .command('audit')
  .description('Audit MCP connections by scanning known config locations')
  .option('-w, --watch', 'Continuously monitor for changes')
  .option('--config-dir <path>', 'Custom config directory')
  .option('-o, --output <format>', 'Output format: console|json|sarif', 'console')
  .option('--interval <seconds>', 'Watch mode polling interval', '5')
  .action(auditCommand);

program.parse();
