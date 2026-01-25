import { readFileSync, existsSync } from 'fs';
import { z } from 'zod';
import type { MCPConfig, MCPServerConfig } from '../types/index.js';

// Zod schema for validation
const AuthConfigSchema = z.object({
  type: z.enum(['bearer', 'api_key', 'basic']),
  token: z.string().optional(),
  env_var: z.string().optional(),
}).optional();

const MCPServerConfigSchema = z.object({
  command: z.string().optional(),
  args: z.array(z.string()).optional(),
  url: z.string().optional(),
  type: z.enum(['stdio', 'http', 'sse']).optional(),
  env: z.record(z.string()).optional(),
  headers: z.record(z.string()).optional(),
  auth: AuthConfigSchema,
});

const MCPConfigSchema = z.object({
  mcpServers: z.record(MCPServerConfigSchema),
});

export class ConfigParseError extends Error {
  constructor(message: string, public details?: unknown) {
    super(message);
    this.name = 'ConfigParseError';
  }
}

export function parseConfigFile(configPath: string): MCPConfig {
  if (!existsSync(configPath)) {
    throw new ConfigParseError(`Config file not found: ${configPath}`);
  }

  let rawContent: string;
  try {
    rawContent = readFileSync(configPath, 'utf-8');
  } catch (error) {
    throw new ConfigParseError(`Failed to read config file: ${configPath}`, error);
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(rawContent);
  } catch (error) {
    throw new ConfigParseError(`Invalid JSON in config file: ${configPath}`, error);
  }

  // Validate against schema
  const result = MCPConfigSchema.safeParse(parsed);
  if (!result.success) {
    throw new ConfigParseError(
      `Invalid MCP config structure: ${result.error.message}`,
      result.error.issues
    );
  }

  return result.data;
}

export function getServerCount(config: MCPConfig): number {
  return Object.keys(config.mcpServers).length;
}

export function getServerNames(config: MCPConfig): string[] {
  return Object.keys(config.mcpServers);
}

export function getServerConfig(config: MCPConfig, serverName: string): MCPServerConfig | undefined {
  return config.mcpServers[serverName];
}

// Serialize config back to a flat representation for rule matching
export function flattenServerConfig(name: string, config: MCPServerConfig): Record<string, unknown> {
  // Join arrays into strings for pattern matching
  const argsString = config.args?.join(' ') ?? '';
  const envString = config.env ? JSON.stringify(config.env) : '';

  return {
    'server.name': name,
    'server.command': config.command,
    'server.args': argsString, // String for regex matching
    'server.args_array': config.args, // Keep array for other checks
    'server.url': config.url,
    'server.type': config.type,
    'server.env': envString, // String for regex matching
    'server.env_object': config.env, // Keep object for other checks
    'server.headers': config.headers,
    'server.auth': config.auth,
    'env.API_KEY': config.env?.API_KEY,
    'env.OPENAI_API_KEY': config.env?.OPENAI_API_KEY,
    'env.ANTHROPIC_API_KEY': config.env?.ANTHROPIC_API_KEY,
    'headers.Authorization': config.headers?.Authorization,
    // Combined string for broad pattern matching
    'server.all_config': `${config.command ?? ''} ${argsString} ${config.url ?? ''} ${envString}`,
  };
}
