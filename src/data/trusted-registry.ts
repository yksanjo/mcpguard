// Trusted MCP Server Registry
// Servers in this list receive a trust score bonus during risk assessment

export interface TrustedServer {
  name: string;
  npm_package?: string;
  github_url?: string;
  verified_by: string;
  last_audit: string;
  trust_level: 'high' | 'medium';
}

export const TRUSTED_SERVERS: TrustedServer[] = [
  // Official Anthropic servers
  {
    name: 'mcp-server-fetch',
    npm_package: '@anthropic-ai/mcp-server-fetch',
    github_url: 'https://github.com/anthropics/mcp-servers',
    verified_by: 'Anthropic',
    last_audit: '2025-01-15',
    trust_level: 'high',
  },
  {
    name: 'mcp-server-filesystem',
    npm_package: '@anthropic-ai/mcp-server-filesystem',
    github_url: 'https://github.com/anthropics/mcp-servers',
    verified_by: 'Anthropic',
    last_audit: '2025-01-15',
    trust_level: 'high',
  },
  {
    name: 'mcp-server-github',
    npm_package: '@anthropic-ai/mcp-server-github',
    github_url: 'https://github.com/anthropics/mcp-servers',
    verified_by: 'Anthropic',
    last_audit: '2025-01-15',
    trust_level: 'high',
  },
  {
    name: 'mcp-server-git',
    npm_package: '@anthropic-ai/mcp-server-git',
    github_url: 'https://github.com/anthropics/mcp-servers',
    verified_by: 'Anthropic',
    last_audit: '2025-01-15',
    trust_level: 'high',
  },
  {
    name: 'mcp-server-postgres',
    npm_package: '@anthropic-ai/mcp-server-postgres',
    github_url: 'https://github.com/anthropics/mcp-servers',
    verified_by: 'Anthropic',
    last_audit: '2025-01-15',
    trust_level: 'high',
  },
  {
    name: 'mcp-server-sqlite',
    npm_package: '@anthropic-ai/mcp-server-sqlite',
    github_url: 'https://github.com/anthropics/mcp-servers',
    verified_by: 'Anthropic',
    last_audit: '2025-01-15',
    trust_level: 'high',
  },
  {
    name: 'mcp-server-puppeteer',
    npm_package: '@anthropic-ai/mcp-server-puppeteer',
    github_url: 'https://github.com/anthropics/mcp-servers',
    verified_by: 'Anthropic',
    last_audit: '2025-01-15',
    trust_level: 'high',
  },
  {
    name: 'mcp-server-brave-search',
    npm_package: '@anthropic-ai/mcp-server-brave-search',
    github_url: 'https://github.com/anthropics/mcp-servers',
    verified_by: 'Anthropic',
    last_audit: '2025-01-15',
    trust_level: 'high',
  },
  {
    name: 'mcp-server-google-maps',
    npm_package: '@anthropic-ai/mcp-server-google-maps',
    github_url: 'https://github.com/anthropics/mcp-servers',
    verified_by: 'Anthropic',
    last_audit: '2025-01-15',
    trust_level: 'high',
  },
  {
    name: 'mcp-server-slack',
    npm_package: '@anthropic-ai/mcp-server-slack',
    github_url: 'https://github.com/anthropics/mcp-servers',
    verified_by: 'Anthropic',
    last_audit: '2025-01-15',
    trust_level: 'high',
  },

  // Community-verified servers
  {
    name: 'claude-code',
    npm_package: '@anthropic-ai/claude-code',
    verified_by: 'Anthropic',
    last_audit: '2025-01-20',
    trust_level: 'high',
  },
];

export function isTrustedServer(serverName: string): boolean {
  const normalizedName = serverName.toLowerCase();
  return TRUSTED_SERVERS.some(
    s =>
      s.name.toLowerCase() === normalizedName ||
      s.npm_package?.toLowerCase() === normalizedName
  );
}

export function getTrustLevel(serverName: string): 'high' | 'medium' | 'unknown' {
  const normalizedName = serverName.toLowerCase();
  const server = TRUSTED_SERVERS.find(
    s =>
      s.name.toLowerCase() === normalizedName ||
      s.npm_package?.toLowerCase() === normalizedName
  );
  return server?.trust_level ?? 'unknown';
}

export function getTrustedServerInfo(serverName: string): TrustedServer | undefined {
  const normalizedName = serverName.toLowerCase();
  return TRUSTED_SERVERS.find(
    s =>
      s.name.toLowerCase() === normalizedName ||
      s.npm_package?.toLowerCase() === normalizedName
  );
}

// Check if server name matches any trusted npm package pattern
export function matchesTrustedPackage(packageName: string): boolean {
  const normalizedName = packageName.toLowerCase();

  // Check for Anthropic official packages
  if (normalizedName.startsWith('@anthropic-ai/')) {
    return true;
  }

  // Check against known trusted list
  return TRUSTED_SERVERS.some(s => {
    if (s.npm_package?.toLowerCase() === normalizedName) return true;
    return false;
  });
}
