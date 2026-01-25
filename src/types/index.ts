// MCPGuard Type Definitions

// ============ MCP Configuration Types ============

export interface MCPConfig {
  mcpServers: Record<string, MCPServerConfig>;
}

export interface MCPServerConfig {
  command?: string;
  args?: string[];
  url?: string;
  type?: 'stdio' | 'http' | 'sse';
  env?: Record<string, string>;
  headers?: Record<string, string>;
  auth?: AuthConfig;
}

export interface AuthConfig {
  type: 'bearer' | 'api_key' | 'basic';
  token?: string;
  env_var?: string;
}

// ============ Threat Classification ============

export enum ThreatType {
  PROMPT_INJECTION = 'prompt_injection',
  TOOL_POISONING = 'tool_poisoning',
  METADATA_ISSUE = 'metadata_issue',
  LOCALHOST_EXPOSURE = 'localhost_exposure',
  MISSING_AUTH = 'missing_auth',
  KNOWN_CVE = 'known_cve',
  RATE_LIMIT_MISSING = 'rate_limit_missing',
  SUSPICIOUS_COMMAND = 'suspicious_command',
  UNKNOWN = 'unknown'
}

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export type RiskLevel = 'HIGH' | 'MEDIUM' | 'LOW';

// ============ Detection Results ============

export interface Finding {
  server_name: string;
  rule_id: string;
  severity: Severity;
  threat_type: ThreatType;
  title: string;
  description: string;
  evidence?: string;
  line_number?: number;
  remediation: string;
  cve_ref?: string;
}

export interface RiskScore {
  total: number;
  confidence: number;
  components: {
    vulnerability: number;
    configuration: number;
    behavioral: number;
    trust: number;
  };
}

export interface ServerScanResult {
  server_name: string;
  config: MCPServerConfig;
  findings: Finding[];
  risk_score: RiskScore;
  risk_level: RiskLevel;
  scan_timestamp: string;
}

export interface ScanSummary {
  total_servers: number;
  high_risk: number;
  medium_risk: number;
  low_risk: number;
  total_findings: number;
  findings_by_severity: Record<Severity, number>;
  overall_risk_level: RiskLevel;
}

export interface ScanReport {
  scan_id: string;
  config_path: string;
  scan_timestamp: string;
  mcpguard_version: string;
  servers: ServerScanResult[];
  summary: ScanSummary;
}

// ============ Rule Engine Types ============

export type RuleCategory =
  | 'injection'
  | 'poisoning'
  | 'network'
  | 'authentication'
  | 'metadata'
  | 'rate_limiting'
  | 'cve';

export interface PatternMatcher {
  type: 'regex' | 'keyword' | 'composite' | 'config' | 'absence';
  target?: string;
  pattern?: string;
  keywords?: string[];
  conditions?: Condition[];
  flags?: string;
}

export interface Condition {
  field: string;
  operator: 'matches' | 'contains' | 'equals' | 'absent' | 'contains_key';
  value: string | boolean;
}

export interface SecurityRule {
  id: string;
  name: string;
  category: RuleCategory;
  severity: Severity;
  description: string;
  threat_type: ThreatType;
  patterns: PatternMatcher[];
  cve_ref?: string;
  remediation: string;
  enabled: boolean;
}

// ============ CVE Database Types ============

export interface CVEEntry {
  id: string;
  title: string;
  description: string;
  severity: Severity;
  affected_packages: string[];
  affected_versions?: string;
  detection_patterns: string[];
  published_date: string;
  references: string[];
}

// ============ CLI Types ============

export interface ScanOptions {
  output: 'console' | 'json' | 'sarif';
  rules?: string;
  severity?: Severity;
  failOn?: Severity;
  noColor?: boolean;
  verbose?: boolean;
  quiet?: boolean;
}

export interface CheckOptions {
  output: 'console' | 'json';
  noCache?: boolean;
}

export interface AuditOptions {
  watch?: boolean;
  configDir?: string;
  output: 'console' | 'json' | 'sarif';
  interval?: number;
}

// ============ Configuration Types ============

export interface MCPGuardConfig {
  rules_path?: string;
  severity_threshold: Severity;
  fail_on: Severity;
  trusted_registries: string[];
  output_format: 'console' | 'json' | 'sarif';
}
