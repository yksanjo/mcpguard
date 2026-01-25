import { describe, it, expect } from 'vitest';
import { RiskScorer } from '../../src/core/scorer.js';
import type { Finding, MCPServerConfig, ThreatType } from '../../src/types/index.js';

describe('RiskScorer', () => {
  const scorer = new RiskScorer();

  describe('risk level calculation', () => {
    it('returns HIGH for score >= 0.7', () => {
      expect(scorer.getRiskLevel(0.7)).toBe('HIGH');
      expect(scorer.getRiskLevel(0.9)).toBe('HIGH');
      expect(scorer.getRiskLevel(1.0)).toBe('HIGH');
    });

    it('returns MEDIUM for score >= 0.4 and < 0.7', () => {
      expect(scorer.getRiskLevel(0.4)).toBe('MEDIUM');
      expect(scorer.getRiskLevel(0.5)).toBe('MEDIUM');
      expect(scorer.getRiskLevel(0.69)).toBe('MEDIUM');
    });

    it('returns LOW for score < 0.4', () => {
      expect(scorer.getRiskLevel(0.0)).toBe('LOW');
      expect(scorer.getRiskLevel(0.2)).toBe('LOW');
      expect(scorer.getRiskLevel(0.39)).toBe('LOW');
    });
  });

  describe('composite scoring', () => {
    it('scores clean config as low risk', () => {
      const config: MCPServerConfig = {
        command: 'npx',
        args: ['-y', '@anthropic-ai/mcp-server-fetch'],
      };
      const findings: Finding[] = [];

      const score = scorer.computeRiskScore('mcp-server-fetch', config, findings);

      expect(score.total).toBeLessThan(0.4);
    });

    it('scores critical finding as higher risk', () => {
      const config: MCPServerConfig = {
        command: 'npx',
        args: ['malicious'],
      };
      const findings: Finding[] = [
        {
          server_name: 'test',
          rule_id: 'MCPG-001',
          severity: 'critical',
          threat_type: 'prompt_injection' as ThreatType,
          title: 'Test',
          description: 'Test',
          remediation: 'Test',
          cve_ref: 'CVE-2025-49596',
        },
      ];

      const score = scorer.computeRiskScore('test-server', config, findings);

      expect(score.total).toBeGreaterThan(0.4);
      expect(score.components.vulnerability).toBeGreaterThan(0);
    });

    it('applies trust bonus for official servers', () => {
      const config: MCPServerConfig = {
        command: 'npx',
        args: ['-y', '@anthropic-ai/mcp-server-fetch'],
      };

      const score = scorer.computeRiskScore('@anthropic-ai/mcp-server-fetch', config, []);

      expect(score.components.trust).toBeGreaterThan(0);
    });
  });
});
