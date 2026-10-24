import type { Severity } from './config.ts';
import type { Lang } from './i18n.ts';
import type { SandboxResult } from '../../../src/sandbox/protocol.js';

export interface SandboxView { status: string; result: SandboxResult | null }

export type { Severity };

export type Category =
  | 'API1' | 'API2' | 'API3' | 'API4' | 'API5' | 'API6' | 'API7' | 'API8' | 'API9' | 'API10'
  | 'INJECTION' | 'SECRETS';

export const CATEGORY_NAMES: Record<Category, string> = {
  API1: 'API1:2023 Broken Object Level Authorization (BOLA)',
  API2: 'API2:2023 Broken Authentication',
  API3: 'API3:2023 Broken Object Property Level Authorization',
  API4: 'API4:2023 Unrestricted Resource Consumption',
  API5: 'API5:2023 Broken Function Level Authorization',
  API6: 'API6:2023 Unrestricted Access to Sensitive Business Flows',
  API7: 'API7:2023 Server Side Request Forgery',
  API8: 'API8:2023 Security Misconfiguration',
  API9: 'API9:2023 Improper Inventory Management',
  API10: 'API10:2023 Unsafe Consumption of APIs',
  INJECTION: 'Injection (SQL / NoSQL / Command)',
  SECRETS: 'Hardcoded Secrets',
};

export const SEVERITY_ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];
export const severityRank = (s: Severity) => SEVERITY_ORDER.length - SEVERITY_ORDER.indexOf(s);

export interface CodeEvidence {
  file: string;
  line: number;
  side: 'before' | 'after';
  quote: string;
}

export interface ImpactStep {
  kind: 'change' | 'access' | 'consequence';
  explanation: string;
  /** 인용문과 줄 번호가 실제 입력 코드와 일치하는 경우에만 보존한다. */
  evidence: CodeEvidence[];
}

export interface SecurityImpact {
  steps: ImpactStep[];
  assumptions: string[];
  saferAlternative: string;
  verification: string[];
  /** 이 분석기는 코드를 실행하지 않는다. AI 응답으로 이 값을 변경할 수 없다. */
  verificationStatus: 'not_run';
  source: 'ai' | 'rule';
}

export interface Finding {
  /** 정적 룰 결과는 S1, S2... (LLM 이 오탐 여부를 판정할 때 참조) */
  id: string;
  source: 'static' | 'llm' | 'static+llm';
  ruleId?: string;
  file: string;
  line?: number;
  severity: Severity;
  category: Category;
  title: string;
  description: string;
  recommendation: string;
  confidence?: number;
  evidence?: string;
  impact?: SecurityImpact;
}

export interface AnalysisResult {
  /** 리포트·LLM 설명의 언어. 이전 버전 결과에는 없을 수 있다 */
  lang?: Lang;
  /** AI 설명을 초등학교 5학년 수준으로 쉽게 썼는지 */
  simple?: boolean;
  risk: Severity | 'none';
  summary: string;
  intent?: string;
  findings: Finding[];
  /** LLM 이 오탐으로 판정해 제외한 정적 결과 */
  dismissed: { finding: Finding; reason: string }[];
  llm: { used: boolean; model?: string; error?: string };
  stats: { filesScanned: number; filesSkipped: number; durationMs: number };
}
