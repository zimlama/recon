import axios, { AxiosError } from 'axios';

const API_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';

export const api = axios.create({
  baseURL: API_URL,
  timeout: 60_000,
  headers: { 'Content-Type': 'application/json' },
});

api.interceptors.response.use(
  (r) => r,
  (error: AxiosError) => {
    if (error.response) {
      const detail = (error.response.data as { detail?: string })?.detail;
      if (detail) {
        error.message = `${error.response.status}: ${detail}`;
      }
    }
    return Promise.reject(error);
  },
);

// ---- Types (will be replaced with openapi-typescript generated) ----

export type JobStatus =
  | 'pending'
  | 'running'
  | 'validating'
  | 'completed'
  | 'failed'
  | 'cancelled';

export type ModuleTier = 'tier_1' | 'tier_2' | 'tier_3';

export interface ModuleInfo {
  name: string;
  description: string;
  phase: string;
  tier: ModuleTier;
  mitre_techniques: string[];
  requires_api_keys: string[];
  requires_consent: boolean;
  estimated_duration_seconds: number | null;
  enabled_by_default: boolean;
}

export interface Finding {
  id: string;
  type: string;
  value: string;
  source: string;
  confidence: number;
  finding_metadata: Record<string, unknown>;
  created_at: string;
}

export interface JobCreate {
  target: string;
  target_type?: string;
  selected_modules: string[];
  user_consent: boolean;
  typed_confirmation: string;
  consent_modal_version?: string;
}

export interface Job {
  id: string;
  target: string;
  target_type: string;
  status: JobStatus;
  selected_modules: string[];
  user_consent: boolean;
  created_at: string;
  started_at: string | null;
  completed_at: string | null;
  duration_seconds: number | null;
  error_message: string | null;
  report_md_path: string | null;
  report_pdf_path: string | null;
  module_runs?: ModuleRun[];
}

export interface ModuleRun {
  id: string;
  module_name: string;
  module_tier: ModuleTier;
  status: string;
  started_at: string | null;
  completed_at: string | null;
  duration_seconds: number | null;
  findings_count: number;
  errors: string[];
  findings?: Finding[];
  validation?: AIValidation | null;
}

export interface AIValidation {
  id: string;
  module_run_id: string;
  summary: string;
  confidence: number;
  recommended_action: string;
  recommended_next_modules: string[];
  model: string;
  total_tokens: number | null;
  cost_usd: number | null;
  validated_at: string;
}

// ---- API functions ----

export async function listModules(): Promise<{ modules: ModuleInfo[]; total: number }> {
  const { data } = await api.get('/api/v1/modules');
  return data;
}

export async function listJobs(
  page = 1,
  pageSize = 20,
  status?: JobStatus,
): Promise<{ items: Job[]; total: number }> {
  const { data } = await api.get('/api/v1/jobs', {
    params: { page, page_size: pageSize, ...(status && { status }) },
  });
  return data;
}

export async function getJob(id: string): Promise<Job> {
  const { data } = await api.get(`/api/v1/jobs/${id}`);
  return data;
}

export async function createJob(payload: JobCreate): Promise<Job> {
  const { data } = await api.post('/api/v1/jobs', payload);
  return data;
}

export async function cancelJob(id: string): Promise<Job> {
  const { data } = await api.post(`/api/v1/jobs/${id}/cancel`);
  return data;
}

export async function deleteJob(id: string): Promise<void> {
  await api.delete(`/api/v1/jobs/${id}`);
}

export async function getFindings(
  jobId: string,
  options: { type?: string; verdict?: string; page?: number; pageSize?: number } = {},
): Promise<{ items: Finding[]; total: number }> {
  const { data } = await api.get(`/api/v1/jobs/${jobId}/findings`, {
    params: {
      ...(options.type && { type: options.type }),
      ...(options.verdict && { verdict: options.verdict }),
      page: options.page || 1,
      page_size: options.pageSize || 50,
    },
  });
  return data;
}

// ---- Handoff packet (mirrors backend/app/handoff/schema.py) ----
// Vendor-neutral public contract for Phase 2 consumers. Schema is
// semver'd via `schema_version`; consumers MUST validate it before
// consuming. See docs/HANDOFF.md.

export interface HandoffSource {
  repo: 'zimlama/recon';
  version: string;
  job_id: string;
  phase: '01-recon-osint';
  completed_at: string;
}

export interface HandoffTarget {
  primary_domain: string;
  authorization_scope: string;
  active_scan_authorized: boolean;
}

export interface HandoffShodanExposure {
  open_ports: number[];
  products: string[];
  cves_observed: string[];
}

export interface HandoffConfirmedTarget {
  subdomain: string;
  ips: string[];
  asn: string | null;
  country: string | null;
  tech_stack_hint: Record<string, string>;
  shodan_exposure: HandoffShodanExposure | null;
  priority_for_next_phase: 'HIGH' | 'MEDIUM' | 'LOW';
  ai_reasoning: string;
  ai_verdict: 'CONFIRMED' | 'LIKELY' | 'SUSPECTED';
  ai_confidence: number;
}

export interface HandoffTechStack {
  web_servers: Record<string, string[]>;
  frameworks: Record<string, string[]>;
  databases: Record<string, string[]>;
  cloud_providers: Record<string, string[]>;
}

export interface HandoffCredentialsExposure {
  emails_found: number;
  breach_count: number;
}

export interface HandoffRecommendedModule {
  module: string;
  priority: 'HIGH' | 'MEDIUM' | 'LOW';
  rationale: string;
}

export interface HandoffCertificate {
  cn: string;
  issuer: string;
  valid_from: string;
  valid_to: string;
  san: string[];
}

export interface HandoffConsentFlags {
  tier_3_modules_run: string[];
  white_hat_only: boolean;
}

export interface HandoffPersonDossierSummary {
  persona_id: string;
  email_hash: string;
  source_modules: string[];
  role_relevance: 'HIGH' | 'MEDIUM' | 'LOW';
  priority_for_targeting: 'HIGH' | 'MEDIUM' | 'LOW';
  confidence: number;
  coherence: 'HIGH' | 'MEDIUM' | 'LOW' | 'NONE' | null;
  breach_exposure_count: number;
  profile_count: number;
}

export interface HandoffPacket {
  schema_version: string;
  schema_url: string;
  source: HandoffSource;
  target: HandoffTarget;
  confirmed_targets: HandoffConfirmedTarget[];
  tech_stack_summary: HandoffTechStack;
  credentials_exposure_summary: HandoffCredentialsExposure;
  certificates: HandoffCertificate[];
  recommended_modules: HandoffRecommendedModule[];
  person_dossiers: HandoffPersonDossierSummary[];
  do_not_scan: string[];
  consent_flags: HandoffConsentFlags;
}

export async function getHandoff(jobId: string): Promise<HandoffPacket> {
  const { data } = await api.get<HandoffPacket>(`/api/v1/jobs/${jobId}/handoff`);
  return data;
}

export async function generateReport(
  jobId: string,
  options: { include_raw_findings?: boolean; include_ai_insights?: boolean; include_annex?: boolean } = {},
): Promise<{ job_id: string; md_path: string; pdf_path: string | null; generated_at: string }> {
  const { data } = await api.post(`/api/v1/jobs/${jobId}/report`, {
    include_raw_findings: options.include_raw_findings ?? true,
    include_ai_insights: options.include_ai_insights ?? true,
    include_annex: options.include_annex ?? true,
  });
  return data;
}

export async function triggerValidation(jobId: string, moduleName?: string): Promise<unknown> {
  if (moduleName) {
    const { data } = await api.post(`/api/v1/jobs/${jobId}/modules/${moduleName}/validate`);
    return data;
  }
  const { data } = await api.post(`/api/v1/jobs/${jobId}/validate`);
  return data;
}
