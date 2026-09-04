/** Tipi dell'API Defenix Exposure Rating (allineati agli schemi Pydantic). */

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type RatingClass = 'A' | 'B' | 'C' | 'D' | 'E';
export type ScanProfile = 'public_passive' | 'verified_standard' | 'verified_extended';

export interface UserProfile {
  id: string;
  tenant_id: string;
  email: string;
  full_name: string | null;
  roles: string[];
  permissions: string[];
}

export interface TokenResponse {
  access_token: string;
  token_type: string;
  expires_in: number;
  profile: UserProfile;
}

export interface Company {
  id: string;
  tenant_id: string;
  legal_name: string;
  slug: string;
  vat_number: string | null;
  country: string | null;
  sector: string | null;
  size_band: string | null;
  notes: string | null;
  is_active: boolean;
  next_scan_due_at: string | null;
  created_at: string;
}

export interface Page<T> {
  items: T[];
  total: number;
  page: number;
  page_size: number;
}

export interface CategoryScore {
  key: string;
  label_it: string;
  weight: number;
  score: number;
  total_deduction: number;
  finding_count: number;
  critical_count: number;
  high_count: number;
}

export interface TrendPoint {
  scan_id: string;
  score: number;
  rating_class: RatingClass;
  confidence: number | null;
  computed_at: string;
}

export interface DashboardOverview {
  company_id: string;
  company_name: string;
  overall_score: number | null;
  rating_class: RatingClass | null;
  rating_label_it: string | null;
  confidence: number | null;
  confidence_label_it: string | null;
  is_provisional: boolean;
  provisional_notice: string | null;
  categories: CategoryScore[];
  severity_counts: Record<Severity, number>;
  trend: TrendPoint[];
  assets: Record<string, number>;
  email_posture: Record<string, unknown>;
  darkweb: Record<string, number>;
  review_progress: Record<string, number | boolean>;
  last_scan: Record<string, unknown> | null;
  open_remediations: number;
  scope_disclaimer_it: string;
}

export interface PortfolioCard {
  company_id: string;
  company_name: string;
  overall_score: number | null;
  rating_class: RatingClass | null;
  confidence: number | null;
  is_provisional: boolean;
  score_delta: number | null;
  critical_findings: number;
  high_findings: number;
  open_remediations: number;
  last_scan_at: string | null;
  next_scan_due_at: string | null;
  scan_status: string | null;
}

export interface PortfolioView {
  companies: PortfolioCard[];
  total_companies: number;
  average_score: number | null;
  companies_below_c: number;
  total_critical_findings: number;
  generated_at: string;
}

export interface Finding {
  id: string;
  reference_code: string;
  finding_type: string;
  title: string;
  description: string | null;
  category: string;
  severity: Severity;
  confidence_class: string;
  ownership_status: string;
  detail: string | null;
  workflow_state: string;
  analyst_validation: string;
  excluded_from_rating: boolean;
  retest_requested: boolean;
  cve_id: string | null;
  cvss_score: number | null;
  epss_score: number | null;
  cisa_kev: boolean;
  internet_facing: boolean;
  first_seen_at: string;
  last_seen_at: string;
  event_date: string | null;
  resolved_at: string | null;
  applied_deduction: number;
  sources_json: string[] | null;
  asset_id: string | null;
  asset_display: string | null;
  attributes_json: Record<string, unknown> | null;
  evidence_summary: string | null;
}

export interface Scan {
  id: string;
  company_id: string;
  profile_key: ScanProfile;
  status: string;
  progress_percent: number;
  current_stage: string | null;
  started_at: string | null;
  finished_at: string | null;
  error_message: string | null;
  mock_mode: boolean;
  scoring_config_version: string | null;
  stats_json: Record<string, unknown> | null;
  previous_scan_id: string | null;
  created_at: string;
}

export interface ToolRun {
  id: string;
  tool_key: string;
  tool_version: string | null;
  status: string;
  target_count: number;
  evidence_count: number;
  duration_seconds: number | null;
  error_message: string | null;
  coverage_impact: number;
  was_mocked: boolean;
}

export interface ScanDetail extends Scan {
  tool_runs: ToolRun[];
}

export interface AuthorizationPreview {
  profile: string;
  allowed: boolean;
  reasons: string[];
  authorization_id: string | null;
  expires_at: string | null;
  tools_planned: string[];
  forbidden_actions: string[];
}

export interface RemediationItem {
  catalog_id: string;
  title_it: string;
  area: string;
  priority: string;
  effort: string;
  skills: string[];
  risk_mitigated_it: string;
  immediate_action_it: string;
  structural_solution_it: string;
  verification_it: string;
  references: string[];
  commercial_services: string[];
  finding_codes: string[];
  max_severity: Severity;
  affected_asset_count: number;
  is_quick_win: boolean;
}

export interface ScanComparison {
  previous_scan_id: string | null;
  current_scan_id: string;
  previous_score: number | null;
  current_score: number;
  score_delta: number | null;
  previous_class: RatingClass | null;
  current_class: RatingClass;
  confidence_delta: number | null;
  new_findings: Array<Record<string, string>>;
  resolved_findings: Array<Record<string, string>>;
  pending_closure: Array<Record<string, string>>;
  reopened_findings: Array<Record<string, string>>;
  new_assets: Array<Record<string, string>>;
  disappeared_assets: Array<Record<string, string>>;
  summary_it: string;
}

export interface ReportVersion {
  id: string;
  version: number;
  format: string;
  file_sha256: string | null;
  file_bytes: number | null;
  generated_at: string;
}

export interface Report {
  id: string;
  scan_id: string;
  report_type: string;
  language: string;
  status: string;
  title: string;
  approved_at: string | null;
  error_message: string | null;
  created_at: string;
  versions: ReportVersion[];
}

export interface ScoreDetail {
  scan_id: string;
  overall_score: number;
  rating_class: RatingClass;
  rating_label_it: string;
  raw_weighted_score: number;
  cap_applied: boolean;
  applied_caps: Array<{ cap_id: string; max_score: number; reason_it: string }>;
  is_provisional: boolean;
  provisional_reason: string | null;
  scoring_config_version: string;
  computed_at: string;
  categories: CategoryScore[];
  confidence: {
    value: number;
    label_it: string;
    is_publishable: boolean;
    factors: Record<string, { ratio: number; weight: number; earned: number; note: string; description_it: string }>;
    penalties: Array<{ key: string; amount: number; reason_it: string }>;
    coverage_matrix: Array<{ tool: string; status: string; note_it: string; optional: boolean; mocked: boolean }>;
  } | null;
  calculation_trace: Record<string, unknown>;
}

export interface Domain {
  id: string;
  company_id: string;
  name: string;
  is_primary: boolean;
  verification_status: string;
  verification_method: string | null;
  verified_at: string | null;
  registrar: string | null;
  registry_expiry_date: string | null;
  dnssec_enabled: boolean | null;
}

export interface ScopeEntry {
  id: string;
  entry_type: string;
  value: string;
  action: string;
  is_active: boolean;
  note: string | null;
}

export interface Authorization {
  id: string;
  company_id: string;
  status: string;
  granting_subject_name: string;
  granting_subject_role: string | null;
  granted_at: string;
  valid_from: string;
  expires_at: string;
  revoked_at: string | null;
  allowed_profiles_json: string[] | null;
  document_reference: string | null;
}

export interface CompanyInput {
  legal_name: string;
  slug: string;
  vat_number?: string | null;
  country?: string | null;
  sector?: string | null;
  size_band?: string | null;
  notes?: string | null;
}

export interface ScopeEntryInput {
  entry_type: string;
  value: string;
  action: string;
  note?: string | null;
}

export interface PurgeResult {
  company_id: string;
  slug: string;
  deleted_rows: Record<string, number>;
  total_rows: number;
}

export interface VerificationChallenge {
  method: string;
  token: string;
  record_name: string | null;
  record_value: string | null;
  file_path: string | null;
  instructions_it: string;
  expires_at: string;
}

export interface VerificationResult {
  verified: boolean;
  status: string;
  method: string | null;
  detail_it: string;
  checked_at: string;
}

export interface Health {
  status: string;
  version: string;
  environment: string;
  database: string;
  redis: string;
  workers: number;
  scan_mock_mode: boolean;
  checked_at: string;
}
