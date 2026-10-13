// Typed client for the local FastAPI backend. All data is real; nothing is mocked.
const BASE = '';

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    headers: { 'Content-Type': 'application/json' },
    ...init,
  });
  if (!res.ok) {
    let detail = `HTTP ${res.status}`;
    try {
      const body = await res.json();
      detail = typeof body.detail === 'string' ? body.detail : JSON.stringify(body.detail);
    } catch { /* keep generic */ }
    throw new Error(detail);
  }
  return res.json() as Promise<T>;
}

export interface RunSummary {
  id: string; experiment_id: string; status: string; params: Record<string, unknown>;
  result: Record<string, unknown> | null; error: string | null;
  started_at: string | null; finished_at: string | null; created_at: string;
  code_version: string | null; progress: number | null;
}
export interface RunDetail extends RunSummary { events: EventRow[]; env_snapshot: Record<string, unknown>; }
export interface EventRow { id: number; ts: string; level: string; run_id: string | null; message: string; }
export interface EvidenceRecord { record_index: number; [key: string]: unknown; }
export interface Sample {
  id: string; label: string; kind: string; created_at: string;
  params: Record<string, unknown>; metadata?: Record<string, unknown>;
  validation?: Record<string, unknown>; ops?: { ts: string; op: string; detail: string }[];
  artefact?: Record<string, unknown>;
}
export interface Finding {
  id: string; title: string; description: string; module: string; status: string;
  confidence: string; severity: string; reproduction: string; limitations: string;
  linked_runs: string[]; linked_evidence: number[]; notes: string;
  created_at: string; history: { ts: string; status: string; note: string }[];
}
export interface ExperimentDefRow {
  id: string; title: string; question: string; objective: string; module: string;
  model: string; method: string; validation: string; notes: string;
  params_schema: Record<string, unknown>; created_at: string; runs?: RunSummary[];
}
export interface Overview {
  backend: string; version: string; python: string; os: string; node: string | null;
  experiments_defined: number; core_experiments_available: number;
  runs_total: number; runs_by_status: Record<string, number>; samples: number;
  findings: number; evidence_records: number;
  snapshot_integrity: { ok: boolean; details: { file: string; match: boolean; exists: boolean }[] };
  recent_events: EventRow[]; last_test_run: string | null; not_implemented: string[];
}
export interface ModelCatalog { [k: string]: Record<string, unknown>; }

export const api = {
  health: () => request<{ status: string; snapshot_integrity: boolean }>('/api/health'),
  overview: () => request<Overview>('/api/overview'),
  modules: () => request<{ models: ModelCatalog; core_experiments: Record<string, { category: string; description: string }>; sample_kinds: string[]; test_suites: Record<string, string[]> }>('/api/modules'),
  experiments: () => request<{ definitions: ExperimentDefRow[]; core_registry: Record<string, { category: string; description: string }> }>('/api/experiments'),
  createExperiment: (d: Partial<ExperimentDefRow>) => request<ExperimentDefRow>('/api/experiments', { method: 'POST', body: JSON.stringify(d) }),
  startRun: (eid: string, params: Record<string, unknown>) => request<{ run_id: string; status: string }>(`/api/experiments/${eid}/runs`, { method: 'POST', body: JSON.stringify({ params }) }),
  runs: (status?: string) => request<RunSummary[]>(`/api/runs${status ? `?status=${status}` : ''}`),
  run: (rid: string) => request<RunDetail>(`/api/runs/${rid}`),
  cancelRun: (rid: string) => request<{ note: string }>(`/api/runs/${rid}/cancel`, { method: 'POST' }),
  rerun: (rid: string) => request<{ run_id: string }>(`/api/runs/${rid}/rerun`, { method: 'POST' }),
  samples: (q?: string, kind?: string) => request<Sample[]>(`/api/wallet-lab/samples?q=${q ?? ''}&kind=${kind ?? ''}`),
  sample: (sid: string) => request<Sample>(`/api/wallet-lab/samples/${sid}`),
  createSample: (d: { label: string; kind: string; params: Record<string, unknown> }) => request<Sample>('/api/wallet-lab/samples', { method: 'POST', body: JSON.stringify(d) }),
  evidence: (q?: string) => request<EvidenceRecord[]>(`/api/evidence?q=${q ?? ''}`),
  evidenceIntegrity: () => request<{ snapshots: { file: string; expected_sha256: string; actual_sha256: string | null; exists: boolean; match: boolean }[]; policy: string }>('/api/evidence/integrity'),
  findings: () => request<Finding[]>('/api/findings'),
  finding: (fid: string) => request<Finding>(`/api/findings/${fid}`),
  createFinding: (d: Partial<Finding>) => request<Finding>('/api/findings', { method: 'POST', body: JSON.stringify(d) }),
  setFindingStatus: (fid: string, status: string, note: string) => request<Finding>(`/api/findings/${fid}/status`, { method: 'PATCH', body: JSON.stringify({ status, note }) }),
  compare: (ids: string[]) => request<{ runs: RunSummary[]; differing_params: string[]; code_versions: Record<string, string>; directly_comparable: boolean; caveat: string | null }>(`/api/comparisons?ids=${ids.join(',')}`),
  reportRun: (rid: string) => request<{ report: Record<string, unknown> }>(`/api/reports/run/${rid}`, { method: 'POST' }),
  reportLab: () => request<Record<string, unknown>>('/api/reports/lab', { method: 'POST' }),
  reports: () => request<{ id: string; scope: string; fmt: string; path: string; payload_hash: string; created_at: string }[]>('/api/reports'),
  events: (runId?: string, level?: string, q?: string) => request<EventRow[]>(`/api/events?run_id=${runId ?? ''}&level=${level ?? ''}&q=${q ?? ''}`),
  testSuites: () => request<{ suites: Record<string, string[]>; all_target: string }>('/api/tests/suites'),
  runTests: (suite: string) => request<{ suite: string; exit_code: number; stdout_tail: string; stderr_tail: string; started_at: string; finished_at: string }>('/api/tests/run', { method: 'POST', body: JSON.stringify({ suite }) }),
  settings: () => request<{ defaults: Record<string, unknown>; current: Record<string, unknown> }>('/api/settings'),
  patchSettings: (values: Record<string, unknown>) => request<{ updated: Record<string, unknown>; rejected_keys: string[] }>('/api/settings', { method: 'PATCH', body: JSON.stringify({ values }) }),
  probeModel: (mid: string, params: Record<string, unknown>) => request<Record<string, unknown>>(`/api/models/${mid}/probe`, { method: 'POST', body: JSON.stringify({ params }) }),
};
