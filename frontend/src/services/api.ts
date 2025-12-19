import axios from 'axios';

const API_BASE_URL = import.meta.env.VITE_API_URL || '/api/v1';

export const api = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Types
export interface Scan {
  id: number;
  name: string;
  scan_type: string;
  status: string;
  total_checks: number;
  passed_checks: number;
  failed_checks: number;
  risk_score: number;
  critical_findings: number;
  high_findings: number;
  medium_findings: number;
  low_findings: number;
  created_at: string;
  started_at: string | null;
  completed_at: string | null;
}

export interface Finding {
  id: number;
  finding_type: string;
  vuln_id: string;
  title: string;
  severity: string;
  target_host: string;
  status: string;
  can_auto_remediate: boolean;
  cvss_score: number | null;
}

export interface CreateScanRequest {
  name: string;
  scan_type: string;
  targets: string[];
  use_ssh: boolean;
  auth_method?: string;
  ssh_username?: string;
  ssh_port?: number;
  sudo_mode?: string;
  stig_profiles?: string[];
  include_cves?: boolean;
}

// API functions
export const scanAPI = {
  list: () => api.get<Scan[]>('/scans'),
  create: (data: CreateScanRequest) => api.post<Scan>('/scans', data),
  get: (id: number) => api.get<Scan>(`/scans/${id}`),
  delete: (id: number) => api.delete(`/scans/${id}`),
  getFindings: (id: number) => api.get<Finding[]>(`/scans/${id}/findings`),
  cancel: (id: number) => api.post(`/scans/${id}/cancel`),
};

export const remediationAPI = {
  remediate: (findingIds: number[], dryRun: boolean = false) =>
    api.post('/remediation', { finding_ids: findingIds, dry_run: dryRun }),
  preview: (findingId: number) =>
    api.get(`/remediation/${findingId}/preview`),
  bulkRemediate: (scanId: number, severity?: string, autoOnly: boolean = true, dryRun: boolean = false) =>
    api.post(`/remediation/bulk`, null, {
      params: { scan_id: scanId, severity, auto_only: autoOnly, dry_run: dryRun }
    }),
};

export const reportAPI = {
  generate: (scanId: number) => api.post(`/reports/${scanId}/generate`),
  download: (scanId: number) => {
    window.open(`${API_BASE_URL}/reports/${scanId}/download`, '_blank');
  },
};

export const systemAPI = {
  testSSH: (data: {
    host: string;
    username: string;
    password?: string;
    private_key_path?: string;
    port?: number;
    auth_method?: string;
  }) => api.post('/system/test-ssh', data),
  getSTIGProfiles: () => api.get<{ profiles: string[] }>('/system/stig-profiles'),
  healthCheck: () => api.get('/system/health'),
  checkDependencies: () => api.get('/system/dependencies'),
};
