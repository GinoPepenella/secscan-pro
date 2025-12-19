import { useParams } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { scanAPI, reportAPI, remediationAPI } from '../services/api';
import { Download, PlayCircle } from 'lucide-react';
import { useState } from 'react';

export default function ScanDetails() {
  const { id } = useParams<{ id: string }>();
  const scanId = parseInt(id || '0');
  const [selectedFindings, setSelectedFindings] = useState<number[]>([]);

  const { data: scan, isLoading: scanLoading } = useQuery({
    queryKey: ['scan', scanId],
    queryFn: async () => {
      const response = await scanAPI.get(scanId);
      return response.data;
    },
    refetchInterval: scan?.status === 'running' ? 5000 : false,
  });

  const { data: findings, isLoading: findingsLoading } = useQuery({
    queryKey: ['findings', scanId],
    queryFn: async () => {
      const response = await scanAPI.getFindings(scanId);
      return response.data;
    },
  });

  const handleDownloadReport = async () => {
    await reportAPI.generate(scanId);
    reportAPI.download(scanId);
  };

  const handleRemediate = async () => {
    if (selectedFindings.length === 0) return;
    await remediationAPI.remediate(selectedFindings);
  };

  if (scanLoading || findingsLoading) {
    return (
      <div className="flex items-center justify-center h-96">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary"></div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold">{scan?.name}</h1>
          <p className="text-muted-foreground">
            Created {scan && new Date(scan.created_at).toLocaleDateString()}
          </p>
        </div>
        <div className="flex gap-2">
          <button
            onClick={handleDownloadReport}
            className="inline-flex items-center gap-2 px-4 py-2 border rounded-md hover:bg-muted"
          >
            <Download className="h-4 w-4" />
            Download Report
          </button>
        </div>
      </div>

      {/* Stats */}
      <div className="grid gap-4 md:grid-cols-4">
        <div className="rounded-lg border bg-card p-6">
          <p className="text-sm font-medium text-muted-foreground">Risk Score</p>
          <p className="mt-2 text-3xl font-bold">{scan?.risk_score.toFixed(1)}</p>
        </div>
        <div className="rounded-lg border bg-card p-6">
          <p className="text-sm font-medium text-muted-foreground">Total Checks</p>
          <p className="mt-2 text-3xl font-bold">{scan?.total_checks}</p>
        </div>
        <div className="rounded-lg border bg-card p-6">
          <p className="text-sm font-medium text-muted-foreground">Failed</p>
          <p className="mt-2 text-3xl font-bold text-red-500">
            {scan?.failed_checks}
          </p>
        </div>
        <div className="rounded-lg border bg-card p-6">
          <p className="text-sm font-medium text-muted-foreground">Passed</p>
          <p className="mt-2 text-3xl font-bold text-green-500">
            {scan?.passed_checks}
          </p>
        </div>
      </div>

      {/* Findings */}
      <div className="rounded-lg border bg-card">
        <div className="p-6 border-b">
          <div className="flex items-center justify-between">
            <h2 className="text-xl font-semibold">Findings</h2>
            {selectedFindings.length > 0 && (
              <button
                onClick={handleRemediate}
                className="inline-flex items-center gap-2 px-4 py-2 bg-primary text-primary-foreground rounded-md hover:bg-primary/90"
              >
                <PlayCircle className="h-4 w-4" />
                Remediate Selected ({selectedFindings.length})
              </button>
            )}
          </div>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead className="border-b bg-muted/50">
              <tr>
                <th className="px-4 py-3 text-left">
                  <input type="checkbox" className="rounded" />
                </th>
                <th className="px-4 py-3 text-left text-sm font-medium">ID</th>
                <th className="px-4 py-3 text-left text-sm font-medium">Title</th>
                <th className="px-4 py-3 text-left text-sm font-medium">Severity</th>
                <th className="px-4 py-3 text-left text-sm font-medium">Target</th>
                <th className="px-4 py-3 text-left text-sm font-medium">Status</th>
                <th className="px-4 py-3 text-left text-sm font-medium">
                  Auto-Fix
                </th>
              </tr>
            </thead>
            <tbody className="divide-y">
              {findings?.map((finding) => (
                <tr key={finding.id} className="hover:bg-muted/50">
                  <td className="px-4 py-3">
                    <input
                      type="checkbox"
                      className="rounded"
                      checked={selectedFindings.includes(finding.id)}
                      onChange={(e) => {
                        if (e.target.checked) {
                          setSelectedFindings([...selectedFindings, finding.id]);
                        } else {
                          setSelectedFindings(
                            selectedFindings.filter((id) => id !== finding.id)
                          );
                        }
                      }}
                    />
                  </td>
                  <td className="px-4 py-3 font-mono text-sm">{finding.vuln_id}</td>
                  <td className="px-4 py-3">{finding.title}</td>
                  <td className="px-4 py-3">
                    <span
                      className={`px-2 py-1 rounded text-xs font-medium ${
                        finding.severity === 'critical'
                          ? 'bg-red-500/10 text-red-500'
                          : finding.severity === 'high'
                          ? 'bg-orange-500/10 text-orange-500'
                          : finding.severity === 'medium'
                          ? 'bg-yellow-500/10 text-yellow-500'
                          : 'bg-blue-500/10 text-blue-500'
                      }`}
                    >
                      {finding.severity}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-sm">{finding.target_host}</td>
                  <td className="px-4 py-3 text-sm">{finding.status}</td>
                  <td className="px-4 py-3">
                    {finding.can_auto_remediate ? (
                      <span className="text-green-500 text-sm">✓</span>
                    ) : (
                      <span className="text-muted-foreground text-sm">-</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
