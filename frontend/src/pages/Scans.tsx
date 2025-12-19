import { useQuery } from '@tanstack/react-query';
import { Link } from 'react-router-dom';
import { scanAPI } from '../services/api';
import { Plus, Download, Trash2 } from 'lucide-react';

export default function Scans() {
  const { data: scans, isLoading, refetch } = useQuery({
    queryKey: ['scans'],
    queryFn: async () => {
      const response = await scanAPI.list();
      return response.data;
    },
    refetchInterval: 5000, // Refetch every 5 seconds to update running scans
  });

  const handleDelete = async (id: number) => {
    if (window.confirm('Are you sure you want to delete this scan?')) {
      await scanAPI.delete(id);
      refetch();
    }
  };

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-96">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary"></div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-3xl font-bold">Scans</h1>
        <Link
          to="/scans/new"
          className="inline-flex items-center gap-2 px-4 py-2 bg-primary text-primary-foreground rounded-md hover:bg-primary/90"
        >
          <Plus className="h-4 w-4" />
          New Scan
        </Link>
      </div>

      {/* Scans Table */}
      <div className="rounded-lg border bg-card">
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead className="border-b bg-muted/50">
              <tr>
                <th className="px-4 py-3 text-left text-sm font-medium">Name</th>
                <th className="px-4 py-3 text-left text-sm font-medium">Type</th>
                <th className="px-4 py-3 text-left text-sm font-medium">Status</th>
                <th className="px-4 py-3 text-left text-sm font-medium">Risk Score</th>
                <th className="px-4 py-3 text-left text-sm font-medium">Findings</th>
                <th className="px-4 py-3 text-left text-sm font-medium">Created</th>
                <th className="px-4 py-3 text-right text-sm font-medium">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y">
              {scans?.length === 0 ? (
                <tr>
                  <td colSpan={7} className="px-4 py-8 text-center text-muted-foreground">
                    No scans found. Create your first scan to get started.
                  </td>
                </tr>
              ) : (
                scans?.map((scan) => (
                  <tr key={scan.id} className="hover:bg-muted/50">
                    <td className="px-4 py-3">
                      <Link
                        to={`/scans/${scan.id}`}
                        className="font-medium hover:text-primary"
                      >
                        {scan.name}
                      </Link>
                    </td>
                    <td className="px-4 py-3">
                      <span className="px-2 py-1 rounded text-xs bg-blue-500/10 text-blue-500">
                        {scan.scan_type.toUpperCase()}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      <span
                        className={`px-2 py-1 rounded text-xs font-medium ${
                          scan.status === 'completed'
                            ? 'bg-green-500/10 text-green-500'
                            : scan.status === 'running'
                            ? 'bg-blue-500/10 text-blue-500'
                            : scan.status === 'failed'
                            ? 'bg-red-500/10 text-red-500'
                            : 'bg-gray-500/10 text-gray-500'
                        }`}
                      >
                        {scan.status}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-2">
                        <div className="w-20 bg-muted rounded-full h-2">
                          <div
                            className={`h-2 rounded-full ${
                              scan.risk_score >= 70
                                ? 'bg-red-500'
                                : scan.risk_score >= 40
                                ? 'bg-orange-500'
                                : 'bg-green-500'
                            }`}
                            style={{ width: `${scan.risk_score}%` }}
                          />
                        </div>
                        <span className="text-sm font-medium">
                          {scan.risk_score.toFixed(1)}
                        </span>
                      </div>
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex gap-1">
                        {scan.critical_findings > 0 && (
                          <span className="px-1.5 py-0.5 rounded text-xs bg-red-500/10 text-red-500">
                            {scan.critical_findings}C
                          </span>
                        )}
                        {scan.high_findings > 0 && (
                          <span className="px-1.5 py-0.5 rounded text-xs bg-orange-500/10 text-orange-500">
                            {scan.high_findings}H
                          </span>
                        )}
                        {scan.medium_findings > 0 && (
                          <span className="px-1.5 py-0.5 rounded text-xs bg-yellow-500/10 text-yellow-500">
                            {scan.medium_findings}M
                          </span>
                        )}
                      </div>
                    </td>
                    <td className="px-4 py-3 text-sm text-muted-foreground">
                      {new Date(scan.created_at).toLocaleDateString()}
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex items-center justify-end gap-2">
                        <button
                          onClick={() => handleDelete(scan.id)}
                          className="p-2 hover:bg-destructive/10 hover:text-destructive rounded"
                        >
                          <Trash2 className="h-4 w-4" />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
