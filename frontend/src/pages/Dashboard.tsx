import { useQuery } from '@tanstack/react-query';
import { scanAPI } from '../services/api';
import { Tooltip, ResponsiveContainer, PieChart, Pie, Cell } from 'recharts';
import { Activity, AlertTriangle, CheckCircle2, TrendingUp } from 'lucide-react';

export default function Dashboard() {
  const { data: scans, isLoading } = useQuery({
    queryKey: ['scans'],
    queryFn: async () => {
      const response = await scanAPI.list();
      return response.data;
    },
  });

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-96">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary"></div>
      </div>
    );
  }

  const stats = scans
    ? {
        total: scans.length,
        completed: scans.filter((s) => s.status === 'completed').length,
        running: scans.filter((s) => s.status === 'running').length,
        failed: scans.filter((s) => s.status === 'failed').length,
      }
    : { total: 0, completed: 0, running: 0, failed: 0 };

  const recentScans = scans?.slice(0, 5) || [];

  // Aggregate findings
  const totalFindings = scans?.reduce(
    (acc, scan) => ({
      critical: acc.critical + scan.critical_findings,
      high: acc.high + scan.high_findings,
      medium: acc.medium + scan.medium_findings,
      low: acc.low + scan.low_findings,
    }),
    { critical: 0, high: 0, medium: 0, low: 0 }
  ) || { critical: 0, high: 0, medium: 0, low: 0 };

  const severityData = [
    { name: 'Critical', value: totalFindings.critical, color: '#dc2626' },
    { name: 'High', value: totalFindings.high, color: '#ea580c' },
    { name: 'Medium', value: totalFindings.medium, color: '#f59e0b' },
    { name: 'Low', value: totalFindings.low, color: '#eab308' },
  ];

  const avgRiskScore =
    scans && scans.length > 0
      ? scans.reduce((acc, scan) => acc + scan.risk_score, 0) / scans.length
      : 0;

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-3xl font-bold">Dashboard</h1>
      </div>

      {/* Stats Cards */}
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        <div className="rounded-lg border bg-card p-6">
          <div className="flex items-center justify-between">
            <p className="text-sm font-medium text-muted-foreground">Total Scans</p>
            <Activity className="h-4 w-4 text-muted-foreground" />
          </div>
          <p className="mt-2 text-3xl font-bold">{stats.total}</p>
        </div>

        <div className="rounded-lg border bg-card p-6">
          <div className="flex items-center justify-between">
            <p className="text-sm font-medium text-muted-foreground">Completed</p>
            <CheckCircle2 className="h-4 w-4 text-green-500" />
          </div>
          <p className="mt-2 text-3xl font-bold">{stats.completed}</p>
        </div>

        <div className="rounded-lg border bg-card p-6">
          <div className="flex items-center justify-between">
            <p className="text-sm font-medium text-muted-foreground">Avg Risk Score</p>
            <TrendingUp className="h-4 w-4 text-muted-foreground" />
          </div>
          <p className="mt-2 text-3xl font-bold">{avgRiskScore.toFixed(1)}</p>
        </div>

        <div className="rounded-lg border bg-card p-6">
          <div className="flex items-center justify-between">
            <p className="text-sm font-medium text-muted-foreground">Total Findings</p>
            <AlertTriangle className="h-4 w-4 text-orange-500" />
          </div>
          <p className="mt-2 text-3xl font-bold">
            {Object.values(totalFindings).reduce((a, b) => a + b, 0)}
          </p>
        </div>
      </div>

      {/* Charts */}
      <div className="grid gap-4 md:grid-cols-2">
        <div className="rounded-lg border bg-card p-6">
          <h3 className="text-lg font-semibold mb-4">Findings by Severity</h3>
          <ResponsiveContainer width="100%" height={300}>
            <PieChart>
              <Pie
                data={severityData}
                cx="50%"
                cy="50%"
                labelLine={false}
                label={({ name, percent }) =>
                  `${name} ${(percent * 100).toFixed(0)}%`
                }
                outerRadius={100}
                fill="#8884d8"
                dataKey="value"
              >
                {severityData.map((entry, index) => (
                  <Cell key={`cell-${index}`} fill={entry.color} />
                ))}
              </Pie>
              <Tooltip />
            </PieChart>
          </ResponsiveContainer>
        </div>

        <div className="rounded-lg border bg-card p-6">
          <h3 className="text-lg font-semibold mb-4">Recent Scans</h3>
          <div className="space-y-3">
            {recentScans.length === 0 ? (
              <p className="text-sm text-muted-foreground">No scans yet</p>
            ) : (
              recentScans.map((scan) => (
                <div
                  key={scan.id}
                  className="flex items-center justify-between p-3 rounded-md bg-muted/50"
                >
                  <div>
                    <p className="font-medium">{scan.name}</p>
                    <p className="text-sm text-muted-foreground">
                      {new Date(scan.created_at).toLocaleDateString()}
                    </p>
                  </div>
                  <div className="flex items-center gap-2">
                    <span
                      className={`px-2 py-1 rounded text-xs font-medium ${
                        scan.status === 'completed'
                          ? 'bg-green-500/10 text-green-500'
                          : scan.status === 'running'
                          ? 'bg-blue-500/10 text-blue-500'
                          : 'bg-red-500/10 text-red-500'
                      }`}
                    >
                      {scan.status}
                    </span>
                    <span className="text-sm font-medium">
                      Risk: {scan.risk_score.toFixed(1)}
                    </span>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
