import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useMutation } from '@tanstack/react-query';
import { scanAPI } from '../services/api';
import { ArrowLeft } from 'lucide-react';

export default function NewScan() {
  const navigate = useNavigate();
  const [formData, setFormData] = useState({
    name: '',
    scan_type: 'combined',
    targets: '',
    use_ssh: false,
    ssh_username: '',
    ssh_port: 22,
    auth_method: 'password',
    sudo_mode: 'sudo',
    include_cves: true,
  });

  const createScanMutation = useMutation({
    mutationFn: async (data: any) => {
      const response = await scanAPI.create(data);
      return response.data;
    },
    onSuccess: () => {
      navigate('/scans');
    },
  });

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();

    const scanData = {
      ...formData,
      targets: formData.targets.split('\n').filter((t) => t.trim()),
      ssh_port: parseInt(formData.ssh_port.toString()),
    };

    createScanMutation.mutate(scanData);
  };

  return (
    <div className="space-y-6 max-w-3xl mx-auto">
      <div className="flex items-center gap-4">
        <button
          onClick={() => navigate('/scans')}
          className="p-2 hover:bg-muted rounded"
        >
          <ArrowLeft className="h-5 w-5" />
        </button>
        <h1 className="text-3xl font-bold">Create New Scan</h1>
      </div>

      <form onSubmit={handleSubmit} className="space-y-6">
        <div className="rounded-lg border bg-card p-6 space-y-4">
          <h2 className="text-lg font-semibold">Basic Information</h2>

          <div className="space-y-2">
            <label className="text-sm font-medium">Scan Name</label>
            <input
              type="text"
              required
              value={formData.name}
              onChange={(e) => setFormData({ ...formData, name: e.target.value })}
              className="w-full px-3 py-2 border rounded-md bg-background"
              placeholder="Production Server Scan"
            />
          </div>

          <div className="space-y-2">
            <label className="text-sm font-medium">Scan Type</label>
            <select
              value={formData.scan_type}
              onChange={(e) =>
                setFormData({ ...formData, scan_type: e.target.value })
              }
              className="w-full px-3 py-2 border rounded-md bg-background"
            >
              <option value="stig">STIG Compliance Only</option>
              <option value="vulnerability">Vulnerability Assessment Only</option>
              <option value="combined">Combined (STIG + Vulnerabilities)</option>
            </select>
          </div>

          <div className="space-y-2">
            <label className="text-sm font-medium">
              Target Hosts (one per line)
            </label>
            <textarea
              required
              value={formData.targets}
              onChange={(e) =>
                setFormData({ ...formData, targets: e.target.value })
              }
              className="w-full px-3 py-2 border rounded-md bg-background h-32"
              placeholder="192.168.1.10&#10;server.example.com&#10;10.0.0.5"
            />
          </div>
        </div>

        <div className="rounded-lg border bg-card p-6 space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="text-lg font-semibold">SSH Configuration</h2>
            <label className="flex items-center gap-2">
              <input
                type="checkbox"
                checked={formData.use_ssh}
                onChange={(e) =>
                  setFormData({ ...formData, use_ssh: e.target.checked })
                }
                className="rounded border-gray-300"
              />
              <span className="text-sm">Use SSH</span>
            </label>
          </div>

          {formData.use_ssh && (
            <div className="space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-2">
                  <label className="text-sm font-medium">Username</label>
                  <input
                    type="text"
                    value={formData.ssh_username}
                    onChange={(e) =>
                      setFormData({ ...formData, ssh_username: e.target.value })
                    }
                    className="w-full px-3 py-2 border rounded-md bg-background"
                  />
                </div>

                <div className="space-y-2">
                  <label className="text-sm font-medium">Port</label>
                  <input
                    type="number"
                    value={formData.ssh_port}
                    onChange={(e) =>
                      setFormData({
                        ...formData,
                        ssh_port: parseInt(e.target.value),
                      })
                    }
                    className="w-full px-3 py-2 border rounded-md bg-background"
                  />
                </div>
              </div>

              <div className="space-y-2">
                <label className="text-sm font-medium">Authentication Method</label>
                <select
                  value={formData.auth_method}
                  onChange={(e) =>
                    setFormData({ ...formData, auth_method: e.target.value })
                  }
                  className="w-full px-3 py-2 border rounded-md bg-background"
                >
                  <option value="password">Password</option>
                  <option value="public_key">Public Key</option>
                </select>
              </div>

              <div className="space-y-2">
                <label className="text-sm font-medium">Sudo Mode</label>
                <select
                  value={formData.sudo_mode}
                  onChange={(e) =>
                    setFormData({ ...formData, sudo_mode: e.target.value })
                  }
                  className="w-full px-3 py-2 border rounded-md bg-background"
                >
                  <option value="sudo">sudo</option>
                  <option value="sudo_su">sudo su</option>
                  <option value="sudo_su_dash">sudo su -</option>
                </select>
              </div>
            </div>
          )}
        </div>

        <div className="flex items-center gap-4">
          <button
            type="submit"
            disabled={createScanMutation.isPending}
            className="px-6 py-2 bg-primary text-primary-foreground rounded-md hover:bg-primary/90 disabled:opacity-50"
          >
            {createScanMutation.isPending ? 'Creating...' : 'Create Scan'}
          </button>
          <button
            type="button"
            onClick={() => navigate('/scans')}
            className="px-6 py-2 border rounded-md hover:bg-muted"
          >
            Cancel
          </button>
        </div>
      </form>
    </div>
  );
}
