import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { useMutation } from '@tanstack/react-query';
import { scanAPI } from '../services/api';
import { ArrowLeft } from 'lucide-react';
import axios from 'axios';

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
    // SSH Credentials
    ssh_password: '',
    ssh_private_key_content: '',
    ssh_private_key_path: '',
    ssh_key_passphrase: '',
    // SCC Configuration
    scc_profiles: [] as string[],
    scc_auto_detect: true,
    // Antivirus Configuration
    av_scan_paths: '',
    av_full_scan: false,
    av_use_clamav: true,
    av_use_yara: true,
    av_yara_rules_path: '',
  });

  const [availableKeys, setAvailableKeys] = useState<any[]>([]);
  const [availableBenchmarks, setAvailableBenchmarks] = useState<any[]>([]);

  // Fetch available SSH keys when component mounts or auth method changes
  useEffect(() => {
    if (formData.auth_method === 'local_ssh_keys') {
      const fetchKeys = async () => {
        try {
          const response = await axios.get('/api/v1/scans/ssh/available-keys');
          setAvailableKeys(response.data.keys || []);
        } catch (error) {
          console.error('Failed to fetch SSH keys:', error);
        }
      };
      fetchKeys();
    }
  }, [formData.auth_method]);

  // Fetch available SCC benchmarks when scan type includes SCC
  useEffect(() => {
    if (formData.scan_type === 'scc' || formData.scan_type === 'full') {
      const fetchBenchmarks = async () => {
        try {
          const response = await axios.get('/api/v1/scans/scc/available-benchmarks');
          setAvailableBenchmarks(response.data.benchmarks || []);
        } catch (error) {
          console.error('Failed to fetch SCC benchmarks:', error);
        }
      };
      fetchBenchmarks();
    }
  }, [formData.scan_type]);

  const createScanMutation = useMutation({
    mutationFn: async (data: any) => {
      const response = await scanAPI.create(data);
      return response.data;
    },
    onSuccess: (scan) => {
      // Navigate to the scan details page to watch progress
      navigate(`/scans/${scan.id}`);
    },
  });

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();

    const scanData = {
      ...formData,
      targets: formData.targets.split('\n').filter((t) => t.trim()),
      ssh_port: parseInt(formData.ssh_port.toString()),
      // Parse antivirus scan paths if provided
      av_scan_paths: formData.av_scan_paths
        ? formData.av_scan_paths.split('\n').filter((p) => p.trim())
        : null,
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
              <option value="scc">SCC (SCAP Compliance Checker)</option>
              <option value="antivirus">Antivirus Scan (ClamAV + YARA)</option>
              <option value="full">Full Scan (All Types)</option>
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
                  <option value="public_key">Public Key (File Path)</option>
                  <option value="private_key_content">Private Key (Paste Content)</option>
                  <option value="local_ssh_keys">Use Local SSH Keys (~/.ssh/)</option>
                </select>
              </div>

              {/* Password Authentication */}
              {formData.auth_method === 'password' && (
                <div className="space-y-2">
                  <label className="text-sm font-medium">SSH Password</label>
                  <input
                    type="password"
                    value={formData.ssh_password}
                    onChange={(e) =>
                      setFormData({ ...formData, ssh_password: e.target.value })
                    }
                    className="w-full px-3 py-2 border rounded-md bg-background"
                    placeholder="Enter SSH password"
                  />
                </div>
              )}

              {/* Public Key File Path */}
              {formData.auth_method === 'public_key' && (
                <div className="space-y-2">
                  <label className="text-sm font-medium">Private Key Path</label>
                  <input
                    type="text"
                    value={formData.ssh_private_key_path}
                    onChange={(e) =>
                      setFormData({ ...formData, ssh_private_key_path: e.target.value })
                    }
                    className="w-full px-3 py-2 border rounded-md bg-background"
                    placeholder="/path/to/private/key"
                  />
                </div>
              )}

              {/* Private Key Content */}
              {formData.auth_method === 'private_key_content' && (
                <div className="space-y-2">
                  <label className="text-sm font-medium">Private Key Content</label>
                  <textarea
                    value={formData.ssh_private_key_content}
                    onChange={(e) =>
                      setFormData({ ...formData, ssh_private_key_content: e.target.value })
                    }
                    className="w-full px-3 py-2 border rounded-md bg-background h-32 font-mono text-xs"
                    placeholder="-----BEGIN RSA PRIVATE KEY-----&#10;...&#10;-----END RSA PRIVATE KEY-----"
                  />
                </div>
              )}

              {/* Local SSH Keys */}
              {formData.auth_method === 'local_ssh_keys' && (
                <div className="space-y-2">
                  <label className="text-sm font-medium">Select SSH Key</label>
                  <select
                    value={formData.ssh_private_key_path}
                    onChange={(e) =>
                      setFormData({ ...formData, ssh_private_key_path: e.target.value })
                    }
                    className="w-full px-3 py-2 border rounded-md bg-background"
                  >
                    <option value="">Auto-detect (try all keys)</option>
                    {availableKeys.map((key) => (
                      <option key={key.path} value={key.path}>
                        {key.name} ({key.modified})
                      </option>
                    ))}
                  </select>
                  {availableKeys.length === 0 && (
                    <p className="text-sm text-yellow-600">No SSH keys found in ~/.ssh/</p>
                  )}
                </div>
              )}

              {/* Key Passphrase */}
              {(formData.auth_method === 'public_key' ||
                formData.auth_method === 'private_key_content' ||
                formData.auth_method === 'local_ssh_keys') && (
                <div className="space-y-2">
                  <label className="text-sm font-medium">Key Passphrase (if required)</label>
                  <input
                    type="password"
                    value={formData.ssh_key_passphrase}
                    onChange={(e) =>
                      setFormData({ ...formData, ssh_key_passphrase: e.target.value })
                    }
                    className="w-full px-3 py-2 border rounded-md bg-background"
                    placeholder="Leave empty if key has no passphrase"
                  />
                </div>
              )}

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

        {/* SCC Configuration */}
        {(formData.scan_type === 'scc' || formData.scan_type === 'full') && (
          <div className="rounded-lg border bg-card p-6 space-y-4">
            <h2 className="text-lg font-semibold">SCC Configuration</h2>

            <div className="space-y-2">
              <label className="flex items-center gap-2">
                <input
                  type="checkbox"
                  checked={formData.scc_auto_detect}
                  onChange={(e) =>
                    setFormData({ ...formData, scc_auto_detect: e.target.checked })
                  }
                  className="rounded border-gray-300"
                />
                <span className="text-sm">Auto-detect OS and apply appropriate STIG</span>
              </label>
            </div>

            {!formData.scc_auto_detect && (
              <div className="space-y-2">
                <label className="text-sm font-medium">Select SCAP Benchmarks</label>
                <select
                  multiple
                  value={formData.scc_profiles}
                  onChange={(e) => {
                    const selected = Array.from(e.target.selectedOptions, option => option.value);
                    setFormData({ ...formData, scc_profiles: selected });
                  }}
                  className="w-full px-3 py-2 border rounded-md bg-background h-40"
                >
                  {availableBenchmarks.map((benchmark) => (
                    <option key={benchmark.id} value={benchmark.path}>
                      {benchmark.name} ({benchmark.version})
                    </option>
                  ))}
                </select>
                <p className="text-sm text-muted-foreground">
                  Hold Ctrl/Cmd to select multiple benchmarks
                </p>
              </div>
            )}
          </div>
        )}

        {/* Antivirus Configuration */}
        {(formData.scan_type === 'antivirus' || formData.scan_type === 'full') && (
          <div className="rounded-lg border bg-card p-6 space-y-4">
            <h2 className="text-lg font-semibold">Antivirus Configuration</h2>

            <div className="grid grid-cols-2 gap-4">
              <label className="flex items-center gap-2">
                <input
                  type="checkbox"
                  checked={formData.av_use_clamav}
                  onChange={(e) =>
                    setFormData({ ...formData, av_use_clamav: e.target.checked })
                  }
                  className="rounded border-gray-300"
                />
                <span className="text-sm">Use ClamAV</span>
              </label>

              <label className="flex items-center gap-2">
                <input
                  type="checkbox"
                  checked={formData.av_use_yara}
                  onChange={(e) =>
                    setFormData({ ...formData, av_use_yara: e.target.checked })
                  }
                  className="rounded border-gray-300"
                />
                <span className="text-sm">Use YARA</span>
              </label>
            </div>

            <div className="space-y-2">
              <label className="flex items-center gap-2">
                <input
                  type="checkbox"
                  checked={formData.av_full_scan}
                  onChange={(e) =>
                    setFormData({ ...formData, av_full_scan: e.target.checked })
                  }
                  className="rounded border-gray-300"
                />
                <span className="text-sm">Full System Scan</span>
              </label>
            </div>

            {!formData.av_full_scan && (
              <div className="space-y-2">
                <label className="text-sm font-medium">
                  Scan Paths (one per line)
                </label>
                <textarea
                  value={formData.av_scan_paths}
                  onChange={(e) =>
                    setFormData({ ...formData, av_scan_paths: e.target.value })
                  }
                  className="w-full px-3 py-2 border rounded-md bg-background h-24"
                  placeholder="/home&#10;/var/www&#10;/opt"
                />
              </div>
            )}

            {formData.av_use_yara && (
              <div className="space-y-2">
                <label className="text-sm font-medium">
                  Custom YARA Rules Path (optional)
                </label>
                <input
                  type="text"
                  value={formData.av_yara_rules_path}
                  onChange={(e) =>
                    setFormData({ ...formData, av_yara_rules_path: e.target.value })
                  }
                  className="w-full px-3 py-2 border rounded-md bg-background"
                  placeholder="/path/to/yara/rules"
                />
              </div>
            )}
          </div>
        )}

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
