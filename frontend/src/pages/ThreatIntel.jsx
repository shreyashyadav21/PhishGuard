import React, { useState, useEffect } from 'react';
import {
  Radar,
  Search,
  Filter,
  AlertTriangle,
  AlertOctagon,
  ShieldAlert,
  Info,
  Calendar,
  Layers,
  X,
  ExternalLink,
  ShieldCheck,
  Activity,
  CheckCircle2
} from 'lucide-react';
import api from '../api/client';
import toast from 'react-hot-toast';

export default function ThreatIntel() {
  const [threats, setThreats] = useState([]);
  const [metrics, setMetrics] = useState({ total_threats: 0, critical_count: 0, high_count: 0, total_observed_scans: 0 });
  const [loading, setLoading] = useState(true);
  const [category, setCategory] = useState('all');
  const [severity, setSeverity] = useState('all');
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedThreat, setSelectedThreat] = useState(null);

  const categories = [
    { id: 'all', label: 'All Categories' },
    { id: 'Domain Impersonation', label: 'Domain Impersonation' },
    { id: 'Credential Theft', label: 'Credential Theft' },
    { id: 'Suspicious Redirection', label: 'Suspicious Redirection' },
    { id: 'Social Engineering', label: 'Social Engineering' },
    { id: 'Malicious URL Structure', label: 'URL Structure' }
  ];

  const severities = ['all', 'Critical', 'High', 'Medium', 'Low'];

  const fetchThreats = async () => {
    setLoading(true);
    try {
      let query = `/threats?`;
      if (category !== 'all') query += `category=${encodeURIComponent(category)}&`;
      if (severity !== 'all') query += `severity=${encodeURIComponent(severity)}&`;
      if (searchTerm.trim()) query += `search=${encodeURIComponent(searchTerm.trim())}&`;

      const res = await api.get(query);
      setThreats(res.data.items || []);
      setMetrics({
        total_threats: res.data.total_threats,
        critical_count: res.data.critical_count,
        high_count: res.data.high_count,
        total_observed_scans: res.data.total_observed_scans
      });
    } catch (err) {
      toast.error('Failed to load threat intelligence feed');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchThreats();
  }, [category, severity]);

  const handleSearchSubmit = (e) => {
    e.preventDefault();
    fetchThreats();
  };

  return (
    <div className="space-y-6 pb-12">
      {/* Header */}
      <div className="bg-[#101A2B] p-6 rounded-2xl border border-white/5 space-y-2">
        <div className="flex items-center space-x-3">
          <div className="w-10 h-10 rounded-xl bg-amber-500/10 text-[#FFB020] flex items-center justify-center border border-amber-500/20 shadow-md">
            <Radar className="w-6 h-6" />
          </div>
          <div>
            <h2 className="text-xl font-extrabold text-white">Threat Intelligence Center</h2>
            <p className="text-xs text-[#9BAAC0]">
              Surveillance on persistent threat indicators, impersonation signatures, and localized IOC telemetry.
            </p>
          </div>
        </div>

        {/* Disclaimer Note */}
        <div className="mt-3 p-3 rounded-lg bg-[#080E19] border border-amber-500/20 text-xs text-amber-300 flex items-start space-x-2">
          <Info className="w-4 h-4 shrink-0 mt-0.5 text-amber-400" />
          <span>
            <strong>Provenance & Integrity Disclosure:</strong> Indicators are derived strictly from your local scan history
            and explicitly labeled demonstration records. PhishGuard does not misrepresent local heuristics as verified global feeds.
          </span>
        </div>
      </div>

      {/* Summary KPI Strip */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <div className="soc-card p-4">
          <span className="text-[11px] font-semibold text-slate-400">Tracked Indicators</span>
          <p className="text-2xl font-black text-white mt-1">{metrics.total_threats}</p>
          <span className="text-[10px] text-slate-400">Total in repository</span>
        </div>
        <div className="soc-card p-4">
          <span className="text-[11px] font-semibold text-slate-400">Critical Threats</span>
          <p className="text-2xl font-black text-rose-400 mt-1">{metrics.critical_count}</p>
          <span className="text-[10px] text-rose-400/80">Immediate perimeter block</span>
        </div>
        <div className="soc-card p-4">
          <span className="text-[11px] font-semibold text-slate-400">High Risk Signals</span>
          <p className="text-2xl font-black text-orange-400 mt-1">{metrics.high_count}</p>
          <span className="text-[10px] text-orange-400/80">Elevated scrutiny</span>
        </div>
        <div className="soc-card p-4">
          <span className="text-[11px] font-semibold text-slate-400">Observed Scan Hits</span>
          <p className="text-2xl font-black text-[#00D4FF] mt-1">{metrics.total_observed_scans}</p>
          <span className="text-[10px] text-cyan-400/80">Historical correlation</span>
        </div>
      </div>

      {/* Filters & Search Toolbar */}
      <div className="soc-card p-4 flex flex-col md:flex-row gap-4 items-center justify-between">
        <form onSubmit={handleSearchSubmit} className="relative w-full md:w-80">
          <input
            type="text"
            placeholder="Search indicator, domain, reason..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full bg-[#080E19] border border-white/10 rounded-xl px-4 py-2 pl-9 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-[#00D4FF]"
          />
          <Search className="w-4 h-4 text-slate-400 absolute left-3 top-2.5" />
        </form>

        <div className="flex flex-wrap items-center gap-2 w-full md:w-auto">
          {/* Category Filter */}
          <select
            value={category}
            onChange={(e) => setCategory(e.target.value)}
            className="bg-[#080E19] border border-white/10 rounded-xl px-3 py-2 text-xs text-slate-300 focus:outline-none focus:border-[#00D4FF]"
          >
            {categories.map((c) => (
              <option key={c.id} value={c.id}>
                {c.label}
              </option>
            ))}
          </select>

          {/* Severity Filter */}
          <div className="flex bg-[#080E19] p-1 rounded-xl border border-white/10 text-xs">
            {severities.map((sev) => (
              <button
                key={sev}
                onClick={() => setSeverity(sev)}
                className={`px-3 py-1 rounded-lg font-semibold capitalize transition-all ${
                  severity === sev
                    ? 'bg-[#00D4FF] text-[#080E19]'
                    : 'text-slate-400 hover:text-white'
                }`}
              >
                {sev}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Threat Indicators Table */}
      <div className="soc-card p-5 space-y-4">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead>
              <tr className="border-b border-white/10 text-slate-400">
                <th className="pb-3 font-semibold">Indicator (Host / Sender)</th>
                <th className="pb-3 font-semibold">Category</th>
                <th className="pb-3 font-semibold">Severity</th>
                <th className="pb-3 font-semibold">Type</th>
                <th className="pb-3 font-semibold">Seen Count</th>
                <th className="pb-3 font-semibold">First Observed</th>
                <th className="pb-3 font-semibold text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/5">
              {threats.length > 0 ? (
                threats.map((threat) => (
                  <tr key={threat.id} className="hover:bg-white/[0.02] transition-colors">
                    <td className="py-3.5 font-mono font-bold text-cyan-300 max-w-xs truncate select-all">
                      {threat.indicator_value}
                    </td>
                    <td className="py-3.5">
                      <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-300 font-medium">
                        {threat.category}
                      </span>
                    </td>
                    <td className="py-3.5">
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] uppercase font-bold ${
                          threat.severity === 'Critical'
                            ? 'bg-rose-500/10 text-rose-400 border border-rose-500/30'
                            : threat.severity === 'High'
                            ? 'bg-orange-500/10 text-orange-400 border border-orange-500/30'
                            : threat.severity === 'Medium'
                            ? 'bg-amber-500/10 text-amber-400 border border-amber-500/30'
                            : 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/30'
                        }`}
                      >
                        {threat.severity}
                      </span>
                    </td>
                    <td className="py-3.5">
                      {threat.is_simulated ? (
                        <span className="px-2 py-0.5 rounded bg-purple-500/10 text-purple-300 border border-purple-500/20 text-[10px] font-semibold">
                          Simulated Seed
                        </span>
                      ) : (
                        <span className="px-2 py-0.5 rounded bg-cyan-500/10 text-cyan-300 border border-cyan-500/20 text-[10px] font-semibold">
                          Live Local Scan
                        </span>
                      )}
                    </td>
                    <td className="py-3.5 font-mono text-slate-300 font-semibold">
                      {threat.scan_count} hits
                    </td>
                    <td className="py-3.5 text-slate-400 font-mono text-[11px]">
                      {new Date(threat.first_observed).toLocaleDateString()}
                    </td>
                    <td className="py-3.5 text-right">
                      <button
                        onClick={() => setSelectedThreat(threat)}
                        className="px-2.5 py-1 rounded bg-[#00D4FF]/10 text-[#00D4FF] hover:bg-[#00D4FF] hover:text-[#080E19] font-semibold text-[11px] transition-all"
                      >
                        Inspect Details
                      </button>
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={7} className="py-8 text-center text-slate-400">
                    No threat indicators match the selected criteria.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Threat Detail Modal */}
      {selectedThreat && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/75 backdrop-blur-sm animate-in fade-in duration-200">
          <div className="bg-[#101A2B] border border-[#00D4FF]/30 w-full max-w-xl rounded-2xl shadow-2xl p-6 space-y-5">
            <div className="flex items-center justify-between border-b border-white/10 pb-4">
              <div className="flex items-center space-x-2">
                <Radar className="w-5 h-5 text-[#FFB020]" />
                <h3 className="text-base font-bold text-white">Threat Intelligence Detail</h3>
              </div>
              <button
                onClick={() => setSelectedThreat(null)}
                className="p-1.5 text-slate-400 hover:text-white rounded-lg hover:bg-white/10"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="space-y-4">
              <div>
                <span className="text-[10px] text-slate-400 uppercase font-semibold">Indicator Signature</span>
                <p className="font-mono text-sm text-cyan-300 bg-[#080E19] p-2.5 rounded-lg border border-white/5 mt-1 select-all">
                  {selectedThreat.indicator_value}
                </p>
              </div>

              <div className="grid grid-cols-2 gap-3 text-xs">
                <div className="bg-[#142238] p-3 rounded-xl border border-white/5">
                  <span className="text-slate-400 text-[10px]">Threat Category</span>
                  <p className="font-bold text-white mt-0.5">{selectedThreat.category}</p>
                </div>
                <div className="bg-[#142238] p-3 rounded-xl border border-white/5">
                  <span className="text-slate-400 text-[10px]">Severity Rating</span>
                  <p className="font-bold text-rose-400 mt-0.5">{selectedThreat.severity}</p>
                </div>
                <div className="bg-[#142238] p-3 rounded-xl border border-white/5">
                  <span className="text-slate-400 text-[10px]">Repository Source</span>
                  <p className="font-bold text-white mt-0.5">
                    {selectedThreat.is_simulated ? 'Demonstration Dataset' : 'Local Sensor Telemetry'}
                  </p>
                </div>
                <div className="bg-[#142238] p-3 rounded-xl border border-white/5">
                  <span className="text-slate-400 text-[10px]">Associated Scans</span>
                  <p className="font-bold text-white mt-0.5 font-mono">{selectedThreat.scan_count} events</p>
                </div>
              </div>

              <div>
                <span className="text-[10px] text-slate-400 uppercase font-semibold">Detection Reason</span>
                <p className="text-xs text-slate-200 bg-[#142238] p-3 rounded-xl border border-white/5 mt-1 leading-relaxed">
                  {selectedThreat.detection_reason}
                </p>
              </div>

              <div>
                <span className="text-[10px] text-slate-400 uppercase font-semibold">Recommended Mitigation</span>
                <div className="flex items-start space-x-2 text-xs text-emerald-300 bg-emerald-950/20 p-3 rounded-xl border border-emerald-500/20 mt-1">
                  <ShieldCheck className="w-4 h-4 text-[#00E6A0] shrink-0 mt-0.5" />
                  <span>{selectedThreat.recommended_action}</span>
                </div>
              </div>
            </div>

            <div className="pt-2 flex justify-end">
              <button
                onClick={() => setSelectedThreat(null)}
                className="px-4 py-2 bg-white/10 hover:bg-white/15 text-white text-xs font-semibold rounded-xl transition-all"
              >
                Close Inspector
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

