import React, { useState, useEffect } from 'react';
import {
  FileText,
  Download,
  ShieldCheck,
  Search,
  Filter,
  Eye,
  CheckCircle2,
  AlertTriangle,
  Layers,
  Printer
} from 'lucide-react';
import api from '../api/client';
import toast from 'react-hot-toast';
import ReportViewModal from '../components/ReportViewModal';

export default function SecurityReports() {
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);
  const [selectedScan, setSelectedScan] = useState(null);
  const [search, setSearch] = useState('');

  const fetchScans = async () => {
    setLoading(true);
    try {
      const res = await api.get('/scans?limit=50&sort_order=desc');
      setScans(res.data.items || []);
    } catch (err) {
      toast.error('Failed to load scan records for report generation');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchScans();
  }, []);

  const openScanDetail = async (scanId) => {
    try {
      const res = await api.get(`/scans/${scanId}`);
      setSelectedScan(res.data);
    } catch (err) {
      toast.error('Unable to fetch detailed report');
    }
  };

  const handleDownload = (scanId) => {
    window.open(`/api/reports/${scanId}/pdf`, '_blank');
  };

  const filteredScans = scans.filter((s) =>
    s.submitted_item.toLowerCase().includes(search.toLowerCase())
  );

  return (
    <div className="space-y-6 pb-12">
      {/* Header */}
      <div className="bg-[#101A2B] p-6 rounded-2xl border border-white/5 space-y-2">
        <div className="flex items-center space-x-3">
          <div className="w-10 h-10 rounded-xl bg-cyan-500/10 text-[#00D4FF] flex items-center justify-center border border-cyan-500/20 shadow-md">
            <FileText className="w-6 h-6" />
          </div>
          <div>
            <h2 className="text-xl font-extrabold text-white">Security Reports & Compliance Export</h2>
            <p className="text-xs text-[#9BAAC0]">
              Generate downloadable, publication-grade PDF threat assessment reports with technical evidence and remediation steps.
            </p>
          </div>
        </div>
      </div>

      {/* Report Types Showcase Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="soc-card p-5 space-y-3">
          <div className="w-9 h-9 rounded-lg bg-cyan-500/10 text-[#00D4FF] flex items-center justify-center">
            <FileText className="w-5 h-5" />
          </div>
          <h3 className="text-sm font-bold text-white">Individual Scan Audit PDF</h3>
          <p className="text-xs text-slate-300 leading-relaxed">
            Detailed technical report containing risk score, homoglyph distance breakdowns, RFC compliance flags, and action lists.
          </p>
          <div className="pt-2 text-[11px] font-mono text-cyan-400">Format: Standard Letter PDF</div>
        </div>

        <div className="soc-card p-5 space-y-3">
          <div className="w-9 h-9 rounded-lg bg-emerald-500/10 text-[#00E6A0] flex items-center justify-center">
            <ShieldCheck className="w-5 h-5" />
          </div>
          <h3 className="text-sm font-bold text-white">Email Lure & Header Audit</h3>
          <p className="text-xs text-slate-300 leading-relaxed">
            Analyzes spoofed display names, reply-to routing divergences, and embedded hyperlinks with privacy redaction by default.
          </p>
          <div className="pt-2 text-[11px] font-mono text-emerald-400">Zero-Secret Redaction Enforced</div>
        </div>

        <div className="soc-card p-5 space-y-3">
          <div className="w-9 h-9 rounded-lg bg-purple-500/10 text-purple-400 flex items-center justify-center">
            <Layers className="w-5 h-5" />
          </div>
          <h3 className="text-sm font-bold text-white">SOC Executive Summary</h3>
          <p className="text-xs text-slate-300 leading-relaxed">
            High-level metrics on threat volume, detection ratios, and category distributions for security awareness teams and leadership.
          </p>
          <div className="pt-2 text-[11px] font-mono text-purple-400">Management & Incident Ready</div>
        </div>
      </div>

      {/* Available Scan Reports Table */}
      <div className="soc-card p-5 space-y-4">
        <div className="flex flex-col sm:flex-row items-center justify-between gap-4">
          <div>
            <h3 className="text-sm font-bold text-white">Available Target Reports</h3>
            <p className="text-xs text-slate-400">Click to preview in SOC console or download as branded PDF</p>
          </div>

          <div className="relative w-full sm:w-64">
            <input
              type="text"
              placeholder="Search target reports..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="w-full bg-[#080E19] border border-white/10 rounded-xl px-4 py-1.5 pl-8 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-[#00D4FF]"
            />
            <Search className="w-3.5 h-3.5 text-slate-400 absolute left-2.5 top-2.5" />
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead>
              <tr className="border-b border-white/10 text-slate-400">
                <th className="pb-3 font-semibold">Report Reference</th>
                <th className="pb-3 font-semibold">Type</th>
                <th className="pb-3 font-semibold">Evaluated Target</th>
                <th className="pb-3 font-semibold">Score</th>
                <th className="pb-3 font-semibold">Classification</th>
                <th className="pb-3 font-semibold">Generated Date</th>
                <th className="pb-3 font-semibold text-right">Download</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/5">
              {filteredScans.length > 0 ? (
                filteredScans.map((scan) => (
                  <tr key={scan.id} className="hover:bg-white/[0.02] transition-colors">
                    <td className="py-3 font-mono font-bold text-cyan-400">
                      PG-RPT-{String(scan.id).padStart(5, '0')}
                    </td>
                    <td className="py-3">
                      <span className="uppercase text-[10px] font-bold px-2 py-0.5 rounded bg-slate-800 text-slate-300">
                        {scan.scan_type}
                      </span>
                    </td>
                    <td className="py-3 font-mono text-slate-200 max-w-xs truncate select-all">
                      {scan.submitted_item}
                    </td>
                    <td className="py-3 font-bold font-mono">
                      <span
                        className={
                          scan.risk_score >= 70
                            ? 'text-rose-400'
                            : scan.risk_score >= 40
                            ? 'text-orange-400'
                            : scan.risk_score >= 20
                            ? 'text-amber-400'
                            : 'text-emerald-400'
                        }
                      >
                        {scan.risk_score}/100
                      </span>
                    </td>
                    <td className="py-3">
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                          scan.risk_score >= 70
                            ? 'bg-rose-500/10 text-rose-400 border border-rose-500/30'
                            : scan.risk_score >= 40
                            ? 'bg-orange-500/10 text-orange-400 border border-orange-500/30'
                            : scan.risk_score >= 20
                            ? 'bg-amber-500/10 text-amber-400 border border-amber-500/30'
                            : 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/30'
                        }`}
                      >
                        {scan.classification_label}
                      </span>
                    </td>
                    <td className="py-3 text-slate-400 font-mono text-[11px]">
                      {new Date(scan.created_at).toLocaleDateString()}
                    </td>
                    <td className="py-3 text-right">
                      <div className="flex items-center justify-end space-x-2">
                        <button
                          onClick={() => openScanDetail(scan.id)}
                          className="p-1.5 rounded-lg bg-white/5 text-slate-300 hover:text-white hover:bg-white/10"
                          title="Preview Report"
                        >
                          <Eye className="w-4 h-4" />
                        </button>
                        <button
                          onClick={() => handleDownload(scan.id)}
                          className="flex items-center space-x-1 px-2.5 py-1 rounded bg-[#00D4FF]/20 text-[#00D4FF] hover:bg-[#00D4FF] hover:text-[#080E19] font-bold text-[11px] transition-all border border-[#00D4FF]/30"
                        >
                          <Download className="w-3.5 h-3.5" />
                          <span>PDF</span>
                        </button>
                      </div>
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={7} className="py-8 text-center text-slate-400">
                    No reports found. Execute a scan to generate your first security report.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Report Modal */}
      {selectedScan && (
        <ReportViewModal report={selectedScan} onClose={() => setSelectedScan(null)} />
      )}
    </div>
  );
}

