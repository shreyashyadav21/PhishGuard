import React, { useState, useEffect } from 'react';
import {
  History,
  Search,
  Filter,
  Trash2,
  FileText,
  Download,
  AlertTriangle,
  RotateCcw,
  CheckCircle2,
  AlertOctagon,
  ChevronLeft,
  ChevronRight,
  ShieldAlert,
  ArrowUpDown
} from 'lucide-react';
import api from '../api/client';
import toast from 'react-hot-toast';
import ReportViewModal from '../components/ReportViewModal';

export default function ScanHistory() {
  const [scans, setScans] = useState([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [scanType, setScanType] = useState('all');
  const [classification, setClassification] = useState('all');
  const [sortOrder, setSortOrder] = useState('desc');
  const [selectedScan, setSelectedScan] = useState(null);
  const [showClearConfirm, setShowClearConfirm] = useState(false);

  const fetchScans = async () => {
    setLoading(true);
    try {
      let query = `/scans?sort_order=${sortOrder}&`;
      if (search.trim()) query += `search=${encodeURIComponent(search.trim())}&`;
      if (scanType !== 'all') query += `scan_type=${encodeURIComponent(scanType)}&`;
      if (classification !== 'all') query += `classification=${encodeURIComponent(classification)}&`;

      const res = await api.get(query);
      setScans(res.data.items || []);
      setTotal(res.data.total || 0);
    } catch (err) {
      toast.error('Failed to load scan records');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchScans();
  }, [scanType, classification, sortOrder]);

  const handleSearchSubmit = (e) => {
    e.preventDefault();
    fetchScans();
  };

  const handleDeleteScan = async (scanId) => {
    try {
      await api.delete(`/scans/${scanId}`);
      toast.success(`Scan record #${scanId} deleted`);
      fetchScans();
    } catch (err) {
      toast.error('Failed to delete scan record');
    }
  };

  const handleClearAll = async () => {
    try {
      await api.delete('/scans?confirm=true');
      toast.success('All scan history cleared');
      setShowClearConfirm(false);
      fetchScans();
    } catch (err) {
      toast.error('Failed to clear scan history');
    }
  };

  const openScanDetail = async (scanId) => {
    try {
      const res = await api.get(`/scans/${scanId}`);
      setSelectedScan(res.data);
    } catch (err) {
      toast.error('Unable to fetch detailed report');
    }
  };

  return (
    <div className="space-y-6 pb-12">
      {/* Header */}
      <div className="bg-[#101A2B] p-6 rounded-2xl border border-white/5 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div className="flex items-center space-x-3">
          <div className="w-10 h-10 rounded-xl bg-purple-500/10 text-purple-400 flex items-center justify-center border border-purple-500/20 shadow-md">
            <History className="w-6 h-6" />
          </div>
          <div>
            <h2 className="text-xl font-extrabold text-white">Scan History Repository</h2>
            <p className="text-xs text-[#9BAAC0]">
              Audited historical log of all evaluated URLs and analyzed email bodies.
            </p>
          </div>
        </div>

        <button
          onClick={() => setShowClearConfirm(true)}
          disabled={scans.length === 0}
          className="flex items-center space-x-2 px-3.5 py-2 bg-rose-500/10 text-rose-400 hover:bg-rose-500 hover:text-white border border-rose-500/30 rounded-xl text-xs font-bold transition-all disabled:opacity-40"
        >
          <Trash2 className="w-4 h-4" />
          <span>Clear History</span>
        </button>
      </div>

      {/* Filter and Search Bar */}
      <div className="soc-card p-4 flex flex-col md:flex-row gap-3 items-center justify-between">
        <form onSubmit={handleSearchSubmit} className="relative w-full md:w-80">
          <input
            type="text"
            placeholder="Search target URL, subject..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full bg-[#080E19] border border-white/10 rounded-xl px-4 py-2 pl-9 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-[#00D4FF]"
          />
          <Search className="w-4 h-4 text-slate-400 absolute left-3 top-2.5" />
        </form>

        <div className="flex flex-wrap items-center gap-2 w-full md:w-auto">
          {/* Scan Type Filter */}
          <select
            value={scanType}
            onChange={(e) => setScanType(e.target.value)}
            className="bg-[#080E19] border border-white/10 rounded-xl px-3 py-2 text-xs text-slate-300 focus:outline-none focus:border-[#00D4FF]"
          >
            <option value="all">All Types</option>
            <option value="url">URL Scans</option>
            <option value="email">Email Scans</option>
          </select>

          {/* Classification Filter */}
          <select
            value={classification}
            onChange={(e) => setClassification(e.target.value)}
            className="bg-[#080E19] border border-white/10 rounded-xl px-3 py-2 text-xs text-slate-300 focus:outline-none focus:border-[#00D4FF]"
          >
            <option value="all">All Classifications</option>
            <option value="safe">Safe (0-19)</option>
            <option value="suspicious">Suspicious (20-39)</option>
            <option value="high">High Risk (40-69)</option>
            <option value="critical">Critical Risk (70-100)</option>
          </select>

          {/* Sort Order Toggle */}
          <button
            onClick={() => setSortOrder(sortOrder === 'desc' ? 'asc' : 'desc')}
            className="flex items-center space-x-1.5 px-3 py-2 bg-[#080E19] border border-white/10 rounded-xl text-xs text-slate-300 hover:text-white"
            title="Toggle Sort Order"
          >
            <ArrowUpDown className="w-3.5 h-3.5 text-cyan-400" />
            <span className="capitalize">{sortOrder === 'desc' ? 'Newest' : 'Oldest'}</span>
          </button>
        </div>
      </div>

      {/* History Table */}
      <div className="soc-card p-5 space-y-4">
        <div className="flex items-center justify-between text-xs text-slate-400 pb-2 border-b border-white/5">
          <span>Total Records: <strong className="text-white">{total}</strong></span>
          <span>Database: SQLite Persistent</span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead>
              <tr className="border-b border-white/10 text-slate-400">
                <th className="pb-3 font-semibold">ID</th>
                <th className="pb-3 font-semibold">Type</th>
                <th className="pb-3 font-semibold">Submitted Item</th>
                <th className="pb-3 font-semibold">Score</th>
                <th className="pb-3 font-semibold">Classification</th>
                <th className="pb-3 font-semibold">Date & Time</th>
                <th className="pb-3 font-semibold text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/5">
              {scans.length > 0 ? (
                scans.map((scan) => (
                  <tr key={scan.id} className="hover:bg-white/[0.02] transition-colors">
                    <td className="py-3 font-mono text-slate-400 font-semibold">
                      #{String(scan.id).padStart(5, '0')}
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
                      {new Date(scan.created_at).toLocaleString()}
                    </td>
                    <td className="py-3 text-right">
                      <div className="flex items-center justify-end space-x-2">
                        <button
                          onClick={() => openScanDetail(scan.id)}
                          className="p-1.5 rounded-lg bg-[#00D4FF]/10 text-[#00D4FF] hover:bg-[#00D4FF] hover:text-[#080E19] transition-all"
                          title="View Technical Report"
                        >
                          <FileText className="w-4 h-4" />
                        </button>
                        <a
                          href={`/api/reports/${scan.id}/pdf`}
                          target="_blank"
                          rel="noreferrer"
                          className="p-1.5 rounded-lg bg-white/5 text-slate-300 hover:text-white hover:bg-white/10 transition-all"
                          title="Download PDF"
                        >
                          <Download className="w-4 h-4" />
                        </a>
                        <button
                          onClick={() => handleDeleteScan(scan.id)}
                          className="p-1.5 rounded-lg bg-rose-500/10 text-rose-400 hover:bg-rose-500 hover:text-white transition-all"
                          title="Delete Scan Record"
                        >
                          <Trash2 className="w-4 h-4" />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={7} className="py-12 text-center text-slate-400">
                    No scan records found matching your filters.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Clear Confirmation Modal */}
      {showClearConfirm && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/75 backdrop-blur-sm animate-in fade-in">
          <div className="bg-[#101A2B] border border-rose-500/40 w-full max-w-md rounded-2xl shadow-2xl p-6 space-y-4">
            <div className="flex items-center space-x-3 text-rose-400">
              <AlertTriangle className="w-6 h-6 shrink-0" />
              <h3 className="text-base font-bold text-white">Confirm History Purge</h3>
            </div>
            <p className="text-xs text-slate-300 leading-relaxed">
              Are you sure you want to delete <strong>all {total}</strong> scan history records,
              indicators, and associated recommendations from the SQLite database? This action is permanent.
            </p>
            <div className="flex justify-end space-x-3 pt-2">
              <button
                onClick={() => setShowClearConfirm(false)}
                className="px-4 py-2 bg-white/10 hover:bg-white/15 text-white text-xs font-semibold rounded-xl"
              >
                Cancel
              </button>
              <button
                onClick={handleClearAll}
                className="px-4 py-2 bg-rose-500 hover:bg-rose-600 text-white text-xs font-bold rounded-xl shadow-md"
              >
                Yes, Purge History
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Report Modal */}
      {selectedScan && (
        <ReportViewModal report={selectedScan} onClose={() => setSelectedScan(null)} />
      )}
    </div>
  );
}

