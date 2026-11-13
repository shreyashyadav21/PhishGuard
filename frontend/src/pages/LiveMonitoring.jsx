import React, { useState, useEffect } from 'react';
import {
  Radio,
  RefreshCw,
  ShieldCheck,
  AlertTriangle,
  AlertOctagon,
  Trash2,
  FolderMinus,
  CheckCircle2,
  Clock,
  Layers,
  ChevronRight,
  ExternalLink
} from 'lucide-react';
import api from '../api/client';
import toast from 'react-hot-toast';
import ReportViewModal from '../components/ReportViewModal';

export default function LiveMonitoring() {
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);
  const [selectedScan, setSelectedScan] = useState(null);
  const [actionLoadingId, setActionLoadingId] = useState(null);

  const fetchLiveFeed = async () => {
    setLoading(true);
    try {
      const res = await api.get('/scans?scan_type=email&limit=30&sort_order=desc');
      setScans(res.data.items || []);
    } catch (err) {
      toast.error('Failed to load live monitoring feed');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchLiveFeed();
    const interval = setInterval(fetchLiveFeed, 20000); // 20s auto-refresh
    return () => clearInterval(interval);
  }, []);

  const handleAction = async (scan, actionType) => {
    setActionLoadingId(scan.id);
    try {
      await api.post('/gmail/actions', {
        account_email: scan.account_email || 'analyst.demo@phishguard-soc.org',
        gmail_message_id: scan.gmail_message_id || `msg_${scan.id}`,
        action_type: actionType,
        scan_id: scan.id
      });
      toast.success(`Action '${actionType.toUpperCase()}' completed successfully`);
      fetchLiveFeed();
    } catch (err) {
      toast.error(err.response?.data?.detail || `Failed to execute ${actionType}`);
    } finally {
      setActionLoadingId(null);
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
          <div className="w-10 h-10 rounded-xl bg-[#00E6A0]/10 text-[#00E6A0] flex items-center justify-center border border-emerald-500/20 shadow-md">
            <Radio className="w-6 h-6 animate-pulse" />
          </div>
          <div>
            <h2 className="text-xl font-extrabold text-white flex items-center gap-2">
              Live Mailbox Surveillance
              <span className="w-2 h-2 rounded-full bg-[#00E6A0] animate-ping"></span>
            </h2>
            <p className="text-xs text-[#9BAAC0]">
              Continuous stream of incoming emails analyzed via Pub/Sub push notifications and History API sync.
            </p>
          </div>
        </div>

        <button
          onClick={fetchLiveFeed}
          className="flex items-center space-x-1.5 px-3.5 py-2 bg-[#142238] border border-white/10 rounded-xl text-xs text-slate-300 hover:text-white hover:border-[#00D4FF] transition-all"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin text-cyan-400' : ''}`} />
          <span>Refresh Stream</span>
        </button>
      </div>

      {/* Surveillance Feed Table */}
      <div className="soc-card p-5 space-y-4">
        <div className="flex items-center justify-between text-xs text-slate-400 pb-2 border-b border-white/5">
          <span>Active Ingestion Feed &bull; Auto-refreshing every 20s</span>
          <span className="text-emerald-400 font-mono font-bold flex items-center gap-1">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-400"></span>
            Sensors: Listening
          </span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead>
              <tr className="border-b border-white/10 text-slate-400">
                <th className="pb-3 font-semibold">Severity</th>
                <th className="pb-3 font-semibold">Subject / Target Message</th>
                <th className="pb-3 font-semibold">Risk Score</th>
                <th className="pb-3 font-semibold">Indicators</th>
                <th className="pb-3 font-semibold">Detected Date</th>
                <th className="pb-3 font-semibold text-right">User Control Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/5">
              {scans.length > 0 ? (
                scans.map((scan) => (
                  <tr key={scan.id} className="hover:bg-white/[0.02] transition-colors">
                    <td className="py-3.5">
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
                    <td className="py-3.5 font-mono text-slate-200 max-w-sm truncate select-all">
                      <button
                        onClick={() => openScanDetail(scan.id)}
                        className="hover:text-cyan-400 text-left font-semibold truncate block w-full"
                      >
                        {scan.submitted_item}
                      </button>
                    </td>
                    <td className="py-3.5 font-bold font-mono">
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
                    <td className="py-3.5 text-slate-400 text-[11px]">
                      {scan.indicator_count} flagged markers
                    </td>
                    <td className="py-3.5 text-slate-400 font-mono text-[11px]">
                      {new Date(scan.created_at).toLocaleTimeString()}
                    </td>
                    <td className="py-3.5 text-right">
                      <div className="flex items-center justify-end space-x-1.5">
                        <button
                          onClick={() => handleAction(scan, 'keep')}
                          disabled={actionLoadingId === scan.id}
                          className="px-2 py-1 rounded bg-white/5 hover:bg-white/10 text-slate-300 text-[11px] font-semibold"
                          title="Keep in Inbox"
                        >
                          Keep
                        </button>
                        <button
                          onClick={() => handleAction(scan, 'quarantine')}
                          disabled={actionLoadingId === scan.id}
                          className="px-2 py-1 rounded bg-amber-500/20 text-amber-300 hover:bg-amber-500 hover:text-black border border-amber-500/30 text-[11px] font-bold"
                          title="Apply Quarantine Label and remove from INBOX"
                        >
                          Quarantine
                        </button>
                        <button
                          onClick={() => handleAction(scan, 'trash')}
                          disabled={actionLoadingId === scan.id}
                          className="px-2 py-1 rounded bg-rose-500/20 text-rose-300 hover:bg-rose-500 hover:text-white border border-rose-500/30 text-[11px] font-bold"
                          title="Move to Trash"
                        >
                          Trash
                        </button>
                      </div>
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={6} className="py-12 text-center text-slate-400">
                    No monitored messages currently in queue. Sync your Gmail or trigger a test scan!
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Modal */}
      {selectedScan && (
        <ReportViewModal report={selectedScan} onClose={() => setSelectedScan(null)} />
      )}
    </div>
  );
}

