import React, { useState, useEffect } from 'react';
import {
  Layers,
  RefreshCw,
  ShieldAlert,
  AlertTriangle,
  Calendar,
  Activity,
  Flame,
  ExternalLink,
  ChevronRight,
  TrendingUp
} from 'lucide-react';
import api from '../api/client';
import toast from 'react-hot-toast';

export default function CampaignDetection() {
  const [campaigns, setCampaigns] = useState([]);
  const [loading, setLoading] = useState(true);
  const [correlating, setCorrelating] = useState(false);

  const fetchCampaigns = async () => {
    setLoading(true);
    try {
      const res = await api.get('/campaigns');
      setCampaigns(res.data || []);
    } catch (err) {
      toast.error('Failed to load campaigns');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchCampaigns();
  }, []);

  const handleRunCorrelation = async () => {
    setCorrelating(true);
    try {
      const res = await api.post('/campaigns/correlate');
      toast.success(`Correlation complete: ${res.data.correlated_campaigns_count} active campaign(s) identified.`);
      fetchCampaigns();
    } catch (err) {
      toast.error('Correlation analysis failed');
    } finally {
      setCorrelating(false);
    }
  };

  return (
    <div className="space-y-6 pb-12 max-w-5xl mx-auto">
      {/* Header */}
      <div className="bg-[#101A2B] p-6 rounded-2xl border border-white/5 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div className="flex items-center space-x-3">
          <div className="w-10 h-10 rounded-xl bg-purple-500/10 text-purple-400 flex items-center justify-center border border-purple-500/20 shadow-md">
            <Layers className="w-6 h-6" />
          </div>
          <div>
            <h2 className="text-xl font-extrabold text-white">Phishing Campaign Correlation Engine</h2>
            <p className="text-xs text-[#9BAAC0]">
              Detects coordinated multi-message attack waves sharing infrastructure, brand targets, and lure templates.
            </p>
          </div>
        </div>

        <button
          onClick={handleRunCorrelation}
          disabled={correlating}
          className="flex items-center space-x-2 px-5 py-2.5 bg-[#00D4FF] text-[#080E19] font-bold text-xs rounded-xl hover:bg-[#00E6A0] transition-all shadow-md shadow-[#00D4FF]/20"
        >
          <RefreshCw className={`w-4 h-4 ${correlating ? 'animate-spin' : ''}`} />
          <span>{correlating ? 'Correlating Clusters...' : 'Run Correlation Analysis'}</span>
        </button>
      </div>

      {/* Campaigns Grid */}
      <div className="space-y-4">
        {campaigns.length > 0 ? (
          campaigns.map((camp) => (
            <div key={camp.id} className="soc-card p-6 space-y-4 hover:border-purple-500/40 transition-colors">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-white/5 pb-3">
                <div className="flex items-center space-x-3">
                  <div className="w-8 h-8 rounded-lg bg-rose-500/10 text-rose-400 flex items-center justify-center font-bold">
                    <Flame className="w-4 h-4" />
                  </div>
                  <div>
                    <h3 className="text-sm font-bold text-white">{camp.name}</h3>
                    <span className="text-[11px] text-slate-400">
                      Target Brand: <strong className="text-cyan-400">{camp.target_brand}</strong> &bull; Origin: <strong className="font-mono text-slate-300">{camp.common_domain}</strong>
                    </span>
                  </div>
                </div>

                <div className="flex items-center space-x-2">
                  <span
                    className={`px-2.5 py-0.5 rounded text-[10px] font-bold uppercase ${
                      camp.severity === 'Critical'
                        ? 'bg-rose-500/20 text-rose-400 border border-rose-500/30'
                        : 'bg-orange-500/20 text-orange-400 border border-orange-500/30'
                    }`}
                  >
                    {camp.severity} Severity
                  </span>
                  <span className="px-2 py-0.5 rounded bg-purple-500/10 text-purple-300 border border-purple-500/20 text-[10px] font-bold">
                    {camp.confidence_score}% Confidence
                  </span>
                </div>
              </div>

              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs">
                <div className="bg-[#080E19] p-3 rounded-xl border border-white/5">
                  <span className="text-slate-500 text-[10px] uppercase font-bold">Correlated Messages</span>
                  <p className="font-mono font-bold text-white mt-0.5 text-sm">{camp.email_count} emails</p>
                </div>
                <div className="bg-[#080E19] p-3 rounded-xl border border-white/5">
                  <span className="text-slate-500 text-[10px] uppercase font-bold">First Observed</span>
                  <p className="font-mono font-bold text-slate-300 mt-0.5">
                    {camp.first_observed ? new Date(camp.first_observed).toLocaleDateString() : 'N/A'}
                  </p>
                </div>
                <div className="bg-[#080E19] p-3 rounded-xl border border-white/5">
                  <span className="text-slate-500 text-[10px] uppercase font-bold">Latest Wave</span>
                  <p className="font-mono font-bold text-cyan-300 mt-0.5">
                    {camp.last_observed ? new Date(camp.last_observed).toLocaleDateString() : 'N/A'}
                  </p>
                </div>
                <div className="bg-[#080E19] p-3 rounded-xl border border-white/5">
                  <span className="text-slate-500 text-[10px] uppercase font-bold">Subject Pattern</span>
                  <p className="font-mono text-slate-300 truncate mt-0.5">{camp.common_subject || 'Urgent Notification'}</p>
                </div>
              </div>
            </div>
          ))
        ) : (
          <div className="soc-card p-12 text-center text-xs text-slate-400 space-y-3">
            <Layers className="w-8 h-8 text-slate-500 mx-auto" />
            <p>No multi-message campaigns detected yet. Click "Run Correlation Analysis" above to process existing scans.</p>
          </div>
        )}
      </div>
    </div>
  );
}

