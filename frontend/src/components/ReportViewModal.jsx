import React from 'react';
import {
  X,
  Download,
  AlertTriangle,
  ShieldCheck,
  CheckCircle2,
  ExternalLink,
  Calendar,
  Layers,
  FileCheck
} from 'lucide-react';
import RiskMeter from './RiskMeter';

export default function ReportViewModal({ report, onClose }) {
  if (!report) return null;

  const handleDownloadPdf = () => {
    if (!report.id) return;
    const url = `/api/reports/${report.id}/pdf`;
    window.open(url, '_blank');
  };

  const indicators = report.indicators || [];
  const positiveObs = report.positive_observations || [];
  const recommendations = report.recommendations || [];

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/75 backdrop-blur-sm animate-in fade-in duration-200">
      <div className="bg-[#101A2B] border border-[#00D4FF]/30 w-full max-w-3xl max-h-[90vh] rounded-2xl shadow-2xl flex flex-col overflow-hidden">
        {/* Header */}
        <div className="px-6 py-4 bg-[#142238] border-b border-white/10 flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <span className="w-2.5 h-2.5 rounded-full bg-[#00D4FF]"></span>
            <div>
              <h2 className="text-base font-bold text-white">
                Phishing Analysis Report #{report.id ? String(report.id).padStart(5, '0') : 'LIVE'}
              </h2>
              <p className="text-xs text-slate-400">
                Target Type: <span className="uppercase font-semibold text-slate-200">{report.scan_type}</span>
              </p>
            </div>
          </div>
          <div className="flex items-center space-x-2">
            <button
              onClick={handleDownloadPdf}
              className="flex items-center space-x-1.5 px-3 py-1.5 bg-[#00D4FF]/20 text-[#00D4FF] hover:bg-[#00D4FF] hover:text-[#080E19] rounded-lg text-xs font-bold transition-all border border-[#00D4FF]/30"
            >
              <Download className="w-4 h-4" />
              <span>Download PDF</span>
            </button>
            <button
              onClick={onClose}
              className="p-1.5 text-slate-400 hover:text-white rounded-lg hover:bg-white/10 transition-colors"
            >
              <X className="w-5 h-5" />
            </button>
          </div>
        </div>

        {/* Content Body */}
        <div className="flex-1 p-6 overflow-y-auto space-y-6">
          {/* Executive Overview Row */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6 items-center bg-[#080E19]/80 p-5 rounded-xl border border-white/5">
            <div className="md:col-span-1 flex justify-center">
              <RiskMeter score={report.risk_score} classification={report.classification} />
            </div>
            <div className="md:col-span-2 space-y-3">
              <div>
                <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">
                  Submitted Content / Target
                </span>
                <p className="font-mono text-sm text-cyan-300 break-all bg-[#142238] p-2.5 rounded-lg border border-white/5 mt-1 select-all">
                  {report.submitted_item || 'N/A'}
                </p>
              </div>

              <div className="grid grid-cols-2 gap-3 text-xs">
                <div className="bg-[#142238] p-2 rounded border border-white/5">
                  <span className="text-slate-400 text-[10px]">Evaluation Status</span>
                  <p className="font-bold text-white capitalize">{report.analysis_details?.analysis_status || 'Completed'}</p>
                </div>
                <div className="bg-[#142238] p-2 rounded border border-white/5">
                  <span className="text-slate-400 text-[10px]">Timestamp</span>
                  <p className="font-mono text-white text-[11px]">
                    {report.created_at ? new Date(report.created_at).toLocaleString() : 'Just now'}
                  </p>
                </div>
              </div>
            </div>
          </div>

          {/* Detected Threat Indicators */}
          <div className="space-y-3">
            <h3 className="text-sm font-bold text-white flex items-center space-x-2">
              <AlertTriangle className="w-4 h-4 text-[#FFB020]" />
              <span>Detected Threat Indicators ({indicators.length})</span>
            </h3>

            {indicators.length > 0 ? (
              <div className="space-y-2">
                {indicators.map((ind, i) => (
                  <div
                    key={i}
                    className="p-3.5 rounded-xl bg-[#142238]/80 border border-white/5 flex flex-col sm:flex-row sm:items-start justify-between gap-3"
                  >
                    <div className="space-y-1">
                      <div className="flex items-center space-x-2">
                        <span className="text-xs font-bold text-white">{ind.name}</span>
                        <span
                          className={`px-2 py-0.5 text-[10px] uppercase font-bold rounded ${
                            ind.severity === 'critical'
                              ? 'bg-rose-500/20 text-rose-400 border border-rose-500/30'
                              : ind.severity === 'high'
                              ? 'bg-orange-500/20 text-orange-400 border border-orange-500/30'
                              : ind.severity === 'medium'
                              ? 'bg-amber-500/20 text-amber-400 border border-amber-500/30'
                              : 'bg-slate-700 text-slate-300'
                          }`}
                        >
                          {ind.severity}
                        </span>
                      </div>
                      <p className="text-xs text-slate-300 leading-relaxed">{ind.description}</p>
                      {ind.evidence && (
                        <p className="text-[11px] font-mono text-cyan-400/80 bg-black/30 px-2 py-1 rounded inline-block">
                          Evidence: {ind.evidence}
                        </p>
                      )}
                    </div>
                    <div className="shrink-0 text-right">
                      <span className="px-2.5 py-1 rounded bg-black/40 border border-white/10 text-xs font-mono font-bold text-white">
                        +{ind.points} pts
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <div className="p-4 rounded-xl bg-[#080E19] border border-white/5 text-center text-xs text-slate-400">
                No threat indicators flagged during static heuristic evaluation.
              </div>
            )}
          </div>

          {/* Positive Observations */}
          {positiveObs.length > 0 && (
            <div className="space-y-2">
              <h3 className="text-sm font-bold text-white flex items-center space-x-2">
                <CheckCircle2 className="w-4 h-4 text-[#00E6A0]" />
                <span>Positive Security Observations</span>
              </h3>
              <div className="p-3.5 rounded-xl bg-[#080E19]/90 border border-emerald-500/20 space-y-1.5">
                {positiveObs.map((obs, idx) => (
                  <div key={idx} className="flex items-start space-x-2 text-xs text-emerald-300">
                    <span className="text-[#00E6A0] mt-0.5">•</span>
                    <span>{obs}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Recommended Actions */}
          <div className="space-y-2">
            <h3 className="text-sm font-bold text-white flex items-center space-x-2">
              <ShieldCheck className="w-4 h-4 text-[#00D4FF]" />
              <span>Recommended Security Actions</span>
            </h3>
            <div className="p-4 rounded-xl bg-[#142238] border border-white/5 space-y-2">
              {recommendations.map((rec, idx) => (
                <div key={idx} className="flex items-start space-x-2.5 text-xs text-slate-200">
                  <span className="w-5 h-5 rounded-full bg-[#00D4FF]/20 text-[#00D4FF] font-bold text-[10px] flex items-center justify-center shrink-0 mt-0.5">
                    {idx + 1}
                  </span>
                  <span className="leading-relaxed">{rec}</span>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Footer */}
        <div className="px-6 py-3 bg-[#080E19] border-t border-white/5 flex items-center justify-between text-xs text-slate-400">
          <span>PhishGuard Static Zero-SSRF Analysis</span>
          <button
            onClick={onClose}
            className="px-4 py-1.5 rounded-lg bg-white/10 hover:bg-white/15 text-white font-medium transition-colors"
          >
            Close Report
          </button>
        </div>
      </div>
    </div>
  );
}

