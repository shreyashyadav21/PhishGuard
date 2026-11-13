import React, { useState } from 'react';
import { AlertTriangle, CheckCircle2, ChevronDown, ChevronUp, ExternalLink, LoaderCircle } from 'lucide-react';
import api from '../api/client';

const riskTone = (score) => {
  if (score >= 70) return 'border-rose-400/25 bg-rose-400/10 text-rose-300';
  if (score >= 40) return 'border-orange-300/25 bg-orange-300/10 text-orange-200';
  if (score >= 20) return 'border-amber-300/25 bg-amber-300/10 text-amber-200';
  return 'border-[#d5ff72]/20 bg-[#d5ff72]/10 text-[#d5ff72]';
};

const severityTone = (severity) => {
  const value = severity?.toLowerCase();
  if (value === 'critical' || value === 'high') return 'text-rose-200 border-rose-300/20 bg-rose-300/10';
  if (value === 'medium') return 'text-amber-200 border-amber-300/20 bg-amber-300/10';
  return 'text-slate-300 border-white/10 bg-white/[0.04]';
};

export default function GmailMessageVerdict({ message }) {
  const [expanded, setExpanded] = useState(false);
  const [details, setDetails] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const indicatorCount = message.indicator_count ?? 0;

  const loadDetails = async () => {
    setLoading(true);
    setError('');
    try {
      const response = await api.get(`/scans/${message.scan_id}`);
      setDetails(response.data);
    } catch (requestError) {
      setError(requestError.response?.data?.detail || 'Could not load this message’s threat details.');
    } finally {
      setLoading(false);
    }
  };

  const toggleDetails = () => {
    const shouldExpand = !expanded;
    setExpanded(shouldExpand);
    if (shouldExpand && !details && !loading) loadDetails();
  };

  return (
    <article className="border-b border-white/[0.07] p-5 last:border-b-0 sm:p-6">
      <div className="flex flex-col gap-4 lg:flex-row lg:items-start">
        <span className={`flex h-10 w-10 shrink-0 items-center justify-center rounded-xl border ${riskTone(message.risk_score)}`}>
          {message.risk_score >= 20
            ? <AlertTriangle className="h-4 w-4" />
            : <CheckCircle2 className="h-4 w-4" />}
        </span>

        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <h4 className="min-w-0 flex-1 break-words text-sm font-bold leading-5 text-[#f3f5e9]">
              {message.subject || '(No subject)'}
            </h4>
            <span className={`rounded-full border px-2.5 py-1 text-[10px] font-bold uppercase tracking-[0.08em] ${riskTone(message.risk_score)}`}>
              {message.classification_label}
            </span>
          </div>
          <p className="mt-1 break-all text-xs text-slate-300">
            <span className="text-slate-500">From:</span> {message.sender || 'Unknown sender'}
          </p>
          {message.account_email && (
            <p className="mt-1 break-all text-xs text-slate-400">
              <span className="text-slate-500">Mailbox:</span> {message.account_email}
            </p>
          )}
          <p className="mt-1 text-[10px] text-slate-500">
            {message.created_at ? new Date(message.created_at).toLocaleString() : 'Time unavailable'}
            <span className="mx-2 text-slate-700">•</span>
            Scan #{message.scan_id}
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-3 lg:justify-end">
          <span className="font-mono text-sm font-bold text-[#f3f5e9]">{message.risk_score}/100</span>
          <span className="text-xs text-slate-400">
            {indicatorCount} {indicatorCount === 1 ? 'signal' : 'signals'}
          </span>
          <button
            type="button"
            onClick={toggleDetails}
            aria-expanded={expanded}
            className="inline-flex items-center gap-1.5 rounded-lg border border-white/10 bg-white/[0.04] px-3 py-2 text-xs font-semibold text-slate-200 transition hover:border-[#d5ff72]/25 hover:bg-[#d5ff72]/[0.06] hover:text-[#d5ff72]"
          >
            {expanded ? 'Hide findings' : indicatorCount ? 'View findings' : 'View analysis'}
            {expanded ? <ChevronUp className="h-3.5 w-3.5" /> : <ChevronDown className="h-3.5 w-3.5" />}
          </button>
        </div>
      </div>

      {expanded && (
        <div className="ml-0 mt-5 border-t border-white/10 pt-5 lg:ml-14">
          {loading ? (
            <div className="flex items-center gap-2 py-3 text-xs text-slate-400">
              <LoaderCircle className="h-4 w-4 animate-spin" />
              Loading findings for this message…
            </div>
          ) : error ? (
            <div role="alert" className="flex flex-wrap items-center gap-3 text-xs text-rose-200">
              <span>{error}</span>
              <button onClick={loadDetails} className="font-bold underline underline-offset-2">Retry</button>
            </div>
          ) : details ? (
            <div className="space-y-5">
              <div>
                <h5 className="font-mono text-[10px] font-bold uppercase tracking-[0.16em] text-[#d5ff72]">
                  {details.indicators.length
                    ? `Threat signals found (${details.indicators.length})`
                    : 'No threat signals found'}
                </h5>
                {details.indicators.length > 0 ? (
                  <div className="mt-3 grid gap-3 xl:grid-cols-2">
                    {details.indicators.map((indicator) => (
                      <div key={indicator.id} className="rounded-xl border border-white/10 bg-[#0b100d]/50 p-4">
                        <div className="flex flex-wrap items-center justify-between gap-2">
                          <p className="text-sm font-semibold text-[#f3f5e9]">{indicator.name}</p>
                          <span className={`rounded-full border px-2 py-0.5 font-mono text-[9px] uppercase tracking-[0.08em] ${severityTone(indicator.severity)}`}>
                            {indicator.severity} · +{indicator.points}
                          </span>
                        </div>
                        <p className="mt-2 text-xs leading-5 text-slate-400">{indicator.description}</p>
                      </div>
                    ))}
                  </div>
                ) : (
                  <p className="mt-2 text-xs leading-5 text-slate-400">
                    The analysis did not identify specific phishing indicators in this message.
                  </p>
                )}
              </div>

              {details.recommendations.length > 0 && (
                <div>
                  <h5 className="font-mono text-[10px] font-bold uppercase tracking-[0.16em] text-slate-300">
                    Recommended actions
                  </h5>
                  <ul className="mt-2 space-y-2">
                    {details.recommendations.map((recommendation, index) => (
                      <li key={`${message.scan_id}-recommendation-${index}`} className="flex gap-2 text-xs leading-5 text-slate-400">
                        <span className="text-[#d5ff72]">•</span>
                        {recommendation}
                      </li>
                    ))}
                  </ul>
                </div>
              )}

              <a
                href={`/api/reports/${message.scan_id}/pdf`}
                target="_blank"
                rel="noreferrer"
                className="inline-flex items-center gap-1.5 text-xs font-semibold text-[#d5ff72] hover:text-white"
              >
                Open full report
                <ExternalLink className="h-3.5 w-3.5" />
              </a>
            </div>
          ) : null}
        </div>
      )}
    </article>
  );
}
