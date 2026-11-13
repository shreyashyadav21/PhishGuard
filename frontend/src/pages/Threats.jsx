import React, { useCallback, useEffect, useState } from 'react';
import { RefreshCw, ShieldAlert } from 'lucide-react';
import api from '../api/client';
import GmailMessageVerdict from '../components/GmailMessageVerdict';

export default function Threats() {
  const [messages, setMessages] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  const refresh = useCallback(async () => {
    try {
      const response = await api.get('/gmail/overview');
      setMessages((response.data.recent_messages || []).filter((message) => message.risk_score >= 20));
      setError('');
    } catch (requestError) {
      setError(requestError.response?.data?.detail || 'Could not load Gmail threat activity.');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    refresh();
    const timer = window.setInterval(refresh, 15000);
    return () => window.clearInterval(timer);
  }, [refresh]);

  return (
    <div className="space-y-6 pb-12">
      <section className="glass-panel flex flex-wrap items-end justify-between gap-4 rounded-[24px] p-6 sm:p-8">
        <div>
          <p className="font-mono text-[10px] uppercase tracking-[0.2em] text-[#d5ff72]">Gmail-linked findings</p>
          <h2 className="mt-3 text-3xl font-black tracking-tight text-[#f3f5e9]">Threat activity</h2>
          <p className="mt-2 max-w-xl text-sm leading-6 text-slate-400">
            Only opened Gmail messages with suspicious or higher risk scores are listed here.
          </p>
        </div>
        <button
          onClick={refresh}
          className="inline-flex items-center gap-2 rounded-xl border border-white/10 bg-white/[0.04] px-3 py-2 text-xs font-semibold text-slate-300 hover:bg-white/[0.08]"
        >
          <RefreshCw className={`h-3.5 w-3.5 ${loading ? 'animate-spin' : ''}`} />
          Refresh
        </button>
      </section>

      {error && (
        <div role="alert" className="glass-panel rounded-xl border-rose-400/20 p-4 text-sm text-rose-200">
          {error}
        </div>
      )}

      <section className="glass-panel overflow-hidden rounded-[24px]">
        {loading && messages.length === 0 ? (
          <p className="p-8 text-center text-sm text-slate-400">Loading threat activity…</p>
        ) : messages.length > 0 ? (
          <div>
            {messages.map((message) => (
              <GmailMessageVerdict key={message.scan_id} message={message} />
            ))}
          </div>
        ) : (
          <div className="px-6 py-14 text-center">
            <span className="mx-auto flex h-12 w-12 items-center justify-center rounded-2xl border border-[#d5ff72]/20 bg-[#d5ff72]/10 text-[#d5ff72]">
              <ShieldAlert className="h-5 w-5" />
            </span>
            <h3 className="mt-4 text-base font-bold text-[#f3f5e9]">No Gmail threats flagged</h3>
            <p className="mt-2 text-sm text-slate-400">New findings appear here after PhishGuard checks a message opened in Gmail.</p>
          </div>
        )}
      </section>
    </div>
  );
}
