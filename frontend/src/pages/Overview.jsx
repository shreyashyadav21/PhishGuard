import React, { useCallback, useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  ArrowRight,
  CheckCircle2,
  Clock3,
  ExternalLink,
  Mail,
  Radio,
  RefreshCw,
  ShieldAlert,
  ShieldCheck,
  WifiOff,
} from 'lucide-react';
import api from '../api/client';
import GmailMessageVerdict from '../components/GmailMessageVerdict';

function StatCard({ label, value, note, icon: Icon, tone }) {
  return (
    <div className="glass-panel rounded-2xl p-5">
      <div className="flex items-start justify-between gap-3">
        <div>
          <p className="font-mono text-[10px] uppercase tracking-[0.18em] text-slate-400">{label}</p>
          <p className="mt-3 text-3xl font-black tracking-tight text-[#f3f5e9]">{value}</p>
          <p className="mt-2 text-xs text-slate-400">{note}</p>
        </div>
        <span className={`flex h-10 w-10 items-center justify-center rounded-xl border ${tone}`}>
          <Icon className="h-4 w-4" />
        </span>
      </div>
    </div>
  );
}

export default function Overview() {
  const navigate = useNavigate();
  const [overview, setOverview] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [updatedAt, setUpdatedAt] = useState(null);

  const refresh = useCallback(async () => {
    try {
      const response = await api.get('/gmail/overview');
      setOverview(response.data);
      setError('');
      setUpdatedAt(new Date());
    } catch (requestError) {
      setError(requestError.response?.data?.detail || 'Could not load Gmail protection data.');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    refresh();
    const timer = window.setInterval(refresh, 15000);
    return () => window.clearInterval(timer);
  }, [refresh]);

  const accounts = overview?.connected_accounts || [];
  const messages = overview?.recent_messages || [];
  const connected = accounts.length > 0;
  const riskBuckets = overview?.risk_buckets || {};

  return (
    <div className="space-y-6 pb-12">
      <section className="glass-panel relative overflow-hidden rounded-[28px] p-6 sm:p-8 lg:p-10">
        <div className="pointer-events-none absolute -right-20 -top-24 h-72 w-72 rounded-full bg-[#d5ff72]/10 blur-3xl" />
        <div className="pointer-events-none absolute -bottom-24 left-1/3 h-56 w-56 rounded-full bg-[#64d5bf]/10 blur-3xl" />
        <div className="relative grid gap-8 lg:grid-cols-[1.2fr_0.8fr] lg:items-end">
          <div>
            <div className="inline-flex items-center gap-2 rounded-full border border-[#d5ff72]/20 bg-[#d5ff72]/[0.07] px-3 py-1.5 font-mono text-[10px] uppercase tracking-[0.16em] text-[#d5ff72]">
              <span className={`h-1.5 w-1.5 rounded-full ${connected ? 'bg-[#d5ff72]' : 'bg-slate-500'}`} />
              {connected ? 'Mailbox connected' : 'Mailbox not connected'}
            </div>
            <h2 className="mt-5 max-w-2xl text-4xl font-black leading-[1.02] tracking-[-0.06em] text-[#f3f5e9] sm:text-5xl">
              Your Gmail, with a second set of eyes.
            </h2>
            <p className="mt-4 max-w-xl text-sm leading-6 text-slate-300 sm:text-base">
              Open a message in Gmail to see its phishing verdict. This dashboard shows real Gmail-linked results only—no sample inboxes or manual email submissions.
            </p>
            <div className="mt-7 flex flex-wrap gap-3">
              <button
                onClick={() => navigate('/gmail-connect')}
                className="inline-flex items-center gap-2 rounded-xl bg-[#d5ff72] px-4 py-3 text-xs font-extrabold uppercase tracking-[0.1em] text-[#101611] transition hover:-translate-y-0.5 hover:bg-[#e1ff9d]"
              >
                {connected ? 'Manage Gmail' : 'Connect Gmail'}
                <ArrowRight className="h-4 w-4" />
              </button>
              <a
                href="https://mail.google.com/"
                target="_blank"
                rel="noreferrer"
                className="inline-flex items-center gap-2 rounded-xl border border-white/15 bg-white/[0.04] px-4 py-3 text-xs font-bold uppercase tracking-[0.1em] text-slate-200 transition hover:bg-white/[0.08]"
              >
                Open Gmail
                <ExternalLink className="h-3.5 w-3.5" />
              </a>
            </div>
          </div>

          <div className="rounded-2xl border border-white/10 bg-[#0b100d]/50 p-5 backdrop-blur-xl">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2 text-xs font-bold uppercase tracking-[0.12em] text-slate-300">
                <Radio className="h-4 w-4 text-[#d5ff72]" />
                Message-open checks
              </div>
              {updatedAt && (
                <span className="font-mono text-[10px] text-slate-500">
                  {updatedAt.toLocaleTimeString()}
                </span>
              )}
            </div>
            <div className="mt-5 space-y-3">
              {connected ? accounts.map((account) => (
                <div key={account.email} className="flex items-center gap-3 rounded-xl border border-white/10 bg-white/[0.04] p-3">
                  <span className="flex h-9 w-9 items-center justify-center rounded-lg border border-[#d5ff72]/20 bg-[#d5ff72]/10 text-[#d5ff72]">
                    <Mail className="h-4 w-4" />
                  </span>
                  <div className="min-w-0 flex-1">
                    <p className="truncate text-sm font-semibold text-[#f3f5e9]">{account.email}</p>
                    <p className="mt-0.5 text-[11px] text-slate-400">
                      {account.last_synced_at
                        ? `Last mailbox sync ${new Date(account.last_synced_at).toLocaleString()}`
                        : 'Connected to PhishGuard'}
                    </p>
                  </div>
                  <CheckCircle2 className="h-4 w-4 shrink-0 text-[#d5ff72]" />
                </div>
              )) : (
                <div className="rounded-xl border border-dashed border-white/15 bg-white/[0.025] p-4">
                  <div className="flex items-center gap-2 text-sm font-semibold text-slate-200">
                    <WifiOff className="h-4 w-4 text-amber-200" />
                    No Gmail account connected
                  </div>
                  <p className="mt-2 text-xs leading-5 text-slate-400">
                    Connect your real mailbox to enable protection and view its scan history here.
                  </p>
                </div>
              )}
            </div>
          </div>
        </div>
      </section>

      {error && (
        <div className="glass-panel flex flex-wrap items-center justify-between gap-3 rounded-2xl border-rose-400/20 p-4">
          <p className="text-sm text-rose-200">{error}</p>
          <button onClick={refresh} className="inline-flex items-center gap-2 text-xs font-bold text-rose-100 hover:text-white">
            <RefreshCw className="h-3.5 w-3.5" />
            Retry
          </button>
        </div>
      )}

      <section className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <StatCard
          label="Gmail messages checked"
          value={loading ? '—' : (overview?.gmail_messages_scanned ?? 0)}
          note="Linked to an opened Gmail message"
          icon={Mail}
          tone="border-[#d5ff72]/20 bg-[#d5ff72]/10 text-[#d5ff72]"
        />
        <StatCard
          label="Threats flagged"
          value={loading ? '—' : (overview?.threats_detected ?? 0)}
          note="Suspicious or higher risk"
          icon={ShieldAlert}
          tone="border-rose-300/20 bg-rose-300/10 text-rose-200"
        />
        <StatCard
          label="Critical risk"
          value={loading ? '—' : (riskBuckets.critical ?? 0)}
          note="Risk score 70 and above"
          icon={ShieldAlert}
          tone="border-orange-300/20 bg-orange-300/10 text-orange-200"
        />
        <StatCard
          label="Low risk"
          value={loading ? '—' : (riskBuckets.safe ?? 0)}
          note="No high-risk signals found"
          icon={ShieldCheck}
          tone="border-[#64d5bf]/20 bg-[#64d5bf]/10 text-[#9bf1dc]"
        />
      </section>

      <section className="glass-panel overflow-hidden rounded-[24px]">
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-white/10 px-5 py-4 sm:px-6">
          <div>
            <p className="font-mono text-[10px] uppercase tracking-[0.18em] text-[#d5ff72]">Mailbox activity</p>
            <h3 className="mt-1 text-xl font-bold text-[#f3f5e9]">Recent Gmail verdicts</h3>
          </div>
          <div className="flex items-center gap-3">
            {updatedAt && (
              <span className="hidden items-center gap-1.5 text-[11px] text-slate-500 sm:inline-flex">
                <Clock3 className="h-3.5 w-3.5" />
                Refreshes every 15 sec
              </span>
            )}
            <button
              onClick={refresh}
              className="inline-flex items-center gap-2 rounded-lg border border-white/10 bg-white/[0.04] px-3 py-2 text-xs font-semibold text-slate-300 hover:bg-white/[0.08]"
            >
              <RefreshCw className={`h-3.5 w-3.5 ${loading ? 'animate-spin' : ''}`} />
              Refresh
            </button>
          </div>
        </div>

        {loading && !overview ? (
          <div className="p-8 text-center text-sm text-slate-400">Loading Gmail verdicts…</div>
        ) : messages.length > 0 ? (
          <div>
            {messages.map((message) => (
              <GmailMessageVerdict key={message.scan_id} message={message} />
            ))}
          </div>
        ) : (
          <div className="px-6 py-12 text-center">
            <span className="mx-auto flex h-12 w-12 items-center justify-center rounded-2xl border border-white/10 bg-white/[0.04] text-slate-300">
              <Mail className="h-5 w-5" />
            </span>
            <h4 className="mt-4 text-base font-bold text-[#f3f5e9]">
              {connected ? 'No Gmail verdicts yet' : 'Your Gmail activity will appear here'}
            </h4>
            <p className="mx-auto mt-2 max-w-md text-sm leading-6 text-slate-400">
              {connected
                ? 'Open a message in Gmail with the PhishGuard extension, or open the add-on panel on Gmail mobile, to generate a verdict.'
                : 'Connect your mailbox, then open a message in Gmail to have PhishGuard analyze it.'}
            </p>
            <button
              onClick={() => navigate(connected ? '/threats' : '/gmail-connect')}
              className="mt-5 inline-flex items-center gap-2 text-xs font-bold uppercase tracking-[0.1em] text-[#d5ff72] hover:text-white"
            >
              {connected ? 'View threat activity' : 'Set up Gmail protection'}
              <ArrowRight className="h-3.5 w-3.5" />
            </button>
          </div>
        )}
      </section>
    </div>
  );
}
