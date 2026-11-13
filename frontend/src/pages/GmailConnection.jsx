import React, { useState, useEffect } from 'react';
import { useSearchParams, useNavigate } from 'react-router-dom';
import {
  Mail,
  ShieldCheck,
  RefreshCw,
  ExternalLink,
  CheckCircle2,
  Trash2,
  AlertTriangle,
  RotateCcw,
  Radio,
  Lock,
  Layers,
  Info,
  Key,
  Copy,
  Check,
  ChevronDown,
  ChevronUp,
  Settings,
  HelpCircle,
  Eye
} from 'lucide-react';
import api from '../api/client';
import toast from 'react-hot-toast';

export default function GmailConnection() {
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();

  const [accounts, setAccounts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [connecting, setConnecting] = useState(false);
  const [syncingId, setSyncingId] = useState(null);

  // OAuth readiness status & credential modal
  const [oauthStatus, setOauthStatus] = useState({ is_configured: false, client_id_preview: null, redirect_uri: '' });
  const [showConfigModal, setShowConfigModal] = useState(false);
  const [showGuide, setShowGuide] = useState(false);
  const [savingCreds, setSavingCreds] = useState(false);
  const [copiedRedirect, setCopiedRedirect] = useState(false);

  // Credential form state
  const [clientId, setClientId] = useState('');
  const [clientSecret, setClientSecret] = useState('');
  const [redirectUri, setRedirectUri] = useState('http://localhost:5173/gmail-connect');
  const [pubsubTopic, setPubsubTopic] = useState('');

  const fetchOauthStatus = async () => {
    try {
      const res = await api.get('/gmail/status');
      setOauthStatus(res.data);
      if (res.data.redirect_uri) {
        setRedirectUri(res.data.redirect_uri);
      }
    } catch (err) {
      console.error('Failed to get OAuth status:', err);
    }
  };

  const fetchAccounts = async () => {
    setLoading(true);
    try {
      const res = await api.get('/gmail/accounts');
      setAccounts((res.data || []).filter((account) => account.email !== 'analyst.demo@phishguard-soc.org'));
    } catch (err) {
      toast.error('Failed to load connected Gmail accounts');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAccounts();
    fetchOauthStatus();

    // Check for OAuth callback or error from Google redirect
    const code = searchParams.get('code');
    const error = searchParams.get('error');

    if (error) {
      toast.error(`Google Authorization notice: ${error}`);
      window.history.replaceState({}, '', window.location.pathname);
    } else if (code) {
      handleOAuthCallback(code);
    }
  }, [searchParams]);

  const handleOAuthCallback = async (authCode) => {
    setConnecting(true);
    try {
      const res = await api.post('/gmail/oauth/callback', {
        code: authCode,
        redirect_uri: window.location.origin + '/gmail-connect'
      });
      toast.success(`Successfully connected Gmail: ${res.data.email}`);
      window.history.replaceState({}, '', window.location.pathname);
      fetchAccounts();
    } catch (err) {
      toast.error(err.response?.data?.detail || 'Google OAuth connection failed');
    } finally {
      setConnecting(false);
    }
  };

  const handleConnectClick = async () => {
    if (!oauthStatus.is_configured) {
      setShowConfigModal(true);
      toast('Configure your Google Cloud OAuth credentials to connect Gmail.', {
        icon: 'ℹ️'
      });
      return;
    }

    try {
      const currentRedirect = window.location.origin + '/gmail-connect';
      const res = await api.get(`/gmail/oauth/url?redirect_uri=${encodeURIComponent(currentRedirect)}`);
      if (res.data.auth_url) {
        window.location.href = res.data.auth_url;
      }
    } catch (err) {
      const detail = err.response?.data?.detail || 'Unable to initialize Google OAuth flow';
      toast.error(detail);
      setShowConfigModal(true);
    }
  };

  const handleSaveCredentials = async (e) => {
    e.preventDefault();
    if (!clientId.trim() || !clientSecret.trim()) {
      toast.error('Client ID and Client Secret are required.');
      return;
    }

    setSavingCreds(true);
    try {
      await api.post('/gmail/credentials', {
        client_id: clientId.trim(),
        client_secret: clientSecret.trim(),
        redirect_uri: redirectUri.trim(),
        pubsub_topic: pubsubTopic.trim() || undefined
      });
      toast.success('Google Cloud credentials saved successfully!');
      setShowConfigModal(false);
      await fetchOauthStatus();
    } catch (err) {
      toast.error(err.response?.data?.detail || 'Failed to save credentials');
    } finally {
      setSavingCreds(false);
    }
  };

  const handleCopyRedirect = () => {
    const textToCopy = redirectUri || 'http://localhost:5173/gmail-connect';
    navigator.clipboard.writeText(textToCopy);
    setCopiedRedirect(true);
    toast.success('Copied redirect URI to clipboard!');
    setTimeout(() => setCopiedRedirect(false), 2000);
  };

  const handleSync = async (accountId) => {
    setSyncingId(accountId);
    try {
      const res = await api.post(`/gmail/sync/${accountId}`);
      toast.success(`Sync completed! ${res.data.processed_new_messages} new message(s) evaluated.`);
      fetchAccounts();
    } catch (err) {
      toast.error(err.response?.data?.detail || 'Sync failed');
    } finally {
      setSyncingId(null);
    }
  };

  const handleDisconnect = async (accountId) => {
    if (!confirm('Are you sure you want to disconnect this Gmail account and stop automatic monitoring?')) return;
    try {
      await api.delete(`/gmail/accounts/${accountId}`);
      toast.success('Account disconnected successfully');
      fetchAccounts();
    } catch (err) {
      toast.error('Failed to disconnect account');
    }
  };

  return (
    <div className="space-y-6 pb-12 max-w-5xl mx-auto">
      {/* Header */}
      <div className="glass-panel p-6 rounded-2xl flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div className="flex items-center space-x-3">
          <div className="w-10 h-10 rounded-xl bg-red-500/10 text-rose-400 flex items-center justify-center border border-rose-500/20 shadow-md">
            <Mail className="w-6 h-6" />
          </div>
          <div>
            <h2 className="text-xl font-extrabold text-white">Gmail Integration & Mailbox Protection</h2>
            <p className="text-xs text-[#9BAAC0]">
              Connect your Google workspace or personal Gmail for real-time phishing surveillance and user-controlled quarantine.
            </p>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-2.5">
          <button
            onClick={handleConnectClick}
            disabled={connecting}
            className="flex items-center space-x-2 px-5 py-2.5 bg-[#00D4FF] text-[#080E19] font-bold text-xs rounded-xl hover:bg-[#00E6A0] transition-all shadow-md shadow-[#00D4FF]/20 shrink-0 disabled:opacity-50"
          >
            {connecting ? <RotateCcw className="w-4 h-4 animate-spin" /> : <ExternalLink className="w-4 h-4" />}
            <span>{connecting ? 'Exchanging Credentials...' : 'Connect Gmail'}</span>
          </button>
        </div>
      </div>

      {/* OAuth Configuration Alert Banner (Displays if GCP client ID is unconfigured) */}
      {!oauthStatus.is_configured && (
        <div className="p-5 rounded-2xl bg-gradient-to-r from-amber-500/10 via-amber-500/5 to-transparent border border-amber-500/30 space-y-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-2 text-amber-400 font-bold text-xs uppercase tracking-wider">
              <AlertTriangle className="w-4 h-4 shrink-0" />
              <span>Google Cloud OAuth 2.0 Client Required for Real Mailbox Connection</span>
            </div>
            <span className="text-[10px] bg-amber-500/20 text-amber-300 font-mono px-2 py-0.5 rounded-full border border-amber-500/30">
              Resolves Google Error 401
            </span>
          </div>

          <p className="text-xs text-slate-300 leading-relaxed">
            A Google Cloud OAuth client is required before PhishGuard can connect a real mailbox. Configure the Client ID and Secret from your Google Cloud Console below.
          </p>

          <div className="flex flex-wrap items-center gap-3 pt-1">
            <button
              onClick={() => setShowConfigModal(true)}
              className="flex items-center space-x-1.5 px-3.5 py-1.5 bg-amber-500/20 hover:bg-amber-500 text-amber-300 hover:text-black rounded-lg text-xs font-bold transition-all border border-amber-500/40"
            >
              <Key className="w-3.5 h-3.5" />
              <span>Configure Google Client ID & Secret</span>
            </button>

            <button
              onClick={() => setShowGuide(!showGuide)}
              className="flex items-center space-x-1 text-xs text-slate-400 hover:text-cyan-400 transition-colors"
            >
              <HelpCircle className="w-3.5 h-3.5" />
              <span>{showGuide ? 'Hide Setup Guide' : 'How to get Google Cloud credentials'}</span>
              {showGuide ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
            </button>
          </div>

          {/* Collapsible Google Cloud Setup Guide */}
          {showGuide && (
            <div className="mt-3 p-4 rounded-xl bg-[#080E19] border border-amber-500/20 text-xs text-slate-300 space-y-2.5 animate-fadeIn">
              <div className="font-bold text-white flex items-center gap-1.5">
                <span>Quick 4-Step Google Cloud Setup:</span>
                <a
                  href="https://console.cloud.google.com/apis/credentials"
                  target="_blank"
                  rel="noreferrer"
                  className="text-cyan-400 hover:underline flex items-center gap-1 font-mono text-[11px]"
                >
                  console.cloud.google.com <ExternalLink className="w-3 h-3" />
                </a>
              </div>
              <ol className="list-decimal list-inside space-y-1.5 text-slate-400">
                <li>Create a project in Google Cloud Console and enable the <strong className="text-white">Gmail API</strong>.</li>
                <li>Go to <strong className="text-white">APIs & Services &gt; Credentials</strong> and click <strong className="text-white">Create Credentials &gt; OAuth client ID</strong>.</li>
                <li>Select Application Type: <strong className="text-white">Web application</strong>.</li>
                <li>
                  Under <strong className="text-white">Authorized redirect URIs</strong>, add:
                  <div className="mt-1 flex items-center gap-2 font-mono bg-black/40 p-1.5 rounded border border-white/10 text-cyan-300 text-[11px]">
                    <span>{redirectUri}</span>
                    <button
                      onClick={handleCopyRedirect}
                      className="ml-auto text-slate-400 hover:text-white p-1"
                      title="Copy URI"
                    >
                      {copiedRedirect ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                    </button>
                  </div>
                </li>
                <li>Copy the generated <strong className="text-white">Client ID</strong> and <strong className="text-white">Client Secret</strong> and paste them in the configuration form.</li>
              </ol>
            </div>
          )}
        </div>
      )}

      {/* When OAuth is configured, show verified badge */}
      {oauthStatus.is_configured && (
        <div className="soc-card p-4 bg-emerald-500/5 border-emerald-500/20 flex items-center justify-between">
          <div className="flex items-center space-x-2.5">
            <CheckCircle2 className="w-5 h-5 text-emerald-400 shrink-0" />
            <div>
              <div className="text-xs font-bold text-emerald-400">Google OAuth 2.0 Credentials Active</div>
              <div className="text-[11px] text-slate-400 font-mono">Client ID: {oauthStatus.client_id_preview}</div>
            </div>
          </div>
          <button
            onClick={() => setShowConfigModal(true)}
            className="flex items-center space-x-1 text-xs text-slate-400 hover:text-cyan-400 px-3 py-1 rounded-lg border border-white/5 hover:border-cyan-500/30 transition-all"
          >
            <Settings className="w-3.5 h-3.5" />
            <span>Edit Credentials</span>
          </button>
        </div>
      )}

      {/* Credentials Configuration Modal / Drawer */}
      {showConfigModal && (
        <div className="soc-card p-6 border-cyan-500/40 bg-[#101A2B]/95 space-y-4 shadow-2xl relative animate-fadeIn">
          <div className="flex items-center justify-between border-b border-white/10 pb-3">
            <div className="flex items-center space-x-2">
              <Key className="w-5 h-5 text-cyan-400" />
              <h3 className="text-sm font-bold text-white">Google Cloud OAuth 2.0 Configuration</h3>
            </div>
            <button
              onClick={() => setShowConfigModal(false)}
              className="text-xs text-slate-400 hover:text-white px-2 py-1 rounded bg-white/5"
            >
              ✕ Close
            </button>
          </div>

          <form onSubmit={handleSaveCredentials} className="space-y-4">
            <div className="space-y-1">
              <label className="text-xs font-semibold text-slate-300 flex items-center justify-between">
                <span>Google OAuth Client ID <span className="text-rose-400">*</span></span>
                <span className="text-[10px] text-slate-500">e.g. 123456789-xxx.apps.googleusercontent.com</span>
              </label>
              <input
                type="text"
                value={clientId}
                onChange={(e) => setClientId(e.target.value)}
                placeholder="Paste your Google OAuth Client ID"
                required
                className="w-full px-3.5 py-2.5 rounded-xl bg-[#080E19] border border-white/10 text-white text-xs font-mono focus:border-cyan-400 focus:outline-none"
              />
            </div>

            <div className="space-y-1">
              <label className="text-xs font-semibold text-slate-300 flex items-center justify-between">
                <span>Google OAuth Client Secret <span className="text-rose-400">*</span></span>
                <span className="text-[10px] text-slate-500">Encrypted with 256-bit Fernet AES</span>
              </label>
              <input
                type="password"
                value={clientSecret}
                onChange={(e) => setClientSecret(e.target.value)}
                placeholder="Paste your Google OAuth Client Secret (GOCSPX-...)"
                required
                className="w-full px-3.5 py-2.5 rounded-xl bg-[#080E19] border border-white/10 text-white text-xs font-mono focus:border-cyan-400 focus:outline-none"
              />
            </div>

            <div className="space-y-1">
              <label className="text-xs font-semibold text-slate-300 flex items-center justify-between">
                <span>Authorized Redirect URI</span>
                <button
                  type="button"
                  onClick={handleCopyRedirect}
                  className="text-[10px] text-cyan-400 hover:underline flex items-center gap-1"
                >
                  {copiedRedirect ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                  <span>{copiedRedirect ? 'Copied' : 'Copy URI'}</span>
                </button>
              </label>
              <input
                type="text"
                value={redirectUri}
                onChange={(e) => setRedirectUri(e.target.value)}
                placeholder="http://localhost:5173/gmail-connect"
                className="w-full px-3.5 py-2.5 rounded-xl bg-[#080E19] border border-white/10 text-slate-300 text-xs font-mono focus:border-cyan-400 focus:outline-none"
              />
              <p className="text-[11px] text-slate-500">
                Must match the Authorized Redirect URI in your Google Cloud Console Web Application credential.
              </p>
            </div>

            <div className="space-y-1">
              <label className="text-xs font-semibold text-slate-300 flex items-center justify-between">
                <span>Optional Cloud Pub/Sub Topic ID</span>
                <span className="text-[10px] text-slate-500">For push notifications</span>
              </label>
              <input
                type="text"
                value={pubsubTopic}
                onChange={(e) => setPubsubTopic(e.target.value)}
                placeholder="projects/your-project/topics/gmail-threats"
                className="w-full px-3.5 py-2.5 rounded-xl bg-[#080E19] border border-white/10 text-slate-300 text-xs font-mono focus:border-cyan-400 focus:outline-none"
              />
            </div>

            <div className="flex items-center justify-end space-x-3 pt-2">
              <button
                type="button"
                onClick={() => setShowConfigModal(false)}
                className="px-4 py-2 rounded-xl bg-white/5 hover:bg-white/10 text-xs text-slate-300 font-bold transition-all"
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={savingCreds}
                className="flex items-center space-x-1.5 px-5 py-2 rounded-xl bg-cyan-400 hover:bg-emerald-400 text-black text-xs font-bold transition-all disabled:opacity-50"
              >
                {savingCreds ? <RotateCcw className="w-3.5 h-3.5 animate-spin" /> : <ShieldCheck className="w-3.5 h-3.5" />}
                <span>{savingCreds ? 'Saving...' : 'Save & Activate'}</span>
              </button>
            </div>
          </form>
        </div>
      )}

      {/* Security Architecture Banner */}
      <div className="soc-card p-5 space-y-3 bg-[#080E19]/80 border-cyan-500/20">
        <div className="flex items-center space-x-2 text-cyan-300 text-xs font-bold">
          <Lock className="w-4 h-4 text-[#00D4FF]" />
          <span>Zero-Knowledge AES/Fernet Token Security</span>
        </div>
        <p className="text-xs text-slate-300 leading-relaxed">
          Google OAuth 2.0 refresh and access tokens are encrypted with military-grade 256-bit Fernet AES encryption
          before persistence. PhishGuard strictly limits scopes to mailbox inspection and quarantine labeling.
          Client secrets are never exposed in browser or extension bundles.
        </p>
      </div>

      {/* Connected Accounts List */}
      <div className="soc-card p-6 space-y-4">
        <div className="flex items-center justify-between border-b border-white/5 pb-3">
          <div>
            <h3 className="text-sm font-bold text-white">Monitored Mailboxes ({accounts.length})</h3>
            <p className="text-[11px] text-slate-400">Mailboxes currently inspected by the heuristic phishing engine.</p>
          </div>
          <button
            onClick={fetchAccounts}
            className="text-xs text-slate-400 hover:text-white flex items-center space-x-1"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin text-cyan-400' : ''}`} />
            <span>Refresh</span>
          </button>
        </div>

        {accounts.length > 0 ? (
          <div className="space-y-3">
            {accounts.map((acc) => (
                <div
                  key={acc.id}
                  className="p-4 rounded-xl bg-[#080E19] border border-white/5 flex flex-col md:flex-row items-start md:items-center justify-between gap-4"
                >
                  <div className="flex items-center space-x-3 w-full md:w-auto">
                    {acc.profile_picture ? (
                      <img
                        src={acc.profile_picture}
                        alt={acc.display_name}
                        className="w-10 h-10 rounded-full border border-white/10"
                      />
                    ) : (
                      <div className="w-10 h-10 rounded-full bg-cyan-500/10 text-cyan-400 flex items-center justify-center font-bold">
                        {acc.email.charAt(0).toUpperCase()}
                      </div>
                    )}
                    <div>
                      <div className="flex items-center space-x-2">
                        <span className="text-sm font-bold text-white font-mono">{acc.email}</span>
                        <span className="w-2 h-2 rounded-full bg-[#00E6A0]" title="Monitoring active"></span>
                        <span className="text-[10px] bg-emerald-500/15 text-emerald-300 px-2 py-0.5 rounded-full font-mono border border-emerald-500/30">
                          GMAIL CONNECTED
                        </span>
                      </div>
                      <div className="text-[11px] text-slate-400 mt-0.5 flex flex-wrap gap-2">
                        <span>Analyst: <strong>{acc.display_name || 'Authorized User'}</strong></span>
                        <span>&bull;</span>
                        <span>Surveillance: <strong className="text-cyan-400">{acc.watch_active ? 'Pub/Sub Push Active' : 'Standby / Manual Sync'}</strong></span>
                      </div>
                    </div>
                  </div>

                  <div className="flex items-center space-x-2 w-full md:w-auto justify-end">
                    <button
                      onClick={() => navigate('/')}
                      className="flex items-center space-x-1.5 px-3 py-1.5 bg-white/5 hover:bg-white/10 text-slate-300 text-xs font-semibold rounded-lg transition-all border border-white/10"
                      title="View Gmail verdicts"
                    >
                      <Eye className="w-3.5 h-3.5 text-cyan-400" />
                      <span>View dashboard</span>
                    </button>

                    <button
                      onClick={() => handleSync(acc.id)}
                      disabled={syncingId === acc.id}
                      className="flex items-center space-x-1.5 px-3 py-1.5 bg-[#00D4FF]/20 text-[#00D4FF] hover:bg-[#00D4FF] hover:text-[#080E19] text-xs font-bold rounded-lg transition-all border border-[#00D4FF]/30 disabled:opacity-50"
                    >
                      <RefreshCw className={`w-3.5 h-3.5 ${syncingId === acc.id ? 'animate-spin' : ''}`} />
                      <span>{syncingId === acc.id ? 'Analyzing...' : 'Sync Mailbox'}</span>
                    </button>

                    <button
                      onClick={() => handleDisconnect(acc.id)}
                      className="p-2 rounded-lg bg-rose-500/10 text-rose-400 hover:bg-rose-500 hover:text-white transition-all"
                      title="Disconnect Mailbox"
                    >
                      <Trash2 className="w-4 h-4" />
                    </button>
                  </div>
                </div>
            ))}
          </div>
        ) : (
          <div className="p-8 text-center rounded-xl bg-[#080E19]/60 border border-white/5 space-y-4">
            <Mail className="w-8 h-8 text-slate-500 mx-auto" />
            <div className="text-xs text-slate-300 font-semibold">No Gmail accounts currently connected.</div>
            <p className="text-xs text-slate-500 max-w-sm mx-auto">
              Connect your real Gmail account to start seeing message verdicts in the dashboard.
            </p>
          </div>
        )}
      </div>
    </div>
  );
}
