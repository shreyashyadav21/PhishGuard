import React, { useState, useEffect } from 'react';
import {
  Settings as SettingsIcon,
  Save,
  Moon,
  Sun,
  Bell,
  Shield,
  Lock,
  Database,
  Cpu,
  RefreshCw,
  Check,
  AlertCircle
} from 'lucide-react';
import api from '../api/client';
import toast from 'react-hot-toast';

export default function SettingsPage() {
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [settings, setSettings] = useState({
    theme: 'dark',
    store_email_body: 'false',
    notification_sound: 'true',
    alert_threshold: '40',
    auto_export_pdf: 'false',
    retention_days: '90',
    engine_version: '3.1.0-SOC'
  });

  const fetchSettings = async () => {
    setLoading(true);
    try {
      const res = await api.get('/settings');
      setSettings(res.data);
    } catch (err) {
      toast.error('Failed to load settings from server');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchSettings();
  }, []);

  const handleChange = (key, value) => {
    setSettings((prev) => ({
      ...prev,
      [key]: String(value)
    }));
  };

  const handleSave = async (e) => {
    e.preventDefault();
    setSaving(true);
    try {
      await api.put('/settings', { settings });
      toast.success('Configuration saved successfully to persistent database');
    } catch (err) {
      toast.error('Failed to save settings');
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="space-y-6 pb-12 max-w-4xl mx-auto">
      {/* Header */}
      <div className="bg-[#101A2B] p-6 rounded-2xl border border-white/5 flex items-center justify-between">
        <div className="flex items-center space-x-3">
          <div className="w-10 h-10 rounded-xl bg-cyan-500/10 text-[#00D4FF] flex items-center justify-center border border-cyan-500/20 shadow-md">
            <SettingsIcon className="w-6 h-6" />
          </div>
          <div>
            <h2 className="text-xl font-extrabold text-white">System & SOC Preferences</h2>
            <p className="text-xs text-[#9BAAC0]">
              Configure detection thresholds, privacy controls, data retention, and interface modes.
            </p>
          </div>
        </div>

        <button
          onClick={handleSave}
          disabled={saving}
          className="flex items-center space-x-2 px-5 py-2.5 bg-[#00D4FF] text-[#080E19] font-bold text-xs rounded-xl hover:bg-[#00E6A0] disabled:opacity-50 transition-all shadow-md shadow-[#00D4FF]/20"
        >
          {saving ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Save className="w-4 h-4" />}
          <span>Save Preferences</span>
        </button>
      </div>

      <form onSubmit={handleSave} className="space-y-5">
        {/* Privacy & Secret Handling */}
        <div className="soc-card p-6 space-y-4">
          <div className="flex items-center space-x-2 border-b border-white/5 pb-3">
            <Lock className="w-4 h-4 text-emerald-400" />
            <h3 className="text-sm font-bold text-white">Privacy & Content Storage Controls</h3>
          </div>

          <div className="flex items-start justify-between gap-4">
            <div className="space-y-1">
              <span className="text-xs font-bold text-white">
                Store Complete Email Bodies in Database
              </span>
              <p className="text-xs text-slate-400 leading-relaxed">
                When disabled (recommended), raw email bodies are purged immediately following heuristic analysis.
                Only sender address, subject line, extracted URLs, and flagged phrase tokens are preserved in SQLite.
              </p>
            </div>
            <label className="relative inline-flex items-center cursor-pointer shrink-0 mt-1">
              <input
                type="checkbox"
                checked={settings.store_email_body === 'true'}
                onChange={(e) => handleChange('store_email_body', e.target.checked)}
                className="sr-only peer"
              />
              <div className="w-11 h-6 bg-slate-800 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-slate-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-emerald-500"></div>
            </label>
          </div>
        </div>

        {/* Threat Alert Thresholds */}
        <div className="soc-card p-6 space-y-4">
          <div className="flex items-center space-x-2 border-b border-white/5 pb-3">
            <Bell className="w-4 h-4 text-[#00D4FF]" />
            <h3 className="text-sm font-bold text-white">Alert Sensitivity & Notifications</h3>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
            <div>
              <label className="block text-xs font-semibold text-slate-300 mb-1.5">
                Minimum Severity Alert Threshold
              </label>
              <select
                value={settings.alert_threshold}
                onChange={(e) => handleChange('alert_threshold', e.target.value)}
                className="w-full bg-[#080E19] border border-white/10 rounded-xl px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-[#00D4FF]"
              >
                <option value="20">Suspicious (Score 20+)</option>
                <option value="40">High Risk Only (Score 40+)</option>
                <option value="70">Critical Risk Only (Score 70+)</option>
              </select>
              <p className="text-[11px] text-slate-500 mt-1">Triggers toast warnings and highlights in SOC console.</p>
            </div>

            <div>
              <label className="block text-xs font-semibold text-slate-300 mb-1.5">
                Audio Warning Chime
              </label>
              <select
                value={settings.notification_sound}
                onChange={(e) => handleChange('notification_sound', e.target.value)}
                className="w-full bg-[#080E19] border border-white/10 rounded-xl px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-[#00D4FF]"
              >
                <option value="true">Enabled (Audible chime on high/critical)</option>
                <option value="false">Muted (Visual notifications only)</option>
              </select>
            </div>
          </div>
        </div>

        {/* Database & Retention Management */}
        <div className="soc-card p-6 space-y-4">
          <div className="flex items-center space-x-2 border-b border-white/5 pb-3">
            <Database className="w-4 h-4 text-purple-400" />
            <h3 className="text-sm font-bold text-white">Database & Scan History Retention</h3>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
            <div>
              <label className="block text-xs font-semibold text-slate-300 mb-1.5">
                Scan Log Retention Period
              </label>
              <select
                value={settings.retention_days}
                onChange={(e) => handleChange('retention_days', e.target.value)}
                className="w-full bg-[#080E19] border border-white/10 rounded-xl px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-[#00D4FF]"
              >
                <option value="30">30 Days</option>
                <option value="60">60 Days</option>
                <option value="90">90 Days</option>
                <option value="365">1 Year</option>
                <option value="indefinite">Keep Indefinitely</option>
              </select>
            </div>

            <div>
              <label className="block text-xs font-semibold text-slate-300 mb-1.5">
                Automatic PDF Report Generation
              </label>
              <select
                value={settings.auto_export_pdf}
                onChange={(e) => handleChange('auto_export_pdf', e.target.value)}
                className="w-full bg-[#080E19] border border-white/10 rounded-xl px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-[#00D4FF]"
              >
                <option value="false">On Demand (Download manually)</option>
                <option value="true">Auto-Prompt on Critical Scans</option>
              </select>
            </div>
          </div>
        </div>

        {/* Engine Specs Info Box */}
        <div className="soc-card p-6 space-y-4">
          <div className="flex items-center space-x-2 border-b border-white/5 pb-3">
            <Cpu className="w-4 h-4 text-cyan-400" />
            <h3 className="text-sm font-bold text-white">Detection Engine Architecture & Version</h3>
          </div>

          <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 text-xs">
            <div className="bg-[#080E19] p-3 rounded-xl border border-white/5">
              <span className="text-slate-500 text-[10px] uppercase font-bold">Engine Core</span>
              <p className="font-mono font-bold text-cyan-300 mt-0.5">{settings.engine_version}</p>
            </div>
            <div className="bg-[#080E19] p-3 rounded-xl border border-white/5">
              <span className="text-slate-500 text-[10px] uppercase font-bold">Execution Mode</span>
              <p className="font-mono font-bold text-white mt-0.5">Zero-SSRF Static</p>
            </div>
            <div className="bg-[#080E19] p-3 rounded-xl border border-white/5">
              <span className="text-slate-500 text-[10px] uppercase font-bold">Framework</span>
              <p className="font-mono font-bold text-white mt-0.5">FastAPI + React 19</p>
            </div>
            <div className="bg-[#080E19] p-3 rounded-xl border border-white/5">
              <span className="text-slate-500 text-[10px] uppercase font-bold">Database</span>
              <p className="font-mono font-bold text-white mt-0.5">SQLite / SQLAlchemy</p>
            </div>
          </div>
        </div>
      </form>
    </div>
  );
}

