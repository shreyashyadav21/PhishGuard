import React, { useState, useEffect } from 'react';
import {
  Paperclip,
  Upload,
  ShieldCheck,
  AlertTriangle,
  AlertOctagon,
  FileCode,
  FileText,
  RotateCcw,
  CheckCircle2,
  Lock,
  Layers,
  Search
} from 'lucide-react';
import api from '../api/client';
import toast from 'react-hot-toast';

export default function AttachmentSecurity() {
  const [attachments, setAttachments] = useState([]);
  const [loadingList, setLoadingList] = useState(true);
  const [uploading, setUploading] = useState(false);
  const [scanResult, setScanResult] = useState(null);

  const fetchAttachments = async () => {
    setLoadingList(true);
    try {
      const res = await api.get('/attachments');
      setAttachments(res.data || []);
    } catch (err) {
      toast.error('Failed to load attachment records');
    } finally {
      setLoadingList(false);
    }
  };

  useEffect(() => {
    fetchAttachments();
  }, []);

  const handleFileUpload = async (e) => {
    const file = e.target.files?.[0];
    if (!file) return;

    setUploading(true);
    setScanResult(null);

    const formData = new FormData();
    formData.append('file', file);

    try {
      const res = await api.post('/attachments/scan', formData, {
        headers: { 'Content-Type': 'multipart/form-data' }
      });
      setScanResult(res.data);
      if (res.data.is_dangerous) {
        toast.error(`High-risk attachment detected! Threat score: ${res.data.threat_score}/100`, { icon: '🚨' });
      } else {
        toast.success('Static inspection complete: File verified safe', { icon: '🛡️' });
      }
      fetchAttachments();
    } catch (err) {
      toast.error(err.response?.data?.detail || 'Attachment inspection failed');
    } finally {
      setUploading(false);
    }
  };

  return (
    <div className="space-y-6 pb-12 max-w-5xl mx-auto">
      {/* Header */}
      <div className="bg-[#101A2B] p-6 rounded-2xl border border-white/5 space-y-2">
        <div className="flex items-center space-x-3">
          <div className="w-10 h-10 rounded-xl bg-orange-500/10 text-orange-400 flex items-center justify-center border border-orange-500/20 shadow-md">
            <Paperclip className="w-6 h-6" />
          </div>
          <div>
            <h2 className="text-xl font-extrabold text-white">Attachment Security & Static Sandbox</h2>
            <p className="text-xs text-[#9BAAC0]">
              Safe static binary inspection: Magic byte signature matching, SHA-256 fingerprinting, double extension detection, and macro analysis.
            </p>
          </div>
        </div>
      </div>

      {/* File Upload Dropzone */}
      <div className="soc-card p-8 border-dashed border-2 border-cyan-500/30 hover:border-cyan-400 text-center space-y-4 transition-colors">
        <div className="w-12 h-12 rounded-2xl bg-cyan-500/10 text-cyan-400 flex items-center justify-center mx-auto">
          <Upload className="w-6 h-6" />
        </div>
        <div>
          <h3 className="text-sm font-bold text-white">Static Attachment Scanner</h3>
          <p className="text-xs text-slate-400 mt-1">
            Drop or select any file to inspect magic bytes, double extensions, and hash fingerprints without code execution.
          </p>
        </div>

        <label className="inline-flex items-center space-x-2 px-5 py-2.5 bg-[#00D4FF] text-[#080E19] font-bold text-xs rounded-xl hover:bg-[#00E6A0] cursor-pointer transition-all shadow-md shadow-[#00D4FF]/20">
          <input type="file" onChange={handleFileUpload} className="hidden" disabled={uploading} />
          <span>{uploading ? 'Analyzing Magic Signatures...' : 'Select File to Inspect'}</span>
        </label>
      </div>

      {/* Live Upload Result Display */}
      {scanResult && (
        <div className="soc-card p-6 space-y-4 animate-in fade-in">
          <div className="flex items-center justify-between border-b border-white/5 pb-3">
            <div className="flex items-center space-x-2">
              <span className="text-base">{scanResult.is_dangerous ? '🚨' : '🛡️'}</span>
              <h3 className="text-sm font-bold text-white">Static Inspection Result: {scanResult.filename}</h3>
            </div>
            <span
              className={`px-3 py-1 rounded-full text-xs font-bold uppercase ${
                scanResult.threat_score >= 70
                  ? 'bg-rose-500/20 text-rose-400 border border-rose-500/40'
                  : scanResult.threat_score >= 40
                  ? 'bg-orange-500/20 text-orange-400 border border-orange-500/40'
                  : scanResult.threat_score >= 20
                  ? 'bg-amber-500/20 text-amber-400 border border-amber-500/40'
                  : 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/40'
              }`}
            >
              Risk: {scanResult.threat_score} / 100 ({scanResult.severity})
            </span>
          </div>

          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs">
            <div className="bg-[#080E19] p-3 rounded-xl border border-white/5">
              <span className="text-slate-500 text-[10px] uppercase font-bold">Extension</span>
              <p className="font-mono font-bold text-white mt-0.5">{scanResult.extension || 'None'}</p>
            </div>
            <div className="bg-[#080E19] p-3 rounded-xl border border-white/5">
              <span className="text-slate-500 text-[10px] uppercase font-bold">MIME Type</span>
              <p className="font-mono font-bold text-cyan-300 truncate mt-0.5">{scanResult.mime_type}</p>
            </div>
            <div className="bg-[#080E19] p-3 rounded-xl border border-white/5">
              <span className="text-slate-500 text-[10px] uppercase font-bold">File Size</span>
              <p className="font-mono font-bold text-white mt-0.5">{Math.round(scanResult.file_size / 1024)} KB</p>
            </div>
            <div className="bg-[#080E19] p-3 rounded-xl border border-white/5">
              <span className="text-slate-500 text-[10px] uppercase font-bold">Safety Assessment</span>
              <p className={`font-bold mt-0.5 ${scanResult.safe_to_open ? 'text-emerald-400' : 'text-rose-400'}`}>
                {scanResult.safe_to_open ? 'Safe to Open' : 'Block / Quarantine'}
              </p>
            </div>
          </div>

          <div>
            <span className="text-[10px] text-slate-400 uppercase font-bold">SHA-256 Checksum</span>
            <p className="font-mono text-xs text-slate-300 bg-[#080E19] p-2.5 rounded-lg border border-white/5 mt-1 select-all break-all">
              {scanResult.sha256_hash}
            </p>
          </div>

          {scanResult.threat_reasons && scanResult.threat_reasons.length > 0 && (
            <div className="space-y-1.5 pt-2">
              <span className="text-xs font-bold text-white">Flagged Threat Signatures:</span>
              <div className="space-y-1">
                {scanResult.threat_reasons.map((r, i) => (
                  <div key={i} className="text-xs text-rose-300 bg-rose-950/20 p-2 rounded-lg border border-rose-500/20">
                    &bull; {r}
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Database Attachments Table */}
      <div className="soc-card p-5 space-y-4">
        <h3 className="text-sm font-bold text-white">Inspected Email Attachments History ({attachments.length})</h3>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead>
              <tr className="border-b border-white/10 text-slate-400">
                <th className="pb-3 font-semibold">Filename</th>
                <th className="pb-3 font-semibold">Threat Score</th>
                <th className="pb-3 font-semibold">Status</th>
                <th className="pb-3 font-semibold">Size</th>
                <th className="pb-3 font-semibold">MIME Type</th>
                <th className="pb-3 font-semibold">SHA-256 Checksum</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/5">
              {attachments.length > 0 ? (
                attachments.map((att) => (
                  <tr key={att.id} className="hover:bg-white/[0.02]">
                    <td className="py-3 font-mono font-bold text-slate-200">
                      {att.filename}
                    </td>
                    <td className="py-3 font-bold font-mono">
                      <span className={att.threat_score >= 40 ? 'text-rose-400' : 'text-emerald-400'}>
                        {att.threat_score}/100
                      </span>
                    </td>
                    <td className="py-3">
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                          att.is_dangerous
                            ? 'bg-rose-500/20 text-rose-400 border border-rose-500/30'
                            : 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
                        }`}
                      >
                        {att.is_dangerous ? 'Malicious' : 'Clean'}
                      </span>
                    </td>
                    <td className="py-3 text-slate-400 font-mono">
                      {Math.round(att.file_size / 1024)} KB
                    </td>
                    <td className="py-3 text-slate-400 font-mono text-[11px] truncate max-w-xs">
                      {att.mime_type}
                    </td>
                    <td className="py-3 font-mono text-cyan-400/80 text-[10px] truncate max-w-xs select-all">
                      {att.sha256_hash}
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={6} className="py-8 text-center text-slate-400">
                    No attachment records evaluated yet.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

