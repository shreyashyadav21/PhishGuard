import React, { useState } from 'react';
import {
  ShieldAlert,
  Search,
  CheckCircle2,
  AlertTriangle,
  Globe,
  Sparkles,
  ExternalLink,
  Layers,
  ArrowRight
} from 'lucide-react';
import toast from 'react-hot-toast';

export default function ImpersonationGuardian() {
  const [testDomain, setTestDomain] = useState('');
  const [simResult, setSimResult] = useState(null);

  const brandProfiles = [
    { name: 'PayPal', official: 'paypal.com', monitored: ['paypa1', 'pay-pal', 'paypal-security'] },
    { name: 'Microsoft', official: 'microsoft.com, live.com, office.com', monitored: ['micros0ft', 'm1crosoft', 'office365'] },
    { name: 'Google', official: 'google.com, accounts.google.com', monitored: ['g00gle', 'goog1e', 'gmail-security'] },
    { name: 'Apple', official: 'apple.com, icloud.com', monitored: ['app1e', 'appleid-verify', 'icloud-auth'] },
    { name: 'Amazon', official: 'amazon.com, aws.amazon.com', monitored: ['amaz0n', 'amzn-prime', 'aws-security'] },
    { name: 'Netflix', official: 'netflix.com', monitored: ['netfl1x', 'netflix-verify', 'renew-netflix'] },
    { name: 'Meta / Facebook', official: 'facebook.com, meta.com', monitored: ['faceb00k', 'meta-support', 'fb-verify'] },
    { name: 'State Bank of India (SBI)', official: 'onlinesbi.sbi, sbi.co.in', monitored: ['onlinesbi-kyc', 'sbicard-update', 'yono-verify'] },
    { name: 'HDFC Bank', official: 'hdfcbank.com', monitored: ['hdfc-netbanking', 'hdfc-kyc', 'hdfcbank-login'] },
    { name: 'ICICI Bank', official: 'icicibank.com', monitored: ['icici-netbanking', 'icicibank-security'] },
  ];

  const handleSimulate = (e) => {
    e.preventDefault();
    const clean = testDomain.trim().toLowerCase();
    if (!clean) return;

    // Local simulation of domain_analyzer.py
    const homoglyphMap = { '0': 'o', '1': 'l', '3': 'e', '4': 'a', '@': 'a', '5': 's', 'vv': 'w', 'rn': 'm' };
    let normalized = clean;
    for (const [k, v] of Object.entries(homoglyphMap)) {
      normalized = normalized.replaceAll(k, v);
    }

    let matchedBrand = null;
    let attackType = null;

    for (const bp of brandProfiles) {
      const bKey = bp.name.toLowerCase().split(' ')[0];
      if (clean.includes(bKey)) {
        matchedBrand = bp.name;
        attackType = 'Direct Brand Keyword Embedded';
        break;
      }
      if (normalized.includes(bKey) && !clean.includes(bKey)) {
        matchedBrand = bp.name;
        attackType = 'Homoglyph Character Substitution (Leetspeak)';
        break;
      }
    }

    setSimResult({
      input: clean,
      normalized: normalized,
      matchedBrand: matchedBrand || 'No brand target matched',
      attackType: attackType || 'Unrecognized target',
      isImpersonation: Boolean(matchedBrand)
    });
  };

  return (
    <div className="space-y-6 pb-12 max-w-5xl mx-auto">
      {/* Header */}
      <div className="bg-[#101A2B] p-6 rounded-2xl border border-white/5 space-y-2">
        <div className="flex items-center space-x-3">
          <div className="w-10 h-10 rounded-xl bg-cyan-500/10 text-[#00D4FF] flex items-center justify-center border border-cyan-500/20 shadow-md">
            <ShieldAlert className="w-6 h-6" />
          </div>
          <div>
            <h2 className="text-xl font-extrabold text-white">Impersonation Guardian & Brand Surveillance</h2>
            <p className="text-xs text-[#9BAAC0]">
              Detects homoglyphs, typosquatting mutations, and deceptive brand keyword nesting across unauthorized infrastructure.
            </p>
          </div>
        </div>
      </div>

      {/* Interactive Brand Mutation Simulator */}
      <div className="soc-card p-6 space-y-4">
        <h3 className="text-sm font-bold text-white flex items-center gap-2">
          <Sparkles className="w-4 h-4 text-cyan-400" />
          <span>Interactive Homoglyph & Typosquatting Simulator</span>
        </h3>
        <p className="text-xs text-slate-300">
          Enter any suspicious domain (e.g., <code className="text-cyan-300">paypa1-security.com</code> or <code className="text-cyan-300">amaz0n-prime.xyz</code>) to test how the homoglyph engine normalizes character substitutions.
        </p>

        <form onSubmit={handleSimulate} className="flex gap-2">
          <input
            type="text"
            placeholder="e.g. paypa1-verification.com"
            value={testDomain}
            onChange={(e) => setTestDomain(e.target.value)}
            className="flex-1 bg-[#080E19] border border-white/10 rounded-xl px-4 py-2.5 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-[#00D4FF] font-mono"
          />
          <button
            type="submit"
            className="px-5 py-2.5 bg-[#00D4FF] text-[#080E19] font-bold text-xs rounded-xl hover:bg-[#00E6A0] transition-all"
          >
            Test Mutation
          </button>
        </form>

        {simResult && (
          <div className="p-4 rounded-xl bg-[#080E19] border border-white/5 space-y-3 animate-in fade-in">
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs">
              <div>
                <span className="text-slate-500 text-[10px] uppercase font-bold">Input String</span>
                <p className="font-mono text-white mt-0.5">{simResult.input}</p>
              </div>
              <div>
                <span className="text-slate-500 text-[10px] uppercase font-bold">Homoglyph Normalization</span>
                <p className="font-mono text-cyan-300 mt-0.5">{simResult.normalized}</p>
              </div>
              <div>
                <span className="text-slate-500 text-[10px] uppercase font-bold">Target Brand</span>
                <p className={`font-bold mt-0.5 ${simResult.isImpersonation ? 'text-rose-400' : 'text-slate-400'}`}>
                  {simResult.matchedBrand}
                </p>
              </div>
            </div>
            {simResult.isImpersonation && (
              <div className="text-xs text-rose-300 bg-rose-950/20 p-2.5 rounded-lg border border-rose-500/20">
                &bull; <strong>Detected Pattern:</strong> {simResult.attackType}. This triggers a +30 point critical risk penalty in PhishGuard risk scoring.
              </div>
            )}
          </div>
        )}
      </div>

      {/* Brand Profiles Matrix */}
      <div className="soc-card p-6 space-y-4">
        <h3 className="text-sm font-bold text-white">Protected Corporate Profiles ({brandProfiles.length})</h3>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {brandProfiles.map((brand, idx) => (
            <div key={idx} className="p-4 rounded-xl bg-[#080E19] border border-white/5 space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-xs font-bold text-white">{brand.name}</span>
                <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                  Protected
                </span>
              </div>
              <div className="text-[11px] text-slate-400">
                Official: <span className="font-mono text-slate-300">{brand.official}</span>
              </div>
              <div className="flex flex-wrap gap-1 pt-1">
                {brand.monitored.map((kw, i) => (
                  <span key={i} className="px-2 py-0.5 rounded bg-white/5 text-slate-300 text-[10px] font-mono">
                    {kw}
                  </span>
                ))}
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

