import React from 'react';
import { useNavigate } from 'react-router-dom';
import { ArrowUpRight, Mail } from 'lucide-react';

export default function Navbar({ collapsed, pageTitle = 'PhishGuard' }) {
  const navigate = useNavigate();

  return (
    <header
      className={`glass-panel fixed right-0 top-0 z-30 flex h-16 items-center justify-between border-b border-white/10 px-4 transition-all duration-300 sm:px-6 ${
        collapsed ? 'left-20' : 'left-64'
      }`}
    >
      <div className="flex items-center gap-3">
        <h1 className="text-lg font-black tracking-tight text-[#f3f5e9]">{pageTitle}</h1>
        <span className="hidden rounded-full border border-white/10 bg-white/[0.04] px-2 py-0.5 font-mono text-[9px] uppercase tracking-[0.18em] text-slate-400 md:inline-flex">
          Gmail signal
        </span>
      </div>

      <button
        onClick={() => navigate('/gmail-connect')}
        className="inline-flex items-center gap-2 rounded-xl border border-[#d5ff72]/20 bg-[#d5ff72]/10 px-3 py-2 text-xs font-bold uppercase tracking-[0.12em] text-[#d5ff72] transition hover:bg-[#d5ff72]/20"
      >
        <Mail className="h-3.5 w-3.5" />
        <span className="hidden sm:inline">Gmail setup</span>
        <ArrowUpRight className="h-3.5 w-3.5" />
      </button>
    </header>
  );
}
