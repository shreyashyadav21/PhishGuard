import React from 'react';
import { NavLink } from 'react-router-dom';
import {
  ChevronLeft,
  ChevronRight,
  FileText,
  Home,
  Mail,
  Settings,
  ShieldAlert,
  ShieldCheck,
  Radio,
} from 'lucide-react';

export default function Sidebar({ collapsed, setCollapsed }) {
  const navItems = [
    { label: 'Home', icon: Home, path: '/' },
    { label: 'Gmail Protection', icon: Mail, path: '/gmail-connect' },
    { label: 'Threats', icon: ShieldAlert, path: '/threats' },
    { label: 'Reports', icon: FileText, path: '/reports' },
    { label: 'Settings', icon: Settings, path: '/settings' },
  ];

  return (
    <aside
      className={`glass-panel fixed left-0 top-0 z-40 flex h-screen flex-col border-r border-white/10 transition-all duration-300 ${
        collapsed ? 'w-20' : 'w-64'
      }`}
    >
      <div className="flex h-16 shrink-0 items-center justify-between border-b border-white/10 px-4">
        <div className="flex items-center gap-3 overflow-hidden">
          <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl border border-[#d5ff72]/25 bg-[#d5ff72]/10">
            <ShieldCheck className="h-5 w-5 text-[#d5ff72]" />
          </div>
          {!collapsed && (
            <div className="flex flex-col">
              <span className="text-base font-black tracking-[0.14em] text-[#f3f5e9]">
                PHISH<span className="text-[#d5ff72]">GUARD</span>
              </span>
              <span className="flex items-center gap-1 text-[9px] font-semibold uppercase tracking-[0.2em] text-[#aeb9a6]">
                <span className="h-1.5 w-1.5 rounded-full bg-[#d5ff72]" />
                inbox signal
              </span>
            </div>
          )}
        </div>
        <button
          onClick={() => setCollapsed(!collapsed)}
          className="rounded-lg p-1.5 text-slate-400 transition hover:bg-white/10 hover:text-white"
          title={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
        >
          {collapsed ? <ChevronRight className="h-4 w-4" /> : <ChevronLeft className="h-4 w-4" />}
        </button>
      </div>

      <nav className="flex-1 space-y-1 overflow-y-auto px-3 py-4">
        {navItems.map((item) => {
          const Icon = item.icon;
          return (
            <NavLink
              key={item.path}
              to={item.path}
              end={item.path === '/'}
              className={({ isActive }) =>
                `flex items-center gap-3 rounded-xl px-3 py-2.5 text-xs font-semibold transition-all ${
                  isActive
                    ? 'border border-[#d5ff72]/25 bg-[#d5ff72]/10 text-[#d5ff72]'
                    : 'text-slate-400 hover:bg-white/5 hover:text-white'
                }`
              }
              title={collapsed ? item.label : undefined}
            >
              <Icon className="h-4 w-4 shrink-0" />
              {!collapsed && <span className="truncate">{item.label}</span>}
            </NavLink>
          );
        })}
      </nav>

      <div className="border-t border-white/10 p-3">
        {!collapsed ? (
          <div className="rounded-2xl border border-white/10 bg-white/[0.04] p-3">
            <div className="flex items-center justify-between gap-3">
              <span className="text-[10px] font-semibold uppercase tracking-[0.2em] text-slate-400">Gmail check</span>
              <span className="rounded-full border border-[#d5ff72]/20 bg-[#d5ff72]/10 px-2 py-0.5 text-[9px] font-bold uppercase tracking-[0.15em] text-[#d5ff72]">on open</span>
            </div>
            <div className="mt-3 flex items-center gap-2 text-sm text-slate-300">
              <Radio className="h-3.5 w-3.5 text-[#d5ff72]" />
              <span>Message verdicts</span>
            </div>
          </div>
        ) : (
          <div className="flex justify-center" title="Gmail checks on message open">
            <Radio className="h-4 w-4 text-[#d5ff72]" />
          </div>
        )}
      </div>
    </aside>
  );
}
