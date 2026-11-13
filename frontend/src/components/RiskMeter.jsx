import React from 'react';
import { ShieldCheck, AlertTriangle, AlertOctagon, ShieldAlert } from 'lucide-react';

export default function RiskMeter({ score = 0, classification = 'safe', size = 'normal' }) {
  // Cap score between 0 and 100
  const clampedScore = Math.max(0, Math.min(100, Math.round(score)));

  let color = '#00E6A0';
  let label = 'Low Risk';
  let Icon = ShieldCheck;
  let bgBadge = 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30';

  if (clampedScore >= 70) {
    color = '#FF4D67';
    label = 'Critical Risk';
    Icon = AlertOctagon;
    bgBadge = 'bg-rose-500/10 text-rose-400 border-rose-500/30';
  } else if (clampedScore >= 40) {
    color = '#FF8C00';
    label = 'High Risk';
    Icon = ShieldAlert;
    bgBadge = 'bg-orange-500/10 text-orange-400 border-orange-500/30';
  } else if (clampedScore >= 20) {
    color = '#FFB020';
    label = 'Suspicious';
    Icon = AlertTriangle;
    bgBadge = 'bg-amber-500/10 text-amber-400 border-amber-500/30';
  }

  if (size === 'compact') {
    return (
      <div className="flex items-center space-x-3">
        <div className="relative w-12 h-12 flex items-center justify-center">
          <svg className="w-12 h-12 transform -rotate-90">
            <circle
              cx="24"
              cy="24"
              r="18"
              stroke="rgba(255, 255, 255, 0.1)"
              strokeWidth="4"
              fill="transparent"
            />
            <circle
              cx="24"
              cy="24"
              r="18"
              stroke={color}
              strokeWidth="4"
              fill="transparent"
              strokeDasharray={113}
              strokeDashoffset={113 - (113 * clampedScore) / 100}
              strokeLinecap="round"
              className="transition-all duration-700 ease-out"
            />
          </svg>
          <span className="absolute text-xs font-bold text-white">{clampedScore}</span>
        </div>
        <span className={`px-2 py-0.5 text-xs font-semibold rounded border ${bgBadge}`}>
          {label}
        </span>
      </div>
    );
  }

  return (
    <div className="flex flex-col items-center justify-center p-4 rounded-xl bg-[#080E19]/60 border border-white/5">
      <div className="relative w-36 h-36 flex items-center justify-center">
        {/* Glow behind the ring */}
        <div
          className="absolute inset-0 rounded-full blur-xl opacity-20 transition-all duration-700"
          style={{ backgroundColor: color }}
        />

        {/* SVG Circular Progress Gauge */}
        <svg className="w-36 h-36 transform -rotate-90">
          <circle
            cx="72"
            cy="72"
            r="56"
            stroke="rgba(255, 255, 255, 0.08)"
            strokeWidth="10"
            fill="transparent"
          />
          <circle
            cx="72"
            cy="72"
            r="56"
            stroke={color}
            strokeWidth="10"
            fill="transparent"
            strokeDasharray={351.8}
            strokeDashoffset={351.8 - (351.8 * clampedScore) / 100}
            strokeLinecap="round"
            className="transition-all duration-1000 ease-out"
          />
        </svg>

        {/* Center Score readout */}
        <div className="absolute flex flex-col items-center justify-center">
          <span className="text-3xl font-extrabold text-white tracking-tight">
            {clampedScore}
          </span>
          <span className="text-[10px] uppercase font-semibold text-slate-400 tracking-wider">
            / 100
          </span>
        </div>
      </div>

      {/* Severity Badge */}
      <div className={`mt-3 inline-flex items-center space-x-1.5 px-3 py-1 rounded-full border text-xs font-bold tracking-wide uppercase ${bgBadge}`}>
        <Icon className="w-3.5 h-3.5" />
        <span>{label}</span>
      </div>

      {/* Meter Scale Legend */}
      <div className="w-full mt-4 pt-3 border-t border-white/5 flex justify-between text-[10px] text-slate-400 font-medium">
        <span className="text-emerald-400">0 Safe</span>
        <span className="text-amber-400">20 Suspicious</span>
        <span className="text-orange-400">40 High</span>
        <span className="text-rose-400">70+ Critical</span>
      </div>
    </div>
  );
}

