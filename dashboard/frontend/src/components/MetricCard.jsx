import React from 'react';

export function MetricCard({ title, value, subtitle, icon: Icon, tone = 'cyan' }) {
  const tones = {
    cyan: 'from-cyan-500/20 to-blue-500/10 border-cyan-400/20 text-cyan-200',
    green: 'from-emerald-500/20 to-green-500/10 border-emerald-400/20 text-emerald-200',
    yellow: 'from-yellow-500/20 to-orange-500/10 border-yellow-400/20 text-yellow-200',
    red: 'from-red-500/20 to-rose-500/10 border-red-400/20 text-red-200',
    violet: 'from-violet-500/20 to-fuchsia-500/10 border-violet-400/20 text-violet-200',
  };
  return (
    <div className={`rounded-2xl border bg-gradient-to-br ${tones[tone] || tones.cyan} p-5 shadow-glow backdrop-blur-xl`}>
      <div className="flex items-start justify-between gap-4">
        <div>
          <p className="text-xs uppercase tracking-[0.22em] text-slate-400">{title}</p>
          <div className="mt-2 text-3xl font-black text-white">{value}</div>
          <p className="mt-2 text-sm text-slate-300">{subtitle}</p>
        </div>
        {Icon && <div className="rounded-2xl bg-white/10 p-3"><Icon className="h-6 w-6" /></div>}
      </div>
    </div>
  );
}
