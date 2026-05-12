import React from 'react';

export function RiskTable({ risks = [] }) {
  const residualClass = (r) => {
    const x = (r || '').toLowerCase();
    if (x === 'high') return 'text-red-200 bg-red-500/10 border-red-400/30';
    if (x === 'medium') return 'text-yellow-200 bg-yellow-500/10 border-yellow-400/30';
    return 'text-emerald-200 bg-emerald-500/10 border-emerald-400/30';
  };
  return (
    <div className="rounded-2xl border border-white/10 bg-slate-950/60 p-5 shadow-glow backdrop-blur-xl">
      <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
        <div>
          <h3 className="text-lg font-bold text-white">Governance Risk Register</h3>
          <p className="text-sm text-slate-400">Risks mapped to live Splunk evidence.</p>
        </div>
      </div>
      <div className="grid gap-3">
        {risks.map((risk) => (
          <div key={risk.id} className="rounded-2xl border border-white/10 bg-white/[0.03] p-4">
            <div className="flex flex-wrap items-start justify-between gap-3">
              <div>
                <div className="flex flex-wrap items-center gap-2">
                  <span className="rounded-lg bg-cyan-500/15 px-2 py-1 font-mono text-xs font-bold text-cyan-200">{risk.id}</span>
                  <span className={`rounded-full border px-2 py-1 text-xs font-semibold ${residualClass(risk.residual)}`}>{risk.residual}</span>
                  <span className="rounded-full border border-white/10 bg-white/5 px-2 py-1 text-xs text-slate-300">{risk.status}</span>
                </div>
                <h4 className="mt-3 font-bold text-white">{risk.title}</h4>
                <p className="mt-1 text-sm text-slate-400">{risk.category} · {risk.owasp}</p>
              </div>
              <div className="text-right">
                <div className="text-2xl font-black text-white">{risk.evidence_count || 0}</div>
                <div className="text-xs uppercase tracking-widest text-slate-400">Evidence events</div>
                <div className={`mt-2 rounded-full px-2 py-1 text-xs font-bold ${risk.live_status === 'LIVE' ? 'bg-emerald-500/15 text-emerald-200' : risk.live_status === 'NO_MATCH' ? 'bg-yellow-500/15 text-yellow-200' : 'bg-slate-500/15 text-slate-300'}`}>{risk.live_status}</div>
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
