import React from 'react';

function badge(severity) {
  const s = (severity || 'info').toLowerCase();
  const cls = s === 'high' || s === 'critical'
    ? 'bg-red-500/15 text-red-200 border-red-400/30'
    : s === 'medium'
    ? 'bg-yellow-500/15 text-yellow-200 border-yellow-400/30'
    : 'bg-emerald-500/15 text-emerald-200 border-emerald-400/30';
  return <span className={`rounded-full border px-2 py-1 text-xs font-semibold ${cls}`}>{s.toUpperCase()}</span>;
}

export function EventTable({ events = [] }) {
  return (
    <div className="overflow-hidden rounded-2xl border border-white/10 bg-slate-950/60 shadow-glow backdrop-blur-xl">
      <div className="border-b border-white/10 px-5 py-4">
        <h3 className="text-lg font-bold text-white">Live Event Timeline</h3>
        <p className="text-sm text-slate-400">Newest security telemetry from Splunk index.</p>
      </div>
      <div className="max-h-[520px] overflow-auto">
        <table className="w-full min-w-[900px] text-left text-sm">
          <thead className="sticky top-0 bg-slate-950/95 text-xs uppercase tracking-wider text-slate-400">
            <tr>
              <th className="px-5 py-3">Time</th>
              <th className="px-5 py-3">Event</th>
              <th className="px-5 py-3">Device</th>
              <th className="px-5 py-3">Role</th>
              <th className="px-5 py-3">Severity</th>
              <th className="px-5 py-3">Action</th>
              <th className="px-5 py-3">Source IP</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-white/5">
            {events.length === 0 ? (
              <tr><td colSpan="7" className="px-5 py-8 text-center text-slate-400">No live events returned yet.</td></tr>
            ) : events.map((e, idx) => (
              <tr key={`${e._time || e.time}-${idx}`} className="hover:bg-white/[0.03]">
                <td className="px-5 py-3 font-mono text-xs text-slate-300">{String(e._time || e.time || '').slice(0, 19)}</td>
                <td className="px-5 py-3 font-bold text-cyan-100">{e.event_type || '-'}</td>
                <td className="px-5 py-3 text-slate-200">{e.device_id || '-'}</td>
                <td className="px-5 py-3 text-slate-300">{e.role || '-'}</td>
                <td className="px-5 py-3">{badge(e.severity)}</td>
                <td className="px-5 py-3 text-slate-300">{e.action || e.message || '-'}</td>
                <td className="px-5 py-3 font-mono text-xs text-slate-400">{e.src_ip || '-'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
