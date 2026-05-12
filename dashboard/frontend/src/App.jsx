import React, { useEffect, useMemo, useState } from 'react';
import { createRoot } from 'react-dom/client';
import { Activity, AlertTriangle, CheckCircle2, Cpu, Gauge, RefreshCw, Shield, ShieldAlert, Server, Zap } from 'lucide-react';
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, PieChart, Pie, Cell, LineChart, Line, CartesianGrid } from 'recharts';
import './index.css';
import { getOverview, API_BASE } from './api';
import { MetricCard } from './components/MetricCard';
import { EventTable } from './components/EventTable';
import { RiskTable } from './components/RiskTable';

const eventNames = ['MSG_DECRYPTED','MSG_DELIVERED','PK_AUTH_OK','KEM_HKDF_DONE','AEAD_ENCRYPT_DONE','REPLAY_REJECT','AEAD_AUTH_FAIL','PK_AUTH_FAIL','RATE_LIMIT_HIT','SOURCE_BLOCKED'];
const colors = ['#22d3ee', '#34d399', '#a78bfa', '#fbbf24', '#fb7185', '#60a5fa', '#f472b6'];

function Shell({ children }) {
  return (
    <div className="min-h-screen">
      <div className="fixed inset-0 -z-10 bg-[linear-gradient(to_right,rgba(255,255,255,.04)_1px,transparent_1px),linear-gradient(to_bottom,rgba(255,255,255,.04)_1px,transparent_1px)] bg-[size:48px_48px]" />
      <div className="mx-auto max-w-7xl px-4 py-6 sm:px-6 lg:px-8">{children}</div>
    </div>
  );
}

function Header({ overview, loading, onRefresh }) {
  const ok = overview?.splunk?.ok;
  return (
    <header className="mb-8 overflow-hidden rounded-3xl border border-white/10 bg-slate-950/70 p-6 shadow-glow backdrop-blur-xl">
      <div className="flex flex-col gap-6 lg:flex-row lg:items-center lg:justify-between">
        <div>
          <div className="mb-3 inline-flex items-center gap-2 rounded-full border border-cyan-400/20 bg-cyan-400/10 px-3 py-1 text-xs font-bold uppercase tracking-[0.22em] text-cyan-200">
            <Shield className="h-4 w-4" /> PQC IoT Command Center
          </div>
          <h1 className="text-3xl font-black tracking-tight text-white sm:text-5xl">Post-Quantum IoT Security Dashboard</h1>
          <p className="mt-3 max-w-3xl text-slate-300">Unified frontend for live Splunk telemetry, Sender/Receiver status, attack validation evidence, and governance risk reporting.</p>
        </div>
        <div className="flex flex-col gap-3 rounded-2xl border border-white/10 bg-white/[0.04] p-4 min-w-[280px]">
          <div className="flex items-center justify-between gap-3">
            <span className="text-sm text-slate-400">Splunk REST</span>
            <span className={`rounded-full px-3 py-1 text-xs font-bold ${ok ? 'bg-emerald-500/15 text-emerald-200' : 'bg-red-500/15 text-red-200'}`}>{ok ? 'LIVE' : 'OFFLINE'}</span>
          </div>
          <div className="font-mono text-xs text-slate-300">{overview?.splunk?.base_url || 'https://localhost:8089'}</div>
          {!ok && <div className="text-xs text-red-200">{overview?.splunk?.reason || overview?.errors?.counts || 'Waiting for backend...'}</div>}
          <button onClick={onRefresh} className="mt-2 inline-flex items-center justify-center gap-2 rounded-xl bg-cyan-500 px-4 py-2 text-sm font-bold text-slate-950 transition hover:bg-cyan-300 disabled:opacity-60" disabled={loading}>
            <RefreshCw className={`h-4 w-4 ${loading ? 'animate-spin' : ''}`} /> Refresh
          </button>
        </div>
      </div>
    </header>
  );
}

function ChartCard({ title, subtitle, children }) {
  return (
    <div className="rounded-2xl border border-white/10 bg-slate-950/60 p-5 shadow-glow backdrop-blur-xl">
      <h3 className="text-lg font-bold text-white">{title}</h3>
      <p className="mb-5 text-sm text-slate-400">{subtitle}</p>
      {children}
    </div>
  );
}

function App() {
  const [overview, setOverview] = useState(null);
  const [loading, setLoading] = useState(false);
  const [lastUpdated, setLastUpdated] = useState(null);

  async function load() {
    setLoading(true);
    try {
      const data = await getOverview();
      setOverview(data);
      setLastUpdated(new Date());
    } catch (e) {
      setOverview({ ok: false, splunk: { ok: false, reason: e.message }, errors: { counts: e.message }, governance: { risks: [], attack_events: [], compliance: 0, posture: 'UNKNOWN' }, recent_events: [], devices: [], severity: [], counts: {} });
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    load();
    const t = setInterval(load, 5000);
    return () => clearInterval(t);
  }, []);

  const counts = overview?.counts || {};
  const gov = overview?.governance || {};
  const successful = (counts.MSG_DECRYPTED || 0) + (counts.MSG_DELIVERED || 0);
  const blocked = (counts.REPLAY_REJECT || 0) + (counts.AEAD_AUTH_FAIL || 0) + (counts.PK_AUTH_FAIL || 0) + (counts.RATE_LIMIT_HIT || 0) + (counts.SOURCE_BLOCKED || 0) + (counts.SENDER_AUTH_FAIL || 0);
  const eventChart = eventNames.map(name => ({ name, count: counts[name] || 0 })).filter(x => x.count > 0 || ['MSG_DECRYPTED','MSG_DELIVERED','PK_AUTH_OK','REPLAY_REJECT'].includes(x.name));
  const severityData = (overview?.severity || []).map((r) => ({ name: (r.severity || 'unknown').toUpperCase(), value: Number(r.count || 0) }));
  const timeline = useMemo(() => {
    const map = new Map();
    for (const row of overview?.timeline || []) {
      const key = String(row._time || '').slice(11,16) || String(row._time || '');
      const prev = map.get(key) || { time: key, count: 0 };
      prev.count += Number(row.count || 0);
      map.set(key, prev);
    }
    return Array.from(map.values()).slice(-24);
  }, [overview]);

  return (
    <Shell>
      <Header overview={overview} loading={loading} onRefresh={load} />

      <div className="mb-6 flex flex-wrap items-center justify-between gap-3 text-sm text-slate-400">
        <div>Backend API: <span className="font-mono text-cyan-200">{API_BASE}</span></div>
        <div>Last updated: <span className="text-slate-200">{lastUpdated ? lastUpdated.toLocaleTimeString() : 'never'}</span></div>
      </div>

      <section className="grid gap-4 md:grid-cols-2 xl:grid-cols-5">
        <MetricCard title="Total Events" value={(overview?.total_events || 0).toLocaleString()} subtitle="Live Splunk telemetry" icon={Activity} tone="cyan" />
        <MetricCard title="Successful PQC" value={successful.toLocaleString()} subtitle="Delivered + decrypted" icon={CheckCircle2} tone="green" />
        <MetricCard title="Blocked Attacks" value={blocked.toLocaleString()} subtitle="Rejected security events" icon={ShieldAlert} tone={blocked > 0 ? 'yellow' : 'green'} />
        <MetricCard title="Compliance" value={`${gov.compliance || 0}%`} subtitle={`${gov.risk_count || 10} risks tracked`} icon={Gauge} tone="violet" />
        <MetricCard title="Posture" value={gov.posture || 'UNKNOWN'} subtitle="Governance status" icon={Server} tone={gov.posture === 'ACCEPTABLE' ? 'green' : 'red'} />
      </section>

      <section className="mt-6 grid gap-6 xl:grid-cols-3">
        <ChartCard title="Event Counts" subtitle="Key events from Sender and Receiver">
          <div className="h-80">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={eventChart} layout="vertical" margin={{ left: 40, right: 16 }}>
                <XAxis type="number" stroke="#94a3b8" />
                <YAxis dataKey="name" type="category" width={150} stroke="#94a3b8" tick={{ fontSize: 11 }} />
                <Tooltip contentStyle={{ background: '#020617', border: '1px solid rgba(255,255,255,.12)', borderRadius: 12 }} />
                <Bar dataKey="count" fill="#22d3ee" radius={[0, 8, 8, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </ChartCard>

        <ChartCard title="Severity Mix" subtitle="SOC-style severity distribution">
          <div className="h-80">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie data={severityData.length ? severityData : [{name:'NO DATA', value:1}]} cx="50%" cy="50%" innerRadius={70} outerRadius={110} dataKey="value" label>
                  {(severityData.length ? severityData : [{name:'NO DATA'}]).map((_, index) => <Cell key={index} fill={colors[index % colors.length]} />)}
                </Pie>
                <Tooltip contentStyle={{ background: '#020617', border: '1px solid rgba(255,255,255,.12)', borderRadius: 12 }} />
              </PieChart>
            </ResponsiveContainer>
          </div>
        </ChartCard>

        <ChartCard title="Telemetry Trend" subtitle="Recent event volume over time">
          <div className="h-80">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={timeline}>
                <CartesianGrid stroke="rgba(148,163,184,.15)" />
                <XAxis dataKey="time" stroke="#94a3b8" />
                <YAxis stroke="#94a3b8" />
                <Tooltip contentStyle={{ background: '#020617', border: '1px solid rgba(255,255,255,.12)', borderRadius: 12 }} />
                <Line type="monotone" dataKey="count" stroke="#34d399" strokeWidth={3} dot={false} />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </ChartCard>
      </section>

      <section className="mt-6 grid gap-6 xl:grid-cols-3">
        <div className="xl:col-span-2"><EventTable events={overview?.recent_events || []} /></div>
        <div className="rounded-2xl border border-white/10 bg-slate-950/60 p-5 shadow-glow backdrop-blur-xl">
          <div className="mb-4 flex items-center gap-3">
            <AlertTriangle className="h-5 w-5 text-yellow-300" />
            <div>
              <h3 className="font-bold text-white">Attack Validation</h3>
              <p className="text-sm text-slate-400">Detection evidence by attack type.</p>
            </div>
          </div>
          <div className="grid gap-3">
            {(gov.attack_events || []).map((a) => (
              <div key={a.event_type} className="rounded-xl border border-white/10 bg-white/[0.03] p-3">
                <div className="flex items-center justify-between gap-3">
                  <div>
                    <div className="font-mono text-xs font-bold text-cyan-200">{a.event_type}</div>
                    <div className="mt-1 text-sm text-slate-300">{a.label}</div>
                    <div className="mt-1 text-xs text-slate-500">{a.risk}</div>
                  </div>
                  <div className={`rounded-2xl px-3 py-2 text-xl font-black ${a.count > 0 ? 'bg-yellow-500/15 text-yellow-200' : 'bg-emerald-500/15 text-emerald-200'}`}>{a.count}</div>
                </div>
              </div>
            ))}
          </div>
        </div>
      </section>

      <section className="mt-6 grid gap-6 xl:grid-cols-3">
        <div className="xl:col-span-2"><RiskTable risks={gov.risks || []} /></div>
        <div className="rounded-2xl border border-white/10 bg-slate-950/60 p-5 shadow-glow backdrop-blur-xl">
          <div className="mb-4 flex items-center gap-3">
            <Cpu className="h-5 w-5 text-violet-300" />
            <div>
              <h3 className="font-bold text-white">Devices</h3>
              <p className="text-sm text-slate-400">Last seen devices from Splunk.</p>
            </div>
          </div>
          <div className="grid gap-3">
            {(overview?.devices || []).length === 0 ? <p className="text-sm text-slate-400">No device data yet.</p> : overview.devices.map((d, i) => (
              <div key={`${d.device_id}-${i}`} className="rounded-xl border border-white/10 bg-white/[0.03] p-4">
                <div className="flex items-center justify-between">
                  <div>
                    <div className="font-bold text-white">{d.device_id || 'unknown'}</div>
                    <div className="text-sm text-slate-400">{d.role || 'unknown role'}</div>
                  </div>
                  <div className="rounded-full bg-cyan-500/15 px-3 py-1 text-sm font-bold text-cyan-200">{d.count || 0}</div>
                </div>
              </div>
            ))}
          </div>
          <div className="mt-6 rounded-2xl border border-cyan-400/20 bg-cyan-400/10 p-4 text-sm text-cyan-100">
            <div className="mb-2 flex items-center gap-2 font-bold"><Zap className="h-4 w-4" /> Demo flow</div>
            <ol className="ml-4 list-decimal space-y-1 text-slate-300">
              <li>Start Splunk + HEC.</li>
              <li>Reset Receiver, then Sender.</li>
              <li>Run attack validation.</li>
              <li>Watch this dashboard update automatically.</li>
            </ol>
          </div>
        </div>
      </section>
    </Shell>
  );
}

createRoot(document.getElementById('root')).render(<App />);
