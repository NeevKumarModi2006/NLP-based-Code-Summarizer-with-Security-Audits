import React, { useState, useCallback, useEffect } from 'react';
import {
  AreaChart, Area,
  LineChart, Line,
  XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer
} from 'recharts';
import {
  Zap, Cpu, MemoryStick, Clock, Gauge, Activity,
  Upload, RefreshCw, CheckCircle, AlertTriangle, CloudRain
} from 'lucide-react';
import './index.css';

/* ----------------------------------------------------------------
   Sample / demo report data
   (In production this would come from the Python API.
    Users paste JSON exported from EnergyReport.to_dict())
---------------------------------------------------------------- */
const DEMO_REPORT = {
  wall_time_s: 2.547,
  cpu_time_s: 1.832,
  peak_memory_mb: 52.3,
  avg_cpu_percent: 71.4,
  estimated_energy_j: 3.319,
  estimated_carbon_gco2: 0.000437,
  rapl_supported: false,
  phase_timings: { spin: 2.001, sleep: 0.502 },
  readings: Array.from({ length: 50 }, (_, i) => ({
    timestamp: Date.now() / 1000 - (50 - i) * 0.05,
    cpu_percent: 60 + Math.sin(i * 0.4) * 30,
    memory_mb: 48 + Math.random() * 8,
    rapl_energy_uj: null,
  })),
};

/* ----------------------------------------------------------------
   Custom recharts tooltip
---------------------------------------------------------------- */
function CustomTooltip({ active, payload, label, unitLabel }) {
  if (!active || !payload?.length) return null;
  return (
    <div className="custom-tooltip">
      <div className="tt-label">t = {Number(label).toFixed(2)} s</div>
      {payload.map((p) => (
        <div className="tt-val" key={p.dataKey}>
          {p.name}: {Number(p.value).toFixed(2)} {unitLabel}
        </div>
      ))}
    </div>
  );
}

/* ----------------------------------------------------------------
   Stat card
---------------------------------------------------------------- */
function StatCard({ icon: Icon, label, value, unit, sub }) {
  return (
    <div className="stat-card animate-in">
      <div className="stat-label">
        <Icon size={13} />
        {label}
      </div>
      <div className="stat-value">
        {value}
        {unit && <span className="stat-unit">{unit}</span>}
      </div>
      {sub && <div className="stat-sub">{sub}</div>}
    </div>
  );
}

/* ----------------------------------------------------------------
   Phase timing table
---------------------------------------------------------------- */
function PhaseTable({ phaseTimings, wallTime }) {
  const entries = Object.entries(phaseTimings);
  if (!entries.length) return null;
  const maxT = Math.max(...entries.map(([, t]) => t));
  return (
    <div className="chart-card animate-in">
      <h3>Phase Timings</h3>
      <table className="phase-table">
        <thead>
          <tr>
            <th>Phase</th>
            <th>Duration</th>
            <th style={{ width: '40%' }}>Share</th>
          </tr>
        </thead>
        <tbody>
          {entries.map(([name, dur]) => (
            <tr key={name}>
              <td>{name}</td>
              <td>{dur.toFixed(3)} s</td>
              <td>
                <span style={{ color: 'var(--text-muted)', fontSize: '0.72rem' }}>
                  {((dur / wallTime) * 100).toFixed(1)} %
                </span>
                <div className="phase-bar-wrap">
                  <div
                    className="phase-bar"
                    style={{ width: `${(dur / maxT) * 100}%` }}
                  />
                </div>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

/* ----------------------------------------------------------------
   Reading charts
---------------------------------------------------------------- */
function ReadingCharts({ readings }) {
  if (!readings?.length) return null;

  // Normalise: x axis = seconds since start
  const t0 = readings[0].timestamp;
  const data = readings.map((r) => ({
    t: +(r.timestamp - t0).toFixed(2),
    cpu: +r.cpu_percent.toFixed(1),
    mem: +r.memory_mb.toFixed(1),
  }));

  const chartProps = {
    margin: { top: 4, right: 10, left: -10, bottom: 0 },
  };

  return (
    <>
      <div className="chart-card animate-in">
        <h3>CPU Utilisation over time</h3>
        <ResponsiveContainer width="100%" height={180}>
          <AreaChart data={data} {...chartProps}>
            <defs>
              <linearGradient id="cpuGrad" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%"  stopColor="var(--text-muted)" stopOpacity={0.15} />
                <stop offset="95%" stopColor="var(--text-muted)" stopOpacity={0} />
              </linearGradient>
            </defs>
            <CartesianGrid stroke="var(--border)" strokeDasharray="3 3" />
            <XAxis dataKey="t" tick={{ fill: 'var(--text-muted)', fontSize: 10 }} tickLine={false} />
            <YAxis domain={[0, 100]} tick={{ fill: 'var(--text-muted)', fontSize: 10 }} tickLine={false} unit="%" />
            <Tooltip content={<CustomTooltip unitLabel="%" />} />
            <Area
              type="monotone"
              dataKey="cpu"
              name="CPU"
              stroke="var(--accent)"
              strokeWidth={2}
              fill="url(#cpuGrad)"
              dot={false}
            />
          </AreaChart>
        </ResponsiveContainer>
      </div>

      <div className="chart-card animate-in">
        <h3>Memory (RSS) over time</h3>
        <ResponsiveContainer width="100%" height={180}>
          <LineChart data={data} {...chartProps}>
            <CartesianGrid stroke="var(--border)" strokeDasharray="3 3" />
            <XAxis dataKey="t" tick={{ fill: 'var(--text-muted)', fontSize: 10 }} tickLine={false} />
            <YAxis tick={{ fill: 'var(--text-muted)', fontSize: 10 }} tickLine={false} unit=" MB" />
            <Tooltip content={<CustomTooltip unitLabel="MB" />} />
            <Line
              type="monotone"
              dataKey="mem"
              name="Memory"
              stroke="var(--text-muted)"
              strokeWidth={2}
              strokeDasharray="4 4"
              dot={false}
            />
          </LineChart>
        </ResponsiveContainer>
      </div>
    </>
  );
}

/* ----------------------------------------------------------------
   Upload / paste zone
---------------------------------------------------------------- */
function UploadZone({ onReport }) {
  const [dragging, setDragging] = useState(false);
  const [error, setError] = useState('');

  const parse = (text) => {
    try {
      const data = JSON.parse(text);
      if (!('wall_time_s' in data)) throw new Error('Not a valid EnergyReport JSON.');
      setError('');
      onReport(data);
    } catch (e) {
      setError(e.message);
    }
  };

  const onDrop = useCallback((e) => {
    e.preventDefault();
    setDragging(false);
    const file = e.dataTransfer.files[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (ev) => parse(ev.target.result);
    reader.readAsText(file);
  }, []);

  const onFileChange = (e) => {
    const file = e.target.files[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (ev) => parse(ev.target.result);
    reader.readAsText(file);
  };

  return (
    <div
      className={`upload-zone${dragging ? ' drag-over' : ''}`}
      onDragOver={(e) => { e.preventDefault(); setDragging(true); }}
      onDragLeave={() => setDragging(false)}
      onDrop={onDrop}
      onClick={() => document.getElementById('file-input').click()}
    >
      <input
        id="file-input"
        type="file"
        accept=".json,application/json"
        style={{ display: 'none' }}
        onChange={onFileChange}
      />
      <div className="upload-icon">
        <Upload size={36} />
      </div>
      <h2>Drop an EnergyReport JSON file</h2>
      <p>
        Export from Python with <code style={{ color: 'var(--text-muted)' }}>report.to_dict()</code>
        {' '}then save as JSON and upload here, or click to browse.
      </p>
      {error && (
        <p style={{ color: 'var(--text-muted)', marginTop: 10, fontSize: '0.8rem' }}>
          ⚠ {error}
        </p>
      )}
    </div>
  );
}

/* ----------------------------------------------------------------
   LOC vs Energy / Carbon Charts (Scalability Analysis)
---------------------------------------------------------------- */
const SCALABILITY_DATA = [
  { loc: 10, energy: 29.01, carbon: 0.0038, memory: 1204.9, wallTime: 11.68, cpuPercent: 7.3 },
  { loc: 50, energy: 65.0, carbon: 0.0085, memory: 1280.0, wallTime: 11.4, cpuPercent: 10.5 },
  { loc: 100, energy: 110.0, carbon: 0.0145, memory: 1360.0, wallTime: 11.1, cpuPercent: 14.5 },
  { loc: 150, energy: 158.75, carbon: 0.0209, memory: 1470.6, wallTime: 10.78, cpuPercent: 18.0 },
  { loc: 250, energy: 310.0, carbon: 0.040, memory: 1440.0, wallTime: 19.5, cpuPercent: 18.3 },
  { loc: 400, energy: 540.0, carbon: 0.071, memory: 1410.0, wallTime: 33.0, cpuPercent: 18.6 },
  { loc: 600, energy: 835.75, carbon: 0.1102, memory: 1383.4, wallTime: 51.81, cpuPercent: 18.9 },
];

const CPU_SCALABILITY_DATA = [...SCALABILITY_DATA].sort((a, b) => a.cpuPercent - b.cpuPercent);

function LocMetricsCharts() {
  const chartProps = { margin: { top: 20, right: 10, left: -20, bottom: 0 } };

  return (
    <div className="section" style={{ marginTop: '2rem' }}>
      <div className="section-title">Scalability Analysis</div>
      <div style={{ display: 'grid', gridTemplateColumns: 'minmax(0, 1fr) minmax(0, 1fr)', gap: '1.5rem', marginBottom: '1.5rem' }}>
        <div className="chart-card animate-in">
          <h3>LOC vs Energy Consumption</h3>
          <ResponsiveContainer width="100%" height={220}>
            <LineChart data={SCALABILITY_DATA} {...chartProps}>
              <CartesianGrid stroke="var(--border)" strokeDasharray="3 3" />
              <XAxis dataKey="loc" tick={{ fill: 'var(--text-muted)', fontSize: 10 }} tickLine={false} unit=" LOC" />
              <YAxis tick={{ fill: 'var(--text-muted)', fontSize: 10 }} tickLine={false} unit=" J" />
              <Tooltip
                contentStyle={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border)', color: 'var(--text-primary)' }}
                itemStyle={{ color: 'var(--accent)' }}
                labelStyle={{ color: 'var(--text-muted)', marginBottom: '5px' }}
                formatter={(val) => [`${val} J`, 'Energy']}
                labelFormatter={(label) => `Lines of Code: ${label}`}
              />
              <Line type="monotone" dataKey="energy" name="Energy" stroke="var(--accent)" strokeWidth={3} dot={false} />
            </LineChart>
          </ResponsiveContainer>
        </div>

        <div className="chart-card animate-in">
          <h3>LOC vs Carbon Emission</h3>
          <ResponsiveContainer width="100%" height={220}>
            <LineChart data={SCALABILITY_DATA} {...chartProps}>
              <CartesianGrid stroke="var(--border)" strokeDasharray="3 3" />
              <XAxis dataKey="loc" tick={{ fill: 'var(--text-muted)', fontSize: 10 }} tickLine={false} unit=" LOC" />
              <YAxis tick={{ fill: 'var(--text-muted)', fontSize: 10 }} tickLine={false} />
              <Tooltip
                contentStyle={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border)', color: 'var(--text-primary)' }}
                itemStyle={{ color: '#10B981' }}
                labelStyle={{ color: 'var(--text-muted)', marginBottom: '5px' }}
                formatter={(val) => [`${val} gCO₂eq`, 'Carbon Emission']}
                labelFormatter={(label) => `Lines of Code: ${label}`}
              />
              <Line type="monotone" dataKey="carbon" name="Carbon" stroke="#10B981" strokeWidth={3} dot={false} />
            </LineChart>
          </ResponsiveContainer>
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'minmax(0, 1fr) minmax(0, 1fr)', gap: '1.5rem', marginBottom: '1.5rem' }}>
        <div className="chart-card animate-in">
          <h3>LOC vs Memory Usage (Peak)</h3>
          <ResponsiveContainer width="100%" height={220}>
            <LineChart data={SCALABILITY_DATA} {...chartProps}>
              <CartesianGrid stroke="var(--border)" strokeDasharray="3 3" />
              <XAxis dataKey="loc" tick={{ fill: 'var(--text-muted)', fontSize: 10 }} tickLine={false} unit=" LOC" />
              <YAxis tick={{ fill: 'var(--text-muted)', fontSize: 10 }} tickLine={false} unit=" MB" />
              <Tooltip
                contentStyle={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border)', color: 'var(--text-primary)' }}
                itemStyle={{ color: '#8B5CF6' }}
                labelStyle={{ color: 'var(--text-muted)', marginBottom: '5px' }}
                formatter={(val) => [`${val} MB`, 'Memory']}
                labelFormatter={(label) => `Lines of Code: ${label}`}
              />
              <Line type="monotone" dataKey="memory" name="Memory" stroke="#8B5CF6" strokeWidth={3} dot={false} />
            </LineChart>
          </ResponsiveContainer>
        </div>

        <div className="chart-card animate-in">
          <h3>LOC vs Execution Time</h3>
          <ResponsiveContainer width="100%" height={220}>
            <LineChart data={SCALABILITY_DATA} {...chartProps}>
              <CartesianGrid stroke="var(--border)" strokeDasharray="3 3" />
              <XAxis dataKey="loc" tick={{ fill: 'var(--text-muted)', fontSize: 10 }} tickLine={false} unit=" LOC" />
              <YAxis tick={{ fill: 'var(--text-muted)', fontSize: 10 }} tickLine={false} unit=" s" />
              <Tooltip
                contentStyle={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border)', color: 'var(--text-primary)' }}
                itemStyle={{ color: '#F59E0B' }}
                labelStyle={{ color: 'var(--text-muted)', marginBottom: '5px' }}
                formatter={(val) => [`${val} s`, 'Execution Time']}
                labelFormatter={(label) => `Lines of Code: ${label}`}
              />
              <Line type="monotone" dataKey="wallTime" name="Execution Time" stroke="#F59E0B" strokeWidth={3} dot={false} />
            </LineChart>
          </ResponsiveContainer>
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'minmax(0, 1fr) minmax(0, 1fr)', gap: '1.5rem' }}>
        <div className="chart-card animate-in">
          <h3>LOC vs CPU Utilisation</h3>
          <ResponsiveContainer width="100%" height={220}>
            <LineChart data={SCALABILITY_DATA} {...chartProps}>
              <CartesianGrid stroke="var(--border)" strokeDasharray="3 3" />
              <XAxis dataKey="loc" tick={{ fill: 'var(--text-muted)', fontSize: 10 }} tickLine={false} unit=" LOC" />
              <YAxis tick={{ fill: 'var(--text-muted)', fontSize: 10 }} tickLine={false} unit=" %" />
              <Tooltip
                contentStyle={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border)', color: 'var(--text-primary)' }}
                itemStyle={{ color: '#EF4444' }}
                labelStyle={{ color: 'var(--text-muted)', marginBottom: '5px' }}
                formatter={(val) => [`${val} %`, 'CPU Utilisation']}
                labelFormatter={(label) => `Lines of Code: ${label}`}
              />
              <Line type="monotone" dataKey="cpuPercent" name="CPU Utilisation" stroke="#EF4444" strokeWidth={3} dot={false} />
            </LineChart>
          </ResponsiveContainer>
        </div>

        <div className="chart-card animate-in">
          <h3>CPU Utilisation vs Execution Time</h3>
          <ResponsiveContainer width="100%" height={220}>
            <LineChart data={CPU_SCALABILITY_DATA} {...chartProps}>
              <CartesianGrid stroke="var(--border)" strokeDasharray="3 3" />
              <XAxis dataKey="cpuPercent" tick={{ fill: 'var(--text-muted)', fontSize: 10 }} tickLine={false} unit=" %" />
              <YAxis tick={{ fill: 'var(--text-muted)', fontSize: 10 }} tickLine={false} unit=" s" />
              <Tooltip
                contentStyle={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border)', color: 'var(--text-primary)' }}
                itemStyle={{ color: '#3B82F6' }}
                labelStyle={{ color: 'var(--text-muted)', marginBottom: '5px' }}
                formatter={(val) => [`${val} s`, 'Execution Time']}
                labelFormatter={(label) => `CPU Utilisation: ${label}%`}
              />
              <Line type="monotone" dataKey="wallTime" name="Execution Time" stroke="#3B82F6" strokeWidth={3} dot={false} />
            </LineChart>
          </ResponsiveContainer>
        </div>
      </div>
    </div>
  );
}

/* ----------------------------------------------------------------
   Dashboard – renders a full EnergyReport
---------------------------------------------------------------- */
function Dashboard({ report, onReset }) {
  const {
    wall_time_s,
    cpu_time_s,
    peak_memory_mb,
    avg_cpu_percent,
    estimated_energy_j,
    estimated_carbon_gco2,
    rapl_supported,
    readings,
    phase_timings,
  } = report;

  return (
    <div>
      {/* ---- Top row: title + controls ---- */}
      <div style={{ display: 'flex', alignItems: 'center', marginBottom: 24, gap: 12 }}>
        <h2 style={{ fontSize: '1rem', fontWeight: 600, flex: 1, color: 'var(--text)' }}>
          Report Overview
        </h2>
        <div className={`rapl-badge ${rapl_supported ? 'hw' : 'est'}`}>
          {rapl_supported
            ? <><CheckCircle size={11} /> RAPL hardware</>
            : <><AlertTriangle size={11} /> TDP estimate</>}
        </div>
        <button className="btn btn-ghost" onClick={onReset}>
          <RefreshCw size={13} /> New report
        </button>
      </div>

      {/* ---- Stat grid ---- */}
      <div className="stat-grid">
        <StatCard icon={Clock}       label="Wall time"       value={wall_time_s.toFixed(3)}        unit="s" />
        <StatCard icon={Cpu}         label="CPU time"        value={cpu_time_s.toFixed(3)}          unit="s" />
        <StatCard icon={MemoryStick} label="Peak memory"     value={peak_memory_mb.toFixed(1)}      unit="MB" />
        <StatCard icon={Gauge}       label="Avg CPU"         value={avg_cpu_percent.toFixed(1)}     unit="%" />
        <StatCard
          icon={Zap}
          label="Energy"
          value={estimated_energy_j.toFixed(4)}
          unit="J"
          sub={rapl_supported ? 'from RAPL' : 'TDP estimate'}
        />
        <StatCard
          icon={CloudRain}
          label="Carbon Emission"
          value={(estimated_carbon_gco2 !== undefined ? estimated_carbon_gco2 : (estimated_energy_j / 3600000.0) * 475.0).toFixed(6)}
          unit="gCO₂eq"
          sub="Global avg intensity"
        />
        <StatCard icon={Activity} label="Snapshots" value={readings.length} unit="" />
      </div>

      {/* ---- Charts ---- */}
      <div className="section">
        <div className="section-title">Resource Timeseries</div>
        <ReadingCharts readings={readings} />
      </div>

      {/* ---- Phase timings ---- */}
      {Object.keys(phase_timings).length > 0 && (
        <div className="section">
          <div className="section-title">Phase Breakdown</div>
          <PhaseTable phaseTimings={phase_timings} wallTime={wall_time_s} />
        </div>
      )}

      {/* ---- LOC vs Metrics Graphs ---- */}
      <LocMetricsCharts />
    </div>
  );
}

/* ----------------------------------------------------------------
   App root
---------------------------------------------------------------- */
export default function App() {
  const [report, setReport] = useState(null);

  useEffect(() => {
    // Auto-fetch the latest report generated by Streamlit
    fetch('/reports/latest_report.json')
      .then(res => res.ok ? res.json() : null)
      .then(data => {
        if (data && data.wall_time_s) {
          setReport(data);
        }
      })
      .catch(() => {});
  }, []);

  return (
    <div className="app">
      {/* Header */}
      <header className="header">
        <div className="header-logo">
          <Zap size={18} strokeWidth={2.5} />
        </div>
        <h1>Energy Monitor</h1>
        <span className="header-badge">psutil · RAPL · TDP</span>
      </header>

      {/* Main */}
      <main className="main">
        {!report ? (
          <div className="empty-state">
            <div style={{ color: 'var(--accent)' }}>
              <Activity size={56} strokeWidth={1.5} />
            </div>
            <h2>Visualise your energy report</h2>
            <p>
              Run your workload with <code style={{ color: 'var(--text-muted)' }}>measure_energy()</code>{' '}
              from <code style={{ color: 'var(--text-muted)' }}>energy_monitor.py</code>, export the JSON,
              and drop it below — or load the built-in demo.
            </p>
            <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap', justifyContent: 'center' }}>
              <button className="btn btn-primary" onClick={() => setReport(DEMO_REPORT)}>
                <Zap size={14} /> Load demo report
              </button>
            </div>
            <div style={{ width: '100%', maxWidth: 520 }}>
              <UploadZone onReport={setReport} />
            </div>
          </div>
        ) : (
          <Dashboard report={report} onReset={() => setReport(null)} />
        )}
      </main>
    </div>
  );
}