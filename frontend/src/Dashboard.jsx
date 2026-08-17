import { useEffect, useMemo, useState } from "react";
import { io } from "socket.io-client";
import {
  Area,
  AreaChart,
  CartesianGrid,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis
} from "recharts";
import AttackMap from "./AttackMap";
import React from "react";
import "leaflet/dist/leaflet.css";

const API_URL = import.meta.env.VITE_API_URL || "http://localhost:5000";
const socket = io(API_URL);

const defaultSnapshot = {
  alerts: [],
  blockedIPs: [],
  metrics: {
    totalRequests: 0,
    anomalies: 0,
    blocked: 0,
    rps: 0,
    riskScore: 0,
    activeAttack: "Normal traffic"
  },
  insights: {
    title: "System stable",
    detail: "Traffic is within the learned baseline.",
    confidence: 0
  },
  simulation: {
    type: "normal",
    endsAt: 0
  }
};

export default function Dashboard() {
  const [snapshot, setSnapshot] = useState(defaultSnapshot);
  const [trafficData, setTrafficData] = useState([]);

  // Administrative action: the token is entered at action time rather than
  // being bundled into the browser application.
  const unblockIP = async (ip) => {
    const token = window.prompt("Enter AutoShield admin token to unblock this IP:");
    if (!token) return;

    const response = await fetch(`${API_URL}/unblock`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${token}`
      },
      body: JSON.stringify({ ip })
    });

    if (!response.ok) {
      const data = await response.json().catch(() => ({}));
      window.alert(data.error || "Unable to unblock IP");
    }
  };

  useEffect(() => {
    const onUpdate = (res) => {
      // 🔥 FIXED STATE MERGE (CRITICAL)
      setSnapshot(prev => ({
        ...prev,
        ...res,
        blockedIPs: res.blockedIPs ?? prev.blockedIPs ?? [],
        alerts: res.alerts ?? prev.alerts ?? []
      }));

      // 🔥 GRAPH ENGINE
      setTrafficData(prev => {
        const rps = res.metrics?.rps || 0;
        const anomalies = res.metrics?.anomalies || 0;

        const threshold = res.baseline?.threshold || 20;

        return [
          ...prev.slice(-30),
          {
            time: new Date().toLocaleTimeString(),
            requests: rps,
            anomalies,
            threshold,
            spike: rps > threshold ? rps : null
          }
        ];
      });
    };

    socket.on("update", onUpdate);

    return () => {
      socket.off("update", onUpdate);
    };
  }, []);

  const { alerts, blockedIPs, metrics, insights, baseline } = snapshot;

  const riskLabel = useMemo(() => {
    if (metrics.riskScore >= 85) return "Critical";
    if (metrics.riskScore >= 65) return "High";
    if (metrics.riskScore >= 40) return "Medium";
    return "Low";
  }, [metrics.riskScore]);

  return (
    <main className="dashboard-shell">

      <section className="dashboard-header">
        <div>
          <p className="eyebrow">The Mavericks | Ignition Hackathon 2026</p>
          <h1>AutoShield Autonomous Cyber Defense</h1>
          <p className="lede">Detect. Decide. Defend. Instantly.</p>
        </div>

        <div className={`risk-orb ${riskLabel.toLowerCase()}`}>
          <span>{metrics.riskScore}</span>
          <strong>{riskLabel}</strong>
          <small>dynamic risk score</small>
        </div>
      </section>

      <div className="metric-grid">
        <MetricCard title="Requests/sec" value={metrics.rps} detail={metrics.activeAttack} />
        <MetricCard title="Total requests" value={metrics.totalRequests} detail="log stream captured" />
        <MetricCard title="Anomalies" value={metrics.anomalies} detail="ML detections" />
        <MetricCard title="Blocked IPs" value={metrics.blocked} detail="autonomous actions" />
      </div>

      <section className="content-grid">
        <div className="card traffic-card">
          <div className="section-heading">
            <div>
              <p className="section-kicker">Real-Time Traffic Graph</p>
              <h2>Dynamic threshold monitoring</h2>
            </div>
            <span className="status-pill">{metrics.activeAttack}</span>
          </div>

          <ResponsiveContainer width="100%" height={280}>
            <AreaChart data={trafficData}>
              <defs>
                <linearGradient id="traffic" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#38bdf8" stopOpacity={0.6} />
                  <stop offset="95%" stopColor="#38bdf8" stopOpacity={0.04} />
                </linearGradient>
              </defs>

              <CartesianGrid stroke="#1e293b" strokeDasharray="3 3" />
              <XAxis dataKey="time" stroke="#94a3b8" minTickGap={28} />
              <YAxis stroke="#94a3b8" />
              <Tooltip contentStyle={{ background: "#0f172a", border: "1px solid #334155" }} />

              <Area dataKey="requests" stroke="#38bdf8" fill="url(#traffic)" strokeWidth={2} />

              <Line dataKey="threshold" stroke="#f97316" strokeDasharray="5 5" dot={false} />

              <Line dataKey="spike" stroke="#ef4444" strokeWidth={3} dot={false} />
            </AreaChart>
          </ResponsiveContainer>
        </div>

        <div className="card ai-card">
          <p className="section-kicker">AI Insights Panel</p>
          <h2>{insights.title}</h2>
          <p>{insights.detail}</p>

          <div className="confidence-meter">
            <span style={{ width: `${Math.min(insights.confidence || 0, 100)}%` }} />
          </div>
          <small>{insights.confidence || 0}% model confidence</small>

          <ResponsiveContainer width="100%" height={150}>
            <LineChart data={trafficData}>
              <XAxis dataKey="time" hide />
              <YAxis hide />
              <Tooltip contentStyle={{ background: "#0f172a", border: "1px solid #334155" }} />

              <Line dataKey="anomalies" stroke="#fb7185" strokeWidth={2} dot={false} />
              <Line dataKey="requests" stroke="#22c55e" strokeWidth={2} dot={false} />
            </LineChart>
          </ResponsiveContainer>
        </div>
      </section>

      <AttackMap alerts={alerts} />

      <section className="content-grid lower-grid">
        <AlertFeed alerts={alerts} />
        <BlockedLog blockedIPs={blockedIPs} unblockIP={unblockIP} />
      </section>
    </main>
  );
}

// 🔹 COMPONENTS
function MetricCard({ title, value, detail }) {
  return (
    <div className="card metric-card">
      <p>{title}</p>
      <strong>{value || 0}</strong>
      <span>{detail}</span>
    </div>
  );
}

function AlertFeed({ alerts }) {
  return (
    <div className="card table-card">
      <p className="section-kicker">Active Alerts Feed</p>
      <h2>Classified threats</h2>

      <div className="event-list">
        {alerts.length === 0 && <p className="empty-state">No active anomalies detected.</p>}
        {alerts.slice(0, 8).map((alert) => (
          <article key={alert.ip + alert.timestamp}>
            <div>
              <strong>{alert.attackType}</strong>
              <span>{alert.ip} | {alert.country}</span>
            </div>
            <div>
              <b>{alert.severity}</b>
            </div>
          </article>
        ))}
      </div>
    </div>
  );
}

function BlockedLog({ blockedIPs = [], unblockIP }) {
  return (
    <div className="card table-card">
      <p className="section-kicker">Blocked IP Log</p>
      <h2>Autonomous action history</h2>

      <div className="event-list compact">
        {blockedIPs.length === 0 && <p className="empty-state">No IPs blocked yet.</p>}

        {blockedIPs.slice(0, 8).map((entry) => (
          <article key={entry.ip + entry.timestamp}>
            <div>
              <strong>{entry.ip}</strong>
              <span>{entry.reason || "Blocked"}</span>
            </div>

            <div style={{ display: "flex", gap: "10px", alignItems: "center" }}>
              <small>{new Date(entry.timestamp).toLocaleTimeString()}</small>

              <button onClick={() => unblockIP(entry.ip)}>
                Unblock
              </button>
            </div>
          </article>
        ))}
      </div>
    </div>
  );
}