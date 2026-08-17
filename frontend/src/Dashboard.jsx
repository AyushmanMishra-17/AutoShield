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
  const [connectionStatus, setConnectionStatus] = useState("connecting");

  useEffect(() => {
    // Create socket connection with reconnection settings
    const socket = io(API_URL, {
      transports: ['websocket', 'polling'],
      reconnection: true,
      reconnectionDelay: 1000,
      reconnectionDelayMax: 5000,
      reconnectionAttempts: Infinity
    });

    const onUpdate = (res) => {
      console.log("📥 Received update:", {
        blockedCount: res.blockedIPs?.length || 0,
        alertCount: res.alerts?.length || 0,
        rps: res.metrics?.rps || 0
      });

      setSnapshot(prev => ({
        ...prev,
        alerts: res.alerts || prev.alerts,
        blockedIPs: res.blockedIPs || prev.blockedIPs,
        metrics: res.metrics || prev.metrics,
        insights: res.insights || prev.insights
      }));

      // Update traffic graph
      setTrafficData(prev => {
        const rps = res.metrics?.rps || 0;
        const anomalies = res.metrics?.anomalies || 0;

        // Dynamic threshold (AI baseline)
        const threshold = Math.max(20, rps * 0.6 + anomalies * 2);

        const next = [
          ...prev.slice(-30),
          {
            time: new Date().toLocaleTimeString(),
            requests: rps,
            anomalies,
            threshold,
            spike: rps > threshold ? rps : null
          }
        ];

        return next;
      });
    };

    const onConnect = () => {
      console.log("✅ Connected to server");
      setConnectionStatus("connected");
    };

    const onDisconnect = () => {
      console.log("❌ Disconnected from server");
      setConnectionStatus("disconnected");
    };

    const onReconnect = (attemptNumber) => {
      console.log(`🔄 Reconnected after ${attemptNumber} attempts`);
      setConnectionStatus("connected");
    };

    const onReconnecting = (attemptNumber) => {
      console.log(`🔄 Reconnecting... attempt ${attemptNumber}`);
      setConnectionStatus("reconnecting");
    };

    socket.on("connect", onConnect);
    socket.on("disconnect", onDisconnect);
    socket.on("reconnect", onReconnect);
    socket.on("reconnecting", onReconnecting);
    socket.on("update", onUpdate);

    return () => {
      socket.off("connect", onConnect);
      socket.off("disconnect", onDisconnect);
      socket.off("reconnect", onReconnect);
      socket.off("reconnecting", onReconnecting);
      socket.off("update", onUpdate);
      socket.disconnect();
    };
  }, []);

  const { alerts, blockedIPs, metrics, insights } = snapshot;

  const riskLabel = useMemo(() => {
    if (metrics.riskScore >= 85) return "Critical";
    if (metrics.riskScore >= 65) return "High";
    if (metrics.riskScore >= 40) return "Medium";
    return "Low";
  }, [metrics.riskScore]);

  return (
    <main className="dashboard-shell">

      {connectionStatus !== "connected" && (
        <div className="attack-banner" style={{ background: "rgba(59, 130, 246, 0.2)", borderColor: "#3b82f6", color: "#dbeafe" }}>
          {connectionStatus === "reconnecting" ? "🔄 Reconnecting to server..." : "⚠️ Disconnected - attempting to reconnect..."}
        </div>
      )}

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

              {/* RPS */}
              <Area
                dataKey="requests"
                stroke="#38bdf8"
                fill="url(#traffic)"
                strokeWidth={2}
              />

              {/* Threshold */}
              <Line
                dataKey="threshold"
                stroke="#f97316"
                strokeDasharray="5 5"
                dot={false}
              />

              {/* 🔥 SPIKE DETECTION */}
              <Line
                dataKey="spike"
                stroke="#ef4444"
                strokeWidth={3}
                dot={false}
              />
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
        <BlockedLog blockedIPs={blockedIPs} />
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
        {alerts.slice(0, 8).map((alert, index) => (
          <article key={`${alert.ip}-${alert.timestamp}-${index}`}>
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

function BlockedLog({ blockedIPs }) {
  return (
    <div className="card table-card">
      <p className="section-kicker">Blocked IP Log</p>
      <h2>Autonomous action history</h2>

      <div className="event-list compact">
        {blockedIPs.length === 0 && <p className="empty-state">No IPs blocked yet.</p>}
        {blockedIPs.slice(0, 8).map((entry, index) => (
          <article key={`${entry.ip}-${entry.timestamp}-${index}`}>
            <div>
              <strong>{entry.ip}</strong>
              <small>{entry.reason}</small>
            </div>
            <small>{new Date(entry.timestamp).toLocaleTimeString()}</small>
          </article>
        ))}
      </div>
    </div>
  );
}